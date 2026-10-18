// Copyright (C) 2026 Ryan Daum <ryan.daum@gmail.com> This program is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Affero General Public License as published by the Free Software Foundation,
// version 3.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.

//! The RuneWorld sequencer's block loop (ADR 0006 decisions 1 and 2), without threads or clocks.
//!
//! A [`Sequencer`] owns the [`BlockDriver`] and the chain tip. The caller (the daemon's block
//! thread, or a test) supplies wall-clock readings and inputs in arrival order:
//!
//! 1. [`Sequencer::open_block`] computes the next block context, `height = h`,
//!    `timestamp = max(ts_{h-1}, floor(wall))`, `seed = SHA-256("rw/v1/seed" || state_root_{h-1}
//!    || h_be64)`, refusing to open when the clock is too far behind or has jumped (decision 1,
//!    time tolerance), then calls `begin_block`.
//! 2. [`Sequencer::submit`] runs one input (an envelope or a sequencer input) to quiescence, if it
//!    fits the block's limits (2,048 inputs, 512 KiB of command batch). Its events have already
//!    gone to the input's session (soft confirmation) when this returns.
//! 3. [`Sequencer::seal`] ends the block: state root, event batch in its canonical encoding
//!    ([`crate::tasks::block_events`]), the `moor-block` header and roots, and the signature. It
//!    returns the sealed block and its seal notice.
//!
//! [`SequencerHooks`] are the journal and signing-guard hook points of decision 4 (S1-2): an
//! input is offered to `before_input` before it runs, a header to `before_sign` before it is
//! signed. [`replay_block`] re-executes a published block and checks its roots.
//!
//! With a [`CheckpointPolicy`] the sequencer also writes a checkpoint (ADR 0006 decision 7) after
//! every `every`-th seal: the canonical state at that height, whose hash is its state root.

use crate::tasks::{
    TaskId,
    block_driver::{BlockDriver, BlockEvent, BlockInput, BlockOutput},
    block_events,
    envelope_admission::{AdmissionRejection, Admitted, OnAdmitted},
};
use moor_block::{
    Block, BlockHeader, ChainParams, ChainTip, CommandBatch, CommandEntry, EventBatch, EventEntry,
    FormatError, Hash, MAX_COMMAND_BATCH_BYTES, MAX_COMMANDS_PER_BLOCK, SealedBlock,
    SequencerInputKind, SequencerKey, durable::RelationHash, seed_for,
};
use moor_common::{
    deterministic::BlockContext,
    tasks::{NoopClientSession, SchedulerError, Session},
};
use moor_db::state_root::checkpoint::CheckpointDir;
use moor_db::state_root::StateRoot;
use moor_var::{Obj, Var};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

/// The block loop's parameters. Defaults are ADR 0006's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequencerParams {
    /// Block cadence (1 s).
    pub cadence: Duration,
    /// Inputs per block (at most the format's 2,048).
    pub max_inputs: usize,
    /// Encoded command batch bytes per block (at most the format's 512 KiB).
    pub max_batch_bytes: usize,
    /// Refuse to open a block when the clock reads more than this many seconds before the
    /// previous block's timestamp.
    pub max_behind_secs: u64,
    /// Refuse to open a block when the wall clock has run this many seconds ahead of the monotonic
    /// time elapsed since the previous block opened (a clock jump).
    pub max_jump_secs: u64,
}

impl Default for SequencerParams {
    fn default() -> Self {
        Self {
            cadence: Duration::from_secs(1),
            max_inputs: MAX_COMMANDS_PER_BLOCK,
            max_batch_bytes: MAX_COMMAND_BATCH_BYTES,
            max_behind_secs: 2,
            max_jump_secs: 60,
        }
    }
}

/// Blocks between checkpoints (ADR 0006 decision 7: one an hour at 1 s blocks).
pub const DEFAULT_CHECKPOINT_EVERY: u64 = 3_600;
/// Checkpoints kept locally (a day of hourly checkpoints).
pub const DEFAULT_CHECKPOINT_KEEP: usize = 24;
/// Blocks between published checkpoints (daily at 1 s blocks).
pub const DEFAULT_CHECKPOINT_PUBLISH_EVERY: u64 = 86_400;

/// When and where the sequencer writes checkpoints.
#[derive(Clone, Debug)]
pub struct CheckpointPolicy {
    pub dir: CheckpointDir,
    /// Write one after every seal at a height divisible by this (0 = never).
    pub every: u64,
    /// Keep the newest this many locally.
    pub keep: usize,
    /// Mark one for publication at heights divisible by this (0 = never).
    pub publish_every: u64,
    /// Recorded in the checkpoint header (informative).
    pub fork_commit: String,
}

impl CheckpointPolicy {
    /// ADR 0006's cadence in `dir`.
    #[must_use]
    pub fn new(dir: CheckpointDir, fork_commit: impl Into<String>) -> Self {
        Self {
            dir,
            every: DEFAULT_CHECKPOINT_EVERY,
            keep: DEFAULT_CHECKPOINT_KEEP,
            publish_every: DEFAULT_CHECKPOINT_PUBLISH_EVERY,
            fork_commit: fork_commit.into(),
        }
    }

    fn due(&self, height: u64) -> bool {
        self.every > 0 && height > 0 && height.is_multiple_of(self.every)
    }
}

/// A checkpoint written after a seal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrittenCheckpoint {
    pub height: u64,
    pub state_root: Hash,
    pub path: PathBuf,
    pub bytes: u64,
    /// Due for publication (`publish_every`).
    pub publish: bool,
    /// Capture, encoding and the fsynced write.
    pub time: Duration,
}

/// Why the sequencer refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum SequencerError {
    #[error(
        "clock reads {wall} s, more than {limit} s behind the previous block's timestamp {prev}"
    )]
    ClockBehind { wall: u64, prev: u64, limit: u64 },
    #[error("clock jumped forward: reads {wall} s where about {expected} s was expected")]
    ClockJumped { wall: u64, expected: u64 },
    #[error("a block is already open")]
    AlreadyOpen,
    #[error("no block is open")]
    NotOpen,
    #[error("the input does not fit the open block's limits")]
    BlockFull,
    #[error("block format: {0}")]
    Format(#[from] FormatError),
    #[error("state root: {0}")]
    StateRoot(String),
    #[error("event encoding: {0}")]
    EventEncoding(String),
    #[error("{0} hook refused: {1}")]
    Hook(&'static str, String),
    #[error("checkpoint: {0}")]
    Checkpoint(String),
}

/// The journal and signing-guard hook points of ADR 0006 decision 4. All default to accepting.
/// An error stops the step it guards: the input does not run, or the header is not signed.
pub trait SequencerHooks: Send {
    /// A block was opened with this context (journal `Open{height, timestamp, seed}`).
    fn opened(&mut self, _ctx: &BlockContext) -> Result<(), String> {
        Ok(())
    }
    /// `entry` is about to run as `command_index` of block `height`: journal it and make it
    /// durable before any of its effects.
    fn before_input(
        &mut self,
        _height: u64,
        _command_index: u64,
        _entry: &CommandEntry,
    ) -> Result<(), String> {
        Ok(())
    }
    /// Group commit: `entries` are about to run as command indices `first_command_index`, ... of
    /// block `height`. Journal them all and make them durable once. Defaults to `before_input`
    /// per entry.
    fn before_inputs(
        &mut self,
        height: u64,
        first_command_index: u64,
        entries: &[CommandEntry],
    ) -> Result<(), String> {
        entries
            .iter()
            .enumerate()
            .try_for_each(|(i, e)| self.before_input(height, first_command_index + i as u64, e))
    }
    /// The unsigned block is final; store it and record `(height, header_hash)` in the signing
    /// guard before the signature is made.
    fn before_sign(
        &mut self,
        _header: &BlockHeader,
        _commands: &CommandBatch,
        _events: &EventBatch,
    ) -> Result<(), String> {
        Ok(())
    }
    /// The block is sealed and signed.
    fn sealed(&mut self, _block: &SealedBlock) -> Result<(), String> {
        Ok(())
    }
    /// The state root of block `height` with the per-relation hashes that feed it, as soon as
    /// `end_block` has computed them (fork API request R3). Derived data: an error is logged and
    /// never stops the seal.
    fn state_root(&mut self, _height: u64, _root: &StateRoot) -> Result<(), String> {
        Ok(())
    }
}

/// Hooks that accept everything (no journal).
pub struct NoHooks;
impl SequencerHooks for NoHooks {}

/// The broadcast after a seal: `{height, header_hash, state_root}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealNotice {
    pub height: u64,
    pub header_hash: Hash,
    pub state_root: Hash,
}

/// What one submitted input did.
#[derive(Debug)]
pub struct InputReceipt {
    pub height: u64,
    pub command_index: u64,
    pub task_id: Option<TaskId>,
    pub result: Option<Result<Var, SchedulerError>>,
    /// The admission verdict, for an envelope.
    pub admission: Option<Result<Admitted, AdmissionRejection>>,
    /// Events the input added to the batch.
    pub events: usize,
    /// The entry's encoded size in the command batch.
    pub entry_bytes: usize,
}

/// A sealed block and what it took.
#[derive(Debug)]
pub struct Sealed {
    pub block: SealedBlock,
    pub notice: SealNotice,
    /// `end_block` including the state root (the O(state) pause before the next block).
    pub end_block_time: Duration,
    /// Encoding the event batch, building the roots and signing.
    pub seal_time: Duration,
    /// Encoded command batch, event batch and signed header bytes.
    pub command_bytes: usize,
    pub event_bytes: usize,
    pub header_bytes: usize,
    /// Tasks cancelled at the boundary, and transaction conflicts (always zero when serial).
    pub abandoned: usize,
    pub conflicts: u64,
    /// The checkpoint written after this seal, if one was due.
    pub checkpoint: Option<WrittenCheckpoint>,
}

struct OpenBlock {
    ctx: BlockContext,
    entries: Vec<CommandEntry>,
    /// Sum of the encoded entries (the batch adds its array head).
    entry_bytes: usize,
    /// Inputs up to this command index are journalled already (group commit or recovery).
    journalled: u64,
}

/// CBOR array head size for `n` entries.
fn array_head_len(n: usize) -> usize {
    match n {
        0..24 => 1,
        24..256 => 2,
        256..65_536 => 3,
        _ => 5,
    }
}

/// The block context that follows `tip` at wall-clock second `wall`.
#[must_use]
pub fn next_context(tip: &ChainTip, wall: u64) -> BlockContext {
    let height = tip.height + 1;
    BlockContext {
        height,
        timestamp: wall.max(tip.timestamp),
        seed: seed_for(&tip.state_root, height),
    }
}

/// The block-driver input for a command batch entry.
fn block_input(entry: &CommandEntry) -> Option<BlockInput> {
    match entry {
        CommandEntry::Envelope(_) => None,
        CommandEntry::Sequencer(input) => match input.kind {
            SequencerInputKind::Disconnected => Some(BlockInput::SequencerDisconnect {
                player: Obj::mk_id(input.player),
            }),
        },
    }
}

/// The canonical event batch of a block's events.
pub fn event_batch(events: &[BlockEvent]) -> Result<EventBatch, SequencerError> {
    let entries = events
        .iter()
        .map(|event| {
            let (seq, command_index, recipient, event) = block_events::entry_parts(event)
                .map_err(|e| SequencerError::EventEncoding(e.to_string()))?;
            Ok(EventEntry {
                seq,
                command_index,
                recipient,
                event,
            })
        })
        .collect::<Result<Vec<_>, SequencerError>>()?;
    Ok(EventBatch::new(entries)?)
}

fn state_root_of(out: &BlockOutput) -> Result<Hash, SequencerError> {
    match &out.state_root {
        Some(Ok(root)) => Ok(root.root),
        Some(Err(e)) => Err(SequencerError::StateRoot(e.to_string())),
        None => Err(SequencerError::StateRoot(
            "the block driver did not take the root".into(),
        )),
    }
}

/// The sequencer: block driver, chain tip, signing key.
pub struct Sequencer {
    driver: BlockDriver,
    key: SequencerKey,
    genesis_root: Hash,
    tip: ChainTip,
    params: SequencerParams,
    hooks: Box<dyn SequencerHooks>,
    open: Option<OpenBlock>,
    /// The previous opening: (wall second, monotonic instant), for jump detection.
    last_open: Option<(u64, Instant)>,
    checkpoints: Option<CheckpointPolicy>,
}

impl Sequencer {
    /// A sequencer continuing after `tip`. The driver's committed state must be `tip`'s.
    pub fn new(
        mut driver: BlockDriver,
        key: SequencerKey,
        genesis_root: Hash,
        tip: ChainTip,
        params: SequencerParams,
        hooks: Box<dyn SequencerHooks>,
    ) -> Self {
        driver.set_state_root_at_end_block(true);
        Self {
            driver,
            key,
            genesis_root,
            tip,
            params: SequencerParams {
                max_inputs: params.max_inputs.min(MAX_COMMANDS_PER_BLOCK),
                max_batch_bytes: params.max_batch_bytes.min(MAX_COMMAND_BATCH_BYTES),
                ..params
            },
            hooks,
            open: None,
            last_open: None,
            checkpoints: None,
        }
    }

    /// Write checkpoints after seals under `policy` (none by default).
    pub fn set_checkpoints(&mut self, policy: Option<CheckpointPolicy>) {
        self.checkpoints = policy;
    }

    #[must_use]
    pub fn checkpoints(&self) -> Option<&CheckpointPolicy> {
        self.checkpoints.as_ref()
    }

    /// Write a checkpoint of the state at the tip into `dir` now (between blocks only), and keep
    /// the newest `keep` there.
    pub fn write_checkpoint(
        &self,
        dir: &CheckpointDir,
        keep: usize,
        fork_commit: &str,
    ) -> Result<WrittenCheckpoint, SequencerError> {
        if self.open.is_some() {
            return Err(SequencerError::AlreadyOpen);
        }
        let failed = |e: String| SequencerError::Checkpoint(e);
        let started = Instant::now();
        let capture = self
            .driver
            .capture_checkpoint()
            .map_err(|e| failed(e.to_string()))?;
        let header_hash = if self.tip.height == 0 {
            [0; 32]
        } else {
            self.tip.hash
        };
        let (header, bytes) = capture
            .encode(self.tip.height, header_hash, fork_commit)
            .map_err(|e| failed(e.to_string()))?;
        if header.state_root != self.tip.state_root {
            return Err(failed(format!(
                "the captured state has root {}, the tip {} has {}",
                moor_block::hex(&header.state_root),
                self.tip.height,
                moor_block::hex(&self.tip.state_root)
            )));
        }
        let path = dir
            .write(&header, &bytes)
            .map_err(|e| failed(e.to_string()))?;
        dir.prune(keep.max(1)).map_err(|e| failed(e.to_string()))?;
        Ok(WrittenCheckpoint {
            height: header.height,
            state_root: header.state_root,
            path,
            bytes: bytes.len() as u64,
            publish: false,
            time: started.elapsed(),
        })
    }

    /// The checkpoint due after the seal that made the current tip, if any. A failure is logged
    /// and skipped: checkpoints shorten recovery, they are not part of the chain.
    fn checkpoint_after_seal(&self) -> Option<WrittenCheckpoint> {
        let policy = self.checkpoints.as_ref()?;
        let height = self.tip.height;
        if !policy.due(height) {
            return None;
        }
        match self.write_checkpoint(&policy.dir, policy.keep, &policy.fork_commit) {
            Ok(written) => Some(WrittenCheckpoint {
                publish: policy.publish_every > 0 && height.is_multiple_of(policy.publish_every),
                ..written
            }),
            Err(e) => {
                tracing::warn!(height, error = %e, "checkpoint not written");
                None
            }
        }
    }

    /// A sequencer at genesis: the driver's current state root is the genesis root.
    pub fn genesis(
        driver: BlockDriver,
        key: SequencerKey,
        params: SequencerParams,
        hooks: Box<dyn SequencerHooks>,
    ) -> Result<Self, SequencerError> {
        let root = driver
            .state_root()
            .map_err(|e| SequencerError::StateRoot(e.to_string()))?
            .root;
        Ok(Self::new(
            driver,
            key,
            root,
            ChainTip::genesis(&root),
            params,
            hooks,
        ))
    }

    #[must_use]
    pub fn tip(&self) -> &ChainTip {
        &self.tip
    }

    #[must_use]
    pub fn genesis_root(&self) -> &Hash {
        &self.genesis_root
    }

    #[must_use]
    pub fn params(&self) -> &SequencerParams {
        &self.params
    }

    /// The chain parameters a replayer verifies signatures with.
    #[must_use]
    pub fn chain_params(&self) -> ChainParams {
        ChainParams {
            genesis_root: self.genesis_root,
            sequencer: self.key.address(),
        }
    }

    #[must_use]
    pub fn driver(&self) -> &BlockDriver {
        &self.driver
    }

    /// The open block's context, if one is open.
    #[must_use]
    pub fn open_context(&self) -> Option<BlockContext> {
        self.open.as_ref().map(|o| o.ctx)
    }

    /// Inputs in the open block.
    #[must_use]
    pub fn open_inputs(&self) -> usize {
        self.open.as_ref().map_or(0, |o| o.entries.len())
    }

    /// The context the next block would get at wall-clock second `wall` and monotonic time
    /// `now`, or why the clock is unusable.
    pub fn check_clock(&self, wall: u64, now: Instant) -> Result<BlockContext, SequencerError> {
        if wall.saturating_add(self.params.max_behind_secs) < self.tip.timestamp {
            return Err(SequencerError::ClockBehind {
                wall,
                prev: self.tip.timestamp,
                limit: self.params.max_behind_secs,
            });
        }
        if let Some((last_wall, last_now)) = self.last_open {
            let expected = last_wall + now.saturating_duration_since(last_now).as_secs();
            if wall > expected.saturating_add(self.params.max_jump_secs) {
                return Err(SequencerError::ClockJumped { wall, expected });
            }
        }
        Ok(next_context(&self.tip, wall))
    }

    /// Open the next block at wall-clock second `wall` (monotonic `now`).
    pub fn open_block(&mut self, wall: u64, now: Instant) -> Result<BlockContext, SequencerError> {
        if self.open.is_some() {
            return Err(SequencerError::AlreadyOpen);
        }
        let ctx = self.check_clock(wall, now)?;
        self.hooks
            .opened(&ctx)
            .map_err(|e| SequencerError::Hook("opened", e))?;
        self.driver.begin_block(ctx);
        self.last_open = Some((wall, now));
        self.open = Some(OpenBlock {
            ctx,
            entries: Vec::new(),
            entry_bytes: 0,
            journalled: 0,
        });
        Ok(ctx)
    }

    /// Whether `entry` fits the open block (false when none is open).
    #[must_use]
    pub fn fits(&self, entry: &CommandEntry) -> bool {
        self.fitting(std::slice::from_ref(entry)) == 1
    }

    /// How many of `entries`, taken in order, fit the open block after its current inputs.
    #[must_use]
    pub fn fitting(&self, entries: &[CommandEntry]) -> usize {
        let Some(open) = &self.open else {
            return 0;
        };
        let mut bytes = open.entry_bytes;
        let mut n = open.entries.len();
        for (i, entry) in entries.iter().enumerate() {
            bytes += entry.encode().len();
            n += 1;
            if n > self.params.max_inputs || array_head_len(n) + bytes > self.params.max_batch_bytes
            {
                return i;
            }
        }
        entries.len()
    }

    /// Group commit (ADR 0006 decision 4): journal the longest prefix of `entries` that fits the
    /// open block as its next command indices, making them durable with one write, before any of
    /// them runs. Returns how many were journalled; the caller then [`Self::submit`]s exactly
    /// those, in order. Entries must pass [`CommandEntry::check`].
    pub fn journal_inputs(&mut self, entries: &[CommandEntry]) -> Result<usize, SequencerError> {
        let n = self.fitting(entries);
        let open = self.open.as_mut().ok_or(SequencerError::NotOpen)?;
        if open.journalled != open.entries.len() as u64 {
            return Err(SequencerError::Hook(
                "before_inputs",
                "journalled inputs have not all run".into(),
            ));
        }
        if n == 0 {
            return Ok(0);
        }
        let first = open.entries.len() as u64 + 1;
        self.hooks
            .before_inputs(open.ctx.height, first, &entries[..n])
            .map_err(|e| SequencerError::Hook("before_inputs", e))?;
        open.journalled = first + n as u64 - 1;
        Ok(n)
    }

    /// Run one input to quiescence as the next command of the open block. Its output goes to
    /// `session` as it commits. `on_admitted` runs after an envelope's admission, before its task.
    pub fn submit(
        &mut self,
        entry: CommandEntry,
        session: Arc<dyn Session>,
        on_admitted: Option<OnAdmitted>,
    ) -> Result<InputReceipt, SequencerError> {
        entry.check()?;
        if !self.fits(&entry) {
            return Err(if self.open.is_none() {
                SequencerError::NotOpen
            } else {
                SequencerError::BlockFull
            });
        }
        let open = self.open.as_mut().ok_or(SequencerError::NotOpen)?;
        let height = open.ctx.height;
        let command_index = open.entries.len() as u64 + 1;
        if command_index > open.journalled {
            self.hooks
                .before_input(height, command_index, &entry)
                .map_err(|e| SequencerError::Hook("before_input", e))?;
            open.journalled = command_index;
        }
        let events_before = self.driver.event_count();
        let entry_bytes = entry.encode().len();
        let outcome = match (&entry, block_input(&entry)) {
            (CommandEntry::Envelope(bytes), _) => {
                self.driver
                    .submit_envelope_with(bytes, session, on_admitted)
            }
            (_, Some(input)) => self.driver.submit(input, session),
            (CommandEntry::Sequencer(_), None) => unreachable!("every sequencer input maps"),
        };
        debug_assert_eq!(outcome.command_index, command_index);
        let receipt = InputReceipt {
            height,
            command_index: outcome.command_index,
            task_id: outcome.task_id,
            result: outcome.result.clone(),
            admission: outcome.admission.clone(),
            events: 0,
            entry_bytes,
        };
        let events = self.driver.event_count() - events_before;
        open.entries.push(entry);
        open.entry_bytes += entry_bytes;
        Ok(InputReceipt { events, ..receipt })
    }

    /// End and seal the open block.
    pub fn seal(&mut self) -> Result<Sealed, SequencerError> {
        let open = self.open.take().ok_or(SequencerError::NotOpen)?;
        let started = Instant::now();
        let out = self.driver.end_block();
        let end_block_time = started.elapsed();
        let started = Instant::now();
        let state_root = state_root_of(&out)?;
        if let Some(Ok(full)) = &out.state_root
            && let Err(e) = self.hooks.state_root(open.ctx.height, full)
        {
            tracing::warn!(height = open.ctx.height, "recording relation hashes: {e}");
        }
        let events = event_batch(&out.events)?;
        let commands = CommandBatch::new(open.entries)?;
        let header = self.tip.next_header(
            open.ctx.timestamp,
            commands.root(),
            events.root(),
            state_root,
        );
        debug_assert_eq!(header.seed, open.ctx.seed);
        let mut sealed = self.sign_and_store(header, commands, events, started)?;
        sealed.end_block_time = end_block_time;
        sealed.abandoned = out.abandoned.len();
        sealed.conflicts = out.conflicts;
        Ok(sealed)
    }

    /// Seal steps after the header is final: `before_sign` (store the unsigned block, record it in
    /// the signing guard), sign, check, `sealed` (store the signature), advance the tip.
    fn sign_and_store(
        &mut self,
        header: BlockHeader,
        commands: CommandBatch,
        events: EventBatch,
        started: Instant,
    ) -> Result<Sealed, SequencerError> {
        self.hooks
            .before_sign(&header, &commands, &events)
            .map_err(|e| SequencerError::Hook("before_sign", e))?;
        let signed = header
            .sign(&self.key, &self.genesis_root)
            .map_err(FormatError::from)?;
        let block = SealedBlock {
            header: signed,
            commands,
            events,
        };
        block.check(&self.tip)?;
        self.hooks
            .sealed(&block)
            .map_err(|e| SequencerError::Hook("sealed", e))?;
        let seal_time = started.elapsed();
        self.tip = block.tip();
        let notice = SealNotice {
            height: self.tip.height,
            header_hash: self.tip.hash,
            state_root: self.tip.state_root,
        };
        let checkpoint = self.checkpoint_after_seal();
        Ok(Sealed {
            command_bytes: block.commands.encode().len(),
            event_bytes: block.events.encode().len(),
            header_bytes: block.header.encode().len(),
            block,
            notice,
            end_block_time: Duration::ZERO,
            seal_time,
            abandoned: 0,
            conflicts: 0,
            checkpoint,
        })
    }

    /// Crash recovery (ADR 0006 decision 4, recovery step 3): re-execute the block the journal
    /// left open, under its recorded context and with its journalled inputs, and seal it. The
    /// inputs are already durable, so they are not journalled again; their events go nowhere but
    /// the batch (the hosts that saw them before the crash are gone).
    pub fn reopen(
        &mut self,
        ctx: BlockContext,
        inputs: Vec<CommandEntry>,
    ) -> Result<Sealed, SequencerError> {
        if self.open.is_some() {
            return Err(SequencerError::AlreadyOpen);
        }
        let height = self.tip.height + 1;
        if ctx.height != height {
            return Err(FormatError::Height {
                expected: height,
                found: ctx.height,
            }
            .into());
        }
        if ctx.seed != seed_for(&self.tip.state_root, height) {
            return Err(FormatError::Seed { height }.into());
        }
        if ctx.timestamp < self.tip.timestamp {
            return Err(FormatError::TimestampDecreases { height }.into());
        }
        self.driver.begin_block(ctx);
        self.open = Some(OpenBlock {
            ctx,
            entries: Vec::new(),
            entry_bytes: 0,
            journalled: inputs.len() as u64,
        });
        for entry in inputs {
            let session: Arc<dyn Session> = Arc::new(NoopClientSession::new());
            self.submit(entry, session, None)?;
        }
        self.seal()
    }

    /// Crash recovery when the database already holds the effects of a stored, unsigned block
    /// (the crash came after `end_block`, before the signature was stored): finish its seal
    /// without executing it again.
    pub fn seal_stored(
        &mut self,
        header: BlockHeader,
        commands: CommandBatch,
        events: EventBatch,
    ) -> Result<Sealed, SequencerError> {
        if self.open.is_some() {
            return Err(SequencerError::AlreadyOpen);
        }
        self.tip.check_next(&header)?;
        let full = self
            .driver
            .state_root()
            .map_err(|e| SequencerError::StateRoot(e.to_string()))?;
        let root = full.root;
        if root != header.state_root {
            return Err(SequencerError::StateRoot(format!(
                "the database root {} is not block {}'s",
                moor_block::hex(&root),
                header.height
            )));
        }
        if let Err(e) = self.hooks.state_root(header.height, &full) {
            tracing::warn!(height = header.height, "recording relation hashes: {e}");
        }
        self.sign_and_store(header, commands, events, Instant::now())
    }

    /// Stop the scheduler under the driver.
    pub fn shutdown(self) -> Result<(), SchedulerError> {
        self.driver.shutdown()
    }
}

/// Why a replayed block did not match its header.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplayMismatch {
    #[error("height {height}: seed does not follow the previous state root")]
    Seed { height: u64 },
    #[error("height {height}: events_root differs (first differing event seq {seq:?})")]
    EventsRoot { height: u64, seq: Option<u64> },
    #[error("height {height}: state_root differs (first differing relation {relation:?})")]
    StateRoot {
        height: u64,
        relation: Option<&'static str>,
    },
    #[error("height {height}: {reason}")]
    Failed { height: u64, reason: String },
}

/// What a replayed block produced, whether or not it matched (fork API request R5): the whole
/// [`BlockOutput`] (per-input outcomes and admission verdicts, events, abandoned tasks), the
/// canonical event batch, the state root with its per-relation hashes, and every check that failed,
/// in check order.
#[derive(Debug)]
pub struct ReplayedBlock {
    /// The driver's output for the block.
    pub output: BlockOutput,
    /// The canonical event batch of the replay.
    pub events: EventBatch,
    /// The replayed state root and its per-relation hashes.
    pub state_root: StateRoot,
    /// `events_root` first, then `state_root`; empty when the block matched.
    pub mismatches: Vec<ReplayMismatch>,
}

impl ReplayedBlock {
    /// Whether every check passed.
    #[must_use]
    pub fn matched(&self) -> bool {
        self.mismatches.is_empty()
    }
}

/// What a published block is compared with beyond its header.
#[derive(Clone, Copy, Debug, Default)]
pub struct Published<'a> {
    /// The node's event batch (names the first differing event on an `events_root` mismatch).
    pub events: Option<&'a EventBatch>,
    /// The sequencer's per-relation hashes for the block (names the differing relation on a
    /// `state_root` mismatch).
    pub relations: Option<&'a [RelationHash]>,
}

/// The block-store form of a state root's per-relation digests.
#[must_use]
pub fn relation_hashes(root: &StateRoot) -> Vec<RelationHash> {
    root.relations
        .iter()
        .map(|r| RelationHash {
            name: r.name.to_string(),
            hash: r.hash,
            entries: r.entries,
        })
        .collect()
}

/// The first relation whose replayed hash differs from `published`.
fn first_differing_relation(root: &StateRoot, published: &[RelationHash]) -> Option<&'static str> {
    root.relations
        .iter()
        .find(|ours| {
            published
                .iter()
                .find(|theirs| theirs.name == ours.name)
                .is_none_or(|theirs| theirs.hash != ours.hash)
        })
        .map(|r| r.name)
}

/// Re-execute `block` (which follows `prev`) on `driver` and return everything it produced, with
/// the checks of [`replay_block`] as data. `Err` only when the block could not be run at all (the
/// seed rule fails before anything executes) or its output could not be encoded.
pub fn replay_block_full(
    driver: &mut BlockDriver,
    prev: &ChainTip,
    block: &Block,
    published: Published<'_>,
) -> Result<ReplayedBlock, ReplayMismatch> {
    let header = &block.header;
    let height = header.height;
    if header.seed != seed_for(&prev.state_root, height) {
        return Err(ReplayMismatch::Seed { height });
    }
    driver.set_state_root_at_end_block(true);
    driver.begin_block(BlockContext {
        height,
        timestamp: header.timestamp,
        seed: header.seed,
    });
    for entry in block.commands.entries() {
        let session: Arc<dyn Session> = Arc::new(NoopClientSession::new());
        match (entry, block_input(entry)) {
            (CommandEntry::Envelope(bytes), _) => {
                driver.submit_envelope(bytes, session);
            }
            (_, Some(input)) => {
                driver.submit(input, session);
            }
            (CommandEntry::Sequencer(_), None) => unreachable!("every sequencer input maps"),
        }
    }
    let output = driver.end_block();
    let failed = |reason: String| ReplayMismatch::Failed { height, reason };
    let events = event_batch(&output.events).map_err(|e| failed(e.to_string()))?;
    let state_root = match &output.state_root {
        Some(Ok(root)) => root.clone(),
        Some(Err(e)) => return Err(failed(e.to_string())),
        None => return Err(failed("no state root".into())),
    };
    let mut mismatches = Vec::new();
    if events.root() != header.events_root {
        let seq = published.events.and_then(|published| {
            let ours = events.entries();
            let theirs = published.entries();
            (0..ours.len().max(theirs.len()))
                .find(|&i| ours.get(i) != theirs.get(i))
                .inspect(|&i| {
                    let show = |e: Option<&EventEntry>| {
                        e.map(|e| {
                            let body = moor_db::state_root::cbor::diagnostic(&e.event, true)
                                .unwrap_or_else(|err| err.to_string());
                            format!("[{}, {}, #{}] {body}", e.seq, e.command_index, e.recipient)
                        })
                    };
                    tracing::warn!(
                        height,
                        replayed = ?show(ours.get(i)),
                        published = ?show(theirs.get(i)),
                        "first differing event"
                    );
                })
                .map(|i| i as u64)
        });
        mismatches.push(ReplayMismatch::EventsRoot { height, seq });
    }
    if state_root.root != header.state_root {
        mismatches.push(ReplayMismatch::StateRoot {
            height,
            relation: published
                .relations
                .and_then(|theirs| first_differing_relation(&state_root, theirs)),
        });
    }
    Ok(ReplayedBlock {
        output,
        events,
        state_root,
        mismatches,
    })
}

/// Re-execute `block` (which follows `prev`) on `driver` and check its event and state roots.
/// `published_events` (the node's event batch, when the segment carries one) names the first
/// differing event on an `events_root` mismatch. See [`replay_block_full`] for the whole output.
pub fn replay_block(
    driver: &mut BlockDriver,
    prev: &ChainTip,
    block: &Block,
    published_events: Option<&EventBatch>,
) -> Result<EventBatch, ReplayMismatch> {
    let replayed = replay_block_full(
        driver,
        prev,
        block,
        Published {
            events: published_events,
            relations: None,
        },
    )?;
    match replayed.mismatches.into_iter().next() {
        Some(mismatch) => Err(mismatch),
        None => Ok(replayed.events),
    }
}
