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

//! Durability and crash recovery for the sequencer (ADR 0006 decision 4).
//!
//! [`DurableHooks`] implement the sequencer's hook points over `moor_block::durable`:
//!
//! - `opened`: journal `Open{height, timestamp, seed}`;
//! - `before_inputs`: journal the inputs and fsync once (group commit) before any of them runs;
//! - `before_sign`: write the unsigned block to the block store and fsync, then record
//!   `(height, header_hash)` in the signing guard and fsync; only then does the sequencer sign;
//! - `sealed`: store the signature (and rotate the journal when it has grown).
//!
//! [`resume`] restarts a sequencer from that state. The caller first decides whether its database
//! can be kept: [`moor_block::durable::BlockStore::height_with_root`] names the sealed height the
//! database's state root belongs to; if none, the caller rebuilds the database from the newest
//! verified checkpoint or genesis (only genesis exists until checkpoint import, S1-5) and calls
//! [`resume`] with the rebuilt driver. [`resume`] then
//!
//! 1. halts if the signing guard records a height the store lacks (that block is recovered, never
//!    re-made), or a header the store does not hold;
//! 2. re-executes the stored sealed blocks above the database's height, checking each block's
//!    event and state roots against the stored header;
//! 3. finishes the block the crash interrupted: a stored unsigned block is re-executed (or, if the
//!    database already holds its effects, only signed) and must come out identical; otherwise the
//!    block the journal left open is re-executed under its recorded context with its journalled
//!    inputs, reproducing the events hosts saw, and sealed.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use moor_block::{
    Block, ChainTip, SealedBlock, SequencerKey,
    durable::{Authorization, BlockStore, DurableError, Journal, JournalledBlock, SigningGuard},
};
use moor_common::deterministic::BlockContext;

use crate::tasks::{
    block_driver::BlockDriver,
    sequencer::{
        ReplayMismatch, Sealed, Sequencer, SequencerError, SequencerHooks, SequencerParams,
        replay_block,
    },
};

/// Which durable write an fsync belonged to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FsyncKind {
    /// Journal inputs (one group commit).
    Journal,
    /// Unsigned block to the block store.
    Store,
    /// Signing guard record.
    Guard,
}

/// fsync durations, drained by the metrics reporter.
#[derive(Default, Debug)]
pub struct FsyncLog {
    samples: Mutex<Vec<(FsyncKind, Duration)>>,
}

impl FsyncLog {
    pub fn record(&self, kind: FsyncKind, took: Duration) {
        self.samples
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((kind, took));
    }

    /// Take every sample recorded since the last drain.
    pub fn drain(&self) -> Vec<(FsyncKind, Duration)> {
        std::mem::take(&mut *self.samples.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

/// The points between durable writes where a crash can happen; a test hook sees each one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    /// `Open` appended to the journal (not yet fsynced).
    Opened { height: u64 },
    /// Inputs up to `last_index` journalled and fsynced; none of the group has run yet.
    InputsJournalled { height: u64, last_index: u64 },
    /// The unsigned block is in the store and fsynced; the guard is not yet written.
    UnsignedStored { height: u64 },
    /// The guard records the block; it is not yet signed.
    GuardRecorded { height: u64 },
    /// Signed and the signature stored; the seal notice and publication have not happened.
    SignatureStored { height: u64 },
}

/// Called at every [`FaultPoint`] (tests kill the process there).
pub type FaultHook = Box<dyn FnMut(FaultPoint) + Send>;

/// The sequencer's durable state, opened.
pub struct DurableParts {
    pub journal: Journal,
    /// The block the journal left open, if any.
    pub open: Option<JournalledBlock>,
    pub store: BlockStore,
    pub guard: SigningGuard,
}

/// [`crate::tasks::sequencer::SequencerHooks`] over the journal, block store and signing guard.
pub struct DurableHooks {
    journal: Journal,
    store: BlockStore,
    guard: SigningGuard,
    fsync: Arc<FsyncLog>,
    fault: Option<FaultHook>,
}

impl DurableHooks {
    #[must_use]
    pub fn new(
        journal: Journal,
        store: BlockStore,
        guard: SigningGuard,
        fsync: Arc<FsyncLog>,
        fault: Option<FaultHook>,
    ) -> Self {
        Self {
            journal,
            store,
            guard,
            fsync,
            fault,
        }
    }

    fn fault(&mut self, point: FaultPoint) {
        if let Some(fault) = &mut self.fault {
            fault(point);
        }
    }
}

impl SequencerHooks for DurableHooks {
    fn opened(&mut self, ctx: &BlockContext) -> Result<(), String> {
        self.journal
            .append_open(ctx.height, ctx.timestamp, &ctx.seed)
            .map_err(|e| e.to_string())?;
        self.fault(FaultPoint::Opened { height: ctx.height });
        Ok(())
    }

    fn before_input(
        &mut self,
        height: u64,
        command_index: u64,
        entry: &moor_block::CommandEntry,
    ) -> Result<(), String> {
        self.before_inputs(height, command_index, std::slice::from_ref(entry))
    }

    fn before_inputs(
        &mut self,
        height: u64,
        first_command_index: u64,
        entries: &[moor_block::CommandEntry],
    ) -> Result<(), String> {
        let took = self
            .journal
            .append_inputs(height, first_command_index, entries)
            .map_err(|e| e.to_string())?;
        self.fsync.record(FsyncKind::Journal, took);
        self.fault(FaultPoint::InputsJournalled {
            height,
            last_index: first_command_index + entries.len() as u64 - 1,
        });
        Ok(())
    }

    fn before_sign(
        &mut self,
        header: &moor_block::BlockHeader,
        commands: &moor_block::CommandBatch,
        events: &moor_block::EventBatch,
    ) -> Result<(), String> {
        let height = header.height;
        if let Some(took) = self
            .store
            .put_unsigned(header, commands, events)
            .map_err(|e| e.to_string())?
        {
            self.fsync.record(FsyncKind::Store, took);
        }
        self.fault(FaultPoint::UnsignedStored { height });
        if let Authorization::Recorded(took) = self
            .guard
            .authorize(height, &header.hash())
            .map_err(|e| e.to_string())?
        {
            self.fsync.record(FsyncKind::Guard, took);
        }
        self.fault(FaultPoint::GuardRecorded { height });
        Ok(())
    }

    fn sealed(&mut self, block: &SealedBlock) -> Result<(), String> {
        let height = block.header.header.height;
        self.store
            .put_signature(height, &block.header.sequencer_sig)
            .map_err(|e| e.to_string())?;
        self.journal.sealed(height).map_err(|e| e.to_string())?;
        self.fault(FaultPoint::SignatureStored { height });
        Ok(())
    }
}

/// Why recovery stopped.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// The database's state root is not any sealed block's: rebuild it (from a checkpoint or
    /// genesis) and resume again.
    #[error("the database's state root {} matches no sealed block; rebuild it", moor_block::hex(.0))]
    Rebuild([u8; 32]),
    /// Recovery must not continue: the durable state is inconsistent or re-execution differs.
    #[error("recovery halts: {0}")]
    Halt(String),
    #[error("replay: {0}")]
    Replay(#[from] ReplayMismatch),
    #[error("durable state: {0}")]
    Durable(#[from] DurableError),
    #[error("sequencer: {0}")]
    Sequencer(#[from] SequencerError),
}

/// How [`resume`] finished the block a crash interrupted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interrupted {
    /// No block was open.
    None,
    /// The stored unsigned block's effects were already in the database: only signed.
    SignedStored,
    /// The stored unsigned block was re-executed (identical) and signed.
    ReexecutedStored,
    /// The journal's open block was re-executed under its recorded context and sealed.
    ReopenedJournal,
}

/// What [`resume`] did.
#[derive(Debug)]
pub struct Recovery {
    /// The sealed height the database was at.
    pub base: u64,
    /// Stored sealed blocks re-executed on top of it.
    pub replayed: u64,
    /// How the interrupted block was finished.
    pub interrupted: Interrupted,
    /// The interrupted block, now sealed, if there was one.
    pub resealed: Option<Sealed>,
}

/// Whether a database whose state root is `root` can be kept (recovery step 1): its root is a
/// sealed block's (or the genesis root), or the stored unsigned block's. Otherwise the caller
/// rebuilds it from the newest verified checkpoint or genesis before [`resume`].
#[must_use]
pub fn database_resumable(store: &BlockStore, root: &[u8; 32]) -> bool {
    store.height_with_root(root).is_some()
        || store.unsigned().is_some_and(|u| &u.state_root == root)
}

/// Re-execute stored blocks `from..=to` on `driver`, checking roots and events.
fn replay_stored(
    driver: &mut BlockDriver,
    store: &BlockStore,
    genesis_root: &[u8; 32],
    from: u64,
    to: u64,
) -> Result<(), RecoveryError> {
    let mut prev = match from.saturating_sub(1) {
        0 => ChainTip::genesis(genesis_root),
        h => store
            .header(h)
            .map(ChainTip::of)
            .ok_or_else(|| RecoveryError::Halt(format!("the block store lacks block {h}")))?,
    };
    for height in from..=to {
        let stored = store.read(height)?;
        let block = Block {
            header: stored.header,
            commands: stored.commands,
        };
        let events = replay_block(driver, &prev, &block, Some(&stored.events))?;
        if events != stored.events {
            return Err(ReplayMismatch::EventsRoot { height, seq: None }.into());
        }
        prev = ChainTip::of(&block.header);
    }
    Ok(())
}

/// Restart a sequencer from its durable state. See the module documentation.
///
/// `driver` holds the database the caller decided to keep (its root is a sealed block's, or a
/// stored unsigned block's) or one rebuilt at genesis. The store must have its chain record.
pub fn resume(
    mut driver: BlockDriver,
    key: SequencerKey,
    params: SequencerParams,
    parts: DurableParts,
    fsync: Arc<FsyncLog>,
    fault: Option<FaultHook>,
) -> Result<(Sequencer, Recovery), RecoveryError> {
    let DurableParts {
        journal,
        open,
        store,
        guard,
    } = parts;
    let chain = store
        .chain()
        .ok_or_else(|| RecoveryError::Halt("the block store has no chain record".into()))?;
    if chain.sequencer != key.address() {
        return Err(RecoveryError::Halt(format!(
            "the block store belongs to sequencer {}, not {}",
            chain.sequencer,
            key.address()
        )));
    }
    let sealed = store.sealed_height();
    let unsigned = store.unsigned().copied();
    let stored_top = unsigned.map_or(sealed, |u| u.height);

    // The guard may only be at or below what the store holds, with the same header.
    if let Some((height, hash)) = guard.last() {
        if height > stored_top {
            return Err(RecoveryError::Halt(format!(
                "the signing guard records height {height}, which the block store lacks; that \
                 block must be recovered, never re-made"
            )));
        }
        let stored = store.header(height).map(|h| h.hash());
        if stored != Some(hash) {
            return Err(RecoveryError::Halt(format!(
                "the signing guard's header at height {height} is not the stored block's"
            )));
        }
    }

    let root = driver
        .state_root()
        .map_err(|e| RecoveryError::Halt(format!("state root: {e}")))?
        .root;
    let tip = store
        .tip()
        .ok_or_else(|| RecoveryError::Halt("the block store has no chain".into()))?;
    // A database already holding the stored unsigned block's effects.
    let holds_unsigned =
        unsigned.is_some_and(|u| u.state_root == root && u.state_root != tip.state_root);
    let base = if holds_unsigned {
        sealed
    } else {
        store
            .height_with_root(&root)
            .ok_or(RecoveryError::Rebuild(root))?
    };
    if base < sealed {
        replay_stored(&mut driver, &store, &chain.genesis_root, base + 1, sealed)?;
    }
    let replayed = sealed - base;

    // The interrupted block: the stored unsigned block, or the journal's open block.
    let open = open.filter(|b| b.height > sealed);
    if let Some(b) = &open
        && b.height != sealed + 1
    {
        return Err(RecoveryError::Halt(format!(
            "the journal opened block {} but the store's tip is {sealed}",
            b.height
        )));
    }
    let interrupted = match unsigned {
        Some(header) => {
            let stored = store.read(header.height)?;
            if let Some(b) = &open
                && (b.timestamp != header.timestamp
                    || b.seed != header.seed
                    || b.inputs.as_slice() != stored.commands.entries())
            {
                return Err(RecoveryError::Halt(format!(
                    "the journal's block {} differs from the stored unsigned block",
                    header.height
                )));
            }
            Some((stored, holds_unsigned))
        }
        None => None,
    };

    let hooks = DurableHooks::new(journal, store, guard, fsync, fault);
    let mut sequencer = Sequencer::new(
        driver,
        key,
        chain.genesis_root,
        tip,
        params,
        Box::new(hooks),
    );
    let (how, resealed) = match (interrupted, open) {
        (Some((stored, true)), _) => (
            Interrupted::SignedStored,
            Some(sequencer.seal_stored(stored.header, stored.commands, stored.events)?),
        ),
        (Some((stored, false)), _) => {
            let ctx = BlockContext {
                height: stored.header.height,
                timestamp: stored.header.timestamp,
                seed: stored.header.seed,
            };
            (
                Interrupted::ReexecutedStored,
                Some(sequencer.reopen(ctx, stored.commands.entries().to_vec())?),
            )
        }
        (None, Some(b)) => {
            let ctx = BlockContext {
                height: b.height,
                timestamp: b.timestamp,
                seed: b.seed,
            };
            (
                Interrupted::ReopenedJournal,
                Some(sequencer.reopen(ctx, b.inputs)?),
            )
        }
        (None, None) => (Interrupted::None, None),
    };
    Ok((
        sequencer,
        Recovery {
            base,
            replayed,
            interrupted: how,
            resealed,
        },
    ))
}
