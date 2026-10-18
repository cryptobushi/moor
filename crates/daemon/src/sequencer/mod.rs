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

//! Sequencer mode (RuneWorld ADR 0006 decisions 1-2): the daemon's block thread.
//!
//! - **One input queue.** RPC threads push pre-verified envelopes and the connection registry
//!   pushes `Disconnected` sequencer inputs onto one channel ([`SequencerHandle`]). Arrival order
//!   at that channel is the log order.
//! - **Block thread.** It owns the kernel's [`Sequencer`] (and so the `BlockDriver`). Each block it
//!   opens the next context, runs every queued input on arrival (its events reach hosts at once,
//!   tagged with the block and command index), and at the 1 s boundary seals: state root, event
//!   batch, header, signature. It then broadcasts the seal notice and hands the block to the DA
//!   thread. Inputs that do not fit a block (2,048 inputs or 512 KiB) wait, in order, for the next.
//! - **DA thread.** It groups sealed blocks into segments and publishes them to the `FileSink`.
//!   If publication falls more than [`MAX_DA_LAG`] blocks behind, the block thread stops opening
//!   blocks until it catches up (ADR 0006 decision 4, safety over liveness).
//!
//! - **Durability (S1-2, decision 4).** The kernel's `DurableHooks` journal each group of inputs
//!   (one fsync for the inputs already queued together) before any of them runs, and store the
//!   unsigned block and the signing-guard record (both fsynced) before the signature. On start
//!   the daemon has already recovered: sealed blocks the sink lacks are handed to the DA thread,
//!   and the tip's seal notice is sent again.
//! - **Log stalled.** While the DA lag halt holds, [`SequencerHandle::log_stalled`] is true and
//!   every connected client gets a system message when the log stalls and when it resumes.

pub mod dev_signer;
pub mod metrics;

use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use flume::{Receiver, RecvTimeoutError, Sender};
use moor_block::{ChainTip, CommandEntry, DaSink, FileSink, SealedBlock, Segment};
use moor_common::tasks::Session;
use moor_kernel::tasks::{
    envelope_admission::OnAdmitted,
    sequencer::{InputReceipt, SealNotice, Sequencer},
    sequencer_recovery::FsyncLog,
};
use tracing::{debug, error, info, warn};

use self::metrics::Metrics;

/// Sealed blocks allowed to wait for publication before the sequencer stops opening blocks.
pub const MAX_DA_LAG: u64 = 300;

/// Blocks per metrics summary line.
const METRICS_WINDOW_BLOCKS: u64 = 60;

/// Inputs journalled together at most (one fsync for inputs already queued together).
const MAX_GROUP_COMMIT: usize = 256;

/// The DA lag halt's state, for hosts (ADR 0006 decision 4, "hosts show log stalled").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogStatus {
    /// More than [`MAX_DA_LAG`] sealed blocks are unpublished: no block opens.
    Stalled { sealed: u64, published: u64 },
    /// Publication caught up; blocks open again.
    Resumed { sealed: u64, published: u64 },
}

/// The reply to one queued input.
pub type InputReply = Result<InputReceipt, String>;

/// One input waiting for the block thread.
pub struct QueuedInput {
    pub entry: CommandEntry,
    /// Where the input's output goes (the submitting connection's session).
    pub session: Arc<dyn Session>,
    /// Run after an envelope's admission, before its task (binds a connecting client).
    pub on_admitted: Option<OnAdmitted>,
    /// When the RPC thread queued it.
    pub received: Instant,
    pub reply: Option<Sender<InputReply>>,
}

/// Heights shared with the RPC threads.
#[derive(Default)]
pub struct SequencerStatus {
    /// Height of the open block, 0 between blocks.
    open: AtomicU64,
    /// Highest sealed height.
    sealed: AtomicU64,
    /// Highest published height.
    published: AtomicU64,
    /// The DA lag halt holds.
    stalled: AtomicBool,
}

/// The RPC side of the input queue.
#[derive(Clone)]
pub struct SequencerHandle {
    inputs: Sender<QueuedInput>,
    status: Arc<SequencerStatus>,
    stop: Arc<AtomicBool>,
}

impl SequencerHandle {
    /// Queue an input; the returned channel gets its receipt once it has run.
    pub fn enqueue(
        &self,
        entry: CommandEntry,
        session: Arc<dyn Session>,
        on_admitted: Option<OnAdmitted>,
    ) -> Result<Receiver<InputReply>, String> {
        let (reply, receipt) = flume::bounded(1);
        self.inputs
            .send(QueuedInput {
                entry,
                session,
                on_admitted,
                received: Instant::now(),
                reply: Some(reply),
            })
            .map_err(|_| "the sequencer has stopped".to_string())?;
        Ok(receipt)
    }

    /// Queue an input and wait (up to `timeout`) for it to run.
    pub fn submit(
        &self,
        entry: CommandEntry,
        session: Arc<dyn Session>,
        on_admitted: Option<OnAdmitted>,
        timeout: Duration,
    ) -> InputReply {
        self.enqueue(entry, session, on_admitted)?
            .recv_timeout(timeout)
            .map_err(|e| format!("no receipt from the sequencer: {e}"))?
    }

    /// The height an input queued now is expected to land in (the open block, or the next).
    #[must_use]
    pub fn current_height(&self) -> u64 {
        match self.status.open.load(Ordering::Acquire) {
            0 => self.status.sealed.load(Ordering::Acquire) + 1,
            open => open,
        }
    }

    /// Highest sealed and published heights.
    #[must_use]
    pub fn heights(&self) -> (u64, u64) {
        (
            self.status.sealed.load(Ordering::Acquire),
            self.status.published.load(Ordering::Acquire),
        )
    }

    /// Whether the log is stalled (the DA lag halt holds): hosts show "log stalled".
    #[must_use]
    pub fn log_stalled(&self) -> bool {
        self.status.stalled.load(Ordering::Acquire)
    }

    /// Ask the block thread to seal its open block, flush publication and stop the scheduler.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
}

/// Everything the block thread needs.
pub struct SequencerParts {
    pub sequencer: Sequencer,
    pub sink: FileSink,
    /// The sink's published tip (the genesis tip when empty).
    pub published: ChainTip,
    /// Sealed blocks after `published`, from the block store, in height order.
    pub pending: Vec<SealedBlock>,
    pub segment_blocks: usize,
    /// The DA lag halt threshold ([`MAX_DA_LAG`] outside tests).
    pub max_da_lag: u64,
    /// Broadcast a seal notice to hosts.
    pub notify: Box<dyn Fn(SealNotice) + Send>,
    /// Tell hosts the log stalled or resumed.
    pub log_status: Box<dyn Fn(LogStatus) + Send>,
    /// fsync samples of the durable hooks.
    pub fsync: Arc<FsyncLog>,
}

/// Start the block and DA threads. The returned handle feeds the input queue; the join handle
/// finishes after [`SequencerHandle::stop`] once the scheduler has stopped.
pub fn start(parts: SequencerParts) -> std::io::Result<(SequencerHandle, JoinHandle<()>)> {
    let (inputs, queue) = flume::unbounded();
    let status = Arc::new(SequencerStatus::default());
    let stop = Arc::new(AtomicBool::new(false));
    let tip = *parts.sequencer.tip();
    let published = parts.published;
    status.sealed.store(tip.height, Ordering::Release);
    status.published.store(published.height, Ordering::Release);
    if tip.height > 0 {
        // A crash between storing a signature and sending its notice would leave hosts without
        // the tip's notice; send it again (hosts treat notices idempotently).
        (parts.notify)(SealNotice {
            height: tip.height,
            header_hash: tip.hash,
            state_root: tip.state_root,
        });
    }
    let handle = SequencerHandle {
        inputs,
        status: status.clone(),
        stop: stop.clone(),
    };
    let (blocks, da_queue) = flume::unbounded::<SealedBlock>();
    let (segments, segment_reports) = flume::unbounded::<(u64, u64)>();
    let da_status = status.clone();
    let segment_blocks = parts
        .segment_blocks
        .clamp(1, moor_block::MAX_SEGMENT_BLOCKS);
    let sink = parts.sink;
    let pending = parts.pending;
    let da = std::thread::Builder::new()
        .name("rw-seq-da".into())
        .spawn(move || {
            da_loop(
                sink,
                published,
                pending,
                da_queue,
                segment_blocks,
                da_status,
                segments,
            );
        })?;
    let block_thread = std::thread::Builder::new()
        .name("rw-seq-block".into())
        .spawn(move || {
            let mut block_loop = BlockLoop {
                sequencer: Some(parts.sequencer),
                queue,
                carry: VecDeque::new(),
                status,
                stop,
                blocks: Some(blocks),
                segment_reports,
                notify: parts.notify,
                log_status: parts.log_status,
                // Publication waits for a full segment, so a lower threshold could never clear.
                max_da_lag: parts.max_da_lag.max(segment_blocks as u64),
                fsync: parts.fsync,
                failed: false,
                metrics: Metrics::new(METRICS_WINDOW_BLOCKS),
            };
            block_loop.run();
            // Closing the block channel lets the DA thread publish what is left and exit.
            block_loop.blocks.take();
            if da.join().is_err() {
                error!("sequencer DA thread panicked");
            }
            block_loop.drain_segment_reports();
            let height = block_loop.status.sealed.load(Ordering::Acquire);
            block_loop.metrics.report_total(height);
            if let Some(sequencer) = block_loop.sequencer.take()
                && let Err(e) = sequencer.shutdown()
            {
                warn!(error = ?e, "scheduler did not stop cleanly");
            }
            info!(height, "sequencer stopped");
        })?;
    Ok((handle, block_thread))
}

fn wall_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct BlockLoop {
    sequencer: Option<Sequencer>,
    queue: Receiver<QueuedInput>,
    /// The input that did not fit the last block; it runs first in the next.
    carry: VecDeque<QueuedInput>,
    status: Arc<SequencerStatus>,
    stop: Arc<AtomicBool>,
    blocks: Option<Sender<SealedBlock>>,
    segment_reports: Receiver<(u64, u64)>,
    notify: Box<dyn Fn(SealNotice) + Send>,
    log_status: Box<dyn Fn(LogStatus) + Send>,
    max_da_lag: u64,
    fsync: Arc<FsyncLog>,
    /// Inputs could not be made durable: the open block is left to crash recovery.
    failed: bool,
    metrics: Metrics,
}

impl BlockLoop {
    fn sequencer(&mut self) -> &mut Sequencer {
        self.sequencer.as_mut().expect("present until shutdown")
    }

    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn drain_segment_reports(&mut self) {
        for (blocks, bytes) in self.segment_reports.try_iter() {
            self.metrics.record_segment(blocks, bytes);
        }
    }

    /// Open the next block, waiting while the clock or the DA lag forbids it. `None` on stop.
    fn open(&mut self) -> Option<()> {
        let mut refused: Option<String> = None;
        loop {
            if self.stopping() {
                return None;
            }
            let (sealed, published) = (
                self.status.sealed.load(Ordering::Acquire),
                self.status.published.load(Ordering::Acquire),
            );
            let stalled = sealed.saturating_sub(published) > self.max_da_lag;
            if stalled != self.status.stalled.swap(stalled, Ordering::AcqRel) {
                (self.log_status)(if stalled {
                    LogStatus::Stalled { sealed, published }
                } else {
                    LogStatus::Resumed { sealed, published }
                });
            }
            let result = if stalled {
                Err(format!(
                    "log stalled: {} sealed blocks are unpublished",
                    sealed - published
                ))
            } else {
                self.sequencer()
                    .open_block(wall_secs(), Instant::now())
                    .map_err(|e| e.to_string())
            };
            match result {
                Ok(ctx) => {
                    if refused.is_some() {
                        info!(height = ctx.height, "block opened after a refusal");
                    }
                    self.status.open.store(ctx.height, Ordering::Release);
                    return Some(());
                }
                Err(reason) => {
                    if refused.as_ref() != Some(&reason) {
                        error!(%reason, "sequencer refuses to open a block");
                        refused = Some(reason);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    fn run(&mut self) {
        let cadence = self.sequencer().params().cadence;
        let mut deadline = Instant::now();
        let mut window_closed: Option<Instant> = None;
        let (height, address) = (
            self.sequencer().tip().height,
            self.sequencer().chain_params().sequencer,
        );
        info!(height, sequencer = %address, "sequencer block loop running");
        loop {
            if self.open().is_none() {
                break;
            }
            let opened = Instant::now();
            if let Some(closed) = window_closed {
                self.metrics
                    .record_pause(opened.saturating_duration_since(closed));
            }
            deadline += cadence;
            if deadline <= opened {
                deadline = opened + cadence;
            }
            let received = self.take_inputs(deadline);
            window_closed = Some(Instant::now());
            if self.failed {
                error!("inputs could not be journalled; the sequencer halts (restart recovers)");
                self.status.open.store(0, Ordering::Release);
                break;
            }
            if !self.seal(&received) {
                break;
            }
            if self.stopping() {
                break;
            }
        }
    }

    /// The next input: one held back from the last group first, else the queue (waiting until
    /// `deadline` when `wait`).
    fn next_input(&mut self, deadline: Instant, wait: bool) -> Option<QueuedInput> {
        if let Some(input) = self.carry.pop_front() {
            return Some(input);
        }
        if !wait {
            return self.queue.try_recv().ok();
        }
        match self.queue.recv_deadline(deadline) {
            Ok(input) => Some(input),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => {
                self.stop.store(true, Ordering::Release);
                None
            }
        }
    }

    /// Run inputs on arrival until `deadline`. Returns their receipt times.
    ///
    /// Group commit: the input that ends the wait and every input already queued behind it (up
    /// to [`MAX_GROUP_COMMIT`]) are journalled with one fsync, then run in order. Waiting for
    /// more would only add latency; under load the queue fills while the fsync runs.
    fn take_inputs(&mut self, deadline: Instant) -> Vec<Instant> {
        let mut received = Vec::new();
        let mut full = false;
        loop {
            if full || self.stopping() {
                // A full block takes nothing more; its inputs wait for the next, in order.
                let now = Instant::now();
                if !self.stopping() && now < deadline {
                    std::thread::sleep(deadline - now);
                }
                break;
            }
            let Some(first) = self.next_input(deadline, true) else {
                break;
            };
            let mut group = vec![first];
            while group.len() < MAX_GROUP_COMMIT {
                match self.next_input(deadline, false) {
                    Some(input) => group.push(input),
                    None => break,
                }
            }
            group.retain(|input| match input.entry.check() {
                Ok(()) => true,
                Err(e) => {
                    if let Some(reply) = &input.reply {
                        let _ = reply.send(Err(format!("not a valid log entry: {e}")));
                    }
                    false
                }
            });
            if group.is_empty() {
                continue;
            }
            let entries: Vec<CommandEntry> = group.iter().map(|i| i.entry.clone()).collect();
            let journalled = match self.sequencer().journal_inputs(&entries) {
                Ok(n) => n,
                Err(e) => {
                    error!(error = %e, "inputs could not be journalled");
                    for input in group {
                        if let Some(reply) = input.reply {
                            let _ = reply.send(Err(format!("the sequencer halted: {e}")));
                        }
                    }
                    self.failed = true;
                    break;
                }
            };
            self.record_fsyncs();
            if journalled < group.len() {
                debug!("block full; inputs wait for the next block");
                for input in group.drain(journalled..).rev() {
                    self.carry.push_front(input);
                }
                full = true;
            }
            for input in group {
                let taken = Instant::now();
                let QueuedInput {
                    entry,
                    session,
                    on_admitted,
                    received: at,
                    reply,
                } = input;
                let result = self
                    .sequencer()
                    .submit(entry, session, on_admitted)
                    .map_err(|e| e.to_string());
                let done = Instant::now();
                if result.is_ok() {
                    self.metrics.record_input(at, taken, done);
                    received.push(at);
                } else if let Err(e) = &result {
                    error!(error = %e, "input could not run");
                }
                if let Some(reply) = reply {
                    let _ = reply.send(result);
                }
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        received
    }

    fn record_fsyncs(&mut self) {
        for (kind, took) in self.fsync.drain() {
            self.metrics.record_fsync(kind, took);
        }
    }

    /// Seal the open block, broadcast its notice, hand it to the DA thread. False on failure: the
    /// sequencer halts rather than publish something it cannot vouch for.
    fn seal(&mut self, received: &[Instant]) -> bool {
        let sealed = match self.sequencer().seal() {
            Ok(sealed) => sealed,
            Err(e) => {
                error!(error = %e, "sealing failed; the sequencer halts");
                self.status.open.store(0, Ordering::Release);
                return false;
            }
        };
        let notice = sealed.notice;
        self.status.sealed.store(notice.height, Ordering::Release);
        self.status.open.store(0, Ordering::Release);
        (self.notify)(notice);
        let notice_at = Instant::now();
        let commands = sealed.block.commands.len();
        let events = sealed.block.events.len();
        debug!(
            height = notice.height,
            commands,
            events,
            end_block_ms = sealed.end_block_time.as_secs_f64() * 1000.0,
            seal_ms = sealed.seal_time.as_secs_f64() * 1000.0,
            header_hash = %moor_block::hex(&notice.header_hash),
            state_root = %moor_block::hex(&notice.state_root),
            "sealed"
        );
        if sealed.conflicts > 0 {
            error!(
                height = notice.height,
                conflicts = sealed.conflicts,
                "transaction conflicts in a serial block"
            );
        }
        self.metrics.record_block(
            commands,
            events,
            sealed.command_bytes,
            sealed.event_bytes,
            sealed.header_bytes,
            sealed.end_block_time,
            notice_at,
            received,
        );
        self.drain_segment_reports();
        self.record_fsyncs();
        let published = self.status.published.load(Ordering::Acquire);
        self.metrics
            .record_da_lag(notice.height.saturating_sub(published));
        self.metrics.maybe_report(notice.height);
        if let Some(blocks) = &self.blocks
            && blocks.send(sealed.block).is_err()
        {
            error!("the DA thread has gone; the sequencer halts");
            return false;
        }
        true
    }
}

fn da_loop(
    mut sink: FileSink,
    mut prev: ChainTip,
    mut pending: Vec<SealedBlock>,
    blocks: Receiver<SealedBlock>,
    segment_blocks: usize,
    status: Arc<SequencerStatus>,
    reports: Sender<(u64, u64)>,
) {
    let mut publish = |pending: &mut Vec<SealedBlock>, prev: &mut ChainTip| -> bool {
        if pending.is_empty() {
            return true;
        }
        let segment = match Segment::from_sealed(*prev, pending, true) {
            Ok(segment) => segment,
            Err(e) => {
                error!(error = %e, "could not build a segment");
                return false;
            }
        };
        match sink.publish(&segment) {
            Ok(receipt) => {
                *prev = segment.tip();
                status.published.store(prev.height, Ordering::Release);
                let _ = reports.send((pending.len() as u64, receipt.bytes));
                debug!(
                    first = receipt.first_height,
                    tip = receipt.tip_height,
                    bytes = receipt.bytes,
                    location = %receipt.location,
                    "segment published"
                );
                pending.clear();
                true
            }
            Err(e) => {
                error!(error = %e, "segment publication failed; will retry");
                false
            }
        }
    };
    // Sealed blocks a crash left unpublished go out first, in full segments.
    while pending.len() >= segment_blocks {
        let rest = pending.split_off(segment_blocks);
        if !publish(&mut pending, &mut prev) {
            pending.extend(rest);
            break;
        }
        pending = rest;
    }
    loop {
        match blocks.recv_timeout(Duration::from_secs(1)) {
            Ok(block) => {
                pending.push(block);
                if pending.len() >= segment_blocks {
                    publish(&mut pending, &mut prev);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                // A failed publication is retried here.
                if pending.len() >= segment_blocks {
                    publish(&mut pending, &mut prev);
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    for attempt in 0..3 {
        if publish(&mut pending, &mut prev) {
            break;
        }
        warn!(attempt, "retrying the final segment");
        std::thread::sleep(Duration::from_millis(200));
    }
    info!(published = prev.height, "sequencer publication flushed");
}
