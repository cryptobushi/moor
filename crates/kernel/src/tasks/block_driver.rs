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

//! The block driver: the STF entry point in deterministic mode.
//!
//! `(prior state, ordered inputs, block context) -> (new state, event batch)`. The driver sets the
//! block context, then for each input in submission order advances the command index, submits the
//! input, and runs the manual executor to quiescence before the next input. Nothing else runs:
//! there is no task pool, timer, request or worker thread.
//!
//! # Ordering rules
//!
//! - Inputs run strictly in submission order; input `k` of a block has command index `k` (the
//!   first is 1).
//! - The run queue is FIFO. A `fork (0)` child is appended when its parent reaches the fork (the
//!   parent commits there), but it runs only after the parent's job ends, that is when the parent
//!   completes, so it sees the parent's final commit. Several children run in creation order;
//!   grandchildren queue behind their aunts and uncles (breadth first).
//! - A wake caused by a job (`resume()`, `wait_task` dependants, `task_send` to a waiting task) is
//!   appended when that job ends, after the children the job created.
//! - `force_input()` queues its command when the calling task commits (not when it is called), in
//!   call order; a rolled-back caller queues nothing.
//! - `suspend(0)`, `commit()` and `suspend_if_needed()` commit and continue inline in the same job.
//! - Events enter the batch when their transaction's session commits. The batch is therefore commit
//!   order, then `notify` order within a commit; `seq` numbers the whole block from 0. A fork's
//!   events follow its parent's and precede the next input's, and carry the parent input's command
//!   index. Unspooled system messages (tracebacks) enter the batch when sent.
//! - At `end_block` every task still suspended is cancelled in ascending id order, so no task
//!   outlives its block (ADR 0001 ratification note 1).
//!
//! # Signed inputs
//!
//! [`BlockDriver::submit_envelope`] is the signed path (RuneWorld ADR 0005): the admission step
//! (`envelope_admission`) verifies and consumes the envelope in its own transaction, then the
//! command, `user_connected`, or creation hooks run as the input's tasks. A rejected envelope runs
//! nothing and adds one [`BlockEventKind::Rejected`] entry; delegations and revocations add one
//! [`BlockEventKind::Sessions`] entry. Either entry follows the input's task events.
//! [`BlockInput::SequencerDisconnect`] is the authority-free disconnect.
//!
//! # State root
//!
//! After the boundary cancellation, `end_block` takes the state root of the committed state (`moor_db::state_root`,
//! state encoding v1) with its per-relation hashes, unless disabled with
//! [`BlockDriver::set_state_root_at_end_block`]. [`BlockDriver::state_root`] and
//! [`BlockDriver::canonical_relation`] read the same thing on demand.

use crate::tasks::{
    TaskHandle,
    block_events,
    charge::TotalsDelta,
    envelope_admission::{AdmissionRejection, Admitted, OnAdmitted, take_result},
    meter::{self, WorldTotals},
    scheduler::Scheduler,
};
use moor_block::{Meter, MeterKind, MeterOutcome};
use moor_common::model::WorldStateError;
use moor_common::{
    deterministic::{self, BlockContext},
    envelope::EnvelopeKind,
    model::ObjectRef,
    tasks::{ConnectionDetails, NarrativeEvent, SchedulerError, Session, SessionError, TaskId},
};
use moor_compiler::compile;
use moor_db::state_root::{CanonicalRelation, StateRoot};
use moor_var::{
    List, NOTHING, Obj, SYSTEM_OBJECT, Symbol, Var, v_bool, v_empty_str, v_int, v_map, v_obj, v_str,
    v_sym,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};
use uuid::Uuid;

pub use crate::tasks::scheduler::manual::RunSummary;

/// Jobs one input may run before its remaining work is cancelled. Generous: a task is a single
/// transaction attempt, and runaway `fork (0)` chains are the only way to approach it.
pub const DEFAULT_JOB_BUDGET: usize = 100_000;

/// One sequenced input.
#[derive(Clone, Debug)]
pub enum BlockInput {
    /// A player command line, parsed and dispatched as from a connection.
    Command { player: Obj, command: String },
    /// MOO statements evaluated as `player` (wizard eval).
    Eval { player: Obj, code: String },
    /// A direct verb call `vloc:verb(@args)` with the given authority.
    Verb {
        player: Obj,
        vloc: Obj,
        verb: Symbol,
        args: List,
        argstr: String,
        authority: Obj,
    },
    /// Sequencer input: `#0:user_connected(player)`, as the daemon submits it.
    Connected { player: Obj },
    /// Sequencer input: `#0:user_disconnected(player)`, as the daemon submits it.
    Disconnected { player: Obj },
    /// Sequencer input for the signed world (ADR 0005 decision 6): a disconnect carries no
    /// signature and no player authority, and runs `player:disfunc()` only.
    SequencerDisconnect { player: Obj },
}

/// What happened to one input.
#[derive(Debug)]
pub struct InputOutcome {
    /// The input's command index within the block (1 for the first).
    pub command_index: u64,
    /// The input's task, if one was created.
    pub task_id: Option<TaskId>,
    /// The task result. `None` while the task is still suspended at quiescence.
    pub result: Option<Result<Var, SchedulerError>>,
    /// How the run to quiescence after this input ended.
    pub run: RunSummary,
    /// For an envelope: the admission step's verdict. `None` for unsigned inputs.
    pub admission: Option<Result<Admitted, AdmissionRejection>>,
}

/// What a batch entry carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockEventKind {
    /// `notify()`, `present()` and similar: sent to the player's connections.
    Narrative(Box<NarrativeEvent>),
    /// `event_log()`: logged without broadcast.
    Logged(Box<NarrativeEvent>),
    /// An unspooled system message (traceback, "task aborted").
    System(String),
    /// The admission step rejected an envelope; nothing ran.
    Rejected {
        kind: Option<EnvelopeKind>,
        session: u32,
        reason: AdmissionRejection,
    },
    /// A delegation registered a session, or a revocation revoked some.
    Sessions(Admitted),
    /// The input's engine measurement, after its other events (block format version 2).
    Meter(Meter),
}

/// One entry of the event batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockEvent {
    /// Position in the block's batch, from 0.
    pub seq: u64,
    /// Command index of the input whose task (or descendant task) produced it.
    pub command_index: u64,
    /// The producing task.
    pub task_id: Option<TaskId>,
    /// Recipient.
    pub player: Obj,
    pub kind: BlockEventKind,
    /// The canonical encoding of `kind` (empty if it could not be encoded), kept so that the
    /// meter's `event_bytes` and the sealed batch encode each event once.
    pub encoded: Vec<u8>,
}

/// The output of one block.
#[derive(Debug)]
pub struct BlockOutput {
    pub block: BlockContext,
    pub outcomes: Vec<InputOutcome>,
    /// The ordered event batch.
    pub events: Vec<BlockEvent>,
    /// Tasks cancelled at the block boundary because they were still suspended.
    pub abandoned: Vec<TaskId>,
    /// Transaction conflicts seen in this block. Serial execution makes this zero.
    pub conflicts: u64,
    /// Each input's meter by command index (also in `events` as `[5, meter]` entries).
    pub meters: Vec<(u64, Meter)>,
    /// What each charged world was charged in the block, by world number.
    pub block_totals: Vec<(i32, WorldTotals)>,
    /// The state root after the block, with its per-relation hashes. `None` when disabled with
    /// [`BlockDriver::set_state_root_at_end_block`].
    pub state_root: Option<Result<StateRoot, WorldStateError>>,
}

#[derive(Default)]
struct EventBatch {
    next_seq: u64,
    events: Vec<BlockEvent>,
}

impl EventBatch {
    fn push(&mut self, task_id: Option<TaskId>, player: Obj, kind: BlockEventKind) {
        let command_index = deterministic::current().map_or(0, |ctx| ctx.command);
        let encoded = block_events::encode_event(&kind).unwrap_or_default();
        if !matches!(kind, BlockEventKind::Meter(_)) {
            meter::add_event(encoded.len() as u64);
        }
        self.events.push(BlockEvent {
            seq: self.next_seq,
            command_index,
            task_id,
            player,
            kind,
            encoded,
        });
        self.next_seq += 1;
    }
}

fn lock(batch: &Mutex<EventBatch>) -> MutexGuard<'_, EventBatch> {
    // Plain data: a poisoned lock is still consistent.
    batch.lock().unwrap_or_else(|e| e.into_inner())
}

fn current_task() -> Option<TaskId> {
    crate::task_context::has_active_task().then(crate::task_context::current_task_id)
}

/// A session that records committed output into the block's event batch and forwards everything
/// to an inner session (a host connection, or `NoopClientSession`).
pub struct BlockSession {
    inner: Arc<dyn Session>,
    batch: Arc<Mutex<EventBatch>>,
    pending: Mutex<Vec<(Option<TaskId>, Obj, BlockEventKind)>>,
}

impl BlockSession {
    fn new(inner: Arc<dyn Session>, batch: Arc<Mutex<EventBatch>>) -> Self {
        Self {
            inner,
            batch,
            pending: Mutex::new(Vec::new()),
        }
    }

    fn spool(&self, player: Obj, kind: BlockEventKind) {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((current_task(), player, kind));
    }
}

impl Session for BlockSession {
    fn switch_player_identity(&self, new_player: Obj, preserve_history: bool) {
        self.inner
            .switch_player_identity(new_player, preserve_history);
    }

    fn commit(&self) -> Result<(), SessionError> {
        let pending = std::mem::take(&mut *self.pending.lock().unwrap_or_else(|e| e.into_inner()));
        {
            let mut batch = lock(&self.batch);
            for (task_id, player, kind) in pending {
                batch.push(task_id, player, kind);
            }
        }
        self.inner.commit()
    }

    fn rollback(&self) -> Result<(), SessionError> {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.inner.rollback()
    }

    fn fork(self: Arc<Self>) -> Result<Arc<dyn Session>, SessionError> {
        let inner = self.inner.clone().fork()?;
        Ok(Arc::new(Self::new(inner, self.batch.clone())))
    }

    fn fork_retry(self: Arc<Self>) -> Result<Arc<dyn Session>, SessionError> {
        let inner = self.inner.clone().fork_retry()?;
        Ok(Arc::new(Self::new(inner, self.batch.clone())))
    }

    fn request_input(
        &self,
        player: Obj,
        input_request_id: Uuid,
        metadata: Option<Vec<(Symbol, Var)>>,
    ) -> Result<(), SessionError> {
        self.inner.request_input(player, input_request_id, metadata)
    }

    fn send_event(&self, player: Obj, event: Box<NarrativeEvent>) -> Result<(), SessionError> {
        self.spool(player, BlockEventKind::Narrative(event.clone()));
        self.inner.send_event(player, event)
    }

    fn log_event(&self, player: Obj, event: Box<NarrativeEvent>) -> Result<(), SessionError> {
        self.spool(player, BlockEventKind::Logged(event.clone()));
        self.inner.log_event(player, event)
    }

    fn send_system_msg(&self, player: Obj, msg: &str) -> Result<(), SessionError> {
        lock(&self.batch).push(
            current_task(),
            player,
            BlockEventKind::System(msg.to_string()),
        );
        self.inner.send_system_msg(player, msg)
    }

    fn notify_shutdown(&self, msg: Option<String>) -> Result<(), SessionError> {
        self.inner.notify_shutdown(msg)
    }

    fn connection_name(&self, player: Obj) -> Result<String, SessionError> {
        self.inner.connection_name(player)
    }

    fn disconnect(&self, player: Obj) -> Result<(), SessionError> {
        self.inner.disconnect(player)
    }

    fn connected_players(&self, include_all: bool) -> Result<Vec<Obj>, SessionError> {
        self.inner.connected_players(include_all)
    }

    fn connected_seconds(&self, player: Obj) -> Result<f64, SessionError> {
        self.inner.connected_seconds(player)
    }

    fn idle_seconds(&self, player: Obj) -> Result<f64, SessionError> {
        self.inner.idle_seconds(player)
    }

    fn connections(&self, player: Option<Obj>) -> Result<Vec<Obj>, SessionError> {
        self.inner.connections(player)
    }

    fn connection_details(
        &self,
        player: Option<Obj>,
    ) -> Result<Vec<ConnectionDetails>, SessionError> {
        self.inner.connection_details(player)
    }

    fn connection_attributes(&self, obj: Obj) -> Result<Var, SessionError> {
        self.inner.connection_attributes(obj)
    }

    fn set_connection_attribute(
        &self,
        connection_obj: Obj,
        key: Symbol,
        value: Var,
    ) -> Result<(), SessionError> {
        self.inner
            .set_connection_attribute(connection_obj, key, value)
    }
}

/// Drives a deterministic-mode scheduler one block at a time. Created by
/// `Scheduler::start_block_driver`; owns all execution on the calling thread.
pub struct BlockDriver {
    scheduler: Scheduler,
    batch: Arc<Mutex<EventBatch>>,
    block: BlockContext,
    outcomes: Vec<InputOutcome>,
    conflicts_at_block_start: u64,
    job_budget: usize,
    root_at_end_block: bool,
    metering: MeterState,
    metering_enabled: bool,
}

/// A charged input waiting for settlement at `end_block`.
#[derive(Clone, Debug)]
struct SettleEntry {
    player: Obj,
    world: Obj,
    meter: Meter,
    leaving: bool,
}

/// The driver's metering state for the open block and, for storage, across blocks.
#[derive(Default)]
struct MeterState {
    /// Each input's meter by command index.
    meters: Vec<(u64, Meter)>,
    /// Inputs a policy was installed for, in command-index order.
    settle: Vec<SettleEntry>,
    /// Net canonical-byte change this block, by object and by paying player.
    block_objects: BTreeMap<Obj, i64>,
    block_payers: BTreeMap<Obj, i64>,
    /// Canonical bytes held since the driver started, by home world and by payer.
    held_by_world: BTreeMap<Obj, i64>,
    held_by_payer: BTreeMap<Obj, i64>,
    /// `home_world` of each object seen (never changes after creation).
    home_cache: BTreeMap<Obj, Obj>,
    /// Time spent attributing storage in `end_block` (nanoseconds), for the cost report.
    attribution_nanos: u64,
}

impl BlockDriver {
    pub(crate) fn new(scheduler: Scheduler) -> Self {
        let block = deterministic::current()
            .map(|ctx| ctx.block)
            .unwrap_or_default();
        let conflicts_at_block_start = scheduler.deterministic_conflicts();
        Self {
            scheduler,
            batch: Arc::default(),
            block,
            outcomes: Vec::new(),
            conflicts_at_block_start,
            job_budget: DEFAULT_JOB_BUDGET,
            root_at_end_block: true,
            metering: MeterState::default(),
            metering_enabled: true,
        }
    }

    /// Turn the engine meter off (no `[5, meter]` entries, no ceiling, no charge hook) or back on.
    /// On by default. For cost measurements; a chain must not change this between blocks.
    pub fn set_metering(&mut self, enabled: bool) {
        self.metering_enabled = enabled;
    }

    /// The canonical bytes of state attributed to each home world since this driver started
    /// (ADR 0007 ratification note 4). Objects with no home world (players, system objects) are
    /// held under `#-1`.
    #[must_use]
    pub fn storage_held_by_world(&self) -> &BTreeMap<Obj, i64> {
        &self.metering.held_by_world
    }

    /// The canonical bytes of state attributed to each paying player since this driver started.
    #[must_use]
    pub fn storage_held_by_payer(&self) -> &BTreeMap<Obj, i64> {
        &self.metering.held_by_payer
    }

    /// Nanoseconds `end_block` has spent attributing storage to worlds (cost report).
    #[must_use]
    pub fn storage_attribution_nanos(&self) -> u64 {
        self.metering.attribution_nanos
    }

    /// The driven scheduler, for read-only queries.
    #[must_use]
    pub fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    /// Change the per-input job budget.
    pub fn set_job_budget(&mut self, budget: usize) {
        self.job_budget = budget;
    }

    /// Whether `end_block` computes the state root (on by default). The root is O(state).
    pub fn set_state_root_at_end_block(&mut self, enabled: bool) {
        self.root_at_end_block = enabled;
    }

    /// The state root of the committed state now. Between blocks this is the root of the last
    /// sealed block.
    pub fn state_root(&self) -> Result<StateRoot, WorldStateError> {
        self.scheduler.database.state_root()
    }

    /// The canonical encoding of one relation of the committed state (the dump endpoint).
    pub fn canonical_relation(&self, name: &str) -> Result<CanonicalRelation, WorldStateError> {
        self.scheduler.database.canonical_relation(name)
    }

    /// Hold the committed state for a checkpoint (ADR 0006 decision 7). O(1); between blocks this
    /// is the state after the last sealed block.
    pub fn capture_checkpoint(
        &self,
    ) -> Result<moor_db::state_root::checkpoint::CheckpointCapture, WorldStateError> {
        self.scheduler.database.capture_checkpoint()
    }

    /// Start a block: install its context (time, seed; command index 0) and empty the batch.
    pub fn begin_block(&mut self, block: BlockContext) {
        deterministic::set_block(block);
        self.block = block;
        *lock(&self.batch) = EventBatch::default();
        self.outcomes.clear();
        meter::set_active(self.metering_enabled);
        moor_db::commit_meter::set_enabled(self.metering_enabled);
        meter::begin_block();
        self.metering.meters.clear();
        self.metering.settle.clear();
        self.metering.block_objects.clear();
        self.metering.block_payers.clear();
        self.conflicts_at_block_start = self.scheduler.deterministic_conflicts();
    }

    /// Wrap `inner` so that its committed output lands in this block's batch.
    #[must_use]
    pub fn session(&self, inner: Arc<dyn Session>) -> Arc<dyn Session> {
        Arc::new(BlockSession::new(inner, self.batch.clone()))
    }

    /// Submit one input and run to quiescence. Output goes to the batch and to `inner`.
    pub fn submit(&mut self, input: BlockInput, inner: Arc<dyn Session>) -> &InputOutcome {
        let session = self.session(inner);
        let (kind, player, log_bytes) = input_subject(&input);
        self.begin_metered_input(kind);
        meter::set_log_bytes(log_bytes);
        let submitted = self.submit_input(input, session);
        // Read the index the input took (the submission advanced it).
        let command_index = deterministic::current().map_or(0, |ctx| ctx.command);
        let run = self.scheduler.run_until_quiescent(self.job_budget);
        let (task_id, result) = match submitted {
            Ok(handle) => (Some(handle.task_id()), take_result(&handle)),
            Err(error) => (None, Some(Err(error))),
        };
        let outcome = outcome_of(false, false, run.budget_exhausted, &result);
        self.finish_metered_input(command_index, kind, player, outcome, None);
        self.outcomes.push(InputOutcome {
            command_index,
            task_id,
            result,
            run,
            admission: None,
        });
        self.outcomes.last().expect("pushed above")
    }

    /// Submit one signed envelope (wire bytes) and run it to quiescence. Output goes to the batch
    /// and to `inner`. Admission, rejection and session events are described in the module docs.
    pub fn submit_envelope(&mut self, bytes: &[u8], inner: Arc<dyn Session>) -> &InputOutcome {
        self.submit_envelope_with(bytes, inner, None)
    }

    /// [`Self::submit_envelope`] with a callback run after admission and before the envelope's
    /// task (the daemon binds a connecting host's connection there).
    pub fn submit_envelope_with(
        &mut self,
        bytes: &[u8],
        inner: Arc<dyn Session>,
        on_admitted: Option<OnAdmitted>,
    ) -> &InputOutcome {
        let session = self.session(inner);
        self.scheduler.begin_sequenced_input();
        self.begin_metered_input(MeterKind::Command);
        meter::set_log_bytes(bytes.len() as u64);
        let command_index = deterministic::current().map_or(0, |ctx| ctx.command);
        let run = self
            .scheduler
            .run_envelope(bytes, session, on_admitted, self.job_budget);
        // Drain anything the envelope's tasks left queued (forks, wakes).
        let tail = self.scheduler.run_until_quiescent(self.job_budget);
        let summary = RunSummary {
            jobs_run: run.run.jobs_run + tail.jobs_run,
            budget_exhausted: run.run.budget_exhausted || tail.budget_exhausted,
        };
        let player = match &run.admission {
            Ok(admitted) => admitted.player(),
            Err(AdmissionRejection::ChargeDenied { player, .. }) => *player,
            Err(_) => moor_var::NOTHING,
        };
        let denied = matches!(run.admission, Err(AdmissionRejection::ChargeDenied { .. }));
        let rejected = run.admission.is_err() && !denied;
        let meter_kind = envelope_meter_kind(run.kind, &run.admission);
        let outcome = outcome_of(denied, rejected, summary.budget_exhausted, &run.result);
        let kind = match &run.admission {
            Err(reason) => Some(BlockEventKind::Rejected {
                kind: run.kind,
                session: run.session,
                reason: reason.clone(),
            }),
            Ok(admitted @ (Admitted::Delegated { .. } | Admitted::Revoked { .. })) => {
                Some(BlockEventKind::Sessions(admitted.clone()))
            }
            Ok(_) => None,
        };
        if let Some(kind) = kind {
            lock(&self.batch).push(None, player, kind);
        }
        self.finish_metered_input(
            command_index,
            meter_kind,
            player,
            outcome,
            run.reservation.as_ref(),
        );
        self.outcomes.push(InputOutcome {
            command_index,
            task_id: run.task_id,
            result: run.result,
            run: summary,
            admission: Some(run.admission),
        });
        self.outcomes.last().expect("pushed above")
    }

    fn submit_input(
        &self,
        input: BlockInput,
        session: Arc<dyn Session>,
    ) -> Result<TaskHandle, SchedulerError> {
        let scheduler = &self.scheduler;
        scheduler.begin_sequenced_input();
        match input {
            BlockInput::Command { player, command } => {
                scheduler.submit_command_task_inner(SYSTEM_OBJECT, player, command, session)
            }
            BlockInput::Eval { player, code } => {
                // The input keeps its command index even when it does not compile.
                let program = compile(&code, scheduler.config.features.compile_options())
                    .map_err(SchedulerError::CompilationError)?;
                scheduler.submit_eval_task_inner(player, player, program, None, session)
            }
            BlockInput::Verb {
                player,
                vloc,
                verb,
                args,
                argstr,
                authority,
            } => scheduler.submit_verb_task_inner(
                player,
                ObjectRef::Id(vloc),
                verb,
                args,
                v_str(&argstr),
                authority,
                session,
            ),
            BlockInput::Connected { player } => {
                self.submit_hook(player, Symbol::mk("user_connected"), session)
            }
            BlockInput::Disconnected { player } => {
                self.submit_hook(player, Symbol::mk("user_disconnected"), session)
            }
            BlockInput::SequencerDisconnect { player } => {
                scheduler.submit_disconnect_input(player, session)
            }
        }
    }

    fn submit_hook(
        &self,
        player: Obj,
        verb: Symbol,
        session: Arc<dyn Session>,
    ) -> Result<TaskHandle, SchedulerError> {
        self.scheduler.submit_verb_task_inner(
            player,
            ObjectRef::Id(SYSTEM_OBJECT),
            verb,
            List::mk_list(&[v_obj(player)]),
            v_empty_str(),
            SYSTEM_OBJECT,
            session,
        )
    }

    /// Events committed so far in this block.
    #[must_use]
    pub fn events(&self) -> Vec<BlockEvent> {
        lock(&self.batch).events.clone()
    }

    /// How many events this block's batch holds so far.
    #[must_use]
    pub fn event_count(&self) -> usize {
        lock(&self.batch).events.len()
    }

    /// The context of the current (or last) block.
    #[must_use]
    pub fn block(&self) -> BlockContext {
        self.block
    }

    /// End the block: cancel any task still suspended, and return the outcomes and event batch.
    pub fn end_block(&mut self) -> BlockOutput {
        let abandoned = self.scheduler.abandon_suspended_tasks();
        // Cancelling can release `wait_task` dependants; none may run past the boundary.
        self.scheduler.run_until_quiescent(self.job_budget);
        // Settlement and storage attribution happen before the root (ADR 0007 decision 3).
        self.settle_block();
        self.attribute_storage();
        let events = std::mem::take(&mut lock(&self.batch).events);
        let state_root = self.root_at_end_block.then(|| self.state_root());
        BlockOutput {
            block: self.block,
            outcomes: std::mem::take(&mut self.outcomes),
            events,
            abandoned,
            conflicts: self.scheduler.deterministic_conflicts() - self.conflicts_at_block_start,
            meters: std::mem::take(&mut self.metering.meters),
            block_totals: meter::all_block_totals(),
            state_root,
        }
    }

    /// Reset the meter for the next input (the caller has advanced the command index).
    fn begin_metered_input(&mut self, kind: MeterKind) {
        if !self.metering_enabled {
            return;
        }
        let _ = moor_db::commit_meter::take();
        let ceiling = self.scheduler.config.deterministic.command_tick_maximum();
        meter::begin_command(kind, SYSTEM_OBJECT.id().0, 0, Some(ceiling));
    }

    /// Close the input's meter: push `[5, meter]` after its events, add it to the block totals,
    /// and queue it for settlement when a charge policy applies.
    fn finish_metered_input(
        &mut self,
        command_index: u64,
        kind: MeterKind,
        player: Obj,
        outcome: MeterOutcome,
        reservation: Option<&crate::tasks::charge::Reservation>,
    ) {
        if !self.metering_enabled {
            return;
        }
        let live = meter::live();
        let delta = moor_db::commit_meter::take();
        let outcome = if live.limit_hit && outcome == MeterOutcome::Ok {
            MeterOutcome::TickCeiling
        } else {
            outcome
        };
        let m = Meter {
            kind,
            world: live.world,
            ticks: live.ticks,
            tasks: live.tasks,
            log_bytes: live.log_bytes,
            events: live.events,
            event_bytes: live.event_bytes,
            objects_created: delta.created,
            objects_recycled: delta.recycled,
            storage_delta: delta.total(),
            policy_ticks: live.policy_ticks,
            outcome,
        };
        // Storage is attributed per object now and resolved to home worlds at `end_block`.
        for (obj, d) in &delta.storage {
            *self.metering.block_objects.entry(*obj).or_insert(0) += d;
        }
        if m.storage_delta != 0 {
            *self.metering.block_payers.entry(player).or_insert(0) += m.storage_delta;
        }
        if let Some(r) = reservation.filter(|r| r.active) {
            self.metering.settle.push(SettleEntry {
                player,
                world: r.world,
                meter: m,
                leaving: r.leaving,
            });
        }
        lock(&self.batch).push(None, player_or_system(player), BlockEventKind::Meter(m));
        meter::record(&m);
        self.metering.meters.push((command_index, m));
    }

    /// `charge(player, meter, 'settle)` for each charged input in command-index order, one system
    /// task per charged world (ascending), then `meter_total` on `#0`, each world and each
    /// player. Runs outside any input (command index 0) and emits no events.
    fn settle_block(&mut self) {
        if !self.metering_enabled || self.metering.settle.is_empty() {
            return;
        }
        deterministic::set_block(self.block);
        let mut by_world: BTreeMap<Obj, Vec<(Obj, Var)>> = BTreeMap::new();
        let mut totals: BTreeMap<Obj, TotalsDelta> = BTreeMap::new();
        for entry in &self.metering.settle {
            by_world
                .entry(entry.world)
                .or_default()
                .push((entry.player, meter_var(&entry.meter, entry.world, entry.leaving)));
            let m = &entry.meter;
            let mut targets = vec![SYSTEM_OBJECT];
            if entry.world != SYSTEM_OBJECT {
                targets.push(entry.world);
            }
            if entry.player != NOTHING {
                targets.push(entry.player);
            }
            for target in targets {
                let t = totals.entry(target).or_default();
                t.ticks += m.ticks;
                t.log_bytes += m.log_bytes;
                t.storage += m.storage_delta;
            }
        }
        for (_, entries) in by_world {
            self.scheduler.settle_world(entries);
        }
        self.scheduler.write_meter_totals(&totals);
    }

    /// Fold this block's storage change into the held-by-world and held-by-payer ledgers.
    fn attribute_storage(&mut self) {
        if !self.metering_enabled {
            return;
        }
        let started = std::time::Instant::now();
        let objects = std::mem::take(&mut self.metering.block_objects);
        let payers = std::mem::take(&mut self.metering.block_payers);
        for (payer, d) in payers {
            *self.metering.held_by_payer.entry(payer).or_insert(0) += d;
        }
        let missing: Vec<Obj> = objects
            .keys()
            .filter(|o| !self.metering.home_cache.contains_key(*o))
            .copied()
            .collect();
        if !missing.is_empty() {
            self.resolve_home_worlds(&missing);
        }
        for (obj, d) in objects {
            let home = self.metering.home_cache.get(&obj).copied().unwrap_or(NOTHING);
            *self.metering.held_by_world.entry(home).or_insert(0) += d;
        }
        self.metering.attribution_nanos += started.elapsed().as_nanos() as u64;
    }

    /// Read `home_world` of each object in one rolled-back transaction. An object that cannot be
    /// read (recycled, or with no such property) has no home world.
    fn resolve_home_worlds(&mut self, objects: &[Obj]) {
        let Ok(ws) = self.scheduler.database.new_world_state() else {
            return;
        };
        let perms = ws.owner_of(&SYSTEM_OBJECT).ok().and_then(|p| {
            ws.flags_of(&p)
                .ok()
                .map(|f| moor_common::model::TaskPermissions::new(p, f))
        });
        if let Some(perms) = perms {
            for obj in objects {
                let home = ws
                    .retrieve_property(&perms, obj, Symbol::mk("home_world"))
                    .ok()
                    .and_then(|v| v.as_object())
                    .unwrap_or(NOTHING);
                self.metering.home_cache.insert(*obj, home);
            }
        }
        let _ = ws.rollback();
    }

    /// `begin_block`, every input in order with its session, then `end_block`.
    pub fn run_block(
        &mut self,
        block: BlockContext,
        inputs: Vec<(BlockInput, Arc<dyn Session>)>,
    ) -> BlockOutput {
        self.begin_block(block);
        for (input, session) in inputs {
            self.submit(input, session);
        }
        self.end_block()
    }

    /// Stop the scheduler. Suspended tasks are saved by the tasks DB as usual.
    pub fn shutdown(self) -> Result<(), SchedulerError> {
        self.scheduler.stop(None)?;
        let lc = self.scheduler.lifecycle.lock();
        lc.task_q.suspended.save_tasks();
        lc.save_schedules();
        Ok(())
    }
}

impl Drop for BlockDriver {
    fn drop(&mut self) {
        meter::set_active(false);
        moor_db::commit_meter::set_enabled(false);
    }
}

/// The recipient of a meter entry: the player, or `#0` when no player is known.
fn player_or_system(player: Obj) -> Obj {
    if player == NOTHING { SYSTEM_OBJECT } else { player }
}

/// The meter kind, the player and the log bytes an unsigned input has.
fn input_subject(input: &BlockInput) -> (MeterKind, Obj, u64) {
    match input {
        BlockInput::Command { player, command } => {
            (MeterKind::Command, *player, command.len() as u64)
        }
        BlockInput::Eval { player, code } => (MeterKind::Command, *player, code.len() as u64),
        BlockInput::Verb { player, .. } => (MeterKind::Command, *player, 0),
        BlockInput::Connected { player } => (MeterKind::Connect, *player, 0),
        BlockInput::Disconnected { player } | BlockInput::SequencerDisconnect { player } => {
            (MeterKind::Sequencer, *player, 0)
        }
    }
}

/// The meter kind of an envelope: a delegation that created a player is `create`, any other
/// delegation counts as `connect` (it registers a session), a revocation is `revoke`.
fn envelope_meter_kind(
    kind: Option<EnvelopeKind>,
    admission: &Result<Admitted, AdmissionRejection>,
) -> MeterKind {
    match (kind, admission) {
        (_, Ok(Admitted::Delegated { created: true, .. })) => MeterKind::Create,
        (Some(EnvelopeKind::Connect | EnvelopeKind::Delegate), _) => MeterKind::Connect,
        (Some(EnvelopeKind::Revoke | EnvelopeKind::RevokeAll), _) => MeterKind::Revoke,
        _ => MeterKind::Command,
    }
}

/// How an input ended, before the tick limit (which the meter reports) is considered.
fn outcome_of(
    denied: bool,
    rejected: bool,
    budget_exhausted: bool,
    result: &Option<Result<Var, SchedulerError>>,
) -> MeterOutcome {
    if denied {
        MeterOutcome::Denied
    } else if rejected
        || budget_exhausted
        || matches!(result, Some(Err(SchedulerError::TaskAbortedCancelled)))
    {
        MeterOutcome::Aborted
    } else {
        MeterOutcome::Ok
    }
}

/// The meter as a charge hook sees it: a map keyed by symbols.
fn meter_var(m: &Meter, world: Obj, leaving: bool) -> Var {
    let int = |n: u64| v_int(i64::try_from(n).unwrap_or(i64::MAX));
    v_map(&[
        (v_sym("kind"), v_sym(m.kind.name())),
        (v_sym("world"), v_obj(world)),
        (v_sym("ticks"), int(m.ticks)),
        (v_sym("tasks"), int(m.tasks)),
        (v_sym("log_bytes"), int(m.log_bytes)),
        (v_sym("events"), int(m.events)),
        (v_sym("event_bytes"), int(m.event_bytes)),
        (v_sym("objects_created"), int(m.objects_created)),
        (v_sym("objects_recycled"), int(m.objects_recycled)),
        (v_sym("storage_delta"), v_int(m.storage_delta)),
        (v_sym("policy_ticks"), int(m.policy_ticks)),
        (v_sym("outcome"), v_sym(m.outcome.name())),
        (v_sym("leaving"), v_bool(leaving)),
    ])
}
