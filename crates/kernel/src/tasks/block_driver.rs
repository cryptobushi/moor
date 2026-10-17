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

use crate::tasks::{
    TaskHandle,
    envelope_admission::{AdmissionRejection, Admitted, take_result},
    scheduler::Scheduler,
};
use moor_common::{
    deterministic::{self, BlockContext},
    envelope::EnvelopeKind,
    model::ObjectRef,
    tasks::{ConnectionDetails, NarrativeEvent, SchedulerError, Session, SessionError, TaskId},
};
use moor_compiler::compile;
use moor_var::{List, Obj, SYSTEM_OBJECT, Symbol, Var, v_empty_str, v_obj, v_str};
use std::sync::{Arc, Mutex, MutexGuard};
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
}

#[derive(Default)]
struct EventBatch {
    next_seq: u64,
    events: Vec<BlockEvent>,
}

impl EventBatch {
    fn push(&mut self, task_id: Option<TaskId>, player: Obj, kind: BlockEventKind) {
        let command_index = deterministic::current().map_or(0, |ctx| ctx.command);
        self.events.push(BlockEvent {
            seq: self.next_seq,
            command_index,
            task_id,
            player,
            kind,
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
        }
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

    /// Start a block: install its context (time, seed; command index 0) and empty the batch.
    pub fn begin_block(&mut self, block: BlockContext) {
        deterministic::set_block(block);
        self.block = block;
        *lock(&self.batch) = EventBatch::default();
        self.outcomes.clear();
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
        let submitted = self.submit_input(input, session);
        // Read the index the input took (the submission advanced it).
        let command_index = deterministic::current().map_or(0, |ctx| ctx.command);
        let run = self.scheduler.run_until_quiescent(self.job_budget);
        let (task_id, result) = match submitted {
            Ok(handle) => (Some(handle.task_id()), take_result(&handle)),
            Err(error) => (None, Some(Err(error))),
        };
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
        let session = self.session(inner);
        self.scheduler.begin_sequenced_input();
        let command_index = deterministic::current().map_or(0, |ctx| ctx.command);
        let run = self
            .scheduler
            .run_envelope(bytes, session, None, self.job_budget);
        // Drain anything the envelope's tasks left queued (forks, wakes).
        let tail = self.scheduler.run_until_quiescent(self.job_budget);
        let summary = RunSummary {
            jobs_run: run.run.jobs_run + tail.jobs_run,
            budget_exhausted: run.run.budget_exhausted || tail.budget_exhausted,
        };
        let player = run
            .admission
            .as_ref()
            .map_or(moor_var::NOTHING, Admitted::player);
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

    /// End the block: cancel any task still suspended, and return the outcomes and event batch.
    pub fn end_block(&mut self) -> BlockOutput {
        let abandoned = self.scheduler.abandon_suspended_tasks();
        // Cancelling can release `wait_task` dependants; none may run past the boundary.
        self.scheduler.run_until_quiescent(self.job_budget);
        let events = std::mem::take(&mut lock(&self.batch).events);
        BlockOutput {
            block: self.block,
            outcomes: std::mem::take(&mut self.outcomes),
            events,
            abandoned,
            conflicts: self.scheduler.deterministic_conflicts() - self.conflicts_at_block_start,
        }
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
