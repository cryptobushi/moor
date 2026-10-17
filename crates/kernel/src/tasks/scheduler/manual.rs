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

//! The manual executor (deterministic mode, audit S1-S4, S9).
//!
//! There is no task pool: dispatch appends a job to one FIFO run queue and the driver runs jobs
//! one at a time on its own thread. Each job opens its transaction when it starts, so it sees every
//! earlier commit, and only one transaction is ever open. After each job the driver drains the
//! immediate-wake queue (FIFO) into the run queue. Quiescence is an empty run queue with no wake
//! pending.
//!
//! Two drivers use this: `BlockDriver` (the STF entry point, no threads at all) and the sequencer
//! loop that `Scheduler::start` runs in deterministic mode, which serves client requests one at a
//! time and runs to quiescence after each.

use super::{Scheduler, SchedulerClientRequest, SchedulerState};
use crate::tasks::block_driver::BlockDriver;
use flume::{Receiver, RecvTimeoutError};
use moor_common::tasks::{SchedulerError, SessionFactory, TaskId};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tracing::{debug, info};

/// How a run to quiescence ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunSummary {
    /// Jobs (task attempts or resumptions) run.
    pub jobs_run: usize,
    /// True when the job budget ran out first; the remaining work was cancelled.
    pub budget_exhausted: bool,
}

impl Scheduler {
    /// True when this scheduler runs on the manual executor (deterministic mode).
    #[must_use]
    pub fn is_manual(&self) -> bool {
        self.manual_queue.is_some()
    }

    /// Mark the start of one sequenced input (a block driver input or a request taken by the
    /// sequencer loop). In deterministic mode this advances the block's command index, which keys
    /// the input's random stream and id counters. Tasks derived from the input (forks,
    /// `force_input`, wakes) keep its index.
    pub(crate) fn begin_sequenced_input(&self) {
        if self.manual_queue.is_some() {
            moor_common::deterministic::next_command();
        }
    }

    /// Transaction conflicts seen in deterministic mode. Always zero unless there is a bug.
    #[must_use]
    pub fn deterministic_conflicts(&self) -> u64 {
        self.deterministic_conflicts.load(Ordering::SeqCst)
    }

    /// Run queued jobs on the calling thread until the run queue is empty and no wake is pending,
    /// or until `budget` jobs have run. On budget exhaustion every active task is cancelled and the
    /// queue is drained again so that no dispatched job is left behind; cancelled jobs end without
    /// running MOO code. Returns immediately on a threaded scheduler.
    pub fn run_until_quiescent(&self, budget: usize) -> RunSummary {
        let Some(queue) = &self.manual_queue else {
            return RunSummary {
                jobs_run: 0,
                budget_exhausted: false,
            };
        };
        let mut jobs_run = 0;
        let mut budget_exhausted = false;
        loop {
            if !budget_exhausted && jobs_run >= budget {
                budget_exhausted = true;
                let lc = self.lifecycle.lock();
                for task in lc.task_q.active.values() {
                    task.control.request_cancel();
                }
            }
            if queue.run_next() {
                jobs_run += 1;
                self.drain_immediate_wakes();
                continue;
            }
            self.drain_immediate_wakes();
            if queue.is_empty() {
                return RunSummary {
                    jobs_run,
                    budget_exhausted,
                };
            }
        }
    }

    /// Ids of the tasks left suspended, ascending.
    #[must_use]
    pub fn suspended_task_ids(&self) -> Vec<TaskId> {
        let lc = self.lifecycle.lock();
        let mut ids: Vec<TaskId> = lc
            .task_q
            .suspended
            .records()
            .map(|record| record.task.task_id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// Enforce the empty task queue at a block boundary (ADR 0001 ratification note 1): cancel
    /// every suspended task, in ascending id order, without running it. Returns their ids.
    pub(crate) fn abandon_suspended_tasks(&self) -> Vec<TaskId> {
        let ids = self.suspended_task_ids();
        let mut lc = self.lifecycle.lock();
        for task_id in &ids {
            if let Some(task) = lc.task_q.suspended.remove_task(*task_id) {
                lc.cancel_undispatched_task(task);
            }
        }
        ids
    }

    /// Start the scheduler with an external block driver and no service threads. Only valid in
    /// deterministic mode. Client requests are refused afterwards: every input goes through the
    /// returned driver.
    pub fn start_block_driver(
        &self,
        bg_session_factory: Arc<dyn SessionFactory>,
    ) -> Result<BlockDriver, SchedulerError> {
        if self.manual_queue.is_none() {
            return Err(SchedulerError::CouldNotStartTask);
        }
        // Dropping the receiver makes `enqueue_client_request` fail instead of queueing work
        // that nothing would serve.
        drop(self.take_client_request_recv()?);
        self.restore_tasks(bg_session_factory);
        self.lifecycle.lock().state = SchedulerState::Running;
        info!("Scheduler started under an external block driver (deterministic mode)");
        Ok(BlockDriver::new(self.clone()))
    }

    /// The deterministic-mode service loop: run one client request, then the run queue to
    /// quiescence, then the next request. Replaces the request, timer and worker threads.
    pub(super) fn sequencer_loop(&self, recv: Receiver<SchedulerClientRequest>) {
        loop {
            match recv.recv_timeout(Duration::from_millis(50)) {
                Ok(request) => {
                    // Each request taken is one sequenced input. Read-only queries take an index
                    // too; the sequence is still a function of the request order alone.
                    self.begin_sequenced_input();
                    request(self);
                    self.run_until_quiescent(usize::MAX);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            if self.state() == SchedulerState::Stopped {
                break;
            }
        }
        debug!("Deterministic sequencer loop exited");
        let lc = self.lifecycle.lock();
        lc.task_q.suspended.save_tasks();
        lc.save_schedules();
    }
}
