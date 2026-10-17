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

use flume::{Receiver, Sender};
use moor_common::threading::{
    DetectionResult, TaskPoolPinningMode, detect_performance_cores, logical_core_count,
    task_pool_pinning_mode,
};
use moor_common::threading::{
    pin_current_thread_to_core, set_current_task_worker_index, set_task_worker_count,
    unpin_current_thread,
};
use parking_lot::Mutex;
use std::{collections::VecDeque, io, sync::Arc, thread::JoinHandle};
use tracing::{error, info, warn};

trait WorkItem {
    fn run(self: Box<Self>);
}

impl<F> WorkItem for F
where
    F: FnOnce() + Send + 'static,
{
    fn run(self: Box<Self>) {
        (*self)()
    }
}

enum WorkerMsg {
    Run(Box<dyn WorkItem + Send + 'static>),
    Stop,
}

type ManualJob = Box<dyn FnOnce() + Send + 'static>;

/// The driver-owned run queue of the manual executor (deterministic mode). Dispatch appends a job;
/// the block driver pops and runs jobs one at a time on its own thread, in FIFO order.
#[derive(Clone, Default)]
pub(crate) struct ManualRunQueue(Arc<Mutex<VecDeque<ManualJob>>>);

impl ManualRunQueue {
    fn push(&self, job: ManualJob) {
        self.0.lock().push_back(job);
    }

    /// Run the oldest queued job on the calling thread. Returns false when the queue is empty.
    /// The queue lock is released before the job runs, so the job may enqueue more work.
    pub(crate) fn run_next(&self) -> bool {
        let Some(job) = self.0.lock().pop_front() else {
            return false;
        };
        job();
        true
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.lock().is_empty()
    }
}

/// Fixed-size task worker pool with explicit worker lifecycle and affinity setup, or (in
/// deterministic mode) a manual run queue with no worker threads at all.
pub(crate) struct TaskThreadPool {
    sender: Sender<WorkerMsg>,
    threads: Vec<JoinHandle<()>>,
    manual: Option<ManualRunQueue>,
}

impl TaskThreadPool {
    pub(crate) fn configured() -> io::Result<Self> {
        // Use topology-derived logical core count for fallback worker sizing so the
        // scheduler pool is not accidentally limited by current-thread affinity.
        let fallback_threads = logical_core_count().max(1);
        let pinning_mode = task_pool_pinning_mode();

        let pinned_core_ids = match pinning_mode {
            TaskPoolPinningMode::None => {
                info!("Task pool pinning disabled by runtime config");
                None
            }
            TaskPoolPinningMode::Auto | TaskPoolPinningMode::Performance => {
                match detect_performance_cores() {
                    Ok(DetectionResult::PerformanceCores(selection)) => {
                        info!(
                            source = selection.source,
                            threshold = selection.threshold,
                            min_metric = selection.min_metric,
                            max_metric = selection.max_metric,
                            metric_tiers = selection.metric_tiers,
                            physical_cores = selection.physical_cores,
                            logical_processors = selection.logical_processors,
                            pinning_mode = ?pinning_mode,
                            "Detected high-performance CPU tier for task pool pinning"
                        );
                        let worker_core_ids =
                            moor_common::threading::worker_performance_core_ids_ref();
                        if worker_core_ids.is_empty() {
                            warn!(
                                "No worker performance cores reserved, task pool pinning disabled"
                            );
                            None
                        } else {
                            info!(
                                reserved_worker_cores = ?worker_core_ids,
                                reserved_service_cores = ?moor_common::threading::service_performance_core_ids_ref(),
                                "Using reserved worker/service performance-core split"
                            );
                            Some(worker_core_ids.to_vec())
                        }
                    }
                    Ok(DetectionResult::NoSelection { reason }) => {
                        if pinning_mode == TaskPoolPinningMode::Performance {
                            warn!(
                                reason,
                                "Task pool pinning mode 'performance' requested, but no high-performance tier detected; using unpinned task pool"
                            );
                        } else {
                            info!(
                                reason,
                                "No clear high-performance CPU tier detected, task pool pinning disabled"
                            );
                        }
                        None
                    }
                    Err(e) => {
                        warn!(error = ?e, "Could not detect CPU topology, using unpinned task pool");
                        None
                    }
                }
            }
        };

        let num_threads = pinned_core_ids
            .as_ref()
            .map_or(fallback_threads, |core_ids| core_ids.len());

        if let Some(core_ids) = &pinned_core_ids {
            info!(worker_threads = num_threads, pinned_cores = ?core_ids,
                "Pinning task pool workers to performance CPU cores");
        } else {
            info!(
                worker_threads = num_threads,
                "Using unpinned task pool workers"
            );
        }
        Self::new(num_threads, pinned_core_ids)
    }

    pub(crate) fn new(num_threads: usize, pinned_core_ids: Option<Vec<usize>>) -> io::Result<Self> {
        Self::with_spawner(num_threads, pinned_core_ids, |builder, run| {
            builder.spawn(run)
        })
    }

    fn with_spawner(
        num_threads: usize,
        pinned_core_ids: Option<Vec<usize>>,
        mut spawn: impl FnMut(
            std::thread::Builder,
            Box<dyn FnOnce() + Send>,
        ) -> io::Result<JoinHandle<()>>,
    ) -> io::Result<Self> {
        let (sender, receiver) = flume::unbounded::<WorkerMsg>();
        let pinned_core_ids = pinned_core_ids.map(std::sync::Arc::new);
        set_task_worker_count(num_threads);

        // Own each handle as soon as it starts. A later spawn failure drops the pool,
        // which signals and joins every worker that already exists.
        let mut pool = Self {
            sender,
            threads: Vec::with_capacity(num_threads),
            manual: None,
        };
        for index in 0..num_threads {
            let receiver = receiver.clone();
            let pinned_core_ids = pinned_core_ids.clone();

            let thread = spawn(
                std::thread::Builder::new().name(format!("moor-task-pool-{index}")),
                Box::new(move || worker_loop(index, receiver, pinned_core_ids)),
            )?;
            pool.threads.push(thread);
        }

        Ok(pool)
    }

    /// A pool with no threads: `spawn` appends to `queue`, which the block driver runs.
    pub(crate) fn manual(queue: ManualRunQueue) -> Self {
        let (sender, _) = flume::unbounded::<WorkerMsg>();
        Self {
            sender,
            threads: Vec::new(),
            manual: Some(queue),
        }
    }

    /// True when this pool is the manual executor's run queue.
    pub(crate) fn is_manual(&self) -> bool {
        self.manual.is_some()
    }

    pub(crate) fn spawn<F>(&self, task: F)
    where
        F: FnOnce() + Send + 'static,
    {
        if let Some(queue) = &self.manual {
            queue.push(Box::new(task));
            return;
        }
        let msg = WorkerMsg::Run(Box::new(task));
        if let Err(e) = self.sender.send(msg) {
            warn!(error = ?e, "Failed to enqueue task into task thread pool");
        }
    }
}

impl Drop for TaskThreadPool {
    fn drop(&mut self) {
        for _ in 0..self.threads.len() {
            self.sender.send(WorkerMsg::Stop).ok();
        }

        while let Some(thread) = self.threads.pop() {
            // The final scheduler reference can be released by a task worker. Its
            // own handle must detach; the queued Stop ends that worker after return.
            if thread.thread().id() == std::thread::current().id() {
                continue;
            }
            if let Err(e) = thread.join() {
                error!(error = ?e, "Task worker thread panicked during join");
            }
        }
    }
}

fn worker_loop(
    index: usize,
    receiver: Receiver<WorkerMsg>,
    pinned_core_ids: Option<std::sync::Arc<Vec<usize>>>,
) {
    set_current_task_worker_index(index);

    if let Some(core_ids) = pinned_core_ids {
        let core_id = core_ids[index % core_ids.len()];
        if let Err(e) = pin_current_thread_to_core(core_id) {
            warn!(
                thread_index = index,
                core_id,
                error = ?e,
                "Failed to pin task worker to core"
            );
        }
    } else if let Err(e) = unpin_current_thread() {
        warn!(
            thread_index = index,
            error = ?e,
            "Failed to clear inherited affinity for unpinned task worker"
        );
    }

    while let Ok(msg) = receiver.recv() {
        match msg {
            WorkerMsg::Run(task) => {
                let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    task.run();
                }));
                if let Err(panic_payload) = panic_result {
                    let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "Task worker panicked with unknown payload".to_string()
                    };

                    error!(
                        thread_index = index,
                        panic_msg, "Task worker recovered from task panic"
                    );
                }
            }
            WorkerMsg::Stop => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    #[test]
    fn partial_startup_joins_started_workers() {
        let stopped = Arc::new(AtomicBool::new(false));
        let observed_stop = stopped.clone();
        let mut spawned = 0;
        let result = TaskThreadPool::with_spawner(2, None, move |builder, run| {
            spawned += 1;
            if spawned == 2 {
                return Err(io::Error::other("injected spawn failure"));
            }
            let stopped = stopped.clone();
            builder.spawn(move || {
                run();
                stopped.store(true, Ordering::Release);
            })
        });

        assert!(result.is_err());
        // This must already be true on return: dropping raw handles would detach.
        assert!(observed_stop.load(Ordering::Acquire));
    }

    #[test]
    fn manual_pool_runs_jobs_in_submission_order_on_the_caller() {
        let queue = ManualRunQueue::default();
        let pool = TaskThreadPool::manual(queue.clone());
        let order = Arc::new(Mutex::new(Vec::new()));
        for i in 0..3 {
            let order = order.clone();
            let inner = queue.clone();
            pool.spawn(move || {
                order.lock().push(i);
                if i == 0 {
                    // Work queued by a running job goes to the back.
                    let order = order.clone();
                    inner.push(Box::new(move || order.lock().push(9)));
                }
            });
        }
        while queue.run_next() {}
        assert_eq!(*order.lock(), [0, 1, 2, 9]);
    }

    #[test]
    fn pool_can_be_released_by_its_own_worker() {
        let pool = TaskThreadPool::new(2, None).unwrap();
        let (send_pool, receive_pool) = flume::bounded::<TaskThreadPool>(1);
        let (finished, completion) = flume::bounded(1);
        pool.spawn(move || {
            drop(receive_pool.recv().unwrap());
            finished.send(()).unwrap();
        });
        send_pool.send(pool).unwrap();

        // A self-join panic is caught by the worker and drops the completion sender.
        completion.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}
