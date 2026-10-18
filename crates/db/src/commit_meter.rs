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

//! Commit-time storage measurement (RuneWorld ADR 0007 decision 2, `storage_delta`).
//!
//! When enabled, every successful write commit measures its working set in the state encoding's
//! canonical sizes (`state_root::working_set_delta`): for each written key, the size of the pair
//! `[key, value]` after the write minus the size of the pair the transaction started from. The
//! result is added to a process-wide accumulator the block driver drains after each input:
//! the net change in canonical bytes per object, and the count of objects whose `object_flags`
//! row was created or deleted. Sizes are canonical encodings, never Fjall bytes (ADR 0001 note 8).
//!
//! The accumulator is process-global because the deterministic executor is single-threaded and
//! owns one database; it is off (and costs one relaxed load per commit) unless a driver turns it on.

use moor_var::Obj;
use std::{
    collections::BTreeMap,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};

/// What committed writes changed since the last [`take`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitDelta {
    /// Net change in canonical bytes, by the object each written row belongs to.
    pub storage: BTreeMap<Obj, i64>,
    /// Objects created (an `object_flags` row inserted).
    pub created: u64,
    /// Objects recycled (an `object_flags` row deleted).
    pub recycled: u64,
}

impl CommitDelta {
    /// Total net change in canonical bytes.
    #[must_use]
    pub fn total(&self) -> i64 {
        self.storage.values().sum()
    }

    pub(crate) fn add_storage(&mut self, obj: Obj, delta: i64) {
        if delta != 0 {
            *self.storage.entry(obj).or_insert(0) += delta;
        }
    }

    fn merge(&mut self, other: CommitDelta) {
        for (obj, delta) in other.storage {
            self.add_storage(obj, delta);
        }
        self.created += other.created;
        self.recycled += other.recycled;
    }
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static SINK: Mutex<CommitDelta> = Mutex::new(CommitDelta {
    storage: BTreeMap::new(),
    created: 0,
    recycled: 0,
});

fn sink() -> MutexGuard<'static, CommitDelta> {
    SINK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Turn commit measurement on or off. Turning it on discards anything accumulated.
pub fn set_enabled(enabled: bool) {
    if enabled {
        *sink() = CommitDelta::default();
    }
    ENABLED.store(enabled, Ordering::SeqCst);
}

#[must_use]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Drain the accumulator.
#[must_use]
pub fn take() -> CommitDelta {
    std::mem::take(&mut *sink())
}

/// A copy of the accumulator, without draining it (for `meter()` mid-command).
#[must_use]
pub fn peek() -> CommitDelta {
    sink().clone()
}

pub(crate) fn record(delta: CommitDelta) {
    sink().merge(delta);
}
