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

//! The engine meter's live state (RuneWorld ADR 0007 decision 2).
//!
//! The block driver runs one input at a time on one thread, and every task of that input (the
//! command, `fork (0)` children, forced input, wakes) runs on that thread too. The measurement is
//! therefore a handful of process-wide counters that the driver resets at each input and reads
//! when the input is quiescent; the VM host adds ticks to them and asks them for the remaining
//! budget. Nothing here is consulted unless a block driver has activated it, so stock and
//! threaded schedulers are untouched.
//!
//! # Ceiling
//!
//! `begin_command` installs the command's tick ceiling, `min(policy ceiling, engine maximum)`.
//! `remaining()` is what the VM host clamps its tick slice to; a command that reaches zero is
//! aborted by the task limit path, which in deterministic mode rolls back and runs no handler.
//! While the charge hook runs (`enter_policy`), ticks count as `policy_ticks` against the
//! engine's small fixed policy ceiling instead.
//!
//! # Block totals
//!
//! The driver adds every finished input's meter to its world's block total (`meter_totals(world,
//! 'block)`); replayers rebuild them by re-executing the block.

use moor_block::{Meter, MeterKind, MeterOutcome};
use std::{
    collections::BTreeMap,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

const NO_CEILING: u64 = u64::MAX;

static ACTIVE: AtomicBool = AtomicBool::new(false);
static POLICY_PHASE: AtomicBool = AtomicBool::new(false);
static LIMIT_HIT: AtomicBool = AtomicBool::new(false);
static CEILING: AtomicU64 = AtomicU64::new(NO_CEILING);
static POLICY_CEILING: AtomicU64 = AtomicU64::new(NO_CEILING);
static TICKS: AtomicU64 = AtomicU64::new(0);
static POLICY_TICKS: AtomicU64 = AtomicU64::new(0);
static TASKS: AtomicU64 = AtomicU64::new(0);
static EVENTS: AtomicU64 = AtomicU64::new(0);
static EVENT_BYTES: AtomicU64 = AtomicU64::new(0);

/// What identifies the input being measured.
#[derive(Clone, Copy, Debug)]
struct Subject {
    kind: MeterKind,
    world: i32,
    log_bytes: u64,
}

static SUBJECT: Mutex<Subject> = Mutex::new(Subject {
    kind: MeterKind::Command,
    world: -1,
    log_bytes: 0,
});
static BLOCK_TOTALS: Mutex<BTreeMap<i32, WorldTotals>> = Mutex::new(BTreeMap::new());

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Plain data: a poisoned lock is still consistent.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What a world was charged in the open block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorldTotals {
    pub inputs: u64,
    pub ticks: u64,
    pub tasks: u64,
    pub log_bytes: u64,
    pub events: u64,
    pub event_bytes: u64,
    pub objects_created: u64,
    pub objects_recycled: u64,
    pub storage_delta: i64,
    pub policy_ticks: u64,
    pub denied: u64,
    pub aborted: u64,
    pub tick_ceiling: u64,
}

impl WorldTotals {
    fn add(&mut self, m: &Meter) {
        self.inputs += 1;
        self.ticks += m.ticks;
        self.tasks += m.tasks;
        self.log_bytes += m.log_bytes;
        self.events += m.events;
        self.event_bytes += m.event_bytes;
        self.objects_created += m.objects_created;
        self.objects_recycled += m.objects_recycled;
        self.storage_delta += m.storage_delta;
        self.policy_ticks += m.policy_ticks;
        match m.outcome {
            MeterOutcome::Ok => {}
            MeterOutcome::Aborted => self.aborted += 1,
            MeterOutcome::TickCeiling => self.tick_ceiling += 1,
            MeterOutcome::Denied => self.denied += 1,
        }
    }
}

/// A read of the counters, for `meter()` and for finishing an input.
#[derive(Clone, Copy, Debug)]
pub struct Live {
    pub kind: MeterKind,
    pub world: i32,
    pub log_bytes: u64,
    pub ticks: u64,
    pub policy_ticks: u64,
    pub tasks: u64,
    pub events: u64,
    pub event_bytes: u64,
    pub ceiling: Option<u64>,
    pub limit_hit: bool,
}

/// Whether a block driver is metering (and the process is in deterministic mode).
#[inline]
#[must_use]
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Turn metering on or off. Done by the block driver.
pub fn set_active(active: bool) {
    ACTIVE.store(active, Ordering::SeqCst);
    if !active {
        lock(&BLOCK_TOTALS).clear();
    }
}

/// Start measuring an input. `ceiling` is the command's tick ceiling (`None` is unbounded).
pub fn begin_command(kind: MeterKind, world: i32, log_bytes: u64, ceiling: Option<u64>) {
    *lock(&SUBJECT) = Subject {
        kind,
        world,
        log_bytes,
    };
    TICKS.store(0, Ordering::Relaxed);
    POLICY_TICKS.store(0, Ordering::Relaxed);
    TASKS.store(0, Ordering::Relaxed);
    EVENTS.store(0, Ordering::Relaxed);
    EVENT_BYTES.store(0, Ordering::Relaxed);
    CEILING.store(ceiling.unwrap_or(NO_CEILING), Ordering::Relaxed);
    POLICY_PHASE.store(false, Ordering::Relaxed);
    LIMIT_HIT.store(false, Ordering::Relaxed);
}

/// Set the envelope wire bytes the input took in the command batch.
pub fn set_log_bytes(log_bytes: u64) {
    lock(&SUBJECT).log_bytes = log_bytes;
}

/// Set the charged world once it is known (after the player's world is resolved).
pub fn set_world(world: i32) {
    lock(&SUBJECT).world = world;
}

/// Replace the command's tick ceiling (the reservation's answer).
pub fn set_ceiling(ceiling: Option<u64>) {
    CEILING.store(ceiling.unwrap_or(NO_CEILING), Ordering::Relaxed);
}

/// Run the charge hook's ticks against `ceiling` as `policy_ticks`, until [`leave_policy`].
pub fn enter_policy(ceiling: u64) {
    POLICY_CEILING.store(ceiling, Ordering::Relaxed);
    LIMIT_HIT.store(false, Ordering::Relaxed);
    POLICY_PHASE.store(true, Ordering::Relaxed);
}

/// Return to counting command ticks. Reports whether the policy ceiling was hit.
pub fn leave_policy() -> bool {
    POLICY_PHASE.store(false, Ordering::Relaxed);
    LIMIT_HIT.swap(false, Ordering::Relaxed)
}

/// Ticks the VM host may still run before the active ceiling, or `None` when unbounded or the
/// meter is off.
#[inline]
#[must_use]
pub fn remaining() -> Option<u64> {
    if !is_active() {
        return None;
    }
    if POLICY_PHASE.load(Ordering::Relaxed) {
        let used = POLICY_TICKS.load(Ordering::Relaxed);
        return Some(POLICY_CEILING.load(Ordering::Relaxed).saturating_sub(used));
    }
    match CEILING.load(Ordering::Relaxed) {
        NO_CEILING => None,
        ceiling => Some(ceiling.saturating_sub(TICKS.load(Ordering::Relaxed))),
    }
}

/// Count ticks a task segment ran.
#[inline]
pub fn add_ticks(ticks: u64) {
    if !is_active() || ticks == 0 {
        return;
    }
    if POLICY_PHASE.load(Ordering::Relaxed) {
        POLICY_TICKS.fetch_add(ticks, Ordering::Relaxed);
    } else {
        TICKS.fetch_add(ticks, Ordering::Relaxed);
    }
}

/// Count one job run.
#[inline]
pub fn add_task() {
    if is_active() && !POLICY_PHASE.load(Ordering::Relaxed) {
        TASKS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Count one event added to the batch, with its canonical size.
#[inline]
pub fn add_event(bytes: u64) {
    if is_active() {
        EVENTS.fetch_add(1, Ordering::Relaxed);
        EVENT_BYTES.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// A task hit a tick limit (its own or the command's ceiling).
pub fn note_limit() {
    if is_active() {
        LIMIT_HIT.store(true, Ordering::Relaxed);
    }
}

/// Whether a tick limit was hit since the input began (or the policy phase was entered).
#[must_use]
pub fn limit_hit() -> bool {
    LIMIT_HIT.load(Ordering::Relaxed)
}

/// Read the counters.
#[must_use]
pub fn live() -> Live {
    let s = *lock(&SUBJECT);
    Live {
        kind: s.kind,
        world: s.world,
        log_bytes: s.log_bytes,
        ticks: TICKS.load(Ordering::Relaxed),
        policy_ticks: POLICY_TICKS.load(Ordering::Relaxed),
        tasks: TASKS.load(Ordering::Relaxed),
        events: EVENTS.load(Ordering::Relaxed),
        event_bytes: EVENT_BYTES.load(Ordering::Relaxed),
        ceiling: match CEILING.load(Ordering::Relaxed) {
            NO_CEILING => None,
            c => Some(c),
        },
        limit_hit: LIMIT_HIT.load(Ordering::Relaxed),
    }
}

/// Start a block: empty the per-world totals.
pub fn begin_block() {
    lock(&BLOCK_TOTALS).clear();
}

/// Add a finished input to its world's block total.
pub fn record(meter: &Meter) {
    lock(&BLOCK_TOTALS)
        .entry(meter.world)
        .or_default()
        .add(meter);
}

/// The open block's total for `world` (zeros when it was charged nothing).
#[must_use]
pub fn block_totals(world: i32) -> WorldTotals {
    lock(&BLOCK_TOTALS).get(&world).copied().unwrap_or_default()
}

/// Every world charged in the open block, ascending.
#[must_use]
pub fn all_block_totals() -> Vec<(i32, WorldTotals)> {
    lock(&BLOCK_TOTALS).iter().map(|(w, t)| (*w, *t)).collect()
}
