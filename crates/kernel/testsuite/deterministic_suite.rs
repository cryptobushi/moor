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
//! Builtin behaviour in deterministic mode. The mode is process-global, so every test holds a lock
//! and runs against its own database.

use std::sync::{Mutex, MutexGuard};

use moor_common::deterministic::{self, BlockContext, DeterministicMode};
use moor_db::Database;
use moor_var::{Var, v_float};

use crate::common::{create_db, run_as_verb};

mod common;

static LOCK: Mutex<()> = Mutex::new(());

/// Holds the process lock, enables deterministic mode for its lifetime and owns a database.
struct Det {
    _guard: MutexGuard<'static, ()>,
    db: Box<dyn Database>,
}

impl Det {
    fn start(height: u64, timestamp: u64, seed: u8) -> Self {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let db = create_db();
        deterministic::configure(&DeterministicMode::on());
        deterministic::set_block(BlockContext {
            height,
            timestamp,
            seed: [seed; 32],
        });
        Self { _guard: guard, db }
    }

    /// Run `body` as a verb, as the next command of the block, and return its value.
    fn run(&self, body: &str) -> Var {
        deterministic::next_command();
        run_as_verb(self.db.as_ref(), body).expect("verb raised")
    }
}

impl Drop for Det {
    fn drop(&mut self) {
        deterministic::disable();
    }
}

#[test]
fn time_returns_block_time() {
    let det = Det::start(1, 1_700_000_000, 1);
    assert_eq!(det.run("return time();"), Var::from(1_700_000_000i64));
}

#[test]
fn ftime_returns_block_time_without_a_fraction() {
    let det = Det::start(1, 1_700_000_000, 1);
    assert_eq!(det.run("return ftime();"), v_float(1_700_000_000.0));
}

#[test]
fn ftime_uptime_is_a_constant() {
    let det = Det::start(1, 1_700_000_000, 1);
    assert_eq!(det.run("return ftime(1);"), v_float(0.0));
}

#[test]
fn ctime_formats_block_time_in_utc() {
    let det = Det::start(1, 1_700_000_000, 1);
    assert_eq!(
        det.run("return ctime();"),
        Var::from("Tue Nov 14 22:13:20 2023 UTC")
    );
}

#[test]
fn ctime_with_an_argument_formats_in_utc() {
    let det = Det::start(1, 1_700_000_000, 1);
    assert_eq!(
        det.run("return ctime(0);"),
        Var::from("Thu Jan 01 00:00:00 1970 UTC")
    );
}
