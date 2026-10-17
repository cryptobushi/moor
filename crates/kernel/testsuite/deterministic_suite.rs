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

use moor_common::{
    deterministic::{self, BlockContext, DeterministicMode, IdDomain},
    model::{HasUuid, TaskPermissions},
    tasks::NarrativeEvent,
    util::BitEnum,
};
use moor_compiler::{CompileOptions, compile};
use moor_db::Database;
use moor_var::{E_PERM, Obj, SYSTEM_OBJECT, Symbol, Var, v_float, v_int, v_list};

use crate::common::{compile_verbs, create_db, run_as_verb};

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

    /// The error code `body` raises. The harness reports uncaught errors as the error value.
    fn raised(&self, body: &str) -> moor_var::ErrorCode {
        self.run(body)
            .as_error()
            .expect("verb did not raise")
            .err_type()
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

#[test]
fn move_stamps_last_move_with_block_time() {
    let det = Det::start(2, 1_700_000_600, 1);
    assert_eq!(
        det.run("x = create(#-1); move(x, #1); return x.last_move[\"time\"];"),
        Var::from(1_700_000_600i64)
    );
}

fn notify_event() -> NarrativeEvent {
    NarrativeEvent::notify(v_int(0), v_int(1), None, false, false, None)
}

#[test]
fn event_ids_and_timestamps_replay_for_the_same_block() {
    let _det = Det::start(3, 1_700_001_000, 1);
    deterministic::next_command();
    let first = notify_event();
    deterministic::set_block(BlockContext {
        height: 3,
        timestamp: 1_700_001_000,
        seed: [1; 32],
    });
    deterministic::next_command();
    let second = notify_event();
    assert_eq!(
        (first.event_id(), first.timestamp()),
        (second.event_id(), second.timestamp())
    );
}

#[test]
fn event_ids_within_a_command_are_distinct() {
    let _det = Det::start(3, 1_700_001_000, 1);
    deterministic::next_command();
    assert_ne!(notify_event().event_id(), notify_event().event_id());
}

#[test]
fn event_timestamp_is_block_time() {
    let _det = Det::start(3, 1_700_001_000, 1);
    let secs = notify_event()
        .timestamp()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(secs, 1_700_001_000);
}

/// What the stream for `command` of a block seeded with `seed` yields first, for `random(max)`.
fn first_random(seed: u8, command: u64, max: i64) -> Var {
    let mut stream = deterministic::RngStream::new(&[seed; 32], command);
    Var::from(stream.range_inclusive(1, max))
}

#[test]
fn random_draws_from_the_command_stream() {
    let det = Det::start(4, 1_700_002_000, 9);
    assert_eq!(
        det.run("return random(1000000);"),
        first_random(9, 1, 1_000_000)
    );
}

#[test]
fn random_differs_between_commands_of_a_block() {
    let det = Det::start(4, 1_700_002_000, 9);
    let first = det.run("return random(1000000000);");
    let second = det.run("return random(1000000000);");
    assert_ne!(first, second);
}

#[test]
fn random_replays_when_the_block_is_replayed() {
    let det = Det::start(4, 1_700_002_000, 9);
    let first = det.run("return random();");
    deterministic::set_block(BlockContext {
        height: 4,
        timestamp: 1_700_002_000,
        seed: [9; 32],
    });
    assert_eq!(det.run("return random();"), first);
}

#[test]
fn random_with_a_range_stays_within_it() {
    let det = Det::start(4, 1_700_002_000, 9);
    let value = det.run("return random(10, 12);");
    assert!(matches!(value.as_integer(), Some(10..=12)));
}

#[test]
fn random_bytes_come_from_the_command_stream() {
    let det = Det::start(5, 1_700_003_000, 4);
    let mut expected = vec![0u8; 20];
    deterministic::RngStream::new(&[4; 32], 1).fill_bytes(&mut expected);
    assert_eq!(det.run("return random_bytes(20);"), Var::from(expected));
}

#[test]
fn crypt_default_salt_replays_for_the_same_command() {
    let det = Det::start(5, 1_700_003_000, 4);
    let hashed = det.run("return crypt(\"secret\");");
    let again = {
        deterministic::set_block(BlockContext {
            height: 5,
            timestamp: 1_700_003_000,
            seed: [4; 32],
        });
        det.run("return crypt(\"secret\");")
    };
    assert_eq!(hashed, again);
}

#[test]
fn salt_replays_for_the_same_command() {
    let det = Det::start(5, 1_700_003_000, 4);
    let first = det.run("return salt();");
    deterministic::set_block(BlockContext {
        height: 5,
        timestamp: 1_700_003_000,
        seed: [4; 32],
    });
    assert_eq!(det.run("return salt();"), first);
}

#[test]
fn salt_differs_between_commands() {
    let det = Det::start(5, 1_700_003_000, 4);
    assert_ne!(det.run("return salt();"), det.run("return salt();"));
}

#[test]
fn age_generate_keypair_is_refused() {
    let det = Det::start(6, 1_700_004_000, 2);
    assert_eq!(det.raised("return age_generate_keypair();"), E_PERM);
}

#[test]
fn age_encrypt_is_refused() {
    let det = Det::start(6, 1_700_004_000, 2);
    assert_eq!(det.raised("return age_encrypt(\"hi\", {\"x\"});"), E_PERM);
}

#[test]
fn age_passphrase_encrypt_is_refused() {
    let det = Det::start(6, 1_700_004_000, 2);
    assert_eq!(
        det.raised("return age_passphrase_encrypt(\"hi\", \"pw\");"),
        E_PERM
    );
}

#[test]
fn paseto_make_local_is_refused() {
    let det = Det::start(6, 1_700_004_000, 2);
    assert_eq!(
        det.raised("return paseto_make_local({{\"a\", 1}});"),
        E_PERM
    );
}

#[test]
fn uuid_derives_from_height_command_and_counter() {
    let det = Det::start(7, 1_700_005_000, 3);
    let expected = deterministic::derive_id(deterministic::IdDomain::Uuid, 7, 1, 0);
    assert_eq!(det.run("return uuid();"), Var::from(expected.to_string()));
}

#[test]
fn uuid_counter_advances_within_a_command() {
    let det = Det::start(7, 1_700_005_000, 3);
    let both = det.run("return {uuid(), uuid()};");
    let expected = |counter| {
        Var::from(
            deterministic::derive_id(deterministic::IdDomain::Uuid, 7, 1, counter).to_string(),
        )
    };
    assert_eq!(both, v_list(&[expected(0), expected(1)]));
}

#[test]
fn uuid_ignores_the_block_seed() {
    let first = Det::start(7, 1_700_005_000, 3).run("return uuid();");
    let second = Det::start(7, 1_700_005_000, 200).run("return uuid();");
    assert_eq!(first, second);
}

#[test]
fn uuid_rebuilt_from_integers_is_unchanged() {
    let det = Det::start(7, 1_700_005_000, 3);
    assert_eq!(
        det.run("return uuid(1, 2);"),
        Var::from("00000000-0000-0001-0000-000000000002")
    );
}

fn wizard() -> TaskPermissions {
    TaskPermissions::new(Obj::mk_id(3), BitEnum::new())
}

#[test]
fn verb_definition_ids_derive_from_the_block() {
    let det = Det::start(8, 1_700_006_000, 5);
    let program = compile("return 1;", CompileOptions::default()).unwrap();
    compile_verbs(
        det.db.as_ref(),
        &[("det_verb_a", &program), ("det_verb_b", &program)],
    );
    let tx = det.db.new_world_state().unwrap();
    let id_of = |name: &str| {
        tx.get_verb(&wizard(), &SYSTEM_OBJECT, Symbol::mk(name))
            .unwrap()
            .uuid()
    };
    assert_eq!(
        [id_of("det_verb_a"), id_of("det_verb_b")],
        [
            deterministic::derive_id(IdDomain::Definition, 8, 0, 0),
            deterministic::derive_id(IdDomain::Definition, 8, 0, 1)
        ]
    );
}

#[test]
fn property_definition_ids_derive_from_the_block() {
    let det = Det::start(8, 1_700_006_000, 5);
    let mut tx = det.db.new_world_state().unwrap();
    tx.define_property(
        &wizard(),
        &SYSTEM_OBJECT,
        &SYSTEM_OBJECT,
        Symbol::mk("det_prop"),
        &Obj::mk_id(3),
        BitEnum::new(),
        Some(v_int(1)),
    )
    .unwrap();
    let defs = tx.properties(&wizard(), &SYSTEM_OBJECT).unwrap();
    let id = defs
        .find_first_named(Symbol::mk("det_prop"))
        .expect("defined")
        .uuid();
    assert_eq!(id, deterministic::derive_id(IdDomain::Definition, 8, 0, 0));
}

#[test]
fn totp_defaults_to_block_time() {
    let det = Det::start(9, 1_700_007_000, 6);
    let default = det.run("return totp(\"JBSWY3DPEHPK3PXP\");");
    let explicit = det.run("return totp(\"JBSWY3DPEHPK3PXP\", 1700007000);");
    assert_eq!(default, explicit);
}

#[test]
fn seconds_left_reports_no_wall_clock_limit() {
    let det = Det::start(10, 1_700_008_000, 7);
    assert_eq!(det.run("return seconds_left();"), v_int(-1));
}
