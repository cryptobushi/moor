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
use moor_var::{E_PERM, Obj, SYSTEM_OBJECT, Symbol, Var, v_float, v_int, v_list, v_map, v_sym};

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

#[test]
fn connected_players_is_empty() {
    let det = Det::start(11, 1_700_009_000, 8);
    assert_eq!(det.run("return connected_players();"), v_list(&[]));
}

#[test]
fn idle_seconds_is_a_constant() {
    let det = Det::start(11, 1_700_009_000, 8);
    assert_eq!(det.run("return idle_seconds(#3);"), v_int(0));
}

#[test]
fn connected_seconds_is_a_constant() {
    let det = Det::start(11, 1_700_009_000, 8);
    assert_eq!(det.run("return connected_seconds(#3);"), v_int(0));
}

#[test]
fn environment_builtins_are_refused() {
    let det = Det::start(11, 1_700_009_000, 8);
    for call in [
        "connection_name(#3)",
        "connection_options(#3)",
        "listeners()",
        "workers()",
        "memory_usage()",
        "db_disk_size()",
        "bf_counters()",
        "db_counters()",
        "sched_counters()",
        "log_cache_stats()",
        "verb_cache_stats()",
        "property_cache_stats()",
        "ancestry_cache_stats()",
        "program_cache_stats()",
        "task_telemetry()",
    ] {
        assert_eq!(det.raised(&format!("return {call};")), E_PERM, "{call}");
    }
}

#[test]
fn block_context_reports_height_time_and_command() {
    let det = Det::start(12, 1_700_010_000, 1);
    let expected = v_map(&[
        (v_sym("height"), v_int(12)),
        (v_sym("time"), v_int(1_700_010_000)),
        (v_sym("command"), v_int(1)),
    ]);
    assert_eq!(det.run("return block_context();"), expected);
}

#[test]
fn block_context_command_advances() {
    let det = Det::start(12, 1_700_010_000, 1);
    det.run("return 0;");
    assert_eq!(det.run("return block_context()['command];"), v_int(2));
}

// --- Manual executor and block driver (S0-4) ---------------------------------------------------

mod executor {
    use std::sync::{Arc, Mutex as StdMutex};

    use moor_common::{
        deterministic::{self, BlockContext, DeterministicMode},
        tasks::{
            Event, NarrativeEvent, NoopClientSession, NoopSystemControl, Session, SessionError,
            SessionFactory,
        },
    };
    use moor_compiler::to_literal;
    use moor_kernel::{
        config::Config,
        tasks::{
            NoopTasksDb,
            block_driver::{BlockDriver, BlockEvent, BlockEventKind, BlockInput, BlockOutput},
            scheduler::Scheduler,
        },
    };
    use moor_var::{Obj, Var, v_int, v_str};

    use super::{LOCK, create_db};

    const WIZARD: Obj = Obj::mk_id(3);

    pub(super) struct Factory;
    impl SessionFactory for Factory {
        fn mk_background_session(
            self: Arc<Self>,
            _player: &Obj,
        ) -> Result<Arc<dyn Session>, SessionError> {
            Ok(Arc::new(NoopClientSession::new()))
        }
    }

    /// A fresh database and a deterministic scheduler under a block driver. Holds the process lock.
    pub(super) struct World {
        driver: Option<BlockDriver>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl World {
        pub(super) fn start() -> Self {
            Self::start_with(DeterministicMode::on())
        }

        pub(super) fn start_with(mode: DeterministicMode) -> Self {
            let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            deterministic::disable();
            deterministic::configure(&mode);
            let scheduler = Scheduler::new(
                semver::Version::new(0, 1, 0),
                create_db(),
                Box::new(NoopTasksDb {}),
                Arc::new(Config {
                    deterministic: mode,
                    ..Config::default()
                }),
                Arc::new(NoopSystemControl::default()),
                None,
                None,
            );
            assert!(scheduler.is_manual());
            let driver = scheduler
                .start_block_driver(Arc::new(Factory))
                .expect("start block driver");
            Self {
                driver: Some(driver),
                _guard: guard,
            }
        }

        pub(super) fn driver(&mut self) -> &mut BlockDriver {
            self.driver.as_mut().expect("driver")
        }

        /// Hand the driver to a sequencer; the world keeps the process lock.
        pub(super) fn take_driver(&mut self) -> BlockDriver {
            self.driver.take().expect("driver")
        }

        pub(super) fn block(&mut self, height: u64, evals: &[&str]) -> BlockOutput {
            let inputs = evals
                .iter()
                .map(|code| {
                    let session: Arc<dyn Session> = Arc::new(NoopClientSession::new());
                    (
                        BlockInput::Eval {
                            player: WIZARD,
                            code: (*code).to_string(),
                        },
                        session,
                    )
                })
                .collect();
            self.driver().run_block(block(height), inputs)
        }

        fn eval(&mut self, code: &str) -> Var {
            let out = self.block(1, &[code]);
            match &out.outcomes[0].result {
                Some(Ok(v)) => v.clone(),
                other => panic!("eval did not return a value: {other:?}"),
            }
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            if let Some(driver) = self.driver.take() {
                driver.shutdown().ok();
            }
            deterministic::disable();
        }
    }

    pub(super) fn block(height: u64) -> BlockContext {
        BlockContext {
            height,
            timestamp: 1_700_000_000 + 60 * height,
            seed: [height as u8; 32],
        }
    }

    /// The `notify` texts of a batch, in batch order.
    pub(super) fn texts(events: &[BlockEvent]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match &e.kind {
                BlockEventKind::Narrative(ev) => match ev.event() {
                    Event::Notify { value, .. } => value.as_string().map(str::to_string),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    /// Every field of every event, ids and timestamps included.
    pub(super) fn canonical(events: &[BlockEvent]) -> String {
        events
            .iter()
            .map(|e| {
                let body = match &e.kind {
                    BlockEventKind::Narrative(ev) | BlockEventKind::Logged(ev) => describe(ev),
                    BlockEventKind::System(msg) => format!("system {msg}"),
                    BlockEventKind::Rejected {
                        kind,
                        session,
                        reason,
                    } => format!("rejected {kind:?} session={session} {reason}"),
                    BlockEventKind::Sessions(admitted) => format!("sessions {admitted:?}"),
                    BlockEventKind::Meter(m) => format!("meter {m:?}"),
                };
                format!(
                    "{} cmd={} task={:?} to={} {}",
                    e.seq, e.command_index, e.task_id, e.player, body
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn describe(ev: &NarrativeEvent) -> String {
        let ts = ev
            .timestamp()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros())
            .unwrap_or(0);
        let body = match ev.event() {
            Event::Notify { value, .. } => to_literal(&value),
            other => format!("{other:?}"),
        };
        format!(
            "id={} ts={ts} author={} {body}",
            ev.event_id(),
            to_literal(ev.author())
        )
    }

    const FORK_TREE: &str = r#"
        fork (0)
          notify(player, "child A");
          fork (0)
            notify(player, "grandchild of A");
          endfork
        endfork
        fork (0)
          notify(player, "child B");
        endfork
        notify(player, "parent");
        return 1;
    "#;

    #[test]
    fn fork_zero_children_run_after_the_parent_in_creation_order() {
        let mut world = World::start();
        let out = world.block(1, &[FORK_TREE, "notify(player, \"next command\");"]);
        assert_eq!(
            texts(&out.events),
            [
                "parent",
                "child A",
                "child B",
                "grandchild of A",
                "next command"
            ]
        );
    }

    #[test]
    fn fork_zero_events_keep_the_parent_command_index() {
        let mut world = World::start();
        let out = world.block(1, &[FORK_TREE, "notify(player, \"next\");"]);
        let indices: Vec<u64> = out.events.iter().map(|e| e.command_index).collect();
        // Each input ends with its meter entry.
        assert_eq!(indices, [1, 1, 1, 1, 1, 2, 2]);
    }

    #[test]
    fn fork_zero_child_sees_the_parent_final_commit() {
        let mut world = World::start();
        let out = world.block(
            1,
            &[
                "add_property(#0, \"s04\", 0, {player, \"rw\"}); return 1;",
                "fork (0) notify(player, \"child sees \" + tostr(#0.s04)); endfork #0.s04 = 42;",
            ],
        );
        assert_eq!(texts(&out.events), ["child sees 42"]);
    }

    #[test]
    fn fork_zero_ordering_is_identical_across_20_runs() {
        let mut batches = Vec::new();
        for _ in 0..20 {
            let mut world = World::start();
            let out = world.block(7, &[FORK_TREE, FORK_TREE, "return random(1000);"]);
            assert_eq!(out.conflicts, 0);
            batches.push(canonical(&out.events));
        }
        assert!(batches.windows(2).all(|w| w[0] == w[1]), "{batches:#?}");
    }

    #[test]
    fn delayed_fork_raises_e_invarg() {
        let mut world = World::start();
        assert_eq!(
            world.eval(
                "try fork (1) endfork return 0; except (E_INVARG) return \"refused\"; endtry"
            ),
            v_str("refused")
        );
    }

    #[test]
    fn timed_suspend_raises_e_invarg() {
        let mut world = World::start();
        assert_eq!(
            world.eval("try suspend(1); return 0; except (E_INVARG) return \"refused\"; endtry"),
            v_str("refused")
        );
    }

    #[test]
    fn suspend_zero_continues_inline_before_forked_children() {
        let mut world = World::start();
        let out = world.block(
            1,
            &["fork (0) notify(player, \"child\"); endfork \
               notify(player, \"before\"); suspend(0); notify(player, \"after\"); return 1;"],
        );
        assert_eq!(texts(&out.events), ["before", "after", "child"]);
    }

    #[test]
    fn waiting_task_recv_raises_e_invarg() {
        let mut world = World::start();
        assert_eq!(
            world.eval("try task_recv(1); return 0; except (E_INVARG) return \"refused\"; endtry"),
            v_str("refused")
        );
    }

    #[test]
    fn read_raises_e_invarg() {
        let mut world = World::start();
        assert_eq!(
            world.eval("try read(); return 0; except (E_INVARG) return \"refused\"; endtry"),
            v_str("refused")
        );
    }

    #[test]
    fn schedule_at_raises_e_invarg() {
        let mut world = World::start();
        assert_eq!(
            world.eval(
                "try schedule_at(#0, \"x\", time() + 10); return 0; \
                 except (E_INVARG) return \"refused\"; endtry"
            ),
            v_str("refused")
        );
    }

    #[test]
    fn indefinitely_suspended_task_is_cancelled_at_the_block_boundary() {
        let mut world = World::start();
        let out = world.block(1, &["fork (0) suspend(); endfork return 1;"]);
        assert_eq!(out.abandoned.len(), 1);
        assert!(world.driver().scheduler().suspended_task_ids().is_empty());
    }

    #[test]
    fn resumed_task_runs_inside_the_block() {
        let mut world = World::start();
        let out = world.block(
            1,
            &[
                "fork t (0) notify(player, \"resumed with \" + tostr(suspend())); endfork \
                 add_property(#0, \"waiter\", t, {player, \"rw\"}); return t;",
                "resume(#0.waiter, 5); return 1;",
            ],
        );
        assert_eq!(texts(&out.events), ["resumed with 5"]);
        assert!(out.abandoned.is_empty());
    }

    #[test]
    fn force_input_runs_after_its_caller_commits() {
        let mut world = World::start();
        let out = world.block(
            1,
            &["force_input(player, \";notify(player, \\\"forced\\\")\"); \
               notify(player, \"caller\"); return 1;"],
        );
        // The core's eval command handler also prints the eval's value after "forced".
        assert_eq!(texts(&out.events)[..2], ["caller", "forced"]);
    }

    #[test]
    fn force_input_from_a_rolled_back_task_runs_nothing() {
        let mut world = World::start();
        let out = world.block(
            1,
            &[
                "force_input(player, \";notify(player, \\\"forced\\\")\"); rollback(); return 1;",
                "notify(player, \"next\"); return 1;",
            ],
        );
        assert_eq!(texts(&out.events), ["next"]);
    }

    #[test]
    fn inputs_take_consecutive_command_indices() {
        let mut world = World::start();
        let out = world.block(
            1,
            &[
                "return block_context()['command];",
                "return block_context()['command];",
            ],
        );
        let values: Vec<_> = out
            .outcomes
            .iter()
            .map(|o| o.result.clone().map(|r| r.ok()))
            .collect();
        assert_eq!(values, [Some(Some(v_int(1))), Some(Some(v_int(2)))]);
    }

    #[test]
    fn serial_execution_reports_no_conflicts() {
        let mut world = World::start();
        // Upstream panics ("stack underflow") on a fork inside a `for` loop in an eval frame,
        // in both modes, so the forks are unrolled.
        let bump = "fork (0) #0.n = #0.n + 1; endfork ";
        let code = format!(
            "add_property(#0, \"n\", 0, {{player, \"rw\"}}); {} return 1;",
            bump.repeat(5)
        );
        let out = world.block(1, &[&code, "return #0.n;"]);
        assert_eq!(out.conflicts, 0);
        assert_eq!(
            out.outcomes[1].result.clone().map(|r| r.ok()),
            Some(Some(v_int(5)))
        );
    }

    /// The block whose batch must match across processes: commands, forks, random, ids.
    const PROCESS_BLOCK: &[&str] = &[
        "add_property(#0, \"log\", {}, {player, \"rw\"}); return 1;",
        FORK_TREE,
        "fork (0) #0.log = {@#0.log, random(1000)}; notify(player, toliteral(#0.log)); endfork \
         fork (0) #0.log = {@#0.log, random(1000)}; notify(player, toliteral(#0.log)); endfork \
         fork (0) #0.log = {@#0.log, random(1000)}; notify(player, toliteral(#0.log)); endfork \
         return 1;",
        "notify(player, uuid()); notify(player, tostr(time())); return #0.log;",
        "o = create(#1); move(o, #2); notify(player, tostr(o)); return o;",
    ];

    /// Child half of the cross-process test. Prints the canonical batch between markers.
    #[test]
    #[ignore = "run as a subprocess by block_batch_is_identical_across_processes"]
    fn block_batch_child() {
        let mut world = World::start();
        let out = world.block(3, PROCESS_BLOCK);
        assert_eq!(out.conflicts, 0);
        println!("BATCH-BEGIN\n{}\nBATCH-END", canonical(&out.events));
    }

    fn child_batch() -> String {
        let exe = std::env::current_exe().expect("test binary");
        let output = std::process::Command::new(exe)
            .args([
                "executor::block_batch_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .expect("run child");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let begin = stdout.find("BATCH-BEGIN\n").expect("batch marker") + "BATCH-BEGIN\n".len();
        let end = stdout.find("\nBATCH-END").expect("batch end marker");
        stdout[begin..end].to_string()
    }

    #[test]
    fn block_batch_is_identical_across_processes() {
        let batches: Vec<String> = (0..5).map(|_| child_batch()).collect();
        assert!(batches[0].lines().count() >= 10, "{}", batches[0]);
        assert!(batches.windows(2).all(|w| w[0] == w[1]), "{batches:#?}");
    }

    // Negative control (ADR 0001 Stage 0 exit c): with deterministic mode off, the same inputs
    // submitted concurrently to the threaded scheduler commit in a timing-dependent order.

    /// Records committed `notify` texts in commit order across all forks.
    pub(super) struct OrderSession {
        order: Arc<StdMutex<Vec<String>>>,
        buf: StdMutex<Vec<String>>,
    }

    impl OrderSession {
        /// A session appending committed `notify` texts (as literals) to `order`.
        pub(super) fn new(order: Arc<StdMutex<Vec<String>>>) -> Self {
            Self {
                order,
                buf: StdMutex::new(vec![]),
            }
        }
    }

    impl Session for OrderSession {
        fn commit(&self) -> Result<(), SessionError> {
            let mut buf = self.buf.lock().unwrap();
            self.order.lock().unwrap().extend(buf.drain(..));
            Ok(())
        }
        fn rollback(&self) -> Result<(), SessionError> {
            self.buf.lock().unwrap().clear();
            Ok(())
        }
        fn fork(self: Arc<Self>) -> Result<Arc<dyn Session>, SessionError> {
            Ok(Arc::new(OrderSession {
                order: self.order.clone(),
                buf: StdMutex::new(vec![]),
            }))
        }
        fn request_input(
            &self,
            _: Obj,
            _: uuid::Uuid,
            _: Option<Vec<(moor_var::Symbol, Var)>>,
        ) -> Result<(), SessionError> {
            Err(SessionError::DeliveryError)
        }
        fn send_event(&self, _: Obj, event: Box<NarrativeEvent>) -> Result<(), SessionError> {
            if let Event::Notify { value, .. } = event.event() {
                self.buf.lock().unwrap().push(to_literal(&value));
            }
            Ok(())
        }
        fn log_event(&self, _: Obj, _: Box<NarrativeEvent>) -> Result<(), SessionError> {
            Ok(())
        }
        fn send_system_msg(&self, _: Obj, _: &str) -> Result<(), SessionError> {
            Ok(())
        }
        fn notify_shutdown(&self, _: Option<String>) -> Result<(), SessionError> {
            Ok(())
        }
        fn connection_name(&self, _: Obj) -> Result<String, SessionError> {
            Ok(String::new())
        }
        fn disconnect(&self, _: Obj) -> Result<(), SessionError> {
            Ok(())
        }
        fn connected_players(&self, _: bool) -> Result<Vec<Obj>, SessionError> {
            Ok(vec![])
        }
        fn connected_seconds(&self, _: Obj) -> Result<f64, SessionError> {
            Ok(0.0)
        }
        fn idle_seconds(&self, _: Obj) -> Result<f64, SessionError> {
            Ok(0.0)
        }
        fn connections(&self, _: Option<Obj>) -> Result<Vec<Obj>, SessionError> {
            Ok(vec![])
        }
        fn connection_details(
            &self,
            _: Option<Obj>,
        ) -> Result<Vec<moor_common::tasks::ConnectionDetails>, SessionError> {
            Ok(vec![])
        }
        fn connection_attributes(&self, _: Obj) -> Result<Var, SessionError> {
            Ok(v_int(0))
        }
        fn set_connection_attribute(
            &self,
            _: Obj,
            _: moor_var::Symbol,
            _: Var,
        ) -> Result<(), SessionError> {
            Ok(())
        }
    }

    /// One trial of the stock scheduler: 8 threads submit an eval each at once.
    fn concurrent_trial() -> Vec<String> {
        let scheduler = Scheduler::new(
            semver::Version::new(0, 1, 0),
            create_db(),
            Box::new(NoopTasksDb {}),
            Arc::new(Config::default()),
            Arc::new(NoopSystemControl::default()),
            None,
            None,
        );
        assert!(!scheduler.is_manual());
        let client = scheduler.client().unwrap();
        let services = scheduler.start(Arc::new(Factory)).unwrap();
        let order = Arc::new(StdMutex::new(Vec::new()));
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|k| {
                let client = client.clone();
                let order = order.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let session: Arc<dyn Session> = Arc::new(OrderSession {
                        order,
                        buf: StdMutex::new(vec![]),
                    });
                    barrier.wait();
                    let code = format!(
                        "fork (0) notify(player, \"fork {k}\"); endfork \
                         for i in [1..200] endfor notify(player, \"cmd {k}\"); return 1;"
                    );
                    moor_kernel::testing::scheduler_test_utils::call_eval(
                        client, session, &WIZARD, code,
                    )
                    .ok();
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        // Let forked children finish.
        std::thread::sleep(std::time::Duration::from_millis(300));
        client.submit_shutdown("done").ok();
        services.join().ok();
        order.lock().unwrap().clone()
    }

    /// `Scheduler::start` in deterministic mode (the daemon path): one sequencer thread serves
    /// client requests and runs each to quiescence.
    #[test]
    fn sequencer_thread_serves_requests_serially() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        deterministic::disable();
        let mode = DeterministicMode::on();
        deterministic::configure(&mode);
        let scheduler = Scheduler::new(
            semver::Version::new(0, 1, 0),
            create_db(),
            Box::new(NoopTasksDb {}),
            Arc::new(Config {
                deterministic: mode,
                ..Config::default()
            }),
            Arc::new(NoopSystemControl::default()),
            None,
            None,
        );
        let client = scheduler.client().unwrap();
        let services = scheduler.start(Arc::new(Factory)).unwrap();
        let order = Arc::new(StdMutex::new(Vec::new()));
        let session: Arc<dyn Session> = Arc::new(OrderSession {
            order: order.clone(),
            buf: StdMutex::new(vec![]),
        });
        let result = moor_kernel::testing::scheduler_test_utils::call_eval(
            client.clone(),
            session,
            &WIZARD,
            FORK_TREE.to_string(),
        );
        assert_eq!(result.ok(), Some(v_int(1)));
        let command = moor_kernel::testing::scheduler_test_utils::call_eval(
            client.clone(),
            Arc::new(NoopClientSession::new()),
            &WIZARD,
            "return block_context()['command];".to_string(),
        );
        client.submit_shutdown("done").ok();
        services.join().ok();
        deterministic::disable();
        assert_eq!(
            *order.lock().unwrap(),
            [
                "\"parent\"",
                "\"child A\"",
                "\"child B\"",
                "\"grandchild of A\""
            ]
        );
        assert_eq!(command.ok(), Some(v_int(2)));
    }

    #[test]
    fn concurrent_submission_to_the_stock_scheduler_diverges() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        deterministic::disable();
        let mut distinct = std::collections::BTreeSet::new();
        for _ in 0..10 {
            distinct.insert(concurrent_trial());
            if distinct.len() > 1 {
                break;
            }
        }
        assert!(
            distinct.len() > 1,
            "10 concurrent trials committed in the same order: {distinct:?}"
        );
    }

    /// Throughput of the serial executor against the stock threaded scheduler (one-at-a-time and
    /// 8 concurrent submitters). Prints numbers; asserts nothing. Run with `--ignored --nocapture`.
    #[test]
    #[ignore = "measurement, not a check"]
    fn perf_serial_vs_stock() {
        const N: usize = 2000;
        let code = "#0.n = #0.n + 1; notify(player, tostr(#0.n)); return #0.n;";
        let setup = "add_property(#0, \"n\", 0, {player, \"rw\"}); return 1;";

        let mut world = World::start();
        world.eval(setup);
        let started = std::time::Instant::now();
        let session: Arc<dyn Session> = Arc::new(NoopClientSession::new());
        world.driver().begin_block(block(2));
        for _ in 0..N {
            world.driver().submit(
                BlockInput::Eval {
                    player: WIZARD,
                    code: code.to_string(),
                },
                session.clone(),
            );
        }
        let out = world.driver().end_block();
        let serial = N as f64 / started.elapsed().as_secs_f64();
        assert_eq!(out.conflicts, 0);
        drop(world);

        let stock = |threads: usize| -> f64 {
            let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            deterministic::disable();
            let scheduler = Scheduler::new(
                semver::Version::new(0, 1, 0),
                create_db(),
                Box::new(NoopTasksDb {}),
                Arc::new(Config::default()),
                Arc::new(NoopSystemControl::default()),
                None,
                None,
            );
            let client = scheduler.client().unwrap();
            let services = scheduler.start(Arc::new(Factory)).unwrap();
            moor_kernel::testing::scheduler_test_utils::call_eval(
                client.clone(),
                Arc::new(NoopClientSession::new()),
                &WIZARD,
                setup.to_string(),
            )
            .unwrap();
            let started = std::time::Instant::now();
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    let client = client.clone();
                    std::thread::spawn(move || {
                        for _ in 0..N / threads {
                            moor_kernel::testing::scheduler_test_utils::call_eval(
                                client.clone(),
                                Arc::new(NoopClientSession::new()),
                                &WIZARD,
                                code.to_string(),
                            )
                            .ok();
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            let rate = N as f64 / started.elapsed().as_secs_f64();
            client.submit_shutdown("done").ok();
            services.join().ok();
            rate
        };
        let stock_serial = stock(1);
        let stock_concurrent = stock(8);
        println!(
            "PERF commands/s: serial executor {serial:.0}, stock one-at-a-time {stock_serial:.0}, \
             stock 8 submitters {stock_concurrent:.0}"
        );
    }
}

#[test]
fn contents_children_and_players_are_in_object_id_order() {
    let det = Det::start(13, 1_700_011_000, 1);
    // Create in one order, move/parent/flag in a scrambled one, and check against sort().
    let ok = det.run(
        "xs = {}; for i in [1..12] xs = {@xs, create(#-1)}; endfor \
         order = {7, 2, 11, 4, 9, 1, 12, 5, 3, 10, 6, 8}; \
         for i in (order) move(xs[i], #1); chparent(xs[i], #1); endfor \
         return {#1.contents == sort(#1.contents), children(#1) == sort(children(#1))};",
    );
    assert_eq!(ok, v_list(&[v_int(1), v_int(1)]));
}

#[test]
fn ordinal_matching_follows_object_id_order() {
    let det = Det::start(14, 1_700_012_000, 1);
    // Swords are created in id order but moved into the room in reverse, so a hash- or
    // recency-ordered contents list would give a different "second sword".
    let picked = det.run(
        "xs = {}; for i in [1..6] x = create(#-1); x.name = \"sword\"; xs = {@xs, x}; endfor \
         for i in [1..6] move(xs[7 - i], #1); endfor \
         keys = {}; for o in (#1.contents) keys = {@keys, {o.name}}; endfor \
         return {complex_match(\"first sword\", #1.contents, keys) == xs[1], \
                 complex_match(\"second sword\", #1.contents, keys) == xs[2], \
                 complex_match(\"sixth sword\", #1.contents, keys) == xs[6]};",
    );
    assert_eq!(picked, v_list(&[v_int(1), v_int(1), v_int(1)]));
}

/// Audit H2 and H3: the order of symbol-keyed maps and of lambda keys must not depend on the order
/// in which this process interned symbols or on where the allocator put a program.
mod ordering {
    use std::cmp::Ordering;

    use moor_var::{Symbol, Var, v_list, v_sym};

    use super::Det;

    /// Interned in descending order on purpose, so first-intern order is the reverse of string order.
    const REVERSED: [&str; 6] = [
        "s0h2_zulu",
        "s0h2_yankee",
        "s0h2_mike",
        "s0h2_bravo",
        "s0h2_alpha",
        "s0h2_aaa",
    ];

    const LAMBDA_KEYS: &str = "l1 = {x} => x + 1; l2 = {x} => x * 2; l3 = {x} => x - 1; \
         return toliteral(mapvalues([l3 -> 3, l1 -> 1, l2 -> 2]));";

    #[test]
    fn symbols_order_by_folded_string_not_intern_order() {
        let mut syms: Vec<Symbol> = REVERSED.iter().map(|s| Symbol::mk(s)).collect();
        syms.sort();
        let names: Vec<_> = syms.iter().map(|s| s.as_string()).collect();
        let mut expected: Vec<_> = REVERSED.iter().map(|s| s.to_string()).collect();
        expected.sort();
        assert_eq!(names, expected);
    }

    #[test]
    fn symbols_that_differ_only_in_case_are_equal_in_order() {
        let (a, b) = (Symbol::mk("S0h2_Case"), Symbol::mk("s0h2_case"));
        assert_eq!(a.cmp(&b), Ordering::Equal);
    }

    #[test]
    fn symbol_order_ignores_case_of_the_spelling() {
        let (upper, lower) = (Symbol::mk("S0H2_UPPER_B"), Symbol::mk("s0h2_upper_a"));
        assert_eq!(lower.cmp(&upper), Ordering::Less);
    }

    #[test]
    fn symbol_keyed_map_iterates_in_string_order() {
        let det = Det::start(1, 1_700_000_000, 1);
        let keys = det.run(
            "m = []; for s in ({'s0h2_zulu, 's0h2_alpha, 's0h2_mike}) m[s] = 1; endfor return mapkeys(m);",
        );
        let expect = v_list(&[v_sym("s0h2_alpha"), v_sym("s0h2_mike"), v_sym("s0h2_zulu")]);
        assert_eq!(keys, expect);
    }

    #[test]
    fn lambda_key_order_is_independent_of_heap_layout() {
        let det = Det::start(1, 1_700_000_000, 1);
        let first = det.run(LAMBDA_KEYS);
        let _junk: Vec<Vec<u8>> = (0..5000).map(|i| vec![0u8; 8 + i % 200]).collect();
        let second = det.run(LAMBDA_KEYS);
        assert_eq!(first, second);
    }

    #[test]
    fn lambda_order_is_antisymmetric_over_distinct_lambdas() {
        let det = Det::start(1, 1_700_000_000, 1);
        let r = det.run("a = {x} => x + 1; b = {x} => x * 2; return {a, b};");
        let l = r.as_list().expect("list");
        let items: Vec<Var> = l.iter().collect();
        let (a, b) = (&items[0], &items[1]);
        assert_ne!(a.cmp(&b), Ordering::Equal);
        assert_eq!(a.cmp(&b), b.cmp(&a).reverse());
    }

    /// Child half of the cross-process test. Interns the pool rotated by `RW_INTERN_SEED`, holds a
    /// seed-dependent amount of heap so program allocations land elsewhere, then prints the
    /// order-sensitive results.
    #[test]
    #[ignore = "run by symbol_and_lambda_order_is_identical_across_processes"]
    fn order_child() {
        let seed: usize = std::env::var("RW_INTERN_SEED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        const POOL: [&str; 8] = [
            "zeta", "alpha", "mid", "beta", "omega", "gamma", "delta", "kappa",
        ];
        for i in 0..POOL.len() {
            Symbol::mk(POOL[(i + seed) % POOL.len()]);
        }
        let _junk: Vec<Vec<u8>> = (0..(seed * 37 + 1))
            .map(|i| vec![0u8; 16 + i % 90])
            .collect();
        let det = Det::start(1, 1_700_000_000, 1);
        let syms: Var = det.run(
            "m = []; for s in ({'zeta, 'alpha, 'mid, 'beta, 'omega, 'gamma, 'delta, 'kappa}) m[s] = tostr(s); endfor return {toliteral(m), mapkeys(m)};",
        );
        let lam: Var = det.run(
            "l1 = {x} => x + 1; l2 = {x} => x * 2; l3 = {x} => x - 1; l4 = {x, y} => x + y; return toliteral(mapvalues([l1 -> 1, l2 -> 2, l3 -> 3, l4 -> 4]));",
        );
        println!(
            "ORDER-BEGIN\n{}\n{}\nORDER-END",
            moor_compiler::to_literal(&syms),
            moor_compiler::to_literal(&lam)
        );
    }

    fn child(seed: usize) -> String {
        let exe = std::env::current_exe().expect("test binary");
        let output = std::process::Command::new(exe)
            .env("RW_INTERN_SEED", seed.to_string())
            .args([
                "ordering::order_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .expect("run child");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let out = String::from_utf8_lossy(&output.stdout).to_string();
        let begin = out.find("ORDER-BEGIN\n").expect("begin marker") + "ORDER-BEGIN\n".len();
        let end = out.find("\nORDER-END").expect("end marker");
        out[begin..end].to_string()
    }

    #[test]
    fn symbol_and_lambda_order_is_identical_across_processes() {
        let runs: Vec<String> = (0..8).map(child).collect();
        assert!(runs[0].contains("alpha"), "{}", runs[0]);
        assert!(runs.windows(2).all(|w| w[0] == w[1]), "{runs:#?}");
    }
}

/// The admission step (RuneWorld ADR 0005): signed envelopes through the block driver.
mod admission {
    use std::sync::Arc;

    use moor_common::{
        deterministic::DeterministicMode,
        envelope::{
            Delegation, Domain, Envelope, EnvelopeKind, SessionSigner, WalletSigner, scope,
        },
        tasks::{NoopClientSession, Session},
    };
    use moor_kernel::tasks::{
        block_driver::{BlockEventKind, BlockInput, BlockOutput},
        envelope_admission::{AdmissionRejection, Admitted},
    };
    use moor_var::{Obj, Var, v_int, v_str};

    use super::executor::{World, block, canonical, texts};

    const WIZARD: Obj = Obj::mk_id(3);
    const DOMAIN: Domain = Domain { salt: [0; 32] };
    /// A day after the test blocks' time.
    const EXPIRES: u64 = 1_700_000_000 + 86_400;

    /// Hooks a core provides for the signed world: the creation hook, `user_created`,
    /// `user_connected`, and a parent for new players with `ping`, `boom` and `disfunc`.
    pub(super) const GENESIS: &str = r##"
        wp = create(#-1);
        add_property(#0, "wallet_parent", wp, {player, "r"});
        add_property(#0, "booms", 0, {player, "rw"});
        add_verb(wp, {player, "rxd", "ping"}, {"any", "any", "any"});
        set_verb_code(wp, "ping", {"notify(player, \"pong \" + argstr);"});
        add_verb(wp, {player, "rxd", "boom"}, {"none", "none", "none"});
        set_verb_code(wp, "boom", {"#0.booms = #0.booms + 1;", "rollback();"});
        add_verb(wp, {player, "rxd", "disfunc"}, {"this", "none", "this"});
        set_verb_code(wp, "disfunc", {"notify(this, \"disfunc \" + tostr(this));"});
        add_verb(#0, {player, "rxd", "create_wallet_player"}, {"this", "none", "this"});
        set_verb_code(#0, "create_wallet_player", {"p = create(#0.wallet_parent);", "set_player_flag(p, 1);", "p.name = args[2];", "return p;"});
        add_verb(#0, {player, "rxd", "user_created"}, {"this", "none", "this"});
        set_verb_code(#0, "user_created", {"notify(args[1], \"created \" + args[1].name);"});
        add_verb(#0, {player, "rxd", "user_connected"}, {"this", "none", "this"});
        set_verb_code(#0, "user_connected", {"notify(args[1], \"connected \" + tostr(args[1]));"});
        return wp;
    "##;

    pub(super) fn wallet(n: u8) -> WalletSigner {
        WalletSigner::from_secret([n; 32]).expect("valid secret")
    }

    pub(super) fn key(n: u8) -> SessionSigner {
        SessionSigner::from_seed([n; 32])
    }

    pub(super) fn delegation(
        session: &SessionSigner,
        nonce: u64,
        create: bool,
        scope: u32,
    ) -> Delegation {
        Delegation {
            session_key: session.public_key(),
            box_key: [0xbb; 32],
            scope,
            expires: EXPIRES,
            nonce,
            create,
        }
    }

    pub(super) fn delegate(w: &WalletSigner, s: &SessionSigner, d: Delegation) -> Envelope {
        w.delegate(&DOMAIN, s, d, 1_000).expect("sign delegation")
    }

    pub(super) fn command(
        s: &SessionSigner,
        player: Obj,
        session: u32,
        nonce: u32,
        text: &str,
    ) -> Envelope {
        s.envelope(
            &DOMAIN,
            player.as_u64(),
            EnvelopeKind::Command,
            session,
            nonce,
            1_000,
            text.as_bytes().to_vec(),
        )
    }

    pub(super) fn noop() -> Arc<dyn Session> {
        Arc::new(NoopClientSession::new())
    }

    /// A world with the genesis hooks, at height 1.
    fn world() -> World {
        world_with(DeterministicMode::on())
    }

    pub(super) fn world_with(mode: DeterministicMode) -> World {
        let mut world = World::start_with(mode);
        let out = world.block(1, &[GENESIS]);
        assert!(
            matches!(out.outcomes[0].result, Some(Ok(_))),
            "genesis failed: {:?}",
            out.outcomes[0].result
        );
        world
    }

    /// Run envelopes as one block at `height`.
    pub(super) fn run(world: &mut World, height: u64, envs: &[&Envelope]) -> BlockOutput {
        let driver = world.driver();
        driver.begin_block(block(height));
        for env in envs {
            driver.submit_envelope(&env.encode(), noop());
        }
        driver.end_block()
    }

    pub(super) fn verdicts(out: &BlockOutput) -> Vec<Result<Admitted, AdmissionRejection>> {
        out.outcomes
            .iter()
            .map(|o| o.admission.clone().expect("envelope outcome"))
            .collect()
    }

    fn rejection(out: &BlockOutput, i: usize) -> AdmissionRejection {
        out.outcomes[i]
            .admission
            .clone()
            .expect("envelope outcome")
            .expect_err("expected a rejection")
    }

    /// Mint a player for wallet 1 with session key 1 (session index 1). Returns the player.
    pub(super) fn create_player(world: &mut World) -> Obj {
        let out = run(
            world,
            2,
            &[&delegate(
                &wallet(1),
                &key(1),
                delegation(&key(1), 1, true, scope::PLAY),
            )],
        );
        match verdicts(&out).remove(0) {
            Ok(Admitted::Delegated {
                player,
                session: 1,
                created: true,
            }) => player,
            other => panic!("create failed: {other:?}"),
        }
    }

    pub(super) fn eval(world: &mut World, height: u64, code: &str) -> Var {
        let out = world.block(height, &[code]);
        match &out.outcomes[0].result {
            Some(Ok(v)) => v.clone(),
            other => panic!("eval failed: {other:?}"),
        }
    }

    #[test]
    fn create_mints_a_player_with_the_wallet_and_runs_user_created() {
        let mut world = world();
        let out = run(
            &mut world,
            2,
            &[&delegate(
                &wallet(1),
                &key(1),
                delegation(&key(1), 1, true, scope::PLAY),
            )],
        );
        let Ok(Admitted::Delegated { player, .. }) = verdicts(&out).remove(0) else {
            panic!("{:?}", out.outcomes[0].admission);
        };
        let name = format!("w-{}", &wallet(1).address().to_hex()[2..10]);
        assert_eq!(texts(&out.events), [format!("created {name}")]);
        assert_eq!(
            eval(
                &mut world,
                3,
                &format!("return {{{player}.wallet, {player}.name, is_player({player})}};")
            ),
            moor_var::v_list(&[v_str(&wallet(1).address().to_hex()), v_str(&name), v_int(1)])
        );
    }

    #[test]
    fn create_registers_the_first_session_in_world_state() {
        let mut world = world();
        let player = create_player(&mut world);
        let row = eval(&mut world, 3, "return #0.admission_sessions[1];");
        let expected = format!(
            "[\"box_key\" -> \"{}\", \"expires\" -> {EXPIRES}, \"key\" -> \"{}\", \"last_nonce\" -> 0, \"player\" -> {player}, \"revoked\" -> 0, \"scope\" -> 1]",
            "bb".repeat(32),
            moor_common::envelope::hex(&key(1).public_key())
        );
        assert_eq!(moor_compiler::to_literal(&row), expected);
    }

    #[test]
    fn signed_command_runs_as_the_session_player() {
        let mut world = world();
        let player = create_player(&mut world);
        let out = run(
            &mut world,
            3,
            &[&command(&key(1), player, 1, 1, "ping hello")],
        );
        assert_eq!(texts(&out.events), ["pong hello"]);
    }

    #[test]
    fn invalid_signature_is_rejected_and_runs_nothing() {
        let mut world = world();
        let player = create_player(&mut world);
        let mut env = command(&key(1), player, 1, 1, "ping hello");
        env.signature[10] ^= 1;
        let out = run(&mut world, 3, &[&env]);
        assert_eq!(
            (rejection(&out, 0), texts(&out.events)),
            (AdmissionRejection::BadSignature, Vec::<String>::new())
        );
    }

    #[test]
    fn signature_by_another_key_is_rejected() {
        let mut world = world();
        let player = create_player(&mut world);
        let out = run(&mut world, 3, &[&command(&key(9), player, 1, 1, "ping")]);
        assert_eq!(rejection(&out, 0), AdmissionRejection::BadSignature);
    }

    #[test]
    fn rejection_emits_a_rejection_event() {
        let mut world = world();
        let player = create_player(&mut world);
        let out = run(&mut world, 3, &[&command(&key(9), player, 1, 1, "ping")]);
        assert!(
            matches!(
                &out.events[..],
                [e, m] if matches!(&e.kind, BlockEventKind::Rejected { kind: Some(EnvelopeKind::Command), session: 1, reason: AdmissionRejection::BadSignature })
                    && matches!(&m.kind, BlockEventKind::Meter(_))
            ),
            "{:?}",
            out.events
        );
    }

    #[test]
    fn stale_nonce_is_rejected_and_gaps_are_allowed() {
        let mut world = world();
        let player = create_player(&mut world);
        let out = run(
            &mut world,
            3,
            &[
                &command(&key(1), player, 1, 5, "ping a"),
                &command(&key(1), player, 1, 5, "ping b"),
                &command(&key(1), player, 1, 3, "ping c"),
                &command(&key(1), player, 1, 9, "ping d"),
            ],
        );
        assert_eq!(
            (rejection(&out, 1), rejection(&out, 2), texts(&out.events)),
            (
                AdmissionRejection::StaleNonce { last: 5, got: 5 },
                AdmissionRejection::StaleNonce { last: 5, got: 3 },
                vec!["pong a".to_string(), "pong d".to_string()]
            )
        );
    }

    #[test]
    fn nonce_is_consumed_when_the_command_aborts() {
        let mut world = world();
        let player = create_player(&mut world);
        let out = run(
            &mut world,
            3,
            &[
                &command(&key(1), player, 1, 1, "boom"),
                &command(&key(1), player, 1, 1, "ping again"),
            ],
        );
        assert_eq!(
            (
                rejection(&out, 1),
                eval(
                    &mut world,
                    4,
                    "return {#0.booms, #0.admission_sessions[1][\"last_nonce\"]};"
                )
            ),
            (
                AdmissionRejection::StaleNonce { last: 1, got: 1 },
                moor_var::v_list(&[v_int(0), v_int(1)])
            )
        );
    }

    #[test]
    fn expired_session_is_rejected() {
        let mut world = world();
        let player = create_player(&mut world);
        // Block time at height h is 1_700_000_000 + 60h; EXPIRES is a day later.
        let height = 86_400 / 60 + 1;
        // The envelope itself is still valid at `height`; only the session has expired.
        let env = key(1).envelope(
            &DOMAIN,
            player.as_u64(),
            EnvelopeKind::Command,
            1,
            1,
            height + 10,
            b"ping".to_vec(),
        );
        let out = run(&mut world, height, &[&env]);
        assert!(matches!(
            rejection(&out, 0),
            AdmissionRejection::SessionExpired { session: 1, .. }
        ));
    }

    #[test]
    fn expired_envelope_is_rejected() {
        let mut world = world();
        let player = create_player(&mut world);
        let env = key(1).envelope(
            &DOMAIN,
            player.as_u64(),
            EnvelopeKind::Command,
            1,
            1,
            2,
            b"ping".to_vec(),
        );
        let out = run(&mut world, 3, &[&env]);
        assert_eq!(
            rejection(&out, 0),
            AdmissionRejection::Expired {
                expiry_height: Some(2),
                height: 3
            }
        );
    }

    #[test]
    fn envelope_is_valid_at_its_expiry_height() {
        let mut world = world();
        let player = create_player(&mut world);
        let env = key(1).envelope(
            &DOMAIN,
            player.as_u64(),
            EnvelopeKind::Command,
            1,
            1,
            3,
            b"ping".to_vec(),
        );
        let out = run(&mut world, 3, &[&env]);
        assert_eq!(texts(&out.events), ["pong "]);
    }

    #[test]
    fn wrong_scope_is_rejected() {
        let mut world = world();
        let out = run(
            &mut world,
            2,
            &[&delegate(
                &wallet(1),
                &key(1),
                delegation(&key(1), 1, true, scope::BUILD),
            )],
        );
        let player = verdicts(&out)[0].clone().unwrap().player();
        let out = run(&mut world, 3, &[&command(&key(1), player, 1, 1, "ping")]);
        assert_eq!(
            rejection(&out, 0),
            AdmissionRejection::WrongScope {
                kind: EnvelopeKind::Command,
                scope: scope::BUILD
            }
        );
    }

    #[test]
    fn replayed_delegation_is_rejected() {
        let mut world = world();
        let env = delegate(
            &wallet(1),
            &key(1),
            delegation(&key(1), 1, true, scope::PLAY),
        );
        run(&mut world, 2, &[&env]);
        let out = run(&mut world, 3, &[&env]);
        assert_eq!(
            rejection(&out, 0),
            AdmissionRejection::StaleDelegationNonce { floor: 1, got: 1 }
        );
    }

    #[test]
    fn replayed_second_delegation_hits_the_nonce_floor() {
        let mut world = world();
        create_player(&mut world);
        let second = delegate(
            &wallet(1),
            &key(2),
            delegation(&key(2), 2, false, scope::PLAY),
        );
        let out = run(&mut world, 3, &[&second, &second]);
        assert_eq!(
            rejection(&out, 1),
            AdmissionRejection::StaleDelegationNonce { floor: 2, got: 2 }
        );
    }

    #[test]
    fn second_session_signs_independently() {
        let mut world = world();
        let player = create_player(&mut world);
        let out = run(
            &mut world,
            3,
            &[
                &delegate(
                    &wallet(1),
                    &key(2),
                    delegation(&key(2), 2, false, scope::PLAY),
                ),
                &command(&key(1), player, 1, 1, "ping one"),
                &command(&key(2), player, 2, 1, "ping two"),
            ],
        );
        assert_eq!(texts(&out.events), ["pong one", "pong two"]);
    }

    #[test]
    fn create_for_an_existing_wallet_is_rejected() {
        let mut world = world();
        let player = create_player(&mut world);
        let out = run(
            &mut world,
            3,
            &[&delegate(
                &wallet(1),
                &key(2),
                delegation(&key(2), 2, true, scope::PLAY),
            )],
        );
        assert_eq!(
            rejection(&out, 0),
            AdmissionRejection::WalletHasPlayer {
                wallet: wallet(1).address(),
                player
            }
        );
    }

    #[test]
    fn delegation_from_an_unknown_wallet_without_create_is_rejected() {
        let mut world = world();
        let out = run(
            &mut world,
            2,
            &[&delegate(
                &wallet(7),
                &key(7),
                delegation(&key(7), 1, false, scope::PLAY),
            )],
        );
        assert_eq!(
            rejection(&out, 0),
            AdmissionRejection::UnknownWallet(wallet(7).address())
        );
    }

    #[test]
    fn revoke_then_command_is_rejected() {
        let mut world = world();
        let player = create_player(&mut world);
        let revoke = key(1).envelope(
            &DOMAIN,
            player.as_u64(),
            EnvelopeKind::Revoke,
            1,
            1,
            1_000,
            vec![],
        );
        let out = run(
            &mut world,
            3,
            &[&revoke, &command(&key(1), player, 1, 2, "ping")],
        );
        assert_eq!(
            verdicts(&out),
            [
                Ok(Admitted::Revoked {
                    player,
                    sessions: vec![1]
                }),
                Err(AdmissionRejection::SessionRevoked(1))
            ]
        );
    }

    #[test]
    fn revoke_all_from_the_wallet_revokes_every_session() {
        let mut world = world();
        let player = create_player(&mut world);
        let revoke_all = wallet(1).revoke_all(&DOMAIN, 3, 1_000).unwrap();
        let out = run(
            &mut world,
            3,
            &[
                &delegate(
                    &wallet(1),
                    &key(2),
                    delegation(&key(2), 2, false, scope::PLAY),
                ),
                &revoke_all,
                &command(&key(1), player, 1, 1, "ping"),
                &command(&key(2), player, 2, 1, "ping"),
            ],
        );
        assert_eq!(
            verdicts(&out)[1..],
            [
                Ok(Admitted::Revoked {
                    player,
                    sessions: vec![1, 2]
                }),
                Err(AdmissionRejection::SessionRevoked(1)),
                Err(AdmissionRejection::SessionRevoked(2))
            ]
        );
    }

    #[test]
    fn revoke_all_replay_is_rejected() {
        let mut world = world();
        create_player(&mut world);
        let revoke_all = wallet(1).revoke_all(&DOMAIN, 3, 1_000).unwrap();
        let out = run(&mut world, 3, &[&revoke_all, &revoke_all]);
        assert_eq!(
            rejection(&out, 1),
            AdmissionRejection::StaleDelegationNonce { floor: 3, got: 3 }
        );
    }

    #[test]
    fn connect_runs_user_connected() {
        let mut world = world();
        let player = create_player(&mut world);
        let connect = key(1).envelope(
            &DOMAIN,
            player.as_u64(),
            EnvelopeKind::Connect,
            1,
            1,
            1_000,
            vec![],
        );
        let out = run(&mut world, 3, &[&connect]);
        assert_eq!(texts(&out.events), [format!("connected {player}")]);
    }

    #[test]
    fn connect_with_text_is_malformed() {
        let mut world = world();
        let player = create_player(&mut world);
        let connect = key(1).envelope(
            &DOMAIN,
            player.as_u64(),
            EnvelopeKind::Connect,
            1,
            1,
            1_000,
            b"x".to_vec(),
        );
        let out = run(&mut world, 3, &[&connect]);
        assert!(matches!(
            rejection(&out, 0),
            AdmissionRejection::Malformed(_)
        ));
    }

    #[test]
    fn sequencer_disconnect_runs_only_disfunc() {
        let mut world = world();
        let player = create_player(&mut world);
        let driver = world.driver();
        driver.begin_block(block(3));
        driver.submit(BlockInput::SequencerDisconnect { player }, noop());
        let out = driver.end_block();
        assert_eq!(texts(&out.events), [format!("disfunc {player}")]);
    }

    #[test]
    fn envelope_for_another_domain_is_rejected() {
        let mut world = world_with(DeterministicMode {
            domain_salt: [7; 32],
            ..DeterministicMode::on()
        });
        let out = run(
            &mut world,
            2,
            &[&delegate(
                &wallet(1),
                &key(1),
                delegation(&key(1), 1, true, scope::PLAY),
            )],
        );
        // The wallet signature recovers to some other address, so the proof of possession is
        // checked against a different digest too; either way nothing is created.
        assert!(matches!(
            rejection(&out, 0),
            AdmissionRejection::BadSignature | AdmissionRejection::BadWalletSignature(_)
        ));
    }

    #[test]
    fn garbage_bytes_are_malformed() {
        let mut world = world();
        let driver = world.driver();
        driver.begin_block(block(2));
        driver.submit_envelope(&[0, 1, 2], noop());
        let out = driver.end_block();
        assert!(matches!(
            rejection(&out, 0),
            AdmissionRejection::Malformed(_)
        ));
    }

    #[test]
    fn admission_properties_belong_to_the_system_principal_and_are_read_only() {
        let mut world = world();
        let player = create_player(&mut world);
        assert_eq!(
            eval(
                &mut world,
                3,
                &format!(
                    "return {{property_info({player}, \"wallet\"), \
                     property_info(#0, \"admission_sessions\"), \
                     property_info(#0, \"admission_wallets\"), #0.owner}};"
                )
            ),
            moor_var::v_list(&[
                moor_var::v_list(&[WIZARD.into(), v_str("r")]),
                moor_var::v_list(&[WIZARD.into(), v_str("r")]),
                moor_var::v_list(&[WIZARD.into(), v_str("r")]),
                WIZARD.into(),
            ])
        );
    }

    /// The signed log the cross-process test replays: create, a second session, commands with a
    /// gap, an aborted command, a rejection, a revoke, a connect.
    fn signed_log(player: Obj) -> Vec<Vec<Envelope>> {
        vec![
            vec![delegate(
                &wallet(1),
                &key(1),
                delegation(&key(1), 1, true, scope::PLAY),
            )],
            vec![
                delegate(
                    &wallet(1),
                    &key(2),
                    delegation(&key(2), 2, false, scope::PLAY),
                ),
                key(1).envelope(
                    &DOMAIN,
                    player.as_u64(),
                    EnvelopeKind::Connect,
                    1,
                    1,
                    1_000,
                    vec![],
                ),
                command(&key(1), player, 1, 2, "ping one"),
                command(&key(2), player, 2, 7, "ping two"),
                command(&key(1), player, 1, 3, "boom"),
                command(&key(1), player, 1, 3, "ping stale"),
            ],
            vec![
                key(2).envelope(
                    &DOMAIN,
                    player.as_u64(),
                    EnvelopeKind::Revoke,
                    2,
                    8,
                    1_000,
                    b"1".to_vec(),
                ),
                command(&key(1), player, 1, 4, "ping revoked"),
                command(&key(2), player, 2, 9, "ping still here"),
            ],
        ]
    }

    /// Run the signed log in a fresh world; returns every batch and the final admission state.
    pub(super) fn signed_run() -> String {
        let mut world = world();
        // The player id the log signs for is the one the first delegation mints: max_object + 1.
        let player = Obj::mk_id(
            eval(&mut world, 1, "return toint(max_object()) + 1;")
                .as_integer()
                .unwrap() as i32,
        );
        let mut transcript = Vec::new();
        for (i, envs) in signed_log(player).iter().enumerate() {
            let refs: Vec<&Envelope> = envs.iter().collect();
            let out = run(&mut world, 2 + i as u64, &refs);
            assert_eq!(out.conflicts, 0);
            transcript.push(canonical(&out.events));
        }
        let state = eval(
            &mut world,
            9,
            "return {#0.admission_sessions, #0.admission_wallets, #0.booms};",
        );
        transcript.push(moor_compiler::to_literal(&state));
        transcript.join("\n--\n")
    }

    #[test]
    fn signed_log_is_identical_across_20_runs() {
        let first = signed_run();
        assert!(
            first.contains("pong still here") && first.contains("session 1 is revoked"),
            "{first}"
        );
        for _ in 1..20 {
            assert_eq!(signed_run(), first);
        }
    }

    #[test]
    #[ignore = "run as a subprocess by signed_log_is_identical_across_processes"]
    fn signed_log_child() {
        println!("SIGNED-BEGIN\n{}\nSIGNED-END", signed_run());
    }

    #[test]
    fn signed_log_is_identical_across_processes() {
        let child = || {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "admission::signed_log_child",
                    "--exact",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .output()
                .expect("run child");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let begin = stdout.find("SIGNED-BEGIN\n").unwrap() + "SIGNED-BEGIN\n".len();
            let end = stdout.find("\nSIGNED-END").unwrap();
            stdout[begin..end].to_string()
        };
        let runs: Vec<String> = (0..3).map(|_| child()).collect();
        assert!(runs.windows(2).all(|w| w[0] == w[1]), "{runs:#?}");
    }

    /// Verify costs: one Ed25519 (ZIP-215) verify per command, one ecrecover per delegation, and the
    /// whole admitted command through the block driver. Run with `--ignored --nocapture`, in debug
    /// and with `--release`.
    #[test]
    #[ignore = "measurement, not a check"]
    fn perf_admission_costs() {
        use moor_common::envelope::{envelope_digest, recover_wallet, verify_session_signature};
        const N: u32 = 2_000;
        let s = key(1);
        let digest = envelope_digest(
            &DOMAIN,
            5,
            &s.public_key(),
            EnvelopeKind::Command,
            1,
            10,
            b"look",
        );
        let sig = s.sign_digest(&digest);
        let started = std::time::Instant::now();
        for _ in 0..N {
            assert!(verify_session_signature(&s.public_key(), &digest, &sig));
        }
        let ed = started.elapsed() / N;

        let d = delegation(&s, 1, true, scope::PLAY);
        let typed = d.digest(&DOMAIN);
        let wsig = wallet(1).sign_digest(&typed).unwrap();
        let started = std::time::Instant::now();
        for _ in 0..N {
            assert!(recover_wallet(&typed, &wsig).is_ok());
        }
        let ec = started.elapsed() / N;

        let mut world = world();
        let player = create_player(&mut world);
        let envs: Vec<Envelope> = (1..=N).map(|n| command(&s, player, 1, n, "ping")).collect();
        let driver = world.driver();
        driver.begin_block(block(3));
        let started = std::time::Instant::now();
        for env in &envs {
            driver.submit_envelope(&env.encode(), noop());
        }
        let signed = started.elapsed() / N;
        driver.end_block();
        driver.begin_block(block(4));
        let started = std::time::Instant::now();
        for _ in 0..N {
            driver.submit(
                BlockInput::Command {
                    player,
                    command: "ping".into(),
                },
                noop(),
            );
        }
        let unsigned = started.elapsed() / N;
        driver.end_block();
        println!(
            "PERF ed25519 verify {ed:?}/command, ecrecover {ec:?}/delegation, \
             signed command {signed:?}, unsigned command {unsigned:?}"
        );
    }
}

/// S0-5: the state root (state encoding v1) under the block driver.
mod state_root {
    use std::{
        collections::BTreeMap,
        path::Path,
        sync::{Arc, MutexGuard},
    };

    use moor_common::{
        deterministic::{self, BlockContext, DeterministicMode},
        tasks::{NoopClientSession, NoopSystemControl, Session, SessionError, SessionFactory},
    };
    use moor_db::{
        Database, DatabaseConfig, TxDB,
        state_root::{
            RELATIONS, StateRoot,
            cbor::{Decoder, Encoder},
            values,
        },
    };
    use moor_kernel::{
        config::Config,
        tasks::{
            NoopTasksDb,
            block_driver::{BlockDriver, BlockInput, BlockOutput},
            scheduler::Scheduler,
        },
    };
    use moor_var::{Obj, Symbol, Var};

    use super::{LOCK, common::load_textdump};

    const WIZARD: Obj = Obj::mk_id(3);

    struct Factory;
    impl SessionFactory for Factory {
        fn mk_background_session(
            self: Arc<Self>,
            _player: &Obj,
        ) -> Result<Arc<dyn Session>, SessionError> {
            Ok(Arc::new(NoopClientSession::new()))
        }
    }

    /// A deterministic world under a block driver that keeps a handle on its database.
    struct World {
        driver: Option<BlockDriver>,
        db: TxDB,
        height: u64,
        /// The wizard inputs run as.
        player: Obj,
        _guard: MutexGuard<'static, ()>,
    }

    impl World {
        fn start() -> Self {
            Self::start_with(|| {})
        }

        /// `before_load` runs after the mode is configured and before the core is loaded.
        fn start_with(before_load: impl FnOnce()) -> Self {
            Self::start_features(before_load, moor_vm::FeaturesConfig::default())
        }

        /// As `start_with`, with the given language features (`use_uuobjids`, `anonymous_objects`).
        fn start_features(before_load: impl FnOnce(), features: moor_vm::FeaturesConfig) -> Self {
            let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            deterministic::disable();
            let mode = DeterministicMode::on();
            deterministic::configure(&mode);
            before_load();
            let (db, _) = TxDB::try_open(None, DatabaseConfig::default()).unwrap();
            load_textdump(&db);
            let scheduler = Scheduler::new(
                semver::Version::new(0, 1, 0),
                Box::new(db.clone()),
                Box::new(NoopTasksDb {}),
                Arc::new(Config {
                    deterministic: mode,
                    features: Arc::new(features),
                    ..Config::default()
                }),
                Arc::new(NoopSystemControl::default()),
                None,
                None,
            );
            let driver = scheduler
                .start_block_driver(Arc::new(Factory))
                .expect("start block driver");
            Self {
                driver: Some(driver),
                db,
                height: 0,
                player: WIZARD,
                _guard: guard,
            }
        }

        fn driver(&mut self) -> &mut BlockDriver {
            self.driver.as_mut().expect("driver")
        }

        /// The next block, with one eval input per element of `evals`. Every input must succeed.
        fn block(&mut self, evals: &[&str]) -> BlockOutput {
            self.height += 1;
            let height = self.height;
            let player = self.player;
            let inputs = evals
                .iter()
                .map(|code| {
                    let session: Arc<dyn Session> = Arc::new(NoopClientSession::new());
                    (
                        BlockInput::Eval {
                            player,
                            code: (*code).to_string(),
                        },
                        session,
                    )
                })
                .collect();
            let out = self.driver().run_block(
                BlockContext {
                    height,
                    timestamp: 1_700_000_000 + 60 * height,
                    seed: [height as u8; 32],
                },
                inputs,
            );
            for (code, outcome) in evals.iter().zip(&out.outcomes) {
                assert!(
                    matches!(outcome.result, Some(Ok(_))),
                    "{code}: {:?}",
                    outcome.result
                );
            }
            assert_eq!(out.conflicts, 0);
            out
        }

        fn eval(&mut self, code: &str) -> Var {
            let out = self.block(&[code]);
            match &out.outcomes[0].result {
                Some(Ok(v)) => v.clone(),
                other => panic!("{other:?}"),
            }
        }

        /// objdef export, files by name, `manifest.json` (wall-clock) left out.
        fn objdef(&self) -> BTreeMap<String, String> {
            let dir = tempfile::tempdir().unwrap();
            let snapshot = self.db.create_snapshot().unwrap();
            moor_objdef::dump_snapshot_object_definitions(snapshot.as_ref(), dir.path()).unwrap();
            let mut files = BTreeMap::new();
            collect(dir.path(), dir.path(), &mut files);
            files
        }
    }

    fn collect(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect(root, &path, out);
            } else if path.file_name().is_some_and(|n| n != "manifest.json") {
                let name = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                out.insert(name, std::fs::read_to_string(&path).unwrap_or_default());
            }
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            if let Some(driver) = self.driver.take() {
                driver.shutdown().ok();
            }
            deterministic::disable();
        }
    }

    fn root(out: &BlockOutput) -> StateRoot {
        out.state_root
            .clone()
            .expect("end_block computes the root")
            .expect("root")
    }

    fn changed(a: &StateRoot, b: &StateRoot) -> Vec<&'static str> {
        a.relations
            .iter()
            .zip(&b.relations)
            .filter(|(x, y)| x != y)
            .map(|(x, _)| x.name)
            .collect()
    }

    #[test]
    fn end_block_reports_one_hash_per_relation() {
        let mut world = World::start();
        let out = world.block(&["return 1;"]);
        let root = root(&out);
        let names: Vec<_> = root.relations.iter().map(|r| r.name).collect();
        assert_eq!(names, RELATIONS);
        assert_eq!(world.driver().state_root().unwrap(), root);
    }

    /// ADR 0006 decision 3: an empty block writes nothing, so it carries the previous root.
    #[test]
    fn an_empty_block_changes_no_relation() {
        let mut world = World::start();
        let before = root(&world.block(&["o = create(#1); move(o, #2); return o;"]));
        for _ in 0..3 {
            let after = root(&world.block(&[]));
            assert_eq!(changed(&before, &after), Vec::<&str>::new());
            assert_eq!(after, before);
        }
    }

    /// A block whose inputs only read (or fail before writing) leaves the root unchanged too.
    #[test]
    fn a_block_of_reads_changes_no_relation() {
        let mut world = World::start();
        let before = root(&world.block(&["return 1;"]));
        let after = root(&world.block(&[
            "return {#2.contents, players(), random(10), uuid(), time()};",
            "return toliteral(#0);",
        ]));
        assert_eq!(after, before);
    }

    #[test]
    fn a_property_write_changes_the_root_and_exactly_one_relation_hash() {
        let mut world = World::start();
        let before =
            root(&world.block(&["add_property(#0, \"n\", 1, {player, \"rw\"}); return 1;"]));
        let after = root(&world.block(&["#0.n = 2; return 1;"]));
        assert_ne!(after.root, before.root);
        assert_eq!(changed(&before, &after), ["object_propvalues"]);
    }

    /// The objdef blind spots (spike report): `last_move` and the sequences are not in an objdef
    /// export, so a change confined to them leaves objdef identical. The root sees both.
    #[test]
    fn last_move_and_sequence_changes_are_in_the_root_but_not_in_objdef() {
        let mut world = World::start();
        let o = world.eval("o = create(#1); move(o, #2); return o;");
        let o = o.as_object().expect("object");
        let before = root(&world.block(&["return 1;"]));
        let objdef_before = world.objdef();

        // Out and back in a later block: same location, new last_move time.
        let code = format!("move({o}, #3); move({o}, #2); return 1;");
        let after_move = root(&world.block(&[code.as_str()]));
        assert_eq!(changed(&before, &after_move), ["object_last_move"]);
        assert_eq!(world.objdef(), objdef_before);

        // Create and recycle: every object relation is as before, max object is not.
        let after_recycle = root(&world.block(&["x = create(#1); recycle(x); return 1;"]));
        assert_eq!(changed(&after_move, &after_recycle), ["sequences"]);
        assert_eq!(world.objdef(), objdef_before);
    }

    /// `contents` order is not extra state: it is derived from `object_location` (S0-3, id order),
    /// so arriving in a different order gives the same contents and the same root. A different
    /// arrangement (the spike's step-4 fork, where "take second sword" took the other sword) is a
    /// different `object_location` relation and so a different root.
    #[test]
    fn contents_order_is_covered_through_object_location() {
        let run = |first: usize, second: usize| {
            let mut world = World::start();
            world.eval("a = create(#1); b = create(#1); move(a, #3); move(b, #3); return 1;");
            let objs = world.eval("return #3.contents;");
            let objs = objs.as_list().unwrap().clone();
            let a = objs.iter_ref().nth(first).unwrap().as_object().unwrap();
            let b = objs.iter_ref().nth(second).unwrap().as_object().unwrap();
            let code = format!("move({a}, #2); move({b}, #2); return #2.contents;");
            let contents = world.eval(&code);
            // Clear last_move differences: both moves happened in the same block.
            (contents, root(&world.block(&[])))
        };
        let (contents_ab, root_ab) = run(0, 1);
        let (contents_ba, root_ba) = run(1, 0);
        assert_eq!(contents_ab, contents_ba);
        assert_eq!(root_ab, root_ba);

        let mut world = World::start();
        world.eval("a = create(#1); b = create(#1); move(a, #3); move(b, #3); return 1;");
        let one_moved = |world: &mut World, which: usize| {
            let code = format!("move(#3.contents[{which}], #2); return 1;");
            root(&world.block(&[code.as_str()]))
        };
        let first = one_moved(&mut world, 1);
        drop(world);
        let mut world = World::start();
        world.eval("a = create(#1); b = create(#1); move(a, #3); move(b, #3); return 1;");
        let second = one_moved(&mut world, 2);
        assert_ne!(first.root, second.root);
        assert!(changed(&first, &second).contains(&"object_location"));
    }

    fn round_trip(v: &Var) {
        let mut e = Encoder::new();
        values::var(&mut e, v).unwrap();
        let bytes = e.into_bytes();
        let mut d = Decoder::new(&bytes);
        let back = values::decode_var(&mut d).unwrap();
        d.finish().unwrap();
        let mut e = Encoder::new();
        values::var(&mut e, &back).unwrap();
        assert_eq!(e.into_bytes(), bytes, "{v:?}");
        assert_eq!(&back, v);
    }

    /// Every Var type, including lambdas (which need the compiler, so are tested here).
    #[test]
    fn every_value_type_round_trips_through_the_canonical_encoding() {
        let mut world = World::start();
        let values = world.eval(
            "return {0, 1, -7, 2.5, -0.0, \"Str\", #3, E_PERM, E_INVARG(\"msg\"), \
             {1, {2}}, ['zeta -> 1, \"a\" -> 2, 3 -> 'c], 'Sym, decode_base64(\"AAEC\"), \
             <#1, .slot = 'v, {1, 2}>, {x} => x + 1, \
             fn(a, ?b = 2, @rest) return {a, b, rest}; endfn, \
             (fn() let y = 5; return {x} => x + y; endfn)(), true, false};",
        );
        let list = values.as_list().expect("list").clone();
        assert_eq!(list.len(), 19);
        for v in list.iter_ref() {
            round_trip(v);
        }
        round_trip(&values);
    }

    /// The scenario the cross-process test replays: objects, moves, symbol-keyed maps, lambdas,
    /// flyweights, `fork (0)`, `random()`, `uuid()`, create and recycle, and an empty block.
    const SCENARIO: &[&[&str]] = &[
        &["add_property(#0, \"m\", [], {player, \"rwc\"}); \
           add_property(#0, \"l\", {}, {player, \"rwc\"}); return 1;"],
        &["o = create(#1); p = create(#1); move(o, #2); move(p, #2); #0.l = {o, p}; return 1;"],
        &["#0.m = ['zeta -> 1, 'alpha -> 2, 'Omega -> 3, \"str\" -> 4, 5 -> 'five]; return 1;"],
        &["#0.m['lam] = {x} => x + 1; \
           f = fn(a, ?b = 2, @rest) let t = a; return {t, b, rest}; endfn; \
           #0.l = {@#0.l, f, <#1, .slot = 'v, {1, 2}>}; return 1;"],
        &["fork (0) #0.l = {@#0.l, random(1000), uuid()}; endfork return 1;"],
        &[
            "x = create(#1); recycle(x); return 1;",
            "move(#0.l[1], #3); return 1;",
        ],
        &[],
    ];

    const INTERN_POOL: &[&str] = &[
        "zeta", "alpha", "omega", "five", "lam", "slot", "v", "m", "l",
    ];

    /// Child half of the cross-process test: interns a symbol pool in an order chosen by
    /// `RW_STATE_ROOT_INTERN` before loading, runs the scenario, prints one root per block.
    #[test]
    #[ignore = "run as a subprocess by state_root_is_identical_across_20_processes"]
    fn state_root_child() {
        let rotate: usize = std::env::var("RW_STATE_ROOT_INTERN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut world = World::start_with(|| {
            let n = INTERN_POOL.len();
            for i in 0..n {
                let name = INTERN_POOL[(i + rotate) % n];
                // Alternate case too: interning order and first-seen case both vary.
                let name = if rotate % 2 == 1 {
                    name.to_uppercase()
                } else {
                    name.to_string()
                };
                let _ = Symbol::mk(&name);
            }
        });
        let mut lines = Vec::new();
        for block in SCENARIO {
            let out = world.block(block);
            let r = root(&out);
            lines.push(format!("{} {}", out.block.height, r.root_hex()));
        }
        for r in &world.driver().state_root().unwrap().relations {
            lines.push(format!(
                "{} {} {}",
                r.name,
                moor_db::state_root::hex(&r.hash),
                r.entries
            ));
        }
        println!("ROOTS-BEGIN\n{}\nROOTS-END", lines.join("\n"));
    }

    fn child_roots(rotate: usize) -> String {
        let exe = std::env::current_exe().expect("test binary");
        let output = std::process::Command::new(exe)
            .args([
                "state_root::state_root_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RW_STATE_ROOT_INTERN", rotate.to_string())
            .output()
            .expect("run child");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let begin = stdout.find("ROOTS-BEGIN\n").expect("marker") + "ROOTS-BEGIN\n".len();
        let end = stdout.find("\nROOTS-END").expect("end marker");
        stdout[begin..end].to_string()
    }

    /// 20 fresh processes, each with a different symbol intern order (and std `HashMap` seeds,
    /// which order program variable declarations), produce the same root after every block.
    #[test]
    fn state_root_is_identical_across_20_processes() {
        let runs: Vec<String> = (0..20).map(child_roots).collect();
        assert_eq!(
            runs[0].lines().count(),
            SCENARIO.len() + RELATIONS.len(),
            "{}",
            runs[0]
        );
        for (i, run) in runs.iter().enumerate() {
            assert_eq!(run, &runs[0], "process {i} differs");
        }
    }

    /// Child half of the objdef genesis test: loads a 12-object objdef core in deterministic mode
    /// (genesis block) and prints the state root.
    #[test]
    #[ignore = "run as a subprocess by objdef_genesis_root_is_identical_across_processes"]
    fn objdef_genesis_child() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        deterministic::disable();
        deterministic::configure(&DeterministicMode::on());
        let dir = tempfile::tempdir().unwrap();
        let mut constants = String::new();
        for i in 0..12 {
            constants.push_str(&format!("define O{i} = #{i};\n"));
            let parent = if i == 0 {
                String::new()
            } else {
                "  parent: O0\n".to_string()
            };
            std::fs::write(
                dir.path().join(format!("o{i}.moo")),
                format!(
                    "object O{i}\n  name: \"object {i}\"\n{parent}  owner: O0\n  readable: true\n\n  \
                     property p{i}a (owner: O0, flags: \"rc\") = {i};\n  \
                     property p{i}b (owner: O0, flags: \"rc\") = \"{i}\";\n\n  \
                     verb \"v{i}\" (this none this) owner: O0 flags: \"rxd\"\n    return {i};\n  endverb\nendobject\n"
                ),
            )
            .unwrap();
        }
        std::fs::write(dir.path().join("constants.moo"), constants).unwrap();
        let (db, _) = TxDB::try_open(None, DatabaseConfig::default()).unwrap();
        let mut loader = db.loader_client().unwrap();
        moor_objdef::ObjectDefinitionLoader::new(loader.as_mut())
            .load_objdef_directory(Default::default(), dir.path(), Default::default())
            .expect("load");
        loader.commit().unwrap();
        let root = db.state_root().unwrap();
        deterministic::disable();
        println!("\nGENESIS {}", root.root_hex());
    }

    /// The objdef loader walks its objects in id order, so the derived verb and property ids (R8)
    /// and therefore the genesis root are the same in every process. It used to walk a `HashMap`.
    #[test]
    fn objdef_genesis_root_is_identical_across_processes() {
        let exe = std::env::current_exe().expect("test binary");
        let roots: Vec<String> = (0..5)
            .map(|_| {
                let output = std::process::Command::new(&exe)
                    .args([
                        "state_root::objdef_genesis_child",
                        "--exact",
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .output()
                    .expect("run child");
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let at = stdout.find("GENESIS ").expect("root line");
                stdout[at..].lines().next().unwrap_or_default().to_string()
            })
            .collect();
        assert!(roots.windows(2).all(|w| w[0] == w[1]), "{roots:#?}");
    }

    /// Root time against DB size (release build): genesis, then 1,000 and 10,000 created objects,
    /// each named, moved into a room and given a property value. Loads the objdef core in
    /// `RW_STATE_ROOT_CORE` (e.g. RuneWorld's stripped `core/`), or the minimal textdump if unset.
    /// Run: `cargo test --release -p moor-kernel --test deterministic-suite
    /// state_root::perf_state_root -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement, not a check"]
    fn perf_state_root() {
        let core = std::env::var("RW_STATE_ROOT_CORE").ok();
        let mut world = match &core {
            Some(dir) => {
                let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
                deterministic::disable();
                let mode = DeterministicMode::on();
                deterministic::configure(&mode);
                let (db, _) = TxDB::try_open(None, DatabaseConfig::default()).unwrap();
                {
                    let mut loader = db.loader_client().unwrap();
                    moor_objdef::ObjectDefinitionLoader::new(loader.as_mut())
                        .load_objdef_directory(
                            moor_compiler::CompileOptions {
                                custom_errors: true,
                                ..Default::default()
                            },
                            Path::new(dir),
                            Default::default(),
                        )
                        .expect("load core");
                    loader.commit().unwrap();
                }
                let scheduler = Scheduler::new(
                    semver::Version::new(0, 1, 0),
                    Box::new(db.clone()),
                    Box::new(NoopTasksDb {}),
                    Arc::new(Config {
                        deterministic: mode,
                        ..Config::default()
                    }),
                    Arc::new(NoopSystemControl::default()),
                    None,
                    None,
                );
                let driver = scheduler.start_block_driver(Arc::new(Factory)).unwrap();
                // The RuneWorld core's wizard is #2 (ArchWizard).
                let player = std::env::var("RW_STATE_ROOT_PLAYER")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .map_or(Obj::mk_id(2), Obj::mk_id);
                World {
                    driver: Some(driver),
                    db,
                    height: 0,
                    player,
                    _guard: guard,
                }
            }
            None => World::start(),
        };
        world.driver().set_state_root_at_end_block(false);
        let wizard = world.eval("return player;");
        println!(
            "core: {}, player {wizard:?}",
            core.as_deref().unwrap_or("minimal textdump")
        );
        world.eval(
            "add_property(#0, \"perf_room\", create(#1), {player, \"rw\"}); \
             add_property(#1, \"perf_v\", 0, {player, \"rw\"}); return 1;",
        );
        let measure = |world: &mut World, label: &str| {
            let mut times = Vec::new();
            let mut last = None;
            for _ in 0..5 {
                let started = std::time::Instant::now();
                let r = world.driver().state_root().unwrap();
                times.push(started.elapsed());
                last = Some(r);
            }
            times.sort();
            let r = last.unwrap();
            let entries: u64 = r.relations.iter().map(|d| d.entries).sum();
            let bytes: usize = RELATIONS
                .iter()
                .map(|n| world.driver().canonical_relation(n).unwrap().encode().len())
                .sum();
            println!(
                "{label:>14}: root median {:?} (min {:?}, max {:?}); {entries} entries, {bytes} canonical bytes",
                times[2], times[0], times[4]
            );
        };
        measure(&mut world, "genesis");
        let mut created = 0;
        for target in [1_000, 10_000] {
            while created < target {
                // 250 objects per input, each its own transaction-sized chunk.
                world.eval(
                    "for i in [1..250] o = create(#1); o.name = \"obj \" + tostr(i); \
                     move(o, #0.perf_room); o.perf_v = {i, \"v\"}; endfor return 1;",
                );
                created += 250;
            }
            measure(&mut world, &format!("+{created} objects"));
        }
    }

    // S0-12: object id allocation.

    fn id_features() -> moor_vm::FeaturesConfig {
        moor_vm::FeaturesConfig {
            use_uuobjids: true,
            anonymous_objects: true,
            ..Default::default()
        }
    }

    /// Creates numbered, "UUID" (type 2) and anonymous objects, recycles some, creates more, and
    /// returns what the program saw.
    const ID_SCENARIO: &[&[&str]] = &[
        &[
            "a = create(#1); b = create(#1, player, 2); c = create(#1, player, 1); \
             return {a, b, c, typeof(b), typeof(c)};",
            "r = {}; for i in [1..40] o = create(#1, player, i % 3); r = {@r, o}; endfor return r;",
        ],
        &[
            "x = create(#1); y = create(#1, player, 2); recycle(x); recycle(y); \
             z = create(#1); w = create(#1, player, 2); return {x, y, z, w};",
        ],
        &[
            "r = {}; for i in [1..60] o = create(#1, player, 0); recycle(o); endfor \
             return create(#1);",
        ],
    ];

    #[test]
    fn create_allocates_sequential_numbered_ids_for_type_zero_and_two() {
        let mut world = World::start_features(|| {}, id_features());
        let max = world.eval("return max_object();");
        let max = max.as_object().unwrap().id().0;
        let v = world.eval("return {create(#1), create(#1, player, 2), create(#1, player, 0)};");
        let ids: Vec<i32> = v
            .as_list()
            .unwrap()
            .iter_ref()
            .map(|o| o.as_object().unwrap().id().0)
            .collect();
        assert_eq!(ids, vec![max + 1, max + 2, max + 3]);
        let kinds = world.eval("o = create(#1, player, 2); return {is_uuobjid(o)};");
        assert_eq!(toliteral_of(&kinds), "{0}");
    }

    #[test]
    fn recycled_ids_are_never_reused_by_create() {
        let mut world = World::start_features(|| {}, id_features());
        let v = world.eval(
            "a = create(#1); recycle(a); b = create(#1); recycle(b); c = create(#1); \
             return {a, b, c};",
        );
        let ids: Vec<i32> = v
            .as_list()
            .unwrap()
            .iter_ref()
            .map(|o| o.as_object().unwrap().id().0)
            .collect();
        assert!(ids[0] < ids[1] && ids[1] < ids[2], "{ids:?}");
    }

    #[test]
    fn anonymous_ids_come_from_the_persisted_counter() {
        let mut world = World::start_features(|| {}, id_features());
        let v = world.eval(
            "a = create(#1, player, 1); b = create(#1, player, 1); \
             return {is_anonymous(a), is_anonymous(b), a != b};",
        );
        assert_eq!(toliteral_of(&v), "{1, 1, 1}");
        let r1 = world
            .driver()
            .canonical_relation("sequences")
            .unwrap()
            .encode();
        world.eval("a = create(#1, player, 1); return 1;");
        let r2 = world
            .driver()
            .canonical_relation("sequences")
            .unwrap()
            .encode();
        assert_ne!(r1, r2, "the anonymous counter is in the sequences relation");
    }

    fn toliteral_of(v: &Var) -> String {
        moor_compiler::to_literal(v)
    }

    #[test]
    fn numbered_and_anonymous_counters_are_in_the_sequences_relation_only() {
        let mut world = World::start_features(|| {}, id_features());
        let before = root(&world.block(&["return 1;"]));
        let after = root(&world.block(&["a = create(#1); b = create(#1, player, 1); return 1;"]));
        let c = changed(&before, &after);
        assert!(c.contains(&"sequences"), "{c:?}");
    }

    /// Child half: runs `ID_SCENARIO`, prints every returned id literal and the root per block.
    #[test]
    #[ignore = "run as a subprocess by object_ids_are_identical_across_20_processes"]
    fn object_ids_child() {
        let rotate: usize = std::env::var("RW_STATE_ROOT_INTERN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut world = World::start_features(
            || {
                let n = INTERN_POOL.len();
                for i in 0..n {
                    let _ = Symbol::mk(INTERN_POOL[(i + rotate) % n]);
                }
            },
            id_features(),
        );
        let mut lines = Vec::new();
        for block in ID_SCENARIO {
            let out = world.block(block);
            for o in &out.outcomes {
                if let Some(Ok(v)) = &o.result {
                    lines.push(format!("{} {}", out.block.height, toliteral_of(v)));
                }
            }
            lines.push(format!("{} {}", out.block.height, root(&out).root_hex()));
        }
        println!("IDS-BEGIN\n{}\nIDS-END", lines.join("\n"));
    }

    fn child_ids(rotate: usize) -> String {
        let exe = std::env::current_exe().expect("test binary");
        let output = std::process::Command::new(exe)
            .args([
                "state_root::object_ids_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RW_STATE_ROOT_INTERN", rotate.to_string())
            .output()
            .expect("run child");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let begin = stdout.find("IDS-BEGIN\n").expect("marker") + "IDS-BEGIN\n".len();
        let end = stdout.find("\nIDS-END").expect("end marker");
        stdout[begin..end].to_string()
    }

    #[test]
    fn object_ids_are_identical_across_20_processes() {
        let runs: Vec<String> = (0..20).map(child_ids).collect();
        assert!(runs[0].lines().count() >= 6, "{}", runs[0]);
        for (i, run) in runs.iter().enumerate() {
            assert_eq!(run, &runs[0], "process {i} differs");
        }
    }
}

// --- Sequencer block loop (S1-1) -------------------------------------------------------------

/// S1-1: the sequencer's block loop over the block driver (ADR 0006 decisions 1-2): context
/// computation, limits, sealing into `moor-block` blocks, publication and replay.
mod sequencer {
    use std::{
        path::Path,
        sync::{Arc, Mutex as StdMutex},
        time::{Duration, Instant},
    };

    use moor_block::{
        Block, ChainTip, CommandEntry, DaSink, EMPTY_ROOT, EventPolicy, FileSink, SealedBlock,
        Segment, SequencerInput, SequencerInputKind, SequencerKey, seed_for,
    };
    use moor_common::{
        deterministic,
        envelope::{Envelope, scope},
        tasks::{NoopClientSession, Session},
    };
    use moor_kernel::tasks::{
        block_events,
        envelope_admission::Admitted,
        sequencer::{
            NoHooks, ReplayMismatch, Sequencer, SequencerError, SequencerParams, replay_block,
        },
    };
    use moor_var::Obj;

    use super::admission::{GENESIS, command, delegate, delegation, key, wallet};
    use super::executor::{OrderSession, World};

    /// Wall-clock seconds of the first block (before the test delegations expire).
    const T0: u64 = 1_700_000_100;

    fn sequencer_key() -> SequencerKey {
        SequencerKey::from_secret(&[0x11; 32]).expect("valid secret")
    }

    fn noop() -> Arc<dyn Session> {
        Arc::new(NoopClientSession::new())
    }

    /// A world with the signed-world hooks loaded before genesis, and a sequencer at genesis.
    fn start(params: SequencerParams) -> (World, Sequencer) {
        let mut world = World::start();
        let out = world.block(0, &[GENESIS]);
        assert!(
            matches!(out.outcomes[0].result, Some(Ok(_))),
            "genesis failed: {:?}",
            out.outcomes[0].result
        );
        let driver = world.take_driver();
        let sequencer = Sequencer::genesis(driver, sequencer_key(), params, Box::new(NoHooks))
            .expect("genesis");
        (world, sequencer)
    }

    fn envelope(env: &Envelope) -> CommandEntry {
        CommandEntry::Envelope(env.encode())
    }

    fn disconnect(player: Obj) -> CommandEntry {
        CommandEntry::Sequencer(SequencerInput {
            kind: SequencerInputKind::Disconnected,
            player: player.id().0,
        })
    }

    /// Open a block at `wall`, run `entries`, seal it.
    fn block(seq: &mut Sequencer, wall: u64, entries: Vec<CommandEntry>) -> SealedBlock {
        seq.open_block(wall, Instant::now()).expect("open");
        for entry in entries {
            seq.submit(entry, noop(), None).expect("submit");
        }
        seq.seal().expect("seal").block
    }

    /// The fixed scenario: create a player, commands, an empty block, a disconnect and a
    /// rejected envelope. Returns the sealed blocks and the created player.
    fn scenario_with_player(seq: &mut Sequencer) -> (Vec<SealedBlock>, Obj) {
        seq.open_block(T0, Instant::now()).expect("open");
        let receipt = seq
            .submit(
                envelope(&delegate(
                    &wallet(1),
                    &key(1),
                    delegation(&key(1), 1, true, scope::PLAY),
                )),
                noop(),
                None,
            )
            .expect("submit");
        let Some(Ok(Admitted::Delegated { player, .. })) = receipt.admission else {
            panic!("create failed: {:?}", receipt.admission);
        };
        let mut sealed = vec![seq.seal().expect("seal").block];
        sealed.push(block(
            seq,
            T0 + 1,
            vec![
                envelope(&command(&key(1), player, 1, 1, "ping a")),
                envelope(&command(&key(1), player, 1, 2, "ping b")),
            ],
        ));
        sealed.push(block(seq, T0 + 1, vec![]));
        sealed.push(block(
            seq,
            T0 + 3,
            vec![
                disconnect(player),
                envelope(&command(&key(9), player, 1, 3, "ping forged")),
            ],
        ));
        (sealed, player)
    }

    fn scenario(seq: &mut Sequencer) -> Vec<SealedBlock> {
        scenario_with_player(seq).0
    }

    fn publish(dir: &Path, genesis_root: &[u8; 32], blocks: &[SealedBlock], per: usize) {
        let mut sink = FileSink::open(dir, EventPolicy::Require).expect("sink");
        let mut prev = ChainTip::genesis(genesis_root);
        for chunk in blocks.chunks(per) {
            let segment = Segment::from_sealed(prev, chunk, true).expect("segment");
            sink.publish(&segment).expect("publish");
            prev = segment.tip();
        }
    }

    /// Every file under the sink, name and bytes, in name order.
    fn sink_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut files: Vec<_> = std::fs::read_dir(dir.join("segments"))
            .expect("segments dir")
            .map(|e| e.expect("entry").path())
            .collect();
        files.push(dir.join("index"));
        files.sort();
        files
            .into_iter()
            .map(|p| {
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    std::fs::read(&p).expect("read"),
                )
            })
            .collect()
    }

    fn run_and_publish(dir: &Path) -> ([u8; 32], Vec<SealedBlock>) {
        let (_world, mut seq) = start(SequencerParams::default());
        let blocks = scenario(&mut seq);
        let genesis = *seq.genesis_root();
        publish(dir, &genesis, &blocks, 2);
        seq.shutdown().expect("shutdown");
        (genesis, blocks)
    }

    #[test]
    fn two_sequencers_fed_the_same_inputs_publish_byte_identical_segments() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        run_and_publish(a.path());
        run_and_publish(b.path());
        let (files_a, files_b) = (sink_files(a.path()), sink_files(b.path()));
        assert!(files_a.len() >= 3, "{:?}", files_a.iter().map(|f| &f.0));
        assert_eq!(files_a, files_b);
    }

    #[test]
    fn the_scenario_admits_rejects_and_disconnects_as_logged() {
        let (_world, mut seq) = start(SequencerParams::default());
        let blocks = scenario(&mut seq);
        // Block 4: the disconnect ran disfunc, the forged command was rejected (an event, no task).
        let last = &blocks[3];
        let kinds: Vec<u8> = last.events.entries().iter().map(|e| e.event[1]).collect();
        assert_eq!(
            kinds,
            vec![
                block_events::event_tag::NARRATIVE as u8,
                block_events::event_tag::METER as u8,
                block_events::event_tag::REJECTED as u8,
                block_events::event_tag::METER as u8
            ]
        );
        seq.shutdown().unwrap();
    }

    #[test]
    fn the_seed_follows_the_previous_state_root() {
        let (_world, mut seq) = start(SequencerParams::default());
        let genesis = *seq.genesis_root();
        let blocks = scenario(&mut seq);
        let mut expected = vec![seed_for(&genesis, 1)];
        for (i, b) in blocks.iter().enumerate().take(blocks.len() - 1) {
            expected.push(seed_for(&b.header.header.state_root, i as u64 + 2));
        }
        let seeds: Vec<_> = blocks.iter().map(|b| b.header.header.seed).collect();
        assert_eq!(seeds, expected);
        seq.shutdown().unwrap();
    }

    #[test]
    fn the_open_block_context_carries_height_timestamp_and_seed() {
        let (_world, mut seq) = start(SequencerParams::default());
        let genesis = *seq.genesis_root();
        let ctx = seq.open_block(T0, Instant::now()).unwrap();
        assert_eq!(
            (ctx.height, ctx.timestamp, ctx.seed),
            (1, T0, seed_for(&genesis, 1))
        );
        seq.seal().unwrap();
        seq.shutdown().unwrap();
    }

    #[test]
    fn a_clock_slightly_behind_keeps_the_previous_timestamp() {
        let (_world, mut seq) = start(SequencerParams::default());
        block(&mut seq, T0 + 5, vec![]);
        let ctx = seq.open_block(T0 + 4, Instant::now()).unwrap();
        assert_eq!(ctx.timestamp, T0 + 5);
        seq.seal().unwrap();
        seq.shutdown().unwrap();
    }

    #[test]
    fn a_clock_more_than_two_seconds_behind_is_refused() {
        let (_world, mut seq) = start(SequencerParams::default());
        block(&mut seq, T0 + 5, vec![]);
        let refused = seq.open_block(T0 + 2, Instant::now());
        assert!(
            matches!(refused, Err(SequencerError::ClockBehind { .. })),
            "{refused:?}"
        );
        seq.shutdown().unwrap();
    }

    #[test]
    fn a_clock_jump_of_more_than_sixty_seconds_is_refused() {
        let (_world, mut seq) = start(SequencerParams::default());
        let opened = Instant::now();
        seq.open_block(T0, opened).unwrap();
        seq.seal().unwrap();
        let refused = seq.open_block(T0 + 120, opened + Duration::from_secs(1));
        assert!(
            matches!(refused, Err(SequencerError::ClockJumped { .. })),
            "{refused:?}"
        );
        seq.shutdown().unwrap();
    }

    #[test]
    fn timestamps_never_decrease_across_blocks() {
        let (_world, mut seq) = start(SequencerParams::default());
        let walls = [T0, T0 + 2, T0 + 1, T0 + 1, T0 + 3];
        let stamps: Vec<u64> = walls
            .iter()
            .map(|w| block(&mut seq, *w, vec![]).header.header.timestamp)
            .collect();
        assert_eq!(stamps, vec![T0, T0 + 2, T0 + 2, T0 + 2, T0 + 3]);
        seq.shutdown().unwrap();
    }

    #[test]
    fn an_input_over_the_count_limit_waits_for_the_next_block() {
        let (_world, mut seq) = start(SequencerParams {
            max_inputs: 2,
            ..SequencerParams::default()
        });
        seq.open_block(T0, Instant::now()).unwrap();
        for player in [10, 11] {
            seq.submit(disconnect(Obj::mk_id(player)), noop(), None)
                .unwrap();
        }
        let third = disconnect(Obj::mk_id(12));
        let refused = seq.submit(third.clone(), noop(), None);
        assert!(
            matches!(refused, Err(SequencerError::BlockFull)),
            "{refused:?}"
        );
        assert_eq!(seq.seal().unwrap().block.commands.len(), 2);
        seq.open_block(T0 + 1, Instant::now()).unwrap();
        let receipt = seq.submit(third, noop(), None).unwrap();
        assert_eq!((receipt.height, receipt.command_index), (2, 1));
        seq.seal().unwrap();
        seq.shutdown().unwrap();
    }

    /// Read through the sequencer's scheduler, the way an RPC thread does, while a block is open.
    fn read_during_block(seq: &Sequencer) {
        use moor_kernel::{
            SchedulerClient,
            tasks::world_state_action::{WorldStateAction, WorldStateResult},
        };
        let client = SchedulerClient::new(seq.driver().scheduler().clone());
        assert!(client.is_sequencer_owned());
        let player = Obj::mk_id(3);
        let results = client
            .read_world_state_batch(vec![
                WorldStateAction::GetObjectFlags { obj: player },
                WorldStateAction::ListObjects { player },
                WorldStateAction::RequestAllObjects { player },
            ])
            .expect("reads are answered in sequencer mode");
        assert!(matches!(
            results[..],
            [
                WorldStateResult::ObjectFlags(_),
                WorldStateResult::ObjectsList(_),
                WorldStateResult::AllObjects(_)
            ]
        ));
    }

    /// One block of two inputs with a read between them (or none): the sealed block, and the
    /// command index and state root observed across the read.
    fn block_with_reads(reads: bool) -> (SealedBlock, [u64; 2]) {
        let (_world, mut seq) = start(SequencerParams::default());
        seq.open_block(T0, Instant::now()).expect("open");
        let first = seq
            .submit(disconnect(Obj::mk_id(10)), noop(), None)
            .expect("first");
        let before = (
            deterministic::current().map(|c| c.command),
            seq.driver().state_root().expect("root").root,
        );
        if reads {
            read_during_block(&seq);
        }
        let after = (
            deterministic::current().map(|c| c.command),
            seq.driver().state_root().expect("root").root,
        );
        assert_eq!(
            before, after,
            "a read moved the command index or the state root"
        );
        let second = seq
            .submit(disconnect(Obj::mk_id(11)), noop(), None)
            .expect("second");
        let sealed = seq.seal().expect("seal").block;
        seq.shutdown().expect("shutdown");
        (sealed, [first.command_index, second.command_index])
    }

    #[test]
    fn a_read_during_a_block_takes_no_command_index() {
        let (_, indices) = block_with_reads(true);
        assert_eq!(indices, [1, 2]);
    }

    #[test]
    fn a_read_during_a_block_leaves_the_sealed_block_unchanged() {
        let (with, _) = block_with_reads(true);
        let (without, _) = block_with_reads(false);
        assert_eq!(
            (
                with.header.header.state_root,
                with.header.header.commands_root,
                with.header.header.events_root
            ),
            (
                without.header.header.state_root,
                without.header.header.commands_root,
                without.header.header.events_root
            )
        );
    }

    #[test]
    fn a_write_through_the_read_path_is_refused_while_a_sequencer_owns_the_scheduler() {
        use moor_kernel::{SchedulerClient, tasks::world_state_action::WorldStateAction};
        let (_world, seq) = start(SequencerParams::default());
        let client = SchedulerClient::new(seq.driver().scheduler().clone());
        let write = WorldStateAction::UpdateProperty {
            player: Obj::mk_id(3),
            authority_principal: Obj::mk_id(3),
            obj: moor_common::model::ObjectRef::Id(Obj::mk_id(0)),
            property: moor_var::Symbol::mk("x"),
            value: moor_var::v_int(1),
        };
        assert!(client.read_world_state_batch(vec![write]).is_err());
        seq.shutdown().unwrap();
    }

    #[test]
    fn an_input_over_the_byte_limit_does_not_fit() {
        // One 80-byte envelope entry is 84 bytes encoded; two plus the array head exceed 160.
        let (_world, mut seq) = start(SequencerParams {
            max_batch_bytes: 160,
            ..SequencerParams::default()
        });
        seq.open_block(T0, Instant::now()).unwrap();
        let entry = envelope(&command(&key(1), Obj::mk_id(3), 1, 1, "go west"));
        assert_eq!(entry.encode().len(), 84);
        seq.submit(entry.clone(), noop(), None).unwrap();
        assert!(!seq.fits(&entry));
        seq.seal().unwrap();
        seq.shutdown().unwrap();
    }

    #[test]
    fn an_empty_block_has_empty_roots_and_the_previous_state_root() {
        let (_world, mut seq) = start(SequencerParams::default());
        let genesis = *seq.genesis_root();
        let b = block(&mut seq, T0, vec![]);
        let h = b.header.header;
        assert_eq!(
            (h.commands_root, h.events_root, h.state_root),
            (EMPTY_ROOT, EMPTY_ROOT, genesis)
        );
        seq.shutdown().unwrap();
    }

    #[test]
    fn events_are_tagged_with_their_inputs_command_index() {
        let (_world, mut seq) = start(SequencerParams::default());
        let blocks = scenario(&mut seq);
        let tags: Vec<(u64, u64)> = blocks[1]
            .events
            .entries()
            .iter()
            .map(|e| (e.seq, e.command_index))
            .collect();
        // Each input's events are followed by its meter entry.
        assert_eq!(tags, vec![(0, 1), (1, 1), (2, 2), (3, 2)]);
        seq.shutdown().unwrap();
    }

    #[test]
    fn events_reach_the_session_before_the_seal() {
        let (_world, mut seq) = start(SequencerParams::default());
        let (_, player) = scenario_with_player(&mut seq);
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let session: Arc<dyn Session> = Arc::new(OrderSession::new(seen.clone()));
        seq.open_block(T0 + 4, Instant::now()).unwrap();
        let receipt = seq
            .submit(
                envelope(&command(&key(1), player, 1, 9, "ping soft")),
                session,
                None,
            )
            .unwrap();
        let before_seal = seen.lock().unwrap().clone();
        seq.seal().unwrap();
        assert_eq!(
            (before_seal, receipt.events, receipt.command_index),
            (vec!["\"pong soft\"".to_string()], 2, 1)
        );
        seq.shutdown().unwrap();
    }

    #[test]
    fn the_rejected_envelope_still_lands_in_the_command_batch() {
        let (_world, mut seq) = start(SequencerParams::default());
        let blocks = scenario(&mut seq);
        assert_eq!(blocks[3].commands.len(), 2);
        seq.shutdown().unwrap();
    }

    /// Replay published blocks on a fresh world from the same genesis.
    fn replay(blocks: &[Block], events: &[moor_block::EventBatch]) -> Result<(), ReplayMismatch> {
        let mut world = World::start();
        let out = world.block(0, &[GENESIS]);
        assert!(matches!(out.outcomes[0].result, Some(Ok(_))));
        let mut driver = world.take_driver();
        let genesis = driver.state_root().expect("root").root;
        let mut prev = ChainTip::genesis(&genesis);
        let result = blocks.iter().zip(events).try_for_each(|(block, batch)| {
            replay_block(&mut driver, &prev, block, Some(batch))?;
            prev = ChainTip::of(&block.header);
            Ok(())
        });
        driver.shutdown().ok();
        result
    }

    fn published(blocks: &[SealedBlock]) -> (Vec<Block>, Vec<moor_block::EventBatch>) {
        (
            blocks
                .iter()
                .map(|b| Block {
                    header: b.header.header,
                    commands: b.commands.clone(),
                })
                .collect(),
            blocks.iter().map(|b| b.events.clone()).collect(),
        )
    }

    #[test]
    fn a_replay_from_genesis_matches_every_root() {
        let (_world, mut seq) = start(SequencerParams::default());
        let sealed = scenario(&mut seq);
        seq.shutdown().unwrap();
        drop(_world);
        let (blocks, events) = published(&sealed);
        assert_eq!(replay(&blocks, &events), Ok(()));
    }

    #[test]
    fn a_replay_detects_a_falsified_state_root() {
        let (_world, mut seq) = start(SequencerParams::default());
        let sealed = scenario(&mut seq);
        seq.shutdown().unwrap();
        drop(_world);
        let (mut blocks, events) = published(&sealed);
        blocks[1].header.state_root[0] ^= 1;
        assert_eq!(
            replay(&blocks, &events),
            Err(ReplayMismatch::StateRoot {
                height: 2,
                relation: None
            })
        );
    }

    #[test]
    fn a_replay_names_the_first_differing_event() {
        let (_world, mut seq) = start(SequencerParams::default());
        let sealed = scenario(&mut seq);
        seq.shutdown().unwrap();
        drop(_world);
        let (mut blocks, mut events) = published(&sealed);
        // Claim a different second event in block 2 and an events_root to match the claim.
        let mut entries = events[1].entries().to_vec();
        entries[1].event[3] ^= 1;
        events[1] = moor_block::EventBatch::new(entries).unwrap();
        blocks[1].header.events_root = events[1].root();
        assert_eq!(
            replay(&blocks, &events),
            Err(ReplayMismatch::EventsRoot {
                height: 2,
                seq: Some(1)
            })
        );
    }

    #[test]
    fn the_delegation_input_creates_the_player_in_block_one() {
        let (_world, mut seq) = start(SequencerParams::default());
        seq.open_block(T0, Instant::now()).unwrap();
        let receipt = seq
            .submit(
                envelope(&delegate(
                    &wallet(1),
                    &key(1),
                    delegation(&key(1), 1, true, scope::PLAY),
                )),
                noop(),
                None,
            )
            .unwrap();
        assert!(
            matches!(
                receipt.admission,
                Some(Ok(Admitted::Delegated { created: true, .. }))
            ),
            "{:?}",
            receipt.admission
        );
        seq.seal().unwrap();
        seq.shutdown().unwrap();
    }
}

// --- Journal, seal persistence, signing guard and crash recovery (S1-2) ---------------------

/// S1-2: ADR 0006 decision 4. The kill tests run the sequencer in child processes of this test
/// binary (`durability::kill_child`) on an on-disk database, kill them with `kill -9` at each
/// phase of a block, restart them, and compare the recovered chain with an uninterrupted run byte
/// for byte (FileSink segments and index, block store, signing guard), and the events hosts saw
/// with the events the chain records.
#[cfg(unix)]
mod durability {
    use std::{
        collections::BTreeMap,
        fs,
        io::Write as _,
        os::unix::process::ExitStatusExt as _,
        path::{Path, PathBuf},
        process::Command,
        sync::{
            Arc, Mutex as StdMutex,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };

    use moor_block::{
        ChainTip, CommandEntry, DaSink, EventPolicy, FileSink, SealedBlock, Segment, SequencerKey,
        durable::{BlockStore, Journal, SigningGuard, StoreChain},
        hex,
    };
    use moor_common::{
        deterministic::{self, DeterministicMode},
        envelope::scope,
        tasks::{NarrativeEvent, NoopClientSession, NoopSystemControl, Session, SessionError},
    };
    use moor_db::{Database, DatabaseConfig, TxDB, state_root::checkpoint::CheckpointDir};
    use moor_kernel::{
        config::Config,
        tasks::{
            NoopTasksDb,
            block_driver::{BlockDriver, BlockEventKind, BlockInput},
            block_events,
            scheduler::Scheduler,
            sequencer::{CheckpointPolicy, SequencerError, SequencerParams},
            sequencer_recovery::{
                DurableHooks, DurableParts, FaultHook, FaultPoint, FsyncLog, RecoveryError,
                database_resumable, resume, usable_checkpoint,
            },
        },
    };
    use moor_var::{Obj, Var, v_int};

    use super::LOCK;
    use super::admission::{GENESIS, command, delegate, delegation, key, wallet};
    use super::executor::{Factory, block as genesis_context};

    const WIZARD: Obj = Obj::mk_id(3);
    const T0: u64 = 1_700_000_100;
    /// Blocks per run; the last takes whatever inputs are left.
    const BLOCKS: u64 = 8;
    /// Planned inputs per block (the script has 11).
    const PLANNED: [usize; 8] = [1, 2, 0, 3, 1, 0, 2, 2];
    /// The player the delegation creates (deterministic object ids).
    const PLAYER_ENV: &str = "RW_KILL_PLAYER";

    /// A verb whose input commits twice (its `fork (0)` child is a second task), so a kill
    /// between the commits leaves hosts with half of the input's events.
    const CHAT: &str = r#"
        add_verb(#0.wallet_parent, {player, "rxd", "chat"}, {"any", "any", "any"});
        set_verb_code(#0.wallet_parent, "chat", {"notify(player, \"a \" + argstr);", "fork (0)", "notify(player, \"b \" + argstr);", "endfork"});
        return 1;
    "#;

    fn sequencer_key() -> SequencerKey {
        SequencerKey::from_secret(&[0x11; 32]).expect("valid secret")
    }

    fn noop() -> Arc<dyn Session> {
        Arc::new(NoopClientSession::new())
    }

    /// The fixed input script: a delegation creating the player, then ten commands.
    fn script(player: Obj) -> Vec<CommandEntry> {
        let mut entries = vec![CommandEntry::Envelope(
            delegate(
                &wallet(1),
                &key(1),
                delegation(&key(1), 1, true, scope::PLAY),
            )
            .encode(),
        )];
        let texts = [
            "ping one",
            "chat two",
            "ping three",
            "chat four",
            "ping five",
            "chat six",
            "ping seven",
            "chat eight",
            "ping nine",
            "chat ten",
        ];
        for (i, text) in texts.iter().enumerate() {
            entries.push(CommandEntry::Envelope(
                command(&key(1), player, 1, i as u32 + 1, text).encode(),
            ));
        }
        entries
    }

    fn open_db(dir: &Path) -> (TxDB, bool) {
        TxDB::try_open(Some(dir), DatabaseConfig::default()).expect("open database")
    }

    /// How recovery step 1 left the database.
    struct Prepared {
        db: TxDB,
        /// Empty: the genesis is built on it.
        fresh: bool,
        /// The previous database was discarded.
        rebuilt: bool,
        /// Restored from the checkpoint at this height.
        checkpoint: Option<u64>,
    }

    /// Recovery step 1: keep the database only if its root is a sealed block's (or the stored
    /// unsigned block's); otherwise rebuild it from the newest usable checkpoint in `checkpoints`,
    /// or at genesis.
    fn prepare_db(dir: &Path, store: &BlockStore, checkpoints: Option<&CheckpointDir>) -> Prepared {
        let (db, fresh) = open_db(dir);
        if store.chain().is_none() {
            return Prepared {
                db,
                fresh,
                rebuilt: false,
                checkpoint: None,
            };
        }
        let mut rebuilt = false;
        let db = if fresh {
            db
        } else {
            let root = db.state_root().expect("state root").root;
            if database_resumable(store, &root) {
                return Prepared {
                    db,
                    fresh: false,
                    rebuilt: false,
                    checkpoint: None,
                };
            }
            drop(db);
            fs::remove_dir_all(dir).expect("remove database");
            rebuilt = true;
            let (db, fresh) = open_db(dir);
            assert!(fresh, "a removed database reopens fresh");
            db
        };
        if let Some(stored) = checkpoints.and_then(|cps| usable_checkpoint(cps, store)) {
            let checkpoint = stored.checkpoint().expect("verified checkpoint");
            let root = db
                .import_checkpoint(&checkpoint)
                .expect("restore checkpoint");
            assert_eq!(root.root, stored.header.state_root);
            return Prepared {
                db,
                fresh: false,
                rebuilt,
                checkpoint: Some(stored.header.height),
            };
        }
        Prepared {
            db,
            fresh: true,
            rebuilt,
            checkpoint: None,
        }
    }

    /// A deterministic scheduler under a block driver; at genesis (`fresh`) the textdump, the
    /// signed-world hooks and `chat` are loaded as block 0.
    fn start_driver(db: TxDB, fresh: bool) -> BlockDriver {
        if fresh {
            crate::common::load_textdump(&db);
        }
        let mode = DeterministicMode::on();
        let scheduler = Scheduler::new(
            semver::Version::new(0, 1, 0),
            Box::new(db),
            Box::new(NoopTasksDb {}),
            Arc::new(Config {
                deterministic: mode,
                ..Config::default()
            }),
            Arc::new(NoopSystemControl::default()),
            None,
            None,
        );
        let mut driver = scheduler
            .start_block_driver(Arc::new(Factory))
            .expect("start block driver");
        if fresh {
            let inputs = [GENESIS, CHAT]
                .iter()
                .map(|code| {
                    (
                        BlockInput::Eval {
                            player: WIZARD,
                            code: (*code).to_string(),
                        },
                        noop(),
                    )
                })
                .collect();
            let out = driver.run_block(genesis_context(0), inputs);
            for outcome in &out.outcomes {
                assert!(
                    matches!(outcome.result, Some(Ok(_))),
                    "genesis failed: {:?}",
                    outcome.result
                );
            }
        }
        driver
    }

    fn kill_now() -> ! {
        let _ = Command::new("kill")
            .args(["-9", &std::process::id().to_string()])
            .status();
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// Where a child kills itself.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Crash {
        /// After the first commit of input `index` of block `height` reached its host.
        MidInput { height: u64, index: u64 },
        /// At a durability fault point.
        Fault(FaultPoint),
        /// At a durability fault point, after giving the database a second to persist.
        Settled(FaultPoint),
        /// After the segment ending at `height` is published.
        Published { height: u64 },
    }

    fn parse_crash(spec: &str) -> Option<Crash> {
        if let Some(rest) = spec.strip_prefix("settled-") {
            return match parse_crash(rest)? {
                Crash::Fault(point) => Some(Crash::Settled(point)),
                other => panic!("only fault points settle: {other:?}"),
            };
        }
        let parts: Vec<&str> = spec.split(':').collect();
        let n = |i: usize| -> u64 { parts[i].parse().expect("crash spec number") };
        Some(match parts.first().copied()? {
            "" => return None,
            "mid" => Crash::MidInput {
                height: n(1),
                index: n(2),
            },
            "opened" => Crash::Fault(FaultPoint::Opened { height: n(1) }),
            "journal" => Crash::Fault(FaultPoint::InputsJournalled {
                height: n(1),
                last_index: n(2),
            }),
            "unsigned" => Crash::Fault(FaultPoint::UnsignedStored { height: n(1) }),
            "guard" => Crash::Fault(FaultPoint::GuardRecorded { height: n(1) }),
            "signed" => Crash::Fault(FaultPoint::SignatureStored { height: n(1) }),
            "published" => Crash::Published { height: n(1) },
            other => panic!("unknown crash spec {other}"),
        })
    }

    /// A host connection: committed narrative events are appended to the `seen` file as
    /// `height index recipient hex(event)`, the bytes the event batch holds for them.
    struct Recorder {
        seen: Arc<StdMutex<fs::File>>,
        height: u64,
        index: u64,
        buf: StdMutex<Vec<(Obj, Box<NarrativeEvent>)>>,
        /// Kill the process right after the next commit that delivers events.
        armed: Arc<AtomicBool>,
    }

    impl Session for Recorder {
        fn commit(&self) -> Result<(), SessionError> {
            let events = std::mem::take(&mut *self.buf.lock().unwrap());
            if events.is_empty() {
                return Ok(());
            }
            let mut out = self.seen.lock().unwrap();
            for (player, event) in events {
                let bytes = block_events::encode_event(&BlockEventKind::Narrative(event))
                    .expect("encode event");
                writeln!(
                    out,
                    "{} {} {} {}",
                    self.height,
                    self.index,
                    player.id().0,
                    hex(&bytes)
                )
                .expect("write seen");
            }
            out.flush().expect("flush seen");
            if self.armed.swap(false, Ordering::AcqRel) {
                kill_now();
            }
            Ok(())
        }
        fn rollback(&self) -> Result<(), SessionError> {
            self.buf.lock().unwrap().clear();
            Ok(())
        }
        fn fork(self: Arc<Self>) -> Result<Arc<dyn Session>, SessionError> {
            Ok(Arc::new(Recorder {
                seen: self.seen.clone(),
                height: self.height,
                index: self.index,
                buf: StdMutex::new(vec![]),
                armed: self.armed.clone(),
            }))
        }
        fn request_input(
            &self,
            _: Obj,
            _: uuid::Uuid,
            _: Option<Vec<(moor_var::Symbol, Var)>>,
        ) -> Result<(), SessionError> {
            Err(SessionError::DeliveryError)
        }
        fn send_event(&self, player: Obj, event: Box<NarrativeEvent>) -> Result<(), SessionError> {
            self.buf.lock().unwrap().push((player, event));
            Ok(())
        }
        fn log_event(&self, _: Obj, _: Box<NarrativeEvent>) -> Result<(), SessionError> {
            Ok(())
        }
        fn send_system_msg(&self, _: Obj, _: &str) -> Result<(), SessionError> {
            Ok(())
        }
        fn notify_shutdown(&self, _: Option<String>) -> Result<(), SessionError> {
            Ok(())
        }
        fn connection_name(&self, _: Obj) -> Result<String, SessionError> {
            Ok(String::new())
        }
        fn disconnect(&self, _: Obj) -> Result<(), SessionError> {
            Ok(())
        }
        fn connected_players(&self, _: bool) -> Result<Vec<Obj>, SessionError> {
            Ok(vec![])
        }
        fn connected_seconds(&self, _: Obj) -> Result<f64, SessionError> {
            Ok(0.0)
        }
        fn idle_seconds(&self, _: Obj) -> Result<f64, SessionError> {
            Ok(0.0)
        }
        fn connections(&self, _: Option<Obj>) -> Result<Vec<Obj>, SessionError> {
            Ok(vec![])
        }
        fn connection_details(
            &self,
            _: Option<Obj>,
        ) -> Result<Vec<moor_common::tasks::ConnectionDetails>, SessionError> {
            Ok(vec![])
        }
        fn connection_attributes(&self, _: Obj) -> Result<Var, SessionError> {
            Ok(v_int(0))
        }
        fn set_connection_attribute(
            &self,
            _: Obj,
            _: moor_var::Symbol,
            _: Var,
        ) -> Result<(), SessionError> {
            Ok(())
        }
    }

    fn append_line(path: &Path, line: &str) {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open");
        writeln!(f, "{line}").expect("append");
    }

    /// Publish complete pairs of blocks (heights `2k-1, 2k`) as segments; with `flush`, the rest.
    fn publish(
        sink: &mut FileSink,
        genesis: &ChainTip,
        pending: &mut Vec<SealedBlock>,
        flush: bool,
        crash: Option<Crash>,
    ) {
        while pending.len() >= 2 || (flush && !pending.is_empty()) {
            let n = pending.len().min(2);
            let chunk: Vec<SealedBlock> = pending.drain(..n).collect();
            let prev = sink.tip().unwrap_or(*genesis);
            let segment = Segment::from_sealed(prev, &chunk, true).expect("segment");
            sink.publish(&segment).expect("publish");
            if crash
                == Some(Crash::Published {
                    height: segment.tip_height(),
                })
            {
                kill_now();
            }
        }
    }

    /// One sequencer process: recover from whatever `dir` holds, then run the script to
    /// `BLOCKS` blocks under `schedule`. Kills itself at `crash`. With `checkpoint_every > 0` it
    /// writes a checkpoint after every such seal and recovers from the newest usable one.
    fn run_child(
        dir: &Path,
        schedule: &[usize],
        crash: Option<Crash>,
        group: bool,
        player: Obj,
        checkpoint_every: u64,
    ) {
        let state = dir.join("state");
        let mut store = BlockStore::open(state.join("blocks")).expect("block store");
        let (journal, open) = Journal::open(state.join("journal")).expect("journal");
        let checkpoints = (checkpoint_every > 0)
            .then(|| CheckpointDir::open(state.join("checkpoints")).expect("checkpoint dir"));
        let Prepared {
            db,
            fresh,
            rebuilt,
            checkpoint,
        } = prepare_db(&dir.join("db"), &store, checkpoints.as_ref());
        let driver = start_driver(db, fresh);
        let key = sequencer_key();
        if store.chain().is_none() {
            let root = driver.state_root().expect("root").root;
            store
                .init_chain(StoreChain {
                    genesis_root: root,
                    sequencer: key.address(),
                })
                .expect("init chain");
        }
        let chain = store.chain().expect("chain");
        if fresh {
            assert_eq!(
                driver.state_root().expect("root").root,
                chain.genesis_root,
                "a rebuilt database is at genesis"
            );
        }
        let guard =
            SigningGuard::open(state.join("sequencer.guard"), chain).expect("signing guard");
        let genesis = ChainTip::genesis(&chain.genesis_root);
        let mut sink = FileSink::open(dir.join("sink"), EventPolicy::Require).expect("sink");
        let sealed = store.sealed_height();
        let published = sink.published_tip().expect("tip");
        let mut pending: Vec<SealedBlock> = (published + 1..=sealed)
            .map(|h| store.sealed_block(h).expect("stored block"))
            .collect();
        let mut consumed: usize = (1..=sealed)
            .map(|h| store.read(h).expect("stored block").commands.len())
            .sum();
        let fault: Option<FaultHook> = match crash {
            Some(Crash::Fault(at)) => Some(Box::new(move |point| {
                if point == at {
                    kill_now();
                }
            })),
            Some(Crash::Settled(at)) => Some(Box::new(move |point| {
                if point == at {
                    std::thread::sleep(Duration::from_secs(1));
                    kill_now();
                }
            })),
            _ => None,
        };
        let parts = DurableParts {
            journal,
            open,
            store,
            guard,
        };
        let (mut seq, recovery) = resume(
            driver,
            key,
            SequencerParams::default(),
            parts,
            Arc::new(FsyncLog::default()),
            fault,
        )
        .unwrap_or_else(|e| panic!("recovery failed: {e}"));
        if let Some(dir) = checkpoints {
            seq.set_checkpoints(Some(CheckpointPolicy {
                every: checkpoint_every,
                keep: 2,
                publish_every: 0,
                ..CheckpointPolicy::new(dir, "test")
            }));
        }
        let notices = dir.join("notices");
        let notice = |n: &moor_kernel::tasks::sequencer::SealNotice| {
            append_line(
                &notices,
                &format!(
                    "{} {} {}",
                    n.height,
                    hex(&n.header_hash),
                    hex(&n.state_root)
                ),
            );
        };
        if let Some(resealed) = &recovery.resealed {
            consumed += resealed.block.commands.len();
            pending.push(resealed.block.clone());
        }
        // After a restart the tip's seal notice is sent again: a crash between storing the
        // signature and sending the notice would otherwise leave hosts without it.
        let tip = *seq.tip();
        if tip.height > 0 {
            notice(&moor_kernel::tasks::sequencer::SealNotice {
                height: tip.height,
                header_hash: tip.hash,
                state_root: tip.state_root,
            });
        }
        println!(
            "RECOVERY rebuilt={rebuilt} checkpoint={checkpoint:?} base={} replayed={} {:?} \
             resealed={:?} tip={}",
            recovery.base,
            recovery.replayed,
            recovery.interrupted,
            recovery.resealed.as_ref().map(|s| s.notice.height),
            tip.height
        );
        publish(
            &mut sink,
            &genesis,
            &mut pending,
            tip.height >= BLOCKS,
            crash,
        );
        let script = script(player);
        let seen = Arc::new(StdMutex::new(
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("seen"))
                .expect("seen"),
        ));
        for height in tip.height + 1..=BLOCKS {
            let left = script.len() - consumed;
            let want = if height == BLOCKS {
                left
            } else {
                schedule[height as usize - 1].min(left)
            };
            seq.open_block(T0 + height, Instant::now()).expect("open");
            let entries = &script[consumed..consumed + want];
            if group {
                assert_eq!(seq.journal_inputs(entries).expect("journal"), want);
            }
            for (i, entry) in entries.iter().enumerate() {
                let index = i as u64 + 1;
                if !group {
                    assert_eq!(
                        seq.journal_inputs(std::slice::from_ref(entry))
                            .expect("journal"),
                        1
                    );
                }
                let armed = crash == Some(Crash::MidInput { height, index });
                let session = Arc::new(Recorder {
                    seen: seen.clone(),
                    height,
                    index,
                    buf: StdMutex::new(vec![]),
                    armed: Arc::new(AtomicBool::new(armed)),
                });
                let receipt = seq.submit(entry.clone(), session, None).expect("submit");
                if consumed + i == 0 {
                    println!("PLAYER {:?}", receipt.admission);
                }
            }
            consumed += want;
            let sealed = seq.seal().expect("seal");
            notice(&sealed.notice);
            pending.push(sealed.block);
            publish(&mut sink, &genesis, &mut pending, height == BLOCKS, crash);
        }
        seq.shutdown().expect("shutdown");
    }

    /// Child process entry; does nothing unless run by a kill test.
    #[test]
    #[ignore = "child process of the S1-2 kill tests"]
    fn kill_child() {
        let Ok(dir) = std::env::var("RW_KILL_DIR") else {
            return;
        };
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        deterministic::disable();
        deterministic::configure(&DeterministicMode::on());
        let schedule: Vec<usize> = std::env::var("RW_KILL_SCHEDULE")
            .expect("schedule")
            .split(',')
            .map(|n| n.parse().expect("schedule number"))
            .collect();
        let crash = parse_crash(&std::env::var("RW_KILL_AT").unwrap_or_default());
        let group = std::env::var("RW_KILL_GROUP").is_ok_and(|v| v == "1");
        let player = Obj::mk_id(
            std::env::var(PLAYER_ENV)
                .expect("player")
                .parse()
                .expect("player number"),
        );
        let checkpoint_every = std::env::var(CHECKPOINT_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        run_child(
            Path::new(&dir),
            &schedule,
            crash,
            group,
            player,
            checkpoint_every,
        );
    }

    /// Checkpoint cadence for a child (blocks; unset or 0 = no checkpoints).
    const CHECKPOINT_ENV: &str = "RW_KILL_CHECKPOINTS";

    /// The object number the script's delegation creates. Fixed by deterministic ids.
    const PLAYER: i32 = 7;

    struct Run {
        killed: bool,
        stdout: String,
    }

    fn run(dir: &Path, schedule: &[usize], crash: &str, group: bool, checkpoints: u64) -> Run {
        let schedule = schedule
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let out = Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "durability::kill_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RW_KILL_DIR", dir)
            .env("RW_KILL_SCHEDULE", schedule)
            .env("RW_KILL_AT", crash)
            .env("RW_KILL_GROUP", if group { "1" } else { "0" })
            .env(PLAYER_ENV, PLAYER.to_string())
            .env(CHECKPOINT_ENV, checkpoints.to_string())
            .output()
            .expect("run child");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        let killed = out.status.signal() == Some(9);
        assert!(
            killed || out.status.success(),
            "child failed ({:?}, crash {crash:?}):\n{stdout}",
            out.status
        );
        Run { killed, stdout }
    }

    /// Chain artifacts compared byte for byte: FileSink segments and index, block store, guard.
    fn artifacts(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut paths: Vec<PathBuf> = fs::read_dir(dir.join("sink/segments"))
            .expect("segments")
            .map(|e| e.expect("entry").path())
            .collect();
        paths.sort();
        paths.push(dir.join("sink/index"));
        paths.push(dir.join("state/blocks/blocks.rwb"));
        paths.push(dir.join("state/sequencer.guard"));
        paths
            .into_iter()
            .map(|p| {
                let name = p
                    .strip_prefix(dir)
                    .expect("under dir")
                    .display()
                    .to_string();
                (name, fs::read(&p).expect("read artifact"))
            })
            .collect()
    }

    type Events = BTreeMap<(u64, u64), Vec<(i32, String)>>;

    /// Narrative events of the stored chain, by `(height, command_index)`.
    fn chain_events(dir: &Path) -> (Vec<usize>, Events) {
        let store = BlockStore::open(dir.join("state/blocks")).expect("block store");
        let mut schedule = Vec::new();
        let mut events = Events::new();
        for height in 1..=store.sealed_height() {
            let block = store.read(height).expect("block");
            schedule.push(block.commands.len());
            for entry in block.events.entries() {
                if u64::from(entry.event[1]) == block_events::event_tag::NARRATIVE {
                    events
                        .entry((height, entry.command_index))
                        .or_default()
                        .push((entry.recipient, hex(&entry.event)));
                }
            }
        }
        (schedule, events)
    }

    /// What the recorder sessions delivered, by `(height, command_index)`.
    fn seen_events(dir: &Path) -> Events {
        let mut events = Events::new();
        for line in fs::read_to_string(dir.join("seen"))
            .unwrap_or_default()
            .lines()
        {
            let f: Vec<&str> = line.split(' ').collect();
            events
                .entry((f[0].parse().unwrap(), f[1].parse().unwrap()))
                .or_default()
                .push((f[2].parse().unwrap(), f[3].to_string()));
        }
        events
    }

    fn notices(dir: &Path) -> std::collections::BTreeSet<String> {
        fs::read_to_string(dir.join("notices"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Heights the recovery runs re-executed (`resealed=Some(h)`).
    fn resealed(stdout: &str) -> Vec<u64> {
        stdout
            .lines()
            .filter_map(|l| l.split("resealed=Some(").nth(1))
            .filter_map(|r| r.split(')').next()?.parse().ok())
            .collect()
    }

    struct Case {
        name: &'static str,
        crashes: &'static [&'static str],
        group: bool,
        lose_db: bool,
        /// Checkpoint cadence (0 = none).
        checkpoints: u64,
    }

    struct Outcome {
        name: &'static str,
        checkpoints: u64,
        schedule: Vec<usize>,
        recovery: Vec<String>,
        resealed: Vec<u64>,
        dir: tempfile::TempDir,
    }

    fn crash_case(case: &Case) -> Outcome {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut recovery = Vec::new();
        let mut resealed_heights = Vec::new();
        for crash in case.crashes {
            let r = run(dir.path(), &PLANNED, crash, case.group, case.checkpoints);
            assert!(
                r.killed,
                "{}: {crash} did not kill the child:\n{}",
                case.name, r.stdout
            );
            recovery.extend(
                r.stdout
                    .lines()
                    .filter_map(|l| l.split("RECOVERY ").nth(1))
                    .map(str::to_string),
            );
            resealed_heights.extend(resealed(&r.stdout));
            if case.lose_db {
                fs::remove_dir_all(dir.path().join("db")).expect("remove db");
            }
        }
        let r = run(dir.path(), &PLANNED, "", case.group, case.checkpoints);
        assert!(!r.killed, "{}: the recovery run was killed", case.name);
        recovery.extend(
            r.stdout
                .lines()
                .filter_map(|l| l.split("RECOVERY ").nth(1))
                .map(str::to_string),
        );
        resealed_heights.extend(resealed(&r.stdout));
        let (schedule, _) = chain_events(dir.path());
        Outcome {
            name: case.name,
            checkpoints: case.checkpoints,
            schedule,
            recovery,
            resealed: resealed_heights,
            dir,
        }
    }

    const CASES: &[Case] = &[
        Case {
            name: "mid-input (block 4, input 2 half delivered)",
            crashes: &["mid:4:2"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "mid-input (block 1, before any seal)",
            crashes: &["mid:1:1"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "after journal write (block 2, input 1)",
            crashes: &["journal:2:1"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "after journal write (block 4, input 2)",
            crashes: &["journal:4:2"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "after journal write, group commit of 3",
            crashes: &["journal:4:3"],
            group: true,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "after open of an empty block",
            crashes: &["opened:3"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "after seal write (block 4)",
            crashes: &["unsigned:4"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "after seal write (empty block 3)",
            crashes: &["unsigned:3"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "after guard write (block 4)",
            crashes: &["guard:4"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "after seal write, database persisted (block 4)",
            crashes: &["settled-unsigned:4"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "after guard write, database persisted (block 4)",
            crashes: &["settled-guard:4"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "after journal write, database persisted (block 4, input 2)",
            crashes: &["settled-journal:4:2"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "after sign (block 4)",
            crashes: &["signed:4"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "after publish (segment 3-4)",
            crashes: &["published:4"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "crash again during recovery (guard, then sign)",
            crashes: &["guard:4", "signed:4"],
            group: false,
            lose_db: false,
            checkpoints: 0,
        },
        Case {
            name: "after sign, database lost",
            crashes: &["signed:6"],
            group: false,
            lose_db: true,
            checkpoints: 0,
        },
        Case {
            name: "mid-input (block 7, input 2), checkpoints every 4 blocks",
            crashes: &["mid:7:2"],
            group: false,
            lose_db: false,
            checkpoints: 4,
        },
    ];

    #[test]
    fn kill_minus_nine_at_every_phase_recovers_the_identical_chain_and_events() {
        let started = Instant::now();
        let outcomes: Vec<Outcome> = std::thread::scope(|s| {
            let handles: Vec<_> = CASES
                .chunks(5)
                .map(|chunk| s.spawn(move || chunk.iter().map(crash_case).collect::<Vec<_>>()))
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().expect("case thread"))
                .collect()
        });
        // One uninterrupted reference run per distinct effective schedule.
        let mut references: BTreeMap<Vec<usize>, tempfile::TempDir> = BTreeMap::new();
        for outcome in &outcomes {
            if !references.contains_key(&outcome.schedule) {
                let dir = tempfile::tempdir().expect("tempdir");
                let r = run(dir.path(), &outcome.schedule, "", false, 0);
                assert!(!r.killed);
                references.insert(outcome.schedule.clone(), dir);
            }
        }
        let planned = references.keys().any(|s| s.as_slice() == PLANNED);
        for (schedule, dir) in &references {
            let (_, events) = chain_events(dir.path());
            assert_eq!(
                seen_events(dir.path()),
                events,
                "reference {schedule:?}: seen = batch"
            );
        }
        let mut matrix = Vec::new();
        for o in &outcomes {
            let reference = references[&o.schedule].path();
            let ours = artifacts(o.dir.path());
            let theirs = artifacts(reference);
            assert_eq!(
                ours.iter().map(|(n, b)| (n, b.len())).collect::<Vec<_>>(),
                theirs.iter().map(|(n, b)| (n, b.len())).collect::<Vec<_>>(),
                "{}: artifact names and sizes",
                o.name
            );
            for ((name, a), (_, b)) in ours.iter().zip(&theirs) {
                assert!(a == b, "{}: {name} differs from the reference", o.name);
            }
            // Host-visible events: everything a host saw is in the chain, byte for byte; only
            // the re-executed block may have inputs whose events hosts saw in part or not at all.
            let (_, batch) = chain_events(o.dir.path());
            let seen = seen_events(o.dir.path());
            for key in seen.keys() {
                assert!(
                    batch.contains_key(key),
                    "{}: hosts saw {key:?}, the chain has no such events",
                    o.name
                );
            }
            for (key, events) in &batch {
                let got = seen.get(key).cloned().unwrap_or_default();
                if o.resealed.contains(&key.0) {
                    assert!(
                        events.starts_with(&got),
                        "{}: {key:?} seen is not a prefix",
                        o.name
                    );
                } else {
                    assert_eq!(
                        &got, events,
                        "{}: {key:?} seen differs from the batch",
                        o.name
                    );
                }
            }
            assert_eq!(
                notices(o.dir.path()),
                notices(reference),
                "{}: seal notices",
                o.name
            );
            if o.checkpoints > 0 {
                assert!(
                    o.recovery
                        .iter()
                        .any(|r| r.contains("rebuilt=true checkpoint=Some(")),
                    "{}: recovery did not restore a checkpoint: {:?}",
                    o.name,
                    o.recovery
                );
            }
            matrix.push(format!(
                "| {} | {:?} | {} | identical |",
                o.name,
                o.schedule,
                o.recovery.join("; ")
            ));
        }
        println!(
            "kill matrix ({:.1} s, planned schedule {:?} among references: {planned}):",
            started.elapsed().as_secs_f64(),
            PLANNED
        );
        for row in matrix {
            println!("{row}");
        }
    }

    /// Durable state for a sequencer at genesis in `dir`, sharing the guard at `guard`.
    fn durable_parts(
        world: &mut super::executor::World,
        dir: &Path,
        guard: &Path,
    ) -> (BlockDriver, DurableParts) {
        let out = world.block(0, &[GENESIS]);
        assert!(matches!(out.outcomes[0].result, Some(Ok(_))));
        let driver = world.take_driver();
        let mut store = BlockStore::open(dir.join("blocks")).expect("store");
        let chain = StoreChain {
            genesis_root: driver.state_root().expect("root").root,
            sequencer: sequencer_key().address(),
        };
        store.init_chain(chain).expect("chain");
        let (journal, open) = Journal::open(dir.join("journal")).expect("journal");
        let guard = SigningGuard::open(guard, chain).expect("guard");
        (
            driver,
            DurableParts {
                journal,
                open,
                store,
                guard,
            },
        )
    }

    fn durable_sequencer(
        world: &mut super::executor::World,
        dir: &Path,
        guard: &Path,
    ) -> Result<moor_kernel::tasks::sequencer::Sequencer, RecoveryError> {
        let (driver, parts) = durable_parts(world, dir, guard);
        resume(
            driver,
            sequencer_key(),
            SequencerParams::default(),
            parts,
            Arc::new(FsyncLog::default()),
            None,
        )
        .map(|(seq, _)| seq)
    }

    /// Seal block 1 with one disconnect under the guard at `guard`.
    fn seal_first_block(dir: &Path, guard: &Path) {
        let mut world = super::executor::World::start();
        let mut seq = durable_sequencer(&mut world, dir, guard).expect("resume");
        seq.open_block(T0, Instant::now()).expect("open");
        seq.submit(disconnect(10), noop(), None).expect("submit");
        seq.seal().expect("the first block 1 is signed");
        seq.shutdown().expect("shutdown");
    }

    fn disconnect(player: i32) -> CommandEntry {
        CommandEntry::Sequencer(moor_block::SequencerInput {
            kind: moor_block::SequencerInputKind::Disconnected,
            player,
        })
    }

    #[test]
    fn the_signing_guard_blocks_a_forced_second_signature_at_a_height() {
        let dir = tempfile::tempdir().expect("tempdir");
        let guard = dir.path().join("sequencer.guard");
        seal_first_block(&dir.path().join("a"), &guard);
        // Same key and chain, a database and store that never saw block 1, the recovery checks
        // bypassed: a different block 1 must still not be signed.
        let mut world = super::executor::World::start();
        let (driver, parts) = durable_parts(&mut world, &dir.path().join("b"), &guard);
        let hooks = DurableHooks::new(
            parts.journal,
            parts.store,
            parts.guard,
            Arc::new(FsyncLog::default()),
            None,
        );
        let mut seq = moor_kernel::tasks::sequencer::Sequencer::genesis(
            driver,
            sequencer_key(),
            SequencerParams::default(),
            Box::new(hooks),
        )
        .expect("genesis");
        seq.open_block(T0, Instant::now()).expect("open");
        seq.submit(disconnect(11), noop(), None).expect("submit");
        let refused = seq.seal();
        assert!(
            matches!(&refused, Err(SequencerError::Hook("before_sign", reason)) if reason.contains("signing guard refuses height 1")),
            "{refused:?}"
        );
        seq.shutdown().expect("shutdown");
        let store = BlockStore::open(dir.path().join("b/blocks")).expect("store");
        assert_eq!(
            (store.sealed_height(), store.unsigned().map(|h| h.height)),
            (0, Some(1)),
            "the refused block is stored unsigned and never signed"
        );
    }

    #[test]
    fn recovery_halts_when_the_guard_records_a_height_the_store_lacks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let guard = dir.path().join("sequencer.guard");
        seal_first_block(&dir.path().join("a"), &guard);
        let mut world = super::executor::World::start();
        let refused = durable_sequencer(&mut world, &dir.path().join("b"), &guard);
        assert!(
            matches!(&refused, Err(RecoveryError::Halt(reason)) if reason.contains("records height 1")),
            "{:?}",
            refused.err()
        );
    }

    #[test]
    fn the_guard_file_is_locked_while_a_sequencer_holds_the_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let guard = dir.path().join("sequencer.guard");
        let mut world = super::executor::World::start();
        let seq = durable_sequencer(&mut world, &dir.path().join("a"), &guard).expect("resume");
        let chain = StoreChain {
            genesis_root: *seq.genesis_root(),
            sequencer: sequencer_key().address(),
        };
        assert!(matches!(
            SigningGuard::open(&guard, chain),
            Err(moor_block::durable::DurableError::Locked(_))
        ));
        seq.shutdown().expect("shutdown");
    }
}

/// The engine meter, the per-command tick ceiling and the `charge` call sites (RuneWorld ADR 0007,
/// issue S1-9). The core's verbs are stood in for by the stubs in `SETUP`, which follow the S1-10
/// contract (`docs/research/s1-10-report.md`).
mod meter {
    use moor_block::{Meter, MeterKind, MeterOutcome};
    use moor_common::{
        deterministic::DeterministicMode,
        envelope::scope,
    };
    use moor_kernel::tasks::{
        block_driver::{BlockEvent, BlockEventKind, BlockInput, BlockOutput},
        block_events,
        envelope_admission::{AdmissionRejection, Admitted},
    };
    use moor_var::{Obj, Var, v_int};

    use super::admission::{
        command, create_player, delegate, delegation, eval, key, noop, run, verdicts, wallet,
        world_with,
    };
    use super::executor::{World, block, canonical};

    /// A verb on `obj` (an expression) with the given body, one statement per line.
    fn verb(obj: &str, name: &str, args: &str, body: &str) -> String {
        let lines: Vec<String> = body
            .trim()
            .lines()
            .map(|l| format!("\"{}\"", l.trim().replace('\\', "\\\\").replace('"', "\\\"")))
            .collect();
        format!(
            "add_verb({obj}, {{player, \"rxd\", \"{name}\"}}, {args}); set_verb_code({obj}, \"{name}\", {{{}}});\n",
            lines.join(", ")
        )
    }

    /// The core's default `charge` body (S1-10): sponsor-all.
    const DEFAULT_CHARGE: &str = r#"
const {who, meter, phase} = args;
typeof(meter) == TYPE_MAP && maphaskey(meter, 'ticks) || raise(E_INVARG, "charge needs a meter with ticks.");
return $world:charge_allow(meter['ticks]);
"#;

    /// The core's `$sysobj:run_charge`, as S1-10 ships it.
    const RUN_CHARGE: &str = r#"
caller_perms().wizard || raise(E_PERM);
const {who, meter, phase} = args;
phase in {'reserve, 'settle} || raise(E_INVARG, "Phase is 'reserve or 'settle.");
typeof(meter) == TYPE_MAP || raise(E_TYPE);
let result = `#0:charge(who, meter, phase) ! ANY => 0';
if (!this:_charge_result_ok(result))
if (phase == 'reserve)
result = $world:charge_deny("The deployment policy failed.");
else
result = $world:charge_allow(0);
endif
endif
if (phase == 'reserve && !result['allow])
return result;
endif
const world = `meter['world] ! E_RANGE => #-1';
const leaving = `meter['leaving] ! E_RANGE => false';
if (leaving || typeof(world) != TYPE_OBJ || !valid(world) || !isa(world, $world))
return result;
endif
const world_result = `world:charge(who, meter, phase) ! ANY => 0';
if (!this:_charge_result_ok(world_result))
if (phase == 'reserve)
return $world:charge_deny("The world's charge policy failed.");
endif
return result;
endif
if (!result['allow])
return result;
endif
if (!world_result['allow])
return world_result;
endif
return $world:charge_allow(min(result['ceiling], world_result['ceiling]));
"#;

    const RESULT_OK: &str = r#"
const {r} = args;
typeof(r) == TYPE_MAP || return false;
maphaskey(r, 'allow) || return false;
return r['allow] ? (maphaskey(r, 'ceiling) && typeof(r['ceiling]) == TYPE_INT && r['ceiling] >= 0) | (maphaskey(r, 'reason) && typeof(r['reason]) == TYPE_STR);
"#;

    /// The policy installed on world `Wi` when a test asks for one: a ceiling, a ban list, a ledger.
    const POLICY: &str = r#"
const {who, meter, phase} = args;
if (phase == 'reserve)
if (who in this.banned)
return $world:charge_deny("banned from this world");
endif
this.reserved = {@this.reserved, {who, meter['kind], meter['leaving]}};
return $world:charge_allow(this.cap);
endif
this.ledger[who] = (who in mapkeys(this.ledger) ? this.ledger[who] | 0) + meter['ticks];
this.settled = {@this.settled, {who, meter['outcome], meter['ticks]}};
return $world:charge_allow(0);
"#;

    /// Stubs of the S1-10 core: `#0.world`, defaults, `run_charge`, a world instance `Wi` with a
    /// start room, and a player parent whose new players start inside `Wi`.
    fn setup(policy: bool) -> String {
        let mut s = String::from(
            r#"
W = create(#-1);
add_property(#0, "world", W, {player, "r"});
add_property(W, "meter_total", ['ticks -> 0, 'log_bytes -> 0, 'storage -> 0, 'settled_at -> 0], {player, "r"});
add_property(#0.wallet_parent, "meter_total", ['ticks -> 0, 'log_bytes -> 0, 'storage -> 0, 'settled_at -> 0], {player, "r"});
add_property(#0, "meter_total", ['ticks -> 0, 'log_bytes -> 0, 'storage -> 0, 'settled_at -> 0], {player, "r"});
Wi = create(W);
add_property(Wi, "cap", 1000000, {player, "r"});
add_property(Wi, "banned", {}, {player, "r"});
add_property(Wi, "ledger", [], {player, "r"});
add_property(Wi, "reserved", {}, {player, "r"});
add_property(Wi, "settled", {}, {player, "r"});
room = create(#-1);
move(room, Wi);
add_property(#0, "start_room", room, {player, "r"});
add_property(#0, "spun", 0, {player, "rw"});
add_property(#0, "handled", 0, {player, "rw"});
T = create(#-1);
add_property(T, "home_world", #-1, {player, "r"});
add_property(#0, "thing_parent", T, {player, "r"});
"#,
        );
        s += &verb("W", "charge_allow", "{\"this\", \"none\", \"this\"}", "return ['allow -> true, 'ceiling -> args[1]];");
        s += &verb("W", "charge_deny", "{\"this\", \"none\", \"this\"}", "return ['allow -> false, 'reason -> args[1]];");
        s += &verb("W", "command_leaves", "{\"this\", \"none\", \"this\"}", "return args[2]['verb] == \"leave\";");
        s += &verb("W", "charge", "{\"this\", \"none\", \"this\"}", DEFAULT_CHARGE);
        s += &verb("#0", "charge", "{\"this\", \"none\", \"this\"}", DEFAULT_CHARGE);
        s += &verb("#0", "run_charge", "{\"this\", \"none\", \"this\"}", RUN_CHARGE);
        s += &verb("#0", "_charge_result_ok", "{\"this\", \"none\", \"this\"}", RESULT_OK);
        s += &verb(
            "#0",
            "create_wallet_player",
            "{\"this\", \"none\", \"this\"}",
            "p = create(#0.wallet_parent);\nset_player_flag(p, 1);\np.name = args[2];\nmove(p, #0.start_room);\nreturn p;",
        );
        let wp = "#0.wallet_parent";
        s += &verb(wp, "spin", "{\"any\", \"any\", \"any\"}", "#0.spun = 1;\nwhile (1)\nendwhile");
        s += &verb(
            wp,
            "spinfork",
            "{\"any\", \"any\", \"any\"}",
            "#0.spun = 2;\nfork (0)\n#0.spun = 3;\nwhile (1)\nendwhile\nendfork",
        );
        s += &verb(wp, "leave", "{\"any\", \"any\", \"any\"}", "notify(player, \"left\");");
        s += &verb(wp, "report", "{\"any\", \"any\", \"any\"}", "notify(player, toliteral(meter()));\nnotify(player, toliteral(meter_totals(player.location.location, 'block)));");
        s += &verb(
            wp,
            "build",
            "{\"any\", \"any\", \"any\"}",
            "o = create(#0.thing_parent);\no.home_world = player.location.location;\nadd_property(o, \"pad\", \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\", {player, \"r\"});\nnotify(player, tostr(o));",
        );
        s += &verb("#0", "handle_task_timeout", "{\"this\", \"none\", \"this\"}", "#0.handled = 1;");
        if policy {
            s += &verb("Wi", "charge", "{\"this\", \"none\", \"this\"}", POLICY);
        }
        s += "return Wi;";
        s
    }

    fn mode(max_command_ticks: u64) -> DeterministicMode {
        DeterministicMode {
            max_command_ticks,
            ..DeterministicMode::on()
        }
    }

    /// Genesis hooks, the stubs, and one player in `Wi`. Returns the world, the player and `Wi`.
    fn started(policy: bool, max_command_ticks: u64) -> (World, Obj, Obj) {
        let mut world = world_with(mode(max_command_ticks));
        // Not height 1: definition ids derive from (height, command, counter), and genesis used it.
        let out = world.block(90, &[&setup(policy)]);
        let wi = match &out.outcomes[0].result {
            Some(Ok(v)) => v.as_object().expect("Wi"),
            other => panic!("setup failed: {other:?}"),
        };
        let player = create_player(&mut world);
        (world, player, wi)
    }

    fn meters(out: &BlockOutput) -> Vec<Meter> {
        out.meters.iter().map(|(_, m)| *m).collect()
    }

    fn meter_events(events: &[BlockEvent]) -> Vec<(u64, Meter)> {
        events
            .iter()
            .filter_map(|e| match &e.kind {
                BlockEventKind::Meter(m) => Some((e.command_index, *m)),
                _ => None,
            })
            .collect()
    }

    fn prop(world: &mut World, height: u64, expr: &str) -> Var {
        eval(world, height, &format!("return {expr};"))
    }

    #[test]
    fn every_input_ends_with_a_meter_entry_after_its_events() {
        let (mut world, player, wi) = started(false, 0);
        let out = run(
            &mut world,
            3,
            &[
                &command(&key(1), player, 1, 1, "ping a"),
                &command(&key(1), player, 1, 2, "ping b"),
            ],
        );
        let entries = meter_events(&out.events);
        assert_eq!(entries.len(), 2, "{}", canonical(&out.events));
        assert_eq!(entries.iter().map(|e| e.0).collect::<Vec<_>>(), [1, 2]);
        for (i, event) in out.events.iter().enumerate() {
            if let BlockEventKind::Meter(_) = event.kind {
                // The meter follows the input's own narrative event and precedes the next input's.
                assert!(matches!(out.events[i - 1].kind, BlockEventKind::Narrative(_)));
            }
        }
        let m = entries[0].1;
        assert_eq!(m.kind, MeterKind::Command);
        assert_eq!(m.outcome, MeterOutcome::Ok);
        assert_eq!(m.world, wi.id().0, "the player's current world is charged");
        assert_eq!(m.tasks, 1);
        assert_eq!(m.events, 1);
        assert!(m.ticks > 0 && m.log_bytes > 0 && m.event_bytes > 0);
        // The nonce moves from 0 to 1: the same canonical size, so nothing else was written.
        assert_eq!(m.storage_delta, 0, "{m:?}");
        assert_eq!(out.meters.iter().map(|(_, m)| *m).collect::<Vec<_>>(), meters(&out));
    }

    #[test]
    fn a_meter_event_is_the_meter_encoding() {
        let (mut world, player, _) = started(false, 0);
        let out = run(&mut world, 3, &[&command(&key(1), player, 1, 1, "ping a")]);
        let event = out.events.last().expect("meter entry");
        let BlockEventKind::Meter(m) = event.kind else {
            panic!("last event is not a meter")
        };
        let bytes = block_events::encode_event(&event.kind).expect("encodes");
        assert_eq!(bytes, m.encode_event());
        assert_eq!(Meter::decode_event(&bytes), Ok(Some(m)));
    }

    #[test]
    fn rejected_envelopes_are_metered_as_aborted() {
        let (mut world, player, _) = started(false, 0);
        let mut bad = command(&key(1), player, 1, 1, "ping a");
        bad.signature[3] ^= 1;
        let out = run(&mut world, 3, &[&bad]);
        let m = meters(&out)[0];
        assert_eq!(m.outcome, MeterOutcome::Aborted);
        assert_eq!((m.ticks, m.tasks), (0, 0));
        assert_eq!(m.world, 0);
    }

    #[test]
    fn fork_zero_children_and_the_parent_share_one_meter() {
        let (mut world, _, _) = started(false, 0);
        let one = world.driver();
        one.begin_block(block(4));
        let wiz: Obj = Obj::mk_id(3);
        for code in [
            "return 1;",
            "fork (0) #0.spun = 5; endfork fork (0) #0.spun = 6; endfork return 1;",
        ] {
            one.submit(
                BlockInput::Eval {
                    player: wiz,
                    code: code.into(),
                },
                noop(),
            );
        }
        let out = one.end_block();
        let m = meters(&out);
        assert_eq!(m[0].tasks, 1);
        assert_eq!(m[1].tasks, 3, "the parent and two children");
        assert!(m[1].ticks > m[0].ticks);
    }

    #[test]
    fn exceeding_the_tick_ceiling_rolls_back_and_runs_no_handler() {
        let (mut world, player, _) = started(false, 5_000);
        let out = run(&mut world, 3, &[&command(&key(1), player, 1, 1, "spin")]);
        let m = meters(&out)[0];
        assert_eq!(m.outcome, MeterOutcome::TickCeiling, "{m:?}");
        assert!(m.ticks <= 5_000 && m.ticks >= 4_900, "ticks {}", m.ticks);
        assert_eq!(m.storage_delta, 0, "only the (same-size) nonce is committed: {m:?}");
        assert_eq!(prop(&mut world, 4, "#0.spun"), v_int(0), "no partial commit");
        assert_eq!(prop(&mut world, 5, "#0.handled"), v_int(0), "no handler ran");
        // The nonce is consumed: 1 is stale, 2 runs.
        let out = run(
            &mut world,
            6,
            &[
                &command(&key(1), player, 1, 1, "ping again"),
                &command(&key(1), player, 1, 2, "ping next"),
            ],
        );
        assert!(matches!(
            verdicts(&out)[0],
            Err(AdmissionRejection::StaleNonce { .. })
        ));
        assert!(verdicts(&out)[1].is_ok());
    }

    #[test]
    fn an_aborted_command_is_the_same_state_as_no_command_but_the_nonce() {
        // Run the same block twice: once with the spinning command, once with a no-op command of
        // the same nonce. The state differs by exactly nothing the command wrote.
        let roots: Vec<_> = ["spin", "ping x"]
            .iter()
            .map(|text| {
                let (mut world, player, _) = started(false, 5_000);
                let out = run(&mut world, 3, &[&command(&key(1), player, 1, 1, text)]);
                out.state_root.expect("root").expect("ok").relations
            })
            .collect();
        // Only `ping` leaves narrative, no state: the two worlds agree relation by relation, so
        // nothing of `spin` (the `#0.spun` write) is committed.
        assert_eq!(roots[0], roots[1]);
    }

    #[test]
    fn the_ceiling_spans_the_forked_children_of_a_command() {
        let (mut world, player, _) = started(false, 5_000);
        let out = run(&mut world, 3, &[&command(&key(1), player, 1, 1, "spinfork")]);
        let m = meters(&out)[0];
        assert_eq!(m.outcome, MeterOutcome::TickCeiling, "{m:?}");
        assert_eq!(m.tasks, 2, "the parent and the child");
        // The parent committed before the child ran; the child's own write is rolled back.
        assert_eq!(prop(&mut world, 4, "#0.spun"), v_int(2));
    }

    #[test]
    fn meter_builtins_report_the_command_so_far_and_the_block_totals() {
        let (mut world, player, wi) = started(false, 0);
        let out = run(
            &mut world,
            3,
            &[
                &command(&key(1), player, 1, 1, "ping a"),
                &command(&key(1), player, 1, 2, "report"),
            ],
        );
        let texts = super::executor::texts(&out.events);
        let report = texts.iter().find(|t| t.contains("ceiling")).expect("meter()");
        assert!(report.contains(&format!("'world -> {wi}")), "{report}");
        assert!(report.contains("'tasks -> 1"), "{report}");
        assert!(report.contains("'kind -> 'command"), "{report}");
        let totals = texts.iter().find(|t| t.contains("inputs")).expect("totals");
        assert!(totals.contains("'inputs -> 1"), "the first command is in the total: {totals}");
    }

    #[test]
    fn sponsor_all_skips_the_hooks() {
        let (mut world, player, wi) = started(false, 0);
        let out = run(&mut world, 3, &[&command(&key(1), player, 1, 1, "ping a")]);
        let m = meters(&out)[0];
        assert_eq!(m.policy_ticks, 0, "no hook ran at 'reserve");
        assert_eq!(
            prop(&mut world, 4, &format!("{wi}.meter_total['ticks]")),
            v_int(0),
            "nothing settled"
        );
        assert_eq!(prop(&mut world, 5, "#0.meter_total['ticks]"), v_int(0));
    }

    #[test]
    fn an_installed_policy_reserves_and_settles_once_per_block() {
        let (mut world, player, wi) = started(true, 0);
        let out = run(
            &mut world,
            3,
            &[
                &command(&key(1), player, 1, 1, "ping a"),
                &command(&key(1), player, 1, 2, "ping b"),
            ],
        );
        let ms = meters(&out);
        assert!(ms.iter().all(|m| m.policy_ticks > 0), "{ms:?}");
        let ticks: u64 = ms.iter().map(|m| m.ticks).sum();
        let log: u64 = ms.iter().map(|m| m.log_bytes).sum();
        // Reserved per command, settled once per block in command-index order.
        let reserved = prop(&mut world, 4, &format!("length({wi}.reserved)"));
        assert_eq!(reserved, v_int(2));
        let settled = prop(&mut world, 5, &format!("{wi}.settled"));
        assert_eq!(
            moor_compiler::to_literal(&settled),
            format!(
                "{{{{{player}, 'ok, {}}}, {{{player}, 'ok, {}}}}}",
                ms[0].ticks, ms[1].ticks
            )
        );
        // meter_total on #0, the world and the player.
        for target in ["#0".to_string(), wi.to_string(), player.to_string()] {
            let t = prop(&mut world, 6, &format!("{target}.meter_total"));
            let text = moor_compiler::to_literal(&t);
            assert!(text.contains(&format!("'ticks -> {ticks}")), "{target}: {text}");
            assert!(text.contains(&format!("'log_bytes -> {log}")), "{target}: {text}");
        }
        // The totals are state: they are in the root of the block that settled them.
        let root = out.state_root.expect("root").expect("ok");
        assert_eq!(root.root, world.driver().state_root().expect("root").root);
        drop(world);
        // A replay of the same inputs in a fresh world settles to the same root.
        let (mut other, p2, _) = started(true, 0);
        let out2 = run(
            &mut other,
            3,
            &[
                &command(&key(1), p2, 1, 1, "ping a"),
                &command(&key(1), p2, 1, 2, "ping b"),
            ],
        );
        assert_eq!(out2.state_root.expect("r").expect("ok").root, root.root);
    }

    #[test]
    fn a_deny_policy_refuses_the_command_and_consumes_the_nonce() {
        let (mut world, player, wi) = started(true, 0);
        eval(&mut world, 2, &format!("{wi}.banned = {{{player}}}; return 1;"));
        let out = run(
            &mut world,
            3,
            &[
                &command(&key(1), player, 1, 1, "ping a"),
                &command(&key(1), player, 1, 1, "ping a"),
            ],
        );
        let verdicts = verdicts(&out);
        assert!(
            matches!(&verdicts[0], Err(AdmissionRejection::ChargeDenied { reason, .. }) if reason == "banned from this world"),
            "{:?}",
            verdicts[0]
        );
        assert!(
            matches!(verdicts[1], Err(AdmissionRejection::StaleNonce { .. })),
            "the denied command's nonce is consumed: {:?}",
            verdicts[1]
        );
        assert_eq!(meters(&out)[0].outcome, MeterOutcome::Denied);
        assert!(super::executor::texts(&out.events).is_empty(), "nothing ran");
        let rejected: Vec<_> = out
            .events
            .iter()
            .filter_map(|e| match &e.kind {
                BlockEventKind::Rejected { reason, .. } => Some((e.player, block_events::rejection_code(reason))),
                _ => None,
            })
            .collect();
        assert_eq!(rejected[0], (player, 19));
    }

    #[test]
    fn leaving_a_world_is_not_charged_to_it() {
        let (mut world, player, wi) = started(true, 0);
        eval(&mut world, 2, &format!("{wi}.banned = {{{player}}}; return 1;"));
        let out = run(&mut world, 3, &[&command(&key(1), player, 1, 1, "leave")]);
        assert_eq!(super::executor::texts(&out.events), ["left"]);
        assert_eq!(meters(&out)[0].outcome, MeterOutcome::Ok);
        // The world's hook did not run at either phase.
        assert_eq!(prop(&mut world, 4, &format!("length({wi}.reserved)")), v_int(0));
        assert_eq!(prop(&mut world, 5, &format!("length({wi}.settled)")), v_int(0));
    }

    #[test]
    fn a_policy_ceiling_sets_the_commands_tick_limit() {
        let (mut world, player, wi) = started(true, 0);
        eval(&mut world, 2, &format!("{wi}.cap = 3000; return 1;"));
        let out = run(&mut world, 3, &[&command(&key(1), player, 1, 1, "spin")]);
        let m = meters(&out)[0];
        assert_eq!(m.outcome, MeterOutcome::TickCeiling);
        assert!(m.ticks <= 3_000 && m.ticks > 2_900, "{m:?}");
        assert_eq!(prop(&mut world, 4, "#0.spun"), v_int(0));
    }

    #[test]
    fn objects_and_storage_are_counted_and_attributed_to_the_home_world() {
        let (mut world, player, wi) = started(false, 0);
        let out = run(&mut world, 3, &[&command(&key(1), player, 1, 1, "build")]);
        let m = meters(&out)[0];
        assert_eq!(m.objects_created, 1, "{m:?}");
        assert!(m.storage_delta > 100, "{m:?}");
        let driver = world.driver();
        let by_world = driver.storage_held_by_world();
        assert!(by_world.get(&wi).copied().unwrap_or(0) > 100, "{by_world:?}");
        assert!(driver.storage_held_by_payer().get(&player).copied().unwrap_or(0) > 100);
        let out = run(&mut world, 4, &[&command(&key(1), player, 1, 2, "ping x")]);
        assert_eq!(meters(&out)[0].objects_created, 0);
    }

    #[test]
    fn recycling_is_counted() {
        let (mut world, _, _) = started(false, 0);
        let out = world.block(
            3,
            &["o = create(#0.thing_parent); recycle(o); return 1;"],
        );
        let m = meters(&out)[0];
        assert_eq!((m.objects_created, m.objects_recycled), (0, 0), "created and gone in one transaction");
        let out = world.block(4, &["#0.spun = create(#0.thing_parent); return 1;"]);
        assert_eq!(meters(&out)[0].objects_created, 1);
        let out = world.block(5, &["recycle(#0.spun); return 1;"]);
        assert_eq!(meters(&out)[0].objects_recycled, 1);
    }

    #[test]
    fn a_delegation_is_metered_as_create() {
        let mut world = world_with(mode(0));
        let out = run(
            &mut world,
            2,
            &[&delegate(&wallet(1), &key(1), delegation(&key(1), 1, true, scope::PLAY))],
        );
        assert_eq!(meters(&out)[0].kind, MeterKind::Create);
    }

    /// The meters of the standard (unsigned) log and the signed log, as text.
    fn transcript() -> String {
        let mut world = World::start();
        let out = world.block(
            3,
            &[
                "add_property(#0, \"log\", {}, {player, \"rw\"}); return 1;",
                "fork (0) notify(player, \"a\"); endfork fork (0) #0.log = {random(1000)}; endfork return 1;",
                "o = create(#1); move(o, #2); notify(player, tostr(o)); return o;",
            ],
        );
        let mut text = out
            .meters
            .iter()
            .map(|(i, m)| format!("{i} {m:?}"))
            .collect::<Vec<_>>()
            .join("\n");
        drop(world);
        text += "\n--signed--\n";
        text += &super::admission::signed_run();
        text
    }

    /// Microseconds per signed command with no policy, and with the policy stub installed
    /// (reserve + settle). Run with `--ignored --nocapture` under `release-fast`.
    #[test]
    #[ignore = "measurement, not a check"]
    fn perf_charge_overhead() {
        const N: u32 = 1_000;
        for policy in [false, true] {
            let (mut world, player, _) = started(policy, 0);
            let mut nonce = 0u32;
            let mut samples = Vec::new();
            for round in 0..5u64 {
                let envs: Vec<_> = (0..N)
                    .map(|_| {
                        nonce += 1;
                        command(&key(1), player, 1, nonce, "ping x").encode()
                    })
                    .collect();
                let driver = world.driver();
                driver.begin_block(block(3 + round));
                let t = std::time::Instant::now();
                for env in &envs {
                    driver.submit_envelope(env, noop());
                }
                let per = t.elapsed().as_secs_f64() * 1e6 / f64::from(N);
                let t = std::time::Instant::now();
                driver.end_block();
                if round > 0 {
                    samples.push((per, t.elapsed().as_secs_f64() * 1e3));
                }
            }
            samples.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
            println!("PERF policy={policy}: median {:.1} us/command, end_block {:.2} ms", samples[samples.len() / 2].0, samples[samples.len() / 2].1);
        }
    }

    #[test]
    fn meters_are_identical_across_20_runs() {
        let first = transcript();
        assert!(first.contains("meter Meter"), "{first}");
        for _ in 1..20 {
            assert_eq!(transcript(), first);
        }
    }

    #[test]
    #[ignore = "run as a subprocess by meters_are_identical_across_20_processes"]
    fn meter_child() {
        println!("METER-BEGIN\n{}\nMETER-END", transcript());
    }

    #[test]
    fn meters_are_identical_across_20_processes() {
        let child = || {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "meter::meter_child",
                    "--exact",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .output()
                .expect("run child");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let begin = stdout.find("METER-BEGIN\n").unwrap() + "METER-BEGIN\n".len();
            let end = stdout.find("\nMETER-END").unwrap();
            stdout[begin..end].to_string()
        };
        let runs: Vec<String> = (0..20).map(|_| child()).collect();
        assert!(runs[0].contains("Meter {"), "{}", runs[0]);
        assert!(runs.windows(2).all(|w| w[0] == w[1]), "{runs:#?}");
    }
}

mod meter_perf {
    use std::time::Instant;

    use super::admission::{command, create_player, key, noop, world_with};
    use super::executor::block;
    use moor_common::deterministic::DeterministicMode;

    /// Microseconds per signed `ping` with the meter off and on (2,000 per block), alternating,
    /// plus the storage attribution cost. Run with `--ignored --nocapture` under `release-fast`.
    #[test]
    #[ignore = "measurement, not a check"]
    fn perf_meter_overhead() {
        const N: u32 = 2_000;
        let mut world = world_with(DeterministicMode::on());
        let player = create_player(&mut world);
        let mut nonce = 0u32;
        let mut height = 3;
        let mut results = [Vec::new(), Vec::new()];
        for round in 0..6 {
            for (i, enabled) in [false, true].into_iter().enumerate() {
                let envs: Vec<_> = (0..N)
                    .map(|_| {
                        nonce += 1;
                        command(&key(1), player, 1, nonce, "ping x").encode()
                    })
                    .collect();
                let driver = world.driver();
                driver.set_metering(enabled);
                driver.begin_block(block(height));
                height += 1;
                let started = Instant::now();
                for env in &envs {
                    driver.submit_envelope(env, noop());
                }
                let loop_time = started.elapsed();
                let end = Instant::now();
                let out = driver.end_block();
                let end_time = end.elapsed();
                assert_eq!(out.conflicts, 0);
                if round > 0 {
                    results[i].push(loop_time.as_secs_f64() * 1e6 / f64::from(N));
                    println!(
                        "PERF round {round} meter={enabled}: {:.1} us/command, end_block {:.2} ms, attribution total {} us",
                        loop_time.as_secs_f64() * 1e6 / f64::from(N),
                        end_time.as_secs_f64() * 1e3,
                        driver.storage_attribution_nanos() / 1000
                    );
                }
            }
        }
        for (i, name) in ["off", "on"].iter().enumerate() {
            let mut v = results[i].clone();
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            println!("PERF meter {name}: median {:.1} us/command (min {:.1})", v[v.len() / 2], v[0]);
        }
    }
}

// --- Checkpoints (S1-5) ----------------------------------------------------------------------

mod checkpoint {
    use std::{
        path::Path,
        sync::{Arc, MutexGuard},
        time::{Duration, Instant},
    };

    use moor_common::{
        deterministic::{self, BlockContext, DeterministicMode},
        tasks::{NoopClientSession, NoopSystemControl, Session, SessionError, SessionFactory},
    };
    use moor_db::{
        Database, DatabaseConfig, TxDB,
        state_root::{
            RELATIONS, StateRoot,
            checkpoint::{Checkpoint, CheckpointError},
        },
    };
    use moor_kernel::{
        config::Config,
        tasks::{
            NoopTasksDb,
            block_driver::{BlockDriver, BlockInput, BlockOutput},
            scheduler::Scheduler,
        },
    };
    use moor_var::Obj;
    use moor_vm::FeaturesConfig;

    use super::{LOCK, common::load_textdump};

    struct Factory;
    impl SessionFactory for Factory {
        fn mk_background_session(
            self: Arc<Self>,
            _player: &Obj,
        ) -> Result<Arc<dyn Session>, SessionError> {
            Ok(Arc::new(NoopClientSession::new()))
        }
    }

    /// The stripped core's language features (`tools/sequencer-soak/soak.sh`).
    fn core_features() -> FeaturesConfig {
        FeaturesConfig {
            rich_notify: true,
            type_dispatch: true,
            flyweight_type: true,
            bool_type: true,
            symbol_type: true,
            use_boolean_returns: true,
            custom_errors: true,
            use_uuobjids: true,
            anonymous_objects: true,
            use_symbols_in_builtins: true,
            ..FeaturesConfig::default()
        }
    }

    fn driver_on(db: &TxDB, features: &FeaturesConfig) -> BlockDriver {
        let scheduler = Scheduler::new(
            semver::Version::new(0, 1, 0),
            Box::new(db.clone()),
            Box::new(NoopTasksDb {}),
            Arc::new(Config {
                deterministic: DeterministicMode::on(),
                features: Arc::new(features.clone()),
                ..Config::default()
            }),
            Arc::new(NoopSystemControl::default()),
            None,
            None,
        );
        scheduler
            .start_block_driver(Arc::new(Factory))
            .expect("start block driver")
    }

    fn context(height: u64) -> BlockContext {
        BlockContext {
            height,
            timestamp: 1_700_000_000 + height,
            seed: [height as u8; 32],
        }
    }

    fn run(driver: &mut BlockDriver, height: u64, inputs: &[BlockInput]) -> BlockOutput {
        let inputs = inputs
            .iter()
            .map(|i| {
                let session: Arc<dyn Session> = Arc::new(NoopClientSession::new());
                (i.clone(), session)
            })
            .collect();
        driver.run_block(context(height), inputs)
    }

    fn eval(player: Obj, code: &str) -> BlockInput {
        BlockInput::Eval {
            player,
            code: code.to_string(),
        }
    }

    fn root(out: &BlockOutput) -> StateRoot {
        out.state_root.clone().expect("root taken").expect("root")
    }

    struct Restored {
        bytes: Vec<u8>,
        db: TxDB,
        root: StateRoot,
        export: Duration,
        parse: Duration,
        import: Duration,
        _dir: tempfile::TempDir,
    }

    /// Export the driver's state as the checkpoint at `height`, verify it and restore it into a
    /// fresh on-disk database.
    fn export_and_restore(driver: &BlockDriver, height: u64) -> Restored {
        let started = Instant::now();
        let capture = driver.capture_checkpoint().expect("capture");
        let (header, bytes) = capture
            .encode(height, [7; 32], "test")
            .expect("encode checkpoint");
        let export = started.elapsed();
        assert_eq!(header.state_root, driver.state_root().expect("root").root);
        let started = Instant::now();
        let checkpoint = Checkpoint::parse(&bytes).expect("parse checkpoint");
        let parse = started.elapsed();
        let dir = tempfile::tempdir().expect("tempdir");
        let (db, fresh) =
            TxDB::try_open(Some(&dir.path().join("db")), DatabaseConfig::default()).expect("open");
        assert!(fresh);
        let started = Instant::now();
        let root = db
            .import_checkpoint(&checkpoint)
            .expect("import checkpoint");
        let import = started.elapsed();
        Restored {
            bytes,
            db,
            root,
            export,
            parse,
            import,
            _dir: dir,
        }
    }

    /// Commands touching every kind of state the minimal world has: numbered, UUID-kind and
    /// anonymous creates, recycles, moves (`last_move`), properties of several types, verbs.
    fn workload(height: u64) -> Vec<BlockInput> {
        let wizard = Obj::mk_id(3);
        vec![
            eval(
                wizard,
                "r = {}; for i in [1..6] o = create(#1, player, i % 3); r = {@r, o}; \
                 if (i % 3 == 0) move(o, #2); endif endfor return r;",
            ),
            eval(
                wizard,
                &format!(
                    "add_property(#0, \"ck{height}\", {{{height}, 1.5, \"s\", ['k -> {{#1}}]}}, \
                     {{player, \"rw\"}}); return 1;"
                ),
            ),
            eval(
                wizard,
                &format!(
                    "x = create(#1); recycle(x); add_verb(#0, {{player, \"rxd\", \"v{height}\"}}, \
                     {{\"this\", \"none\", \"this\"}}); set_verb_code(#0, \"v{height}\", \
                     {{\"return {height} + 1;\"}}); return #0:v{height}();"
                ),
            ),
        ]
    }

    /// A world restored from a checkpoint is the same world: same root, the same file when
    /// exported again, and the same roots as the original over further blocks.
    #[test]
    fn a_restored_world_executes_like_the_original() {
        let _guard: MutexGuard<'static, ()> = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        deterministic::disable();
        deterministic::configure(&DeterministicMode::on());
        let features = FeaturesConfig {
            use_uuobjids: true,
            anonymous_objects: true,
            ..FeaturesConfig::default()
        };
        let (db, _) = TxDB::try_open(None, DatabaseConfig::default()).expect("open");
        load_textdump(&db);
        let mut original = driver_on(&db, &features);
        for height in 1..=10 {
            let out = run(&mut original, height, &workload(height));
            for o in &out.outcomes {
                assert!(matches!(o.result, Some(Ok(_))), "{:?}", o.result);
            }
        }
        let restored = export_and_restore(&original, 10);
        assert_eq!(restored.root, original.state_root().expect("root"));
        let mut copy = driver_on(&restored.db, &features);
        let again = export_and_restore(&copy, 10);
        assert!(again.bytes == restored.bytes, "re-export differs");
        for height in 11..=15 {
            let a = run(&mut original, height, &workload(height));
            let b = run(&mut copy, height, &workload(height));
            assert_eq!(root(&a), root(&b), "height {height}");
            let results = |o: &BlockOutput| {
                o.outcomes
                    .iter()
                    .map(|x| format!("{:?}", x.result))
                    .collect::<Vec<_>>()
            };
            assert_eq!(results(&a), results(&b), "height {height}");
        }
        copy.shutdown().ok();
        original.shutdown().ok();
        deterministic::disable();
    }

    /// A checkpoint with one flipped byte, or with another root in its header, is refused before
    /// anything is written; a restore into a database that is not empty is refused.
    #[test]
    fn corrupted_checkpoints_are_refused() {
        let _guard: MutexGuard<'static, ()> = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        deterministic::disable();
        deterministic::configure(&DeterministicMode::on());
        let (db, _) = TxDB::try_open(None, DatabaseConfig::default()).expect("open");
        load_textdump(&db);
        let mut driver = driver_on(&db, &FeaturesConfig::default());
        run(&mut driver, 1, &[eval(Obj::mk_id(3), "return create(#1);")]);
        let (header, bytes) = driver
            .capture_checkpoint()
            .unwrap()
            .encode(1, [1; 32], "test")
            .unwrap();
        let mut flipped = bytes.clone();
        let at = bytes.len() / 2;
        flipped[at] ^= 0x40;
        assert!(Checkpoint::parse(&flipped).is_err());
        let body = &bytes[header.encode().len()..];
        let mut other = header.clone();
        other.state_root[31] ^= 1;
        let mut forged = other.encode();
        forged.extend_from_slice(body);
        assert!(matches!(
            Checkpoint::parse(&forged),
            Err(CheckpointError::RootMismatch { .. })
        ));
        assert!(matches!(
            db.import_checkpoint(&Checkpoint::parse(&bytes).unwrap()),
            Err(CheckpointError::NotEmpty)
        ));
        driver.shutdown().ok();
        deterministic::disable();
    }

    /// S1-5 acceptance: export -> import -> root equality on the stripped core after 10,000
    /// commands from the create-heavy harness log (`tools/replay/commands-create.log`, S0-12),
    /// with a genesis wallet binding (admission state). Run (release):
    /// `RW_CHECKPOINT_CORE=.../core RW_CHECKPOINT_LOG=.../commands-create.log cargo test
    /// --profile release-fast -p moor-kernel --test deterministic-suite
    /// checkpoint::stripped_core_10000_commands -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs RW_CHECKPOINT_CORE and RW_CHECKPOINT_LOG; prints measurements"]
    fn stripped_core_10000_commands() {
        let (Ok(core), Ok(log)) = (
            std::env::var("RW_CHECKPOINT_CORE"),
            std::env::var("RW_CHECKPOINT_LOG"),
        ) else {
            eprintln!("RW_CHECKPOINT_CORE / RW_CHECKPOINT_LOG unset; skipped");
            return;
        };
        let total: usize = std::env::var("RW_CHECKPOINT_COMMANDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000);
        let per_block = 100;
        let _guard: MutexGuard<'static, ()> = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        deterministic::disable();
        deterministic::configure(&DeterministicMode::on());
        let features = core_features();
        let dir = tempfile::tempdir().expect("tempdir");
        let (db, _) =
            TxDB::try_open(Some(&dir.path().join("db")), DatabaseConfig::default()).expect("open");
        {
            let mut loader = db.loader_client().unwrap();
            moor_objdef::ObjectDefinitionLoader::new(loader.as_mut())
                .load_objdef_directory(
                    features.compile_options(),
                    Path::new(&core),
                    Default::default(),
                )
                .expect("load core");
            loader.commit().unwrap();
        }
        let wizard = Obj::mk_id(2);
        let scheduler = Scheduler::new(
            semver::Version::new(0, 1, 0),
            Box::new(db.clone()),
            Box::new(NoopTasksDb {}),
            Arc::new(Config {
                deterministic: DeterministicMode::on(),
                features: Arc::new(features.clone()),
                ..Config::default()
            }),
            Arc::new(NoopSystemControl::default()),
            None,
            None,
        );
        scheduler
            .assign_wallet(wizard, moor_common::envelope::Address([0xab; 20]))
            .expect("genesis wallet");
        let mut driver = scheduler
            .start_block_driver(Arc::new(Factory))
            .expect("start block driver");
        driver.set_state_root_at_end_block(false);
        // The harness core's #6 (a thing) and #2 (a room) are the stripped core's $thing and
        // $first_room; every line runs as the stripped core's wizard.
        let lines: Vec<BlockInput> = std::fs::read_to_string(&log)
            .expect("read log")
            .lines()
            .filter(|l| l.starts_with("#3 ") || l.starts_with("#4 "))
            .filter_map(|l| l.split_once(' ').map(|(_, rest)| rest.to_string()))
            .map(|line| match line.strip_prefix(';') {
                Some(code) => eval(
                    wizard,
                    &code.replace("#6", "$thing").replace("#2", "$first_room"),
                ),
                None => BlockInput::Command {
                    player: wizard,
                    command: line,
                },
            })
            .collect();
        assert!(!lines.is_empty(), "no commands in {log}");
        let started = Instant::now();
        let mut height = 0;
        let mut ok = 0usize;
        let mut sent = 0usize;
        while sent < total {
            height += 1;
            let n = per_block.min(total - sent);
            let inputs: Vec<BlockInput> = (sent..sent + n)
                .map(|i| lines[i % lines.len()].clone())
                .collect();
            let out = run(&mut driver, height, &inputs);
            ok += out
                .outcomes
                .iter()
                .filter(|o| matches!(o.result, Some(Ok(_))))
                .count();
            sent += n;
        }
        let execute = started.elapsed();
        let started = Instant::now();
        let original = driver.state_root().expect("root");
        let root_time = started.elapsed();
        let restored = export_and_restore(&driver, height);
        assert_eq!(restored.root, original, "restored root");
        let mut copy = driver_on(&restored.db, &features);
        let again = export_and_restore(&copy, height);
        assert!(again.bytes == restored.bytes, "re-export differs");
        // One more block on both.
        driver.set_state_root_at_end_block(true);
        copy.set_state_root_at_end_block(true);
        let next: Vec<BlockInput> = lines.iter().take(per_block).cloned().collect();
        let a = run(&mut driver, height + 1, &next);
        let b = run(&mut copy, height + 1, &next);
        assert_eq!(root(&a), root(&b), "after one more block");
        let entries: u64 = original.relations.iter().map(|r| r.entries).sum();
        println!(
            "CHECKPOINT commands={sent} ok={ok} blocks={height} execute={:.1}s root={:?} \
             entries={entries} bytes={} export={:?} parse={:?} import={:?} root={}",
            execute.as_secs_f64(),
            root_time,
            restored.bytes.len(),
            restored.export,
            restored.parse,
            restored.import,
            original.root_hex()
        );
        for r in &original.relations {
            println!("  {:<26} {:>8} entries", r.name, r.entries);
        }
        assert_eq!(original.relations.len(), RELATIONS.len());
        copy.shutdown().ok();
        driver.shutdown().ok();
        deterministic::disable();
    }
}
