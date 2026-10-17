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

    struct Factory;
    impl SessionFactory for Factory {
        fn mk_background_session(
            self: Arc<Self>,
            _player: &Obj,
        ) -> Result<Arc<dyn Session>, SessionError> {
            Ok(Arc::new(NoopClientSession::new()))
        }
    }

    /// A fresh database and a deterministic scheduler under a block driver. Holds the process lock.
    struct World {
        driver: Option<BlockDriver>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl World {
        fn start() -> Self {
            let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
            assert!(scheduler.is_manual());
            let driver = scheduler
                .start_block_driver(Arc::new(Factory))
                .expect("start block driver");
            Self {
                driver: Some(driver),
                _guard: guard,
            }
        }

        fn driver(&mut self) -> &mut BlockDriver {
            self.driver.as_mut().expect("driver")
        }

        fn block(&mut self, height: u64, evals: &[&str]) -> BlockOutput {
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

    fn block(height: u64) -> BlockContext {
        BlockContext {
            height,
            timestamp: 1_700_000_000 + 60 * height,
            seed: [height as u8; 32],
        }
    }

    /// The `notify` texts of a batch, in batch order.
    fn texts(events: &[BlockEvent]) -> Vec<String> {
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
    fn canonical(events: &[BlockEvent]) -> String {
        events
            .iter()
            .map(|e| {
                let body = match &e.kind {
                    BlockEventKind::Narrative(ev) | BlockEventKind::Logged(ev) => describe(ev),
                    BlockEventKind::System(msg) => format!("system {msg}"),
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
        assert_eq!(indices, [1, 1, 1, 1, 2]);
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
    struct OrderSession {
        order: Arc<StdMutex<Vec<String>>>,
        buf: StdMutex<Vec<String>>,
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
