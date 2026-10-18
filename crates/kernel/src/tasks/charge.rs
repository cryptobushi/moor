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

//! The engine side of the core's `charge(player, meter, phase)` hook (RuneWorld ADR 0007
//! decision 3, core contract in `docs/research/s1-10-report.md`).
//!
//! # Reserve
//!
//! After admission has verified an envelope and before its task runs, [`Scheduler::reserve_charge`]
//! decides the charged world (the player's current world: the nearest `#0.world` descendant on
//! the location chain, else `#0`) and whether any policy is installed. When neither `#0:charge`
//! nor the world's `charge` differs from the core default (sponsor-all), nothing runs: the result
//! is identical, so the engine skips the call. Otherwise one system task runs inside admission's
//! transaction (it inherits the transaction that holds the nonce, so the nonce and anything the
//! policy wrote commit together, exactly as the nonce survives an aborted command):
//!
//! ```text
//! leaving = w:command_leaves(who, pc)                  ; the core's free-leave classifier
//! meter   = ['kind, 'world, 'ticks -> engine maximum, 'log_bytes, 'leaving]
//! result  = #0:run_charge(who, meter, 'reserve)        ; #0:charge, then the world's unless leaving
//! ```
//!
//! An error, a malformed result, or exhausting the fixed policy tick ceiling is a denial. `allow`
//! sets the command's tick ceiling to `min(ceiling, engine maximum)`.
//!
//! # Settle
//!
//! [`BlockDriver::end_block`] calls `#0:run_charge(who, meter, 'settle)` once per charged input, in
//! command-index order, in one system task per world, before the state root, then writes
//! `meter_total` natively on `#0`, each charged world and each charged player.
//!
//! # Identity check
//!
//! "Overridden" means the resolved verb's program differs from the core default's code. The
//! comparison ignores line-number tables, so comments in the verb do not matter.

use crate::tasks::{
    envelope_admission::Admitted,
    meter,
    scheduler::Scheduler,
};
use moor_block::MeterKind;
use moor_common::{
    deterministic,
    model::{HasUuid, TaskPermissions, VerbLookup, WorldState},
    tasks::{NoopClientSession, SchedulerError, Session},
};
use moor_compiler::{CompileOptions, Program, compile};
use moor_var::{
    Associative, NOTHING, Obj, SYSTEM_OBJECT, Sequence, Symbol, Var, program::ProgramType, v_bool,
    v_int, v_list, v_map, v_obj, v_str, v_sym,
};
use std::sync::{Arc, Mutex, OnceLock};

/// The code of the core's default `charge` (`$world:charge` and `#0:charge`).
const DEFAULT_CHARGE_SOURCE: &str = r#"
const {who, meter, phase} = args;
typeof(meter) == TYPE_MAP && maphaskey(meter, 'ticks) || raise(E_INVARG, "charge needs a meter with ticks.");
return $world:charge_allow(meter['ticks]);
"#;

/// The reserve task: classify, build the meter, call the core's entry. Free variables (`who`,
/// `w`, `pc`, `kind`, `ceiling`, `log_bytes`, `check_leave`) are bound by the engine.
const RESERVE_SOURCE: &str = r#"
leaving = 0;
if (check_leave && valid(w))
  leaving = `w:command_leaves(who, pc) ! ANY => 0' ? true | false;
endif
m = ['kind -> kind, 'world -> w, 'ticks -> ceiling, 'log_bytes -> log_bytes, 'leaving -> leaving];
return {leaving, #0:run_charge(who, m, 'reserve)};
"#;

/// The settle task: `entries` is `{{player, meter}, ...}` in command-index order.
const SETTLE_SOURCE: &str = r#"
for entry in (entries)
  `#0:run_charge(entry[1], entry[2], 'settle) ! ANY => 0';
endfor
return 1;
"#;

fn compiled(cell: &'static OnceLock<Program>, source: &str) -> &'static Program {
    cell.get_or_init(|| {
        compile(source, CompileOptions::default()).expect("the engine's charge sources compile")
    })
}

fn default_charge() -> &'static Program {
    static CELL: OnceLock<Program> = OnceLock::new();
    compiled(&CELL, DEFAULT_CHARGE_SOURCE)
}

fn reserve_program() -> &'static Program {
    static CELL: OnceLock<Program> = OnceLock::new();
    compiled(&CELL, RESERVE_SOURCE)
}

fn settle_program() -> &'static Program {
    static CELL: OnceLock<Program> = OnceLock::new();
    compiled(&CELL, SETTLE_SOURCE)
}

/// Whether `program` is the same code as `reference`, ignoring line-number tables.
fn same_code(program: &Program, reference: &Program) -> bool {
    if std::ptr::eq(&*program.0, &*reference.0) {
        return true;
    }
    let mut a = (*program.0).clone();
    let mut b = (*reference.0).clone();
    for p in [&mut a, &mut b] {
        p.line_number_spans.clear();
        p.fork_line_number_spans.clear();
        p.source_declarations = None;
    }
    a == b
}

/// Programs already verified to be the default, by allocation. A verb edit installs a new program
/// allocation, so a stale entry never matches.
fn known_defaults() -> &'static Mutex<Vec<Program>> {
    static KNOWN: OnceLock<Mutex<Vec<Program>>> = OnceLock::new();
    KNOWN.get_or_init(|| Mutex::new(Vec::new()))
}

fn is_default_program(program: &Program) -> bool {
    let mut known = known_defaults().lock().unwrap_or_else(|e| e.into_inner());
    if known.iter().any(|k| std::ptr::eq(&*k.0, &*program.0)) {
        return true;
    }
    if same_code(program, default_charge()) {
        if known.len() >= 64 {
            known.clear();
        }
        known.push(program.clone());
        return true;
    }
    false
}

/// What reserving a command's charge decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reservation {
    /// The charged world (`#0` when the player is in none).
    pub world: Obj,
    /// The core classified the command as only leaving the world.
    pub leaving: bool,
    /// A policy is installed, so the hook ran (and settlement will run).
    pub active: bool,
    /// The command's tick ceiling, already clamped to the engine maximum.
    pub ceiling: u64,
    /// Set when the hook denied (or failed).
    pub denied: Option<String>,
}

impl Reservation {
    fn skipped(world: Obj, ceiling: u64) -> Self {
        Self {
            world,
            leaving: false,
            active: false,
            ceiling,
            denied: None,
        }
    }
}

/// The system principal: the owner of `#0`.
fn system_perms(ws: &dyn WorldState) -> Option<TaskPermissions> {
    let principal = ws.owner_of(&SYSTEM_OBJECT).ok()?;
    let flags = ws.flags_of(&principal).ok()?;
    Some(TaskPermissions::new(principal, flags))
}

/// `$world:containing(player.location)`: the nearest instance of `class` at or above the
/// player's location, else `NOTHING`.
fn current_world(ws: &dyn WorldState, perms: &TaskPermissions, class: &Obj, player: &Obj) -> Obj {
    let mut at = ws.location_of(perms, player).unwrap_or(NOTHING);
    for _ in 0..256 {
        if at == NOTHING || !ws.valid(&at).unwrap_or(false) {
            break;
        }
        if ws.isa(&at, class).unwrap_or(false) {
            return at;
        }
        at = ws.location_of(perms, &at).unwrap_or(NOTHING);
    }
    NOTHING
}

/// Whether `charge` resolved on `obj` is something other than the core default.
fn charge_overridden(ws: &dyn WorldState, perms: &TaskPermissions, obj: &Obj) -> bool {
    let Ok(Some(def)) = ws.lookup_verb(perms, VerbLookup::method(obj, Symbol::mk("charge"))) else {
        // No `charge` at all: nothing to call.
        return false;
    };
    let Ok((ProgramType::MooR(program), _)) = ws.retrieve_verb(perms, &def.location(), def.uuid())
    else {
        return true;
    };
    !is_default_program(&program)
}

fn map_get(map: &Var, key: &str) -> Option<Var> {
    map.as_map()?.get(&v_sym(key)).ok()
}

impl Scheduler {
    /// The charge hook's reservation for an admitted command or connect. Called with admission's
    /// transaction parked in `preopened_tx`; when it runs the hook, the hook's task takes it.
    pub(crate) fn reserve_charge(
        &self,
        admitted: &Admitted,
        kind: MeterKind,
        text: &str,
        log_bytes: u64,
    ) -> Reservation {
        let engine_max = self.config.deterministic.command_tick_maximum();
        let player = admitted.player();
        // Resolve the world and the policy under the admission transaction (read only).
        let (world, class, active) = {
            let guard = self.preopened_tx.lock();
            let Some(ws) = guard.as_deref() else {
                return Reservation::skipped(SYSTEM_OBJECT, engine_max);
            };
            let Some(perms) = system_perms(ws) else {
                return Reservation::skipped(SYSTEM_OBJECT, engine_max);
            };
            let class = ws
                .retrieve_property(&perms, &SYSTEM_OBJECT, Symbol::mk("world"))
                .ok()
                .and_then(|v| v.as_object());
            let Some(class) = class.filter(|c| ws.valid(c).unwrap_or(false)) else {
                return Reservation::skipped(SYSTEM_OBJECT, engine_max);
            };
            let world = current_world(ws, &perms, &class, &player);
            let charged = if world == NOTHING { SYSTEM_OBJECT } else { world };
            let active = charge_overridden(ws, &perms, &SYSTEM_OBJECT)
                || (world != NOTHING && charge_overridden(ws, &perms, &world));
            (charged, class, active)
        };
        let _ = class;
        meter::set_world(world.id().0);
        if !active {
            return Reservation::skipped(world, engine_max);
        }
        let principal = {
            let guard = self.preopened_tx.lock();
            guard
                .as_deref()
                .and_then(|ws| ws.owner_of(&SYSTEM_OBJECT).ok())
        };
        let Some(principal) = principal else {
            return Reservation::skipped(world, engine_max);
        };

        // `pc` carries what the free-leave classifier reads: the verb and its object string.
        let trimmed = text.trim();
        let (verb, rest) = trimmed
            .split_once(char::is_whitespace)
            .map_or((trimmed, ""), |(v, r)| (v, r.trim()));
        let pc = v_map(&[
            (v_sym("verb"), v_str(verb)),
            (v_sym("dobjstr"), v_str(rest)),
        ]);
        let env = vec![
            (Symbol::mk("who"), v_obj(player)),
            (
                Symbol::mk("w"),
                v_obj(if world == SYSTEM_OBJECT { NOTHING } else { world }),
            ),
            (Symbol::mk("pc"), pc),
            (Symbol::mk("kind"), v_sym(kind.name())),
            (Symbol::mk("ceiling"), v_int(engine_max as i64)),
            (Symbol::mk("log_bytes"), v_int(log_bytes as i64)),
            (
                Symbol::mk("check_leave"),
                v_bool(kind == MeterKind::Command),
            ),
        ];
        let policy_max = self.config.deterministic.policy_tick_maximum();
        meter::enter_policy(policy_max);
        let session: Arc<dyn Session> = Arc::new(NoopClientSession::new());
        let submitted = self.submit_eval_task_inner(
            principal,
            principal,
            reserve_program().clone(),
            Some(env),
            session,
        );
        let result = self.run_policy_task(submitted);
        let limit = meter::leave_policy();

        let denied = |leaving, reason: &str| Reservation {
            world,
            leaving,
            active: true,
            ceiling: engine_max,
            denied: Some(reason.to_string()),
        };
        if limit {
            return denied(false, "The charge policy exceeded its tick ceiling.");
        }
        let Some(Ok(value)) = result else {
            return denied(false, "The charge policy failed.");
        };
        let Some((leaving, verdict)) = value.as_list().and_then(|l| {
            Some((l.index(0).ok()?.is_true(), l.index(1).ok()?))
        }) else {
            return denied(false, "The charge policy returned nothing.");
        };
        if map_get(&verdict, "allow").is_some_and(|a| a.is_true()) {
            let ceiling = map_get(&verdict, "ceiling")
                .and_then(|c| c.as_integer())
                .and_then(|c| u64::try_from(c).ok())
                .map_or(engine_max, |c| c.min(engine_max));
            return Reservation {
                world,
                leaving,
                active: true,
                ceiling,
                denied: None,
            };
        }
        let reason = map_get(&verdict, "reason")
            .and_then(|r| r.as_string().map(str::to_string))
            .unwrap_or_else(|| "This command is not funded.".to_string());
        denied(leaving, &reason)
    }

    /// Run one system task to quiescence and return its result.
    fn run_policy_task(
        &self,
        submitted: Result<crate::tasks::TaskHandle, SchedulerError>,
    ) -> Option<Result<Var, SchedulerError>> {
        self.run_until_quiescent(usize::MAX);
        match submitted {
            Ok(handle) => crate::tasks::envelope_admission::take_result(&handle),
            Err(e) => Some(Err(e)),
        }
    }

    /// Settle one world: `#0:run_charge(who, meter, 'settle)` for each entry in order, in one
    /// system task. Policy errors are ignored (settlement cannot deny).
    pub(crate) fn settle_world(&self, entries: Vec<(Obj, Var)>) {
        let principal = self
            .database
            .new_world_state()
            .ok()
            .and_then(|ws| {
                let p = ws.owner_of(&SYSTEM_OBJECT).ok();
                let _ = ws.rollback();
                p
            });
        let Some(principal) = principal else { return };
        let list = v_list(
            &entries
                .into_iter()
                .map(|(who, m)| v_list(&[v_obj(who), m]))
                .collect::<Vec<_>>(),
        );
        let n = list.len().unwrap_or(1).max(1) as u64;
        let policy_max = self.config.deterministic.policy_tick_maximum();
        meter::begin_command(MeterKind::Sequencer, 0, 0, None);
        meter::enter_policy(policy_max.saturating_mul(n));
        let session: Arc<dyn Session> = Arc::new(NoopClientSession::new());
        let submitted = self.submit_eval_task_inner(
            principal,
            principal,
            settle_program().clone(),
            Some(vec![(Symbol::mk("entries"), list)]),
            session,
        );
        let _ = self.run_policy_task(submitted);
        let _ = meter::leave_policy();
    }

    /// Add `deltas` to `meter_total` on each target: ticks, log bytes and storage, with
    /// `settled_at` set to block time. Targets without the property are skipped.
    pub(crate) fn write_meter_totals(&self, deltas: &std::collections::BTreeMap<Obj, TotalsDelta>) {
        if deltas.is_empty() {
            return;
        }
        let Ok(mut ws) = self.database.new_world_state() else {
            return;
        };
        let Some(perms) = system_perms(ws.as_ref()) else {
            let _ = ws.rollback();
            return;
        };
        let now = deterministic::now_secs() as i64;
        let name = Symbol::mk("meter_total");
        for (target, d) in deltas {
            let Ok(current) = ws.retrieve_property(&perms, target, name) else {
                continue;
            };
            let get = |key: &str| {
                map_get(&current, key)
                    .and_then(|v| v.as_integer())
                    .unwrap_or(0)
            };
            let updated = v_map(&[
                (v_sym("ticks"), v_int(get("ticks") + d.ticks as i64)),
                (v_sym("log_bytes"), v_int(get("log_bytes") + d.log_bytes as i64)),
                (v_sym("storage"), v_int(get("storage") + d.storage)),
                (v_sym("settled_at"), v_int(now)),
            ]);
            let _ = ws.update_property(&perms, target, name, &updated);
        }
        let _ = ws.commit();
    }
}

/// What settlement adds to one `meter_total`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TotalsDelta {
    pub ticks: u64,
    pub log_bytes: u64,
    pub storage: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_sources_compile() {
        let _ = (default_charge(), reserve_program(), settle_program());
    }

    #[test]
    fn comments_and_line_numbers_do_not_make_an_override() {
        let commented = compile(
            &format!("\"A comment.\";\n\n{DEFAULT_CHARGE_SOURCE}"),
            CompileOptions::default(),
        )
        .unwrap();
        assert!(same_code(&commented, default_charge()));
    }

    #[test]
    fn a_different_body_is_an_override() {
        let other = compile(
            "return ['allow -> false, 'reason -> \"no\"];",
            CompileOptions::default(),
        )
        .unwrap();
        assert!(!same_code(&other, default_charge()));
    }
}
