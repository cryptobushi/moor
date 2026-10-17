//! PROTOTYPE (throwaway). Boots mooR in-process from an objdef directory, feeds a command log one
//! command at a time, and after each command prints one JSON line with the raw (un-hashed) state
//! dump and the ordered event stream. Hashing/diffing is done by the Python driver.
//!
//! usage: replay-worker <core-objdef-dir> <command-log> [settle_ms]
//! Log lines: `#<player> <command>`; `#<player> ;<moo statements>` evals; `# ...` comments.

use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, UNIX_EPOCH},
};

use moor_common::{
    model::CommitResult,
    tasks::{
        ConnectionDetails, Event, NarrativeEvent, NoopSystemControl, Session, SessionError,
        SessionFactory,
    },
};
use moor_compiler::to_literal;
use moor_db::{Database, DatabaseConfig, TxDB};
use moor_kernel::{
    config::Config,
    tasks::{NoopTasksDb, scheduler::Scheduler},
    testing::scheduler_test_utils,
};
use moor_var::{Obj, Symbol, Var, SYSTEM_OBJECT};
use serde_json::{Value, json};
use uuid::Uuid;

/// One committed output record, tagged with the step that was current when it committed.
struct Rec {
    step: usize,
    norm: Value,
    raw: Value,
}

#[derive(Default)]
struct Sink {
    step: usize,
    recs: Vec<Rec>,
}

struct CaptureSession {
    sink: Arc<Mutex<Sink>>,
    buf: Mutex<Vec<(Value, Value)>>,
}

impl CaptureSession {
    fn new(sink: Arc<Mutex<Sink>>) -> Self {
        Self { sink, buf: Mutex::new(vec![]) }
    }
}

fn describe(kind: &str, player: &Obj, ev: &NarrativeEvent) -> (Value, Value) {
    let body = match ev.event() {
        Event::Notify { value, content_type, no_flush, no_newline, metadata } => json!({
            "notify": to_literal(&value),
            "content_type": content_type.map(|s| s.as_str().to_string()),
            "no_flush": no_flush, "no_newline": no_newline,
            "metadata": metadata.map(|m| m.iter().map(|(k, v)| format!("{}={}", k.as_str(), to_literal(v))).collect::<Vec<_>>()),
        }),
        other => json!({ "other": format!("{other:?}") }),
    };
    let norm = json!({ "kind": kind, "player": player.to_string(), "author": to_literal(ev.author()), "event": body });
    let ts = ev.timestamp().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0);
    let raw = json!({ "norm": norm, "event_id": ev.event_id().to_string(), "timestamp_us": ts });
    (norm, raw)
}

impl Session for CaptureSession {
    fn commit(&self) -> Result<(), SessionError> {
        let mut buf = self.buf.lock().unwrap();
        let mut sink = self.sink.lock().unwrap();
        let step = sink.step;
        for (norm, raw) in buf.drain(..) {
            sink.recs.push(Rec { step, norm, raw });
        }
        Ok(())
    }
    fn rollback(&self) -> Result<(), SessionError> {
        self.buf.lock().unwrap().clear();
        Ok(())
    }
    fn fork(self: Arc<Self>) -> Result<Arc<dyn Session>, SessionError> {
        Ok(Arc::new(CaptureSession::new(self.sink.clone())))
    }
    fn request_input(&self, _p: Obj, _id: Uuid, _m: Option<Vec<(Symbol, Var)>>) -> Result<(), SessionError> {
        Err(SessionError::DeliveryError)
    }
    fn send_event(&self, player: Obj, event: Box<NarrativeEvent>) -> Result<(), SessionError> {
        self.buf.lock().unwrap().push(describe("event", &player, &event));
        Ok(())
    }
    fn log_event(&self, player: Obj, event: Box<NarrativeEvent>) -> Result<(), SessionError> {
        self.buf.lock().unwrap().push(describe("log_event", &player, &event));
        Ok(())
    }
    fn send_system_msg(&self, player: Obj, msg: &str) -> Result<(), SessionError> {
        // Not spooled by the engine: goes straight to the sink.
        let norm = json!({ "kind": "system", "player": player.to_string(), "msg": msg });
        let mut sink = self.sink.lock().unwrap();
        let step = sink.step;
        sink.recs.push(Rec { step, raw: norm.clone(), norm });
        Ok(())
    }
    fn notify_shutdown(&self, _m: Option<String>) -> Result<(), SessionError> { Ok(()) }
    fn connection_name(&self, player: Obj) -> Result<String, SessionError> { Ok(format!("player-{player}")) }
    fn disconnect(&self, _p: Obj) -> Result<(), SessionError> { Ok(()) }
    fn connected_players(&self, _all: bool) -> Result<Vec<Obj>, SessionError> { Ok(vec![]) }
    fn connected_seconds(&self, _p: Obj) -> Result<f64, SessionError> { Ok(0.0) }
    fn idle_seconds(&self, _p: Obj) -> Result<f64, SessionError> { Ok(0.0) }
    fn connections(&self, _p: Option<Obj>) -> Result<Vec<Obj>, SessionError> {
        Err(SessionError::NoConnectionForPlayer(SYSTEM_OBJECT))
    }
    fn connection_details(&self, _p: Option<Obj>) -> Result<Vec<ConnectionDetails>, SessionError> {
        Err(SessionError::NoConnectionForPlayer(SYSTEM_OBJECT))
    }
    fn connection_attributes(&self, _o: Obj) -> Result<Var, SessionError> { Ok(moor_var::v_list(&[])) }
    fn set_connection_attribute(&self, _c: Obj, _k: Symbol, _v: Var) -> Result<(), SessionError> { Ok(()) }
}

struct Factory(Arc<Mutex<Sink>>);
impl SessionFactory for Factory {
    fn mk_background_session(self: Arc<Self>, _p: &Obj) -> Result<Arc<dyn Session>, SessionError> {
        Ok(Arc::new(CaptureSession::new(self.0.clone())))
    }
}

/// Canonical objdef dump: files sorted by name, concatenated as {name: text}.
fn objdef_dump(db: &TxDB) -> Value {
    let dir = tempfile::tempdir().expect("tempdir");
    let snap = db.create_snapshot().expect("snapshot");
    moor_objdef::dump_snapshot_object_definitions(snap.as_ref(), dir.path()).expect("dump");
    let mut files = std::collections::BTreeMap::new();
    collect(dir.path(), dir.path(), &mut files);
    json!(files)
}

fn collect(root: &Path, dir: &Path, out: &mut std::collections::BTreeMap<String, String>) {
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(root, &p, out);
        } else if p.file_name().is_some_and(|n| n == "manifest.json") {
            // manifest carries wall-clock epochs and timings; not state.
        } else {
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().to_string();
            out.insert(rel, fs::read_to_string(&p).unwrap_or_default());
        }
    }
}

const PROBE: &str = r#"
r = {};
for i in [0..toint(max_object())]
  o = toobj(i);
  if (valid(o))
    try lm = o.last_move; except (ANY) lm = "none"; endtry
    r = {@r, {o, o.name, o.owner, parent(o), o.location, o.contents, lm}};
  endif
endfor
return {max_object(), r, players(), children(#6)};
"#;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (core, log) = (&args[1], &args[2]);
    let settle = Duration::from_millis(args.get(3).and_then(|s| s.parse().ok()).unwrap_or(150));

    let features = Arc::new(moor_kernel::config::FeaturesConfig::default());
    let (db, _) = TxDB::try_open(None, DatabaseConfig::default()).expect("open db");
    {
        let mut loader = db.loader_client().unwrap();
        moor_objdef::ObjectDefinitionLoader::new(loader.as_mut())
            .load_objdef_directory(features.compile_options(), Path::new(core), Default::default())
            .expect("load core");
        assert!(matches!(loader.commit(), Ok(CommitResult::Success { .. })));
    }
    let sink = Arc::new(Mutex::new(Sink::default()));
    let scheduler = Scheduler::new(
        semver::Version::new(0, 1, 0),
        Box::new(db.clone()) as Box<dyn Database>,
        Box::new(NoopTasksDb {}),
        Arc::new(Config { features: features.clone(), ..Config::default() }),
        Arc::new(NoopSystemControl::default()),
        None,
        None,
    );
    let client = scheduler.client().unwrap();
    let handle = scheduler.start(Arc::new(Factory(sink.clone()))).expect("start");

    let wizard = Obj::mk_id(3);
    let mut cmds: Vec<(Option<(Obj, String)>, String)> = vec![(None, "# boot".into())];
    for line in fs::read_to_string(log).unwrap().lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("##") { continue; }
        let rest = line.strip_prefix('#').unwrap();
        let (num, cmd) = rest.split_once(' ').unwrap_or((rest, ""));
        let p = Obj::mk_id(num.parse().expect("player id"));
        cmds.push((Some((p, cmd.to_string())), line.to_string()));
    }

    let mut emitted = 0usize;
    for (step, (c, label)) in cmds.iter().enumerate() {
        sink.lock().unwrap().step = step;
        let result = match c {
            None => "boot".to_string(),
            Some((p, cmd)) => {
                let session: Arc<dyn Session> = Arc::new(CaptureSession::new(sink.clone()));
                let r = if let Some(code) = cmd.strip_prefix(';') {
                    scheduler_test_utils::call_eval_with_features(client.clone(), session, p, code.to_string(), features.clone())
                } else {
                    scheduler_test_utils::call_command(client.clone(), session, p, cmd)
                };
                match r { Ok(v) => to_literal(&v), Err(e) => format!("ERR {e:?}") }
            }
        };
        std::thread::sleep(settle);
        let probe_session: Arc<dyn Session> = Arc::new(CaptureSession::new(sink.clone()));
        let probe = scheduler_test_utils::call_eval_with_features(
            client.clone(), probe_session, &wizard, PROBE.to_string(), features.clone(),
        )
        .map(|v| to_literal(&v))
        .unwrap_or_else(|e| format!("ERR {e:?}"));
        let (norm, raw): (Vec<Value>, Vec<Value>) = {
            let s = sink.lock().unwrap();
            let r = &s.recs[emitted..];
            // Records from the settle window of this step; late async records land in later steps.
            (r.iter().map(|x| json!({"step": x.step, "rec": x.norm})).collect(),
             r.iter().map(|x| json!({"step": x.step, "rec": x.raw})).collect())
        };
        emitted += norm.len();
        let line = json!({
            "step": step, "label": label, "result": result,
            "probe": probe, "objdef": objdef_dump(&db),
            "events": norm, "events_raw": raw,
        });
        println!("{line}");
    }
    client.submit_shutdown("done").ok();
    let _ = handle.join();
}
