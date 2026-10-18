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

//! Read-only state routes of a sequencer (fork API request R3; spec
//! `docs/spec/block-format-v0.md` §14), so a replayer can name the relation and the key a
//! mismatching block differs in without a second verifier.
//!
//! A minimal HTTP/1.1 listener on `--sequencer-read-addr`, std only, one request at a time. Routes
//! (all `GET`, no authentication; bind a loopback address):
//!
//! - `/v1/rw/state/{height}`: JSON `{height, state_root, relations: [{name, hash, entries}]}`, the
//!   per-relation hashes the sequencer recorded when it sealed (or re-executed) that block. Any
//!   height the log holds; 404 for one recorded before the log existed.
//! - `/v1/rw/state/{height}/{relation}`: the relation's canonical entries, one `<key hex> <value
//!   hex>` line each in canonical order (the replayer's dump format). **Only the sealed tip** can
//!   be dumped live, because the database cannot go back: the block thread serves it between two
//!   blocks, when the committed state is exactly the tip's. Any other height is `409` with the
//!   current tip; for history, replay with `moorc ... replay-sink --stop-at H --dump-dir D`.
//!   `tip` in place of the height dumps whatever the sealed tip is, and the answer's `X-Rw-Height`
//!   header says which height that was.
//! - `/v1/rw/genesis`: the genesis record (`genesis.cbor`).

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::Mutex,
    thread::JoinHandle,
    time::Duration,
};

use flume::Sender;
use moor_block::durable::{RelationHash, RelationLog};
use moor_db::state_root::{CanonicalRelation, RELATIONS, RelationDigest, StateRoot, hex};
use tracing::{debug, warn};

use super::SequencerHandle;

/// How long a dump request waits for the block thread (it answers once per block).
const DUMP_TIMEOUT: Duration = Duration::from_secs(15);

/// A live dump request, served by the block thread between blocks.
pub struct StateRequest {
    /// The height the caller wants; only the sealed tip can be served. `None`: the sealed tip,
    /// whatever it is.
    pub height: Option<u64>,
    pub relation: String,
    pub reply: Sender<StateReply>,
}

/// The block thread's answer.
#[derive(Debug)]
pub enum StateReply {
    /// The relation's canonical entries as `key-hex value-hex` lines, after the block at `height`.
    Entries {
        height: u64,
        body: Vec<u8>,
    },
    /// The requested height is not the sealed tip.
    NotTip {
        tip: u64,
    },
    /// No such relation.
    UnknownRelation,
    Failed(String),
}

/// The text form of a canonical relation: one `<key hex> <value hex>` line per entry.
#[must_use]
pub fn entries_text(relation: &CanonicalRelation) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in &relation.entries {
        out.extend_from_slice(hex(k).as_bytes());
        out.push(b' ');
        out.extend_from_slice(hex(v).as_bytes());
        out.push(b'\n');
    }
    out
}

/// The JSON manifest of one block's recorded relation hashes. The state root is recomputed from
/// them (null when the relation list is not the one this build knows).
#[must_use]
pub fn manifest_json(height: u64, relations: &[RelationHash]) -> String {
    let digests: Option<Vec<RelationDigest>> = relations
        .iter()
        .map(|r| {
            RELATIONS
                .iter()
                .find(|name| **name == r.name)
                .map(|name| RelationDigest {
                    name,
                    hash: r.hash,
                    entries: r.entries,
                })
        })
        .collect();
    let root = digests
        .map(|d| format!("\"{}\"", hex(&StateRoot::from_relations(d).root)))
        .unwrap_or_else(|| "null".to_string());
    let list: Vec<String> = relations
        .iter()
        .map(|r| {
            format!(
                "{{\"name\":\"{}\",\"hash\":\"{}\",\"entries\":{}}}",
                r.name,
                hex(&r.hash),
                r.entries
            )
        })
        .collect();
    format!(
        "{{\"height\":{height},\"state_root\":{root},\"relations\":[{}]}}\n",
        list.join(",")
    )
}

struct Response {
    status: &'static str,
    content_type: &'static str,
    /// The height a dump is of (`X-Rw-Height`).
    height: Option<u64>,
    body: Vec<u8>,
}

impl Response {
    fn json(status: &'static str, body: String) -> Self {
        Self {
            status,
            content_type: "application/json",
            height: None,
            body: body.into_bytes(),
        }
    }

    fn error(status: &'static str, message: &str) -> Self {
        Self::json(status, format!("{{\"error\":{message:?}}}\n"))
    }
}

struct Service {
    handle: SequencerHandle,
    state_dir: PathBuf,
    /// The relation log as last read; reopened when a height is missing from it.
    log: Mutex<Option<RelationLog>>,
}

impl Service {
    fn route(&self, path: &str) -> Response {
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        match parts.as_slice() {
            ["v1", "rw", "genesis"] => match std::fs::read(self.state_dir.join("genesis.cbor")) {
                Ok(bytes) => Response {
                    status: "200 OK",
                    content_type: "application/cbor",
                    height: None,
                    body: bytes,
                },
                Err(_) => Response::error("404 Not Found", "this sequencer has no genesis record"),
            },
            ["v1", "rw", "state", height] => match height.parse() {
                Ok(height) => self.manifest(height),
                Err(_) => Response::error("400 Bad Request", "the height is not a number"),
            },
            ["v1", "rw", "state", "tip", relation] => self.dump(None, relation),
            ["v1", "rw", "state", height, relation] => match height.parse() {
                Ok(height) => self.dump(Some(height), relation),
                Err(_) => Response::error("400 Bad Request", "the height is not a number"),
            },
            _ => Response::error("404 Not Found", "no such route"),
        }
    }

    fn recorded(&self, height: u64) -> Result<Option<Vec<RelationHash>>, String> {
        let mut cached = self.log.lock().unwrap_or_else(|e| e.into_inner());
        for attempt in 0..2 {
            if let Some(log) = cached.as_ref()
                && let Some(found) = log.get(height).map_err(|e| e.to_string())?
            {
                return Ok(Some(found));
            }
            if attempt == 0 {
                *cached = RelationLog::open_read_only(self.state_dir.join("blocks"))
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(None)
    }

    fn manifest(&self, height: u64) -> Response {
        match self.recorded(height) {
            Ok(Some(relations)) => Response::json("200 OK", manifest_json(height, &relations)),
            Ok(None) => Response::error(
                "404 Not Found",
                "no relation hashes are recorded for this height",
            ),
            Err(e) => Response::error("500 Internal Server Error", &e),
        }
    }

    fn dump(&self, height: Option<u64>, relation: &str) -> Response {
        let (reply, answer) = flume::bounded(1);
        let request = StateRequest {
            height,
            relation: relation.to_string(),
            reply,
        };
        if self.handle.state_requests.send(request).is_err() {
            return Response::error("503 Service Unavailable", "the sequencer has stopped");
        }
        match answer.recv_timeout(DUMP_TIMEOUT) {
            Ok(StateReply::Entries { height, body }) => Response {
                status: "200 OK",
                content_type: "text/plain",
                height: Some(height),
                body,
            },
            Ok(StateReply::NotTip { tip }) => Response::json(
                "409 Conflict",
                format!("{{\"error\":\"only the sealed tip can be dumped live\",\"tip\":{tip}}}\n"),
            ),
            Ok(StateReply::UnknownRelation) => Response::error("404 Not Found", "no such relation"),
            Ok(StateReply::Failed(e)) => Response::error("500 Internal Server Error", &e),
            Err(_) => Response::error("504 Gateway Timeout", "the block thread did not answer"),
        }
    }
}

fn handle_connection(service: &Service, mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 8192 {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut line = text.lines().next().unwrap_or("").split_whitespace();
    let response = match (line.next(), line.next()) {
        (Some("GET"), Some(path)) => service.route(path.split('?').next().unwrap_or(path)),
        (Some(_), Some(_)) => Response::error("405 Method Not Allowed", "GET only"),
        _ => Response::error("400 Bad Request", "not an HTTP request"),
    };
    let height = response
        .height
        .map(|h| format!("X-Rw-Height: {h}\r\n"))
        .unwrap_or_default();
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\n{height}Content-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    if stream
        .write_all(header.as_bytes())
        .and_then(|()| stream.write_all(&response.body))
        .is_err()
    {
        debug!("state route client went away");
    }
}

/// Serve the state routes on `addr` until the sequencer stops. Returns the bound address (useful
/// with port 0) and the listener thread.
pub fn serve(
    addr: &str,
    handle: SequencerHandle,
    state_dir: &Path,
) -> std::io::Result<(std::net::SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let bound = listener.local_addr()?;
    let service = Service {
        handle,
        state_dir: state_dir.to_path_buf(),
        log: Mutex::new(None),
    };
    let thread = std::thread::Builder::new()
        .name("rw-seq-state".into())
        .spawn(move || {
            while !service.handle.is_stopping() {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        handle_connection(&service, stream);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(e) => {
                        warn!(error = %e, "state route accept failed");
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
            }
        })?;
    Ok((bound, thread))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicBool};

    use super::super::SequencerStatus;

    /// A handle whose state requests go to `requests`.
    fn handle(requests: Sender<StateRequest>) -> SequencerHandle {
        let (inputs, _queue) = flume::unbounded();
        SequencerHandle {
            inputs,
            state_requests: requests,
            status: Arc::new(SequencerStatus::default()),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    fn get(addr: std::net::SocketAddr, request: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).unwrap();
        let status = raw.split_whitespace().nth(1).unwrap().parse().unwrap();
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    fn get_path(addr: std::net::SocketAddr, path: &str) -> (u16, String) {
        get(addr, &format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n"))
    }

    fn digests() -> Vec<RelationHash> {
        RELATIONS
            .iter()
            .enumerate()
            .map(|(i, name)| RelationHash {
                name: (*name).to_string(),
                hash: [i as u8; 32],
                entries: i as u64,
            })
            .collect()
    }

    /// A state directory with relation hashes for heights 3 and 5, served; the "block thread"
    /// answers dumps for a sealed tip of 5.
    fn serving() -> (tempfile::TempDir, std::net::SocketAddr, SequencerHandle) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("blocks")).unwrap();
        let mut log = RelationLog::open(dir.path().join("blocks")).unwrap();
        log.put(3, &digests()).unwrap();
        log.put(5, &digests()).unwrap();
        let (requests, queue) = flume::unbounded::<StateRequest>();
        std::thread::spawn(move || {
            for r in queue {
                let answer = if r.height.is_some_and(|h| h != 5) {
                    StateReply::NotTip { tip: 5 }
                } else if !RELATIONS.contains(&r.relation.as_str()) {
                    StateReply::UnknownRelation
                } else {
                    StateReply::Entries {
                        height: 5,
                        body: b"01 02\n".to_vec(),
                    }
                };
                let _ = r.reply.send(answer);
            }
        });
        let handle = handle(requests);
        let (addr, _thread) = serve("127.0.0.1:0", handle.clone(), dir.path()).unwrap();
        (dir, addr, handle)
    }

    #[test]
    fn the_manifest_lists_the_recorded_relation_hashes_and_the_recomputed_root() {
        let (_dir, addr, handle) = serving();
        let (status, body) = get_path(addr, "/v1/rw/state/3");
        handle.stop();
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let root = StateRoot::from_relations(
            digests()
                .iter()
                .zip(RELATIONS)
                .map(|(d, name)| RelationDigest {
                    name,
                    hash: d.hash,
                    entries: d.entries,
                })
                .collect(),
        );
        assert_eq!(
            (
                json["height"].as_u64(),
                json["state_root"].as_str(),
                json["relations"].as_array().map(Vec::len)
            ),
            (Some(3), Some(hex(&root.root).as_str()), Some(14))
        );
    }

    #[test]
    fn a_height_without_recorded_hashes_is_404() {
        let (_dir, addr, handle) = serving();
        let (status, _) = get_path(addr, "/v1/rw/state/4");
        handle.stop();
        assert_eq!(status, 404);
    }

    #[test]
    fn a_relation_dump_of_the_sealed_tip_is_served_as_entry_lines() {
        let (_dir, addr, handle) = serving();
        let (status, body) = get_path(addr, "/v1/rw/state/5/object_flags");
        handle.stop();
        assert_eq!((status, body.as_str()), (200, "01 02\n"));
    }

    #[test]
    fn tip_dumps_whatever_the_sealed_tip_is_and_names_its_height() {
        let (_dir, addr, handle) = serving();
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .write_all(b"GET /v1/rw/state/tip/object_flags HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).unwrap();
        handle.stop();
        assert!(
            raw.contains("X-Rw-Height: 5\r\n") && raw.ends_with("01 02\n"),
            "{raw}"
        );
    }

    #[test]
    fn a_dump_of_a_past_height_is_409_with_the_tip() {
        let (_dir, addr, handle) = serving();
        let (status, body) = get_path(addr, "/v1/rw/state/3/object_flags");
        handle.stop();
        assert_eq!((status, body.contains("\"tip\":5")), (409, true));
    }

    #[test]
    fn an_unknown_relation_is_404() {
        let (_dir, addr, handle) = serving();
        let (status, _) = get_path(addr, "/v1/rw/state/5/nope");
        handle.stop();
        assert_eq!(status, 404);
    }

    #[test]
    fn the_genesis_record_is_served_when_the_state_directory_has_one() {
        let (dir, addr, handle) = serving();
        assert_eq!(get_path(addr, "/v1/rw/genesis").0, 404);
        std::fs::write(dir.path().join("genesis.cbor"), b"\x01").unwrap();
        let (status, body) = get_path(addr, "/v1/rw/genesis");
        handle.stop();
        assert_eq!((status, body.as_bytes()), (200, &b"\x01"[..]));
    }

    #[test]
    fn only_get_is_served_and_unknown_routes_are_404() {
        let (_dir, addr, handle) = serving();
        let post = get(addr, "POST /v1/rw/state/3 HTTP/1.1\r\nHost: x\r\n\r\n").0;
        let other = get_path(addr, "/v1/other").0;
        handle.stop();
        assert_eq!((post, other), (405, 404));
    }

    #[test]
    fn a_stopped_sequencer_answers_503_to_a_dump() {
        let (requests, queue) = flume::unbounded::<StateRequest>();
        drop(queue);
        let dir = tempfile::tempdir().unwrap();
        let handle = handle(requests);
        let (addr, _thread) = serve("127.0.0.1:0", handle.clone(), dir.path()).unwrap();
        let (status, _) = get_path(addr, "/v1/rw/state/1/object_flags");
        handle.stop();
        assert_eq!(status, 503);
    }

    #[test]
    fn entries_text_is_key_space_value_per_line() {
        let relation = CanonicalRelation {
            name: "object_flags",
            entries: vec![(vec![1, 2], vec![0xff]), (vec![3], vec![])],
        };
        assert_eq!(entries_text(&relation), b"0102 ff\n03 \n");
    }
}
