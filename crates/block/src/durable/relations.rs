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

//! The per-relation state hashes of every sealed block (fork API request R3; ADR 0006
//! ratification note 3; spec `docs/spec/block-format-v0.md` §14).
//!
//! A header carries one `state_root`. The S0-5 root is built from one hash per relation, and a
//! verifier whose root differs can name the relation that differs only if it can see the
//! sequencer's. The sequencer therefore keeps, per sealed block, the relation hashes and entry
//! counts that fed the root, in `relations.rwr` beside the block store:
//!
//! ```text
//! file    = magic "rw/v1/relations\0" || record*          ; records framed as in `record`
//! names   = [0, [name, ...]]                              ; first record: the relation names, once
//! digests = [1, height, [[hash(32), entries], ...]]       ; in the order of `names`
//! ```
//!
//! The file is derived data: every record is reproducible by replaying the block, so it is
//! **not fsynced** and a lost tail is simply absent (a replayer then says so and falls back to the
//! keys the block wrote). Records are appended as blocks seal, or when recovery re-executes a
//! block, in any height order; a height recorded twice must agree.
//!
//! It takes no lock of its own: the writable [`RelationLog`] lives inside the [`super::BlockStore`],
//! which holds the directory lock. [`RelationLog::open_read_only`] reads a live sequencer's file
//! without a lock (a torn tail is ignored), so a verifier on the node can use it.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use super::{DurableError, record};
use crate::cbor::{Decoder, Encoder};
use crate::hash::Hash;

const MAGIC: &[u8; 16] = b"rw/v1/relations\0";
/// File name inside the block store directory.
pub const RELATIONS_FILE: &str = "relations.rwr";
const NAMES: u64 = 0;
const DIGESTS: u64 = 1;
/// More relations than any state encoding defines; a larger record is corrupt.
const MAX_RELATIONS: usize = 256;

/// One relation's digest at a sealed height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationHash {
    pub name: String,
    /// SHA-256 of the relation's canonical encoding.
    pub hash: Hash,
    /// Number of entries.
    pub entries: u64,
}

/// The per-relation hashes of sealed blocks. See the module documentation.
#[derive(Debug)]
pub struct RelationLog {
    path: PathBuf,
    /// `None` when opened read-only.
    file: Option<File>,
    names: Option<Vec<String>>,
    /// Height to the payload's offset and length.
    index: BTreeMap<u64, (u64, usize)>,
}

impl RelationLog {
    /// Open (creating if needed) the log in `dir`, cutting off a torn tail. The caller holds the
    /// directory lock.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, DurableError> {
        let path = dir.as_ref().join(RELATIONS_FILE);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .append(true)
            .open(&path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if bytes.len() < MAGIC.len() {
            if !MAGIC.starts_with(&bytes) {
                return Err(DurableError::corrupt(
                    path.display().to_string(),
                    "no magic",
                ));
            }
            file.set_len(0)?;
            file.write_all(MAGIC)?;
            bytes = MAGIC.to_vec();
        }
        let (mut log, valid_len) = Self::load(path, &bytes)?;
        if valid_len != bytes.len() {
            file.set_len(valid_len as u64)?;
        }
        log.file = Some(file);
        Ok(log)
    }

    /// Open a sequencer's log for reading, taking no lock and changing nothing. `None` if the
    /// file does not exist.
    pub fn open_read_only(dir: impl AsRef<Path>) -> Result<Option<Self>, DurableError> {
        let path = dir.as_ref().join(RELATIONS_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if bytes.len() < MAGIC.len() {
            return Ok(Some(Self {
                path,
                file: None,
                names: None,
                index: BTreeMap::new(),
            }));
        }
        Ok(Some(Self::load(path, &bytes)?.0))
    }

    fn load(path: PathBuf, bytes: &[u8]) -> Result<(Self, usize), DurableError> {
        let what = path.display().to_string();
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(DurableError::corrupt(what, "no magic"));
        }
        let scan = record::scan(bytes, MAGIC.len())
            .map_err(|reason| DurableError::corrupt(what.clone(), reason))?;
        let mut log = Self {
            path,
            file: None,
            names: None,
            index: BTreeMap::new(),
        };
        for range in &scan.payloads {
            log.load_record(&bytes[range.clone()], range.start as u64)
                .map_err(|reason| {
                    DurableError::corrupt(
                        what.clone(),
                        format!("record at {}: {reason}", range.start),
                    )
                })?;
        }
        Ok((log, scan.valid_len))
    }

    fn load_record(&mut self, payload: &[u8], offset: u64) -> Result<(), String> {
        let mut d = Decoder::new(payload);
        d.array().map_err(|e| e.to_string())?;
        match d.uint().map_err(|e| e.to_string())? {
            NAMES => {
                if self.names.is_some() {
                    return Err("second names record".into());
                }
                let names = decode_names(&mut d)?;
                d.finish().map_err(|e| e.to_string())?;
                self.names = Some(names);
            }
            DIGESTS => {
                let height = d.uint().map_err(|e| e.to_string())?;
                let n = self.names.as_ref().ok_or("digests before names")?.len();
                if d.array().map_err(|e| e.to_string())? != n {
                    return Err(format!("block {height}: not {n} digests"));
                }
                self.index.insert(height, (offset, payload.len()));
            }
            other => return Err(format!("unknown record type {other}")),
        }
        Ok(())
    }

    /// The relation names the log was written with; `None` before the first record.
    #[must_use]
    pub fn names(&self) -> Option<&[String]> {
        self.names.as_deref()
    }

    /// The heights recorded, lowest first.
    pub fn heights(&self) -> impl Iterator<Item = u64> + '_ {
        self.index.keys().copied()
    }

    /// The highest height recorded.
    #[must_use]
    pub fn last_height(&self) -> Option<u64> {
        self.index.keys().next_back().copied()
    }

    /// The relation hashes of the block at `height`, if recorded.
    pub fn get(&self, height: u64) -> Result<Option<Vec<RelationHash>>, DurableError> {
        let Some(&(offset, len)) = self.index.get(&height) else {
            return Ok(None);
        };
        let names = self.names.as_ref().ok_or_else(|| {
            DurableError::corrupt(self.path.display().to_string(), "digests without names")
        })?;
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut payload = vec![0u8; len];
        file.read_exact(&mut payload)?;
        decode_digests(&payload, names)
            .map(Some)
            .map_err(|reason| DurableError::corrupt(self.path.display().to_string(), reason))
    }

    /// Record the relation hashes of the block at `height`. A height already recorded must hold
    /// the same hashes (`Ok(false)`: nothing written); different ones are a conflict, which means
    /// two executions of one block disagreed. The relation names must be those of the first call.
    pub fn put(&mut self, height: u64, relations: &[RelationHash]) -> Result<bool, DurableError> {
        let what = || self.path.display().to_string();
        if relations.is_empty() || relations.len() > MAX_RELATIONS {
            return Err(DurableError::corrupt(
                what(),
                format!("{} relations", relations.len()),
            ));
        }
        let names: Vec<String> = relations.iter().map(|r| r.name.clone()).collect();
        match &self.names {
            Some(existing) if *existing != names => {
                return Err(DurableError::corrupt(
                    what(),
                    "the relation list differs from the one this log was started with",
                ));
            }
            _ => {}
        }
        if let Some(existing) = self.get(height)? {
            return if existing == relations {
                Ok(false)
            } else {
                Err(DurableError::RelationsConflict { height })
            };
        }
        let mut out = Vec::new();
        if self.names.is_none() {
            let mut e = Encoder::new();
            e.array(2);
            e.uint(NAMES);
            e.array(names.len());
            for name in &names {
                e.text(name);
            }
            out.extend_from_slice(&record::frame(&e.into_bytes()));
        }
        let mut e = Encoder::new();
        e.array(3);
        e.uint(DIGESTS);
        e.uint(height);
        e.array(relations.len());
        for r in relations {
            e.array(2);
            e.bytes(&r.hash);
            e.uint(r.entries);
        }
        let payload = e.into_bytes();
        let framed = record::frame(&payload);
        let file = self.file.as_mut().ok_or_else(|| {
            DurableError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "the relation log is open read-only",
            ))
        })?;
        let start = file.metadata()?.len() + out.len() as u64 + 4;
        out.extend_from_slice(&framed);
        file.write_all(&out)?;
        if self.names.is_none() {
            self.names = Some(names);
        }
        self.index.insert(height, (start, payload.len()));
        Ok(true)
    }
}

fn decode_names(d: &mut Decoder<'_>) -> Result<Vec<String>, String> {
    let n = d.array().map_err(|e| e.to_string())?;
    if n == 0 || n > MAX_RELATIONS {
        return Err(format!("{n} relation names"));
    }
    (0..n)
        .map(|_| d.text().map(str::to_owned).map_err(|e| e.to_string()))
        .collect()
}

fn decode_digests(payload: &[u8], names: &[String]) -> Result<Vec<RelationHash>, String> {
    let mut d = Decoder::new(payload);
    d.array_of(3).map_err(|e| e.to_string())?;
    d.uint().map_err(|e| e.to_string())?;
    d.uint().map_err(|e| e.to_string())?;
    d.array_of(names.len()).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        d.array_of(2).map_err(|e| e.to_string())?;
        out.push(RelationHash {
            name: name.clone(),
            hash: d.bytes_fixed().map_err(|e| e.to_string())?,
            entries: d.uint().map_err(|e| e.to_string())?,
        });
    }
    d.finish().map_err(|e| e.to_string())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digests(seed: u8) -> Vec<RelationHash> {
        ["a", "b", "c"]
            .iter()
            .enumerate()
            .map(|(i, n)| RelationHash {
                name: (*n).into(),
                hash: [seed + i as u8; 32],
                entries: u64::from(seed) * 10 + i as u64,
            })
            .collect()
    }

    #[test]
    fn hashes_round_trip_across_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RelationLog::open(dir.path()).unwrap();
        assert!(log.put(1, &digests(1)).unwrap());
        assert!(log.put(2, &digests(2)).unwrap());
        drop(log);
        let log = RelationLog::open(dir.path()).unwrap();
        assert_eq!(log.get(2).unwrap(), Some(digests(2)));
        assert_eq!(log.get(1).unwrap(), Some(digests(1)));
        assert_eq!(log.get(3).unwrap(), None);
    }

    #[test]
    fn a_height_recorded_twice_must_agree() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RelationLog::open(dir.path()).unwrap();
        assert!(log.put(1, &digests(1)).unwrap());
        assert!(!log.put(1, &digests(1)).unwrap());
        assert!(matches!(
            log.put(1, &digests(2)),
            Err(DurableError::RelationsConflict { height: 1 })
        ));
    }

    #[test]
    fn heights_may_be_recorded_out_of_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RelationLog::open(dir.path()).unwrap();
        log.put(5, &digests(5)).unwrap();
        log.put(3, &digests(3)).unwrap();
        drop(log);
        let log = RelationLog::open(dir.path()).unwrap();
        assert_eq!(log.heights().collect::<Vec<_>>(), [3, 5]);
        assert_eq!(log.get(3).unwrap(), Some(digests(3)));
    }

    #[test]
    fn a_torn_tail_is_dropped_and_the_log_keeps_working() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RelationLog::open(dir.path()).unwrap();
        log.put(1, &digests(1)).unwrap();
        log.put(2, &digests(2)).unwrap();
        drop(log);
        let path = dir.path().join(RELATIONS_FILE);
        let len = fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len - 5)
            .unwrap();
        let mut log = RelationLog::open(dir.path()).unwrap();
        assert_eq!(log.heights().collect::<Vec<_>>(), [1]);
        assert!(log.put(2, &digests(2)).unwrap());
        assert_eq!(log.get(2).unwrap(), Some(digests(2)));
    }

    #[test]
    fn a_read_only_open_ignores_a_torn_tail_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RelationLog::open(dir.path()).unwrap();
        log.put(1, &digests(1)).unwrap();
        log.put(2, &digests(2)).unwrap();
        drop(log);
        let path = dir.path().join(RELATIONS_FILE);
        let len = fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len - 5)
            .unwrap();
        let log = RelationLog::open_read_only(dir.path()).unwrap().unwrap();
        assert_eq!(log.heights().collect::<Vec<_>>(), [1]);
        assert_eq!(fs::metadata(&path).unwrap().len(), len - 5);
    }

    #[test]
    fn a_read_only_open_of_a_missing_log_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(RelationLog::open_read_only(dir.path()).unwrap().is_none());
    }

    #[test]
    fn a_different_relation_list_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RelationLog::open(dir.path()).unwrap();
        log.put(1, &digests(1)).unwrap();
        let mut other = digests(2);
        other.pop();
        assert!(log.put(2, &other).is_err());
    }
}
