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

//! The input journal (ADR 0006 decision 4, "Journal").
//!
//! Directory layout:
//!
//! - `<first:012>.rwj`: journal files, named by the first height they may open. Only the newest is
//!   live; older ones are left only by an interrupted rotation and are deleted on open.
//! - `LOCK`: exclusive lock while open.
//!
//! A journal file is the 16-byte magic `rw/v1/journal\0\0\0` followed by framed records
//! ([`super::record`]) whose payloads are canonical CBOR:
//!
//! ```text
//! open  = [0, height, timestamp, seed(32)]                 ; begin_block, not fsynced on its own
//! input = [1, height, command_index, entry]                ; entry: the command batch entry bytes
//! ```
//!
//! Inputs follow their block's `open` with command indices 1, 2, ... and are fsynced (as a group
//! when several arrive together) before any of them runs. Heights of `open` records increase.
//! On restart only the last `open` matters: blocks before it are in the block store. Rotation
//! happens between blocks, once the live file exceeds a size: a new file is created and synced,
//! then the old one is deleted.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{DurableError, lock_exclusive, record, sync_dir, timed_sync};
use crate::cbor::{Decoder, Encoder};
use crate::command::CommandEntry;
use crate::hash::Hash;

const MAGIC: &[u8; 16] = b"rw/v1/journal\0\0\0";
const EXTENSION: &str = "rwj";
const OPEN: u64 = 0;
const INPUT: u64 = 1;

/// Rotate the live journal file at the first seal after it exceeds this many bytes.
pub const DEFAULT_ROTATE_BYTES: u64 = 64 * 1024 * 1024;

/// The block a journal left open: its recorded context and the inputs journalled for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalledBlock {
    pub height: u64,
    pub timestamp: u64,
    pub seed: Hash,
    /// In command-index order (index `k + 1` at position `k`).
    pub inputs: Vec<CommandEntry>,
}

/// The append-only input journal. See the module documentation for the format.
#[derive(Debug)]
pub struct Journal {
    dir: PathBuf,
    file: File,
    len: u64,
    rotate_bytes: u64,
    _lock: File,
}

fn file_name(first: u64) -> String {
    format!("{first:012}.{EXTENSION}")
}

fn journal_files(dir: &Path) -> Result<Vec<(u64, PathBuf)>, DurableError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == EXTENSION)
            && let Some(first) = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u64>().ok())
        {
            files.push((first, path));
        }
    }
    files.sort();
    Ok(files)
}

fn create_file(dir: &Path, first: u64) -> Result<File, DurableError> {
    let path = dir.join(file_name(first));
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .append(true)
        .open(&path)?;
    file.write_all(MAGIC)?;
    file.sync_all()?;
    sync_dir(dir)?;
    Ok(file)
}

fn encode_open(height: u64, timestamp: u64, seed: &Hash) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(4);
    e.uint(OPEN);
    e.uint(height);
    e.uint(timestamp);
    e.bytes(seed);
    e.into_bytes()
}

fn encode_input(height: u64, command_index: u64, entry: &CommandEntry) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(4);
    e.uint(INPUT);
    e.uint(height);
    e.uint(command_index);
    entry.encode_into(&mut e);
    e.into_bytes()
}

/// Read the live file's records into the last open block.
fn replay(path: &Path, payloads: &[&[u8]]) -> Result<Option<JournalledBlock>, DurableError> {
    let what = || path.display().to_string();
    let mut open: Option<JournalledBlock> = None;
    for (i, payload) in payloads.iter().enumerate() {
        let bad = |reason: String| DurableError::corrupt(what(), format!("record {i}: {reason}"));
        let mut d = Decoder::new(payload);
        d.array_of(4).map_err(|e| bad(e.to_string()))?;
        match d.uint().map_err(|e| bad(e.to_string()))? {
            OPEN => {
                let height = d.uint().map_err(|e| bad(e.to_string()))?;
                let timestamp = d.uint().map_err(|e| bad(e.to_string()))?;
                let seed = d.bytes_fixed().map_err(|e| bad(e.to_string()))?;
                if let Some(prev) = &open
                    && height <= prev.height
                {
                    return Err(bad(format!("open {height} after open {}", prev.height)));
                }
                open = Some(JournalledBlock {
                    height,
                    timestamp,
                    seed,
                    inputs: Vec::new(),
                });
            }
            INPUT => {
                let height = d.uint().map_err(|e| bad(e.to_string()))?;
                let index = d.uint().map_err(|e| bad(e.to_string()))?;
                let entry = CommandEntry::decode_from(&mut d).map_err(|e| bad(e.to_string()))?;
                let block = open
                    .as_mut()
                    .filter(|b| b.height == height)
                    .ok_or_else(|| bad(format!("input for {height} outside its block")))?;
                if index != block.inputs.len() as u64 + 1 {
                    return Err(bad(format!(
                        "input {index} of block {height} after {} inputs",
                        block.inputs.len()
                    )));
                }
                block.inputs.push(entry);
            }
            other => return Err(bad(format!("unknown record type {other}"))),
        }
        d.finish().map_err(|e| bad(e.to_string()))?;
    }
    Ok(open)
}

impl Journal {
    /// Open (creating if needed) the journal in `dir`, cutting off a torn tail. Returns the
    /// journal and the last block it opened, with that block's journalled inputs.
    pub fn open(dir: impl AsRef<Path>) -> Result<(Self, Option<JournalledBlock>), DurableError> {
        Self::open_with(dir, DEFAULT_ROTATE_BYTES)
    }

    /// [`Self::open`] with a rotation size.
    pub fn open_with(
        dir: impl AsRef<Path>,
        rotate_bytes: u64,
    ) -> Result<(Self, Option<JournalledBlock>), DurableError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let lock_path = dir.join("LOCK");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;
        lock_exclusive(&lock, &lock_path)?;
        let mut files = journal_files(&dir)?;
        let Some((_, live)) = files.pop() else {
            let file = create_file(&dir, 1)?;
            let journal = Self {
                dir,
                file,
                len: MAGIC.len() as u64,
                rotate_bytes,
                _lock: lock,
            };
            return Ok((journal, None));
        };
        for (_, stale) in &files {
            fs::remove_file(stale)?;
        }
        if !files.is_empty() {
            sync_dir(&dir)?;
        }
        let mut file = OpenOptions::new().read(true).append(true).open(&live)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if bytes.len() < MAGIC.len() {
            if !MAGIC.starts_with(&bytes) {
                return Err(DurableError::corrupt(
                    live.display().to_string(),
                    "no magic",
                ));
            }
            // Torn while being created.
            file.set_len(0)?;
            file.write_all(MAGIC)?;
            file.sync_all()?;
            bytes = MAGIC.to_vec();
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(DurableError::corrupt(
                live.display().to_string(),
                "no magic",
            ));
        }
        let scan = record::scan(&bytes, MAGIC.len())
            .map_err(|reason| DurableError::corrupt(live.display().to_string(), reason))?;
        if scan.valid_len != bytes.len() {
            file.set_len(scan.valid_len as u64)?;
            file.sync_all()?;
        }
        let payloads: Vec<&[u8]> = scan.payloads.iter().map(|r| &bytes[r.clone()]).collect();
        let open = replay(&live, &payloads)?;
        let journal = Self {
            dir,
            file,
            len: scan.valid_len as u64,
            rotate_bytes,
            _lock: lock,
        };
        Ok((journal, open))
    }

    /// The journal's directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), DurableError> {
        self.file.write_all(bytes)?;
        self.len += bytes.len() as u64;
        Ok(())
    }

    /// Record `Open{height, timestamp, seed}`. Not fsynced on its own: it becomes durable with
    /// the block's first input, and an empty block needs no journal (its seal is in the store).
    pub fn append_open(
        &mut self,
        height: u64,
        timestamp: u64,
        seed: &Hash,
    ) -> Result<(), DurableError> {
        self.append(&record::frame(&encode_open(height, timestamp, seed)))
    }

    /// Record `entries` as command indices `first_index`, `first_index + 1`, ... of block
    /// `height` and fsync once. Returns the fsync time.
    pub fn append_inputs(
        &mut self,
        height: u64,
        first_index: u64,
        entries: &[CommandEntry],
    ) -> Result<Duration, DurableError> {
        let mut bytes = Vec::new();
        for (i, entry) in entries.iter().enumerate() {
            bytes.extend(record::frame(&encode_input(
                height,
                first_index + i as u64,
                entry,
            )));
        }
        self.append(&bytes)?;
        Ok(timed_sync(&self.file)?)
    }

    /// Block `height` is sealed and stored: rotate the live file if it has grown past the
    /// rotation size. The new file is named for `height + 1`.
    pub fn sealed(&mut self, height: u64) -> Result<(), DurableError> {
        if self.len <= self.rotate_bytes {
            return Ok(());
        }
        let old = journal_files(&self.dir)?;
        let file = create_file(&self.dir, height + 1)?;
        for (first, path) in old {
            if first != height + 1 {
                fs::remove_file(path)?;
            }
        }
        sync_dir(&self.dir)?;
        self.file = file;
        self.len = MAGIC.len() as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{SequencerInput, SequencerInputKind};

    fn input(player: i32) -> CommandEntry {
        CommandEntry::Sequencer(SequencerInput {
            kind: SequencerInputKind::Disconnected,
            player,
        })
    }

    #[test]
    fn the_last_open_block_and_its_inputs_come_back() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut j, open) = Journal::open(dir.path()).unwrap();
            assert_eq!(open, None);
            j.append_open(1, 10, &[1; 32]).unwrap();
            j.append_inputs(1, 1, &[input(4)]).unwrap();
            j.append_open(2, 11, &[2; 32]).unwrap();
            j.append_inputs(2, 1, &[input(5), input(6)]).unwrap();
        }
        let (_, open) = Journal::open(dir.path()).unwrap();
        assert_eq!(
            open,
            Some(JournalledBlock {
                height: 2,
                timestamp: 11,
                seed: [2; 32],
                inputs: vec![input(5), input(6)],
            })
        );
    }

    #[test]
    fn a_torn_input_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut j, _) = Journal::open(dir.path()).unwrap();
            j.append_open(1, 10, &[1; 32]).unwrap();
            j.append_inputs(1, 1, &[input(4), input(5)]).unwrap();
        }
        let path = dir.path().join(file_name(1));
        let len = fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len - 2)
            .unwrap();
        let (_, open) = Journal::open(dir.path()).unwrap();
        assert_eq!(open.unwrap().inputs, vec![input(4)]);
    }

    #[test]
    fn a_second_open_is_locked_out() {
        let dir = tempfile::tempdir().unwrap();
        let _first = Journal::open(dir.path()).unwrap();
        assert!(matches!(
            Journal::open(dir.path()),
            Err(DurableError::Locked(_))
        ));
    }

    #[test]
    fn rotation_keeps_only_the_new_file() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut j, _) = Journal::open_with(dir.path(), 10).unwrap();
            j.append_open(1, 10, &[1; 32]).unwrap();
            j.append_inputs(1, 1, &[input(4)]).unwrap();
            j.sealed(1).unwrap();
            j.append_open(2, 11, &[2; 32]).unwrap();
        }
        let names: Vec<u64> = journal_files(dir.path())
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, vec![2]);
        let (_, open) = Journal::open(dir.path()).unwrap();
        assert_eq!(open.map(|b| (b.height, b.inputs.len())), Some((2, 0)));
    }

    #[test]
    fn an_input_out_of_sequence_is_corruption() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut j, _) = Journal::open(dir.path()).unwrap();
            j.append_open(1, 10, &[1; 32]).unwrap();
            j.append_inputs(1, 2, &[input(4)]).unwrap();
        }
        assert!(matches!(
            Journal::open(dir.path()),
            Err(DurableError::Corrupt { .. })
        ));
    }
}
