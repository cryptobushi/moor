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

//! The sequencer's local durable state (ADR 0006 decision 4): the input [`Journal`], the local
//! [`BlockStore`] of sealed blocks and the [`SigningGuard`].
//!
//! The rule is "inputs are durable before they take effect; outputs are reproducible". The journal
//! makes each input durable before it runs; the block store holds every sealed block (unsigned
//! first, then its signature); the guard records `(height, header_hash)` before the key signs, so
//! the key never signs two different headers at one height.
//!
//! All three are append-only files of framed records ([`record`]): a crash can only tear the last
//! record, which is dropped on open. Payloads are canonical CBOR in the block format's profile.
//! "fsync" is `File::sync_data`/`sync_all`, which is `fcntl(F_FULLFSYNC)` on macOS and
//! `fdatasync`/`fsync` on Linux.

mod block_store;
mod guard;
mod journal;
pub mod record;
mod relations;

use std::fs::File;
use std::path::Path;
use std::time::{Duration, Instant};

pub use block_store::{BlockStore, StoreChain, StoredBlock};
pub use guard::{Authorization, SigningGuard};
pub use journal::{Journal, JournalledBlock};
pub use relations::{RELATIONS_FILE, RelationHash, RelationLog};

use crate::error::FormatError;
use crate::hash::Hash;

/// Why durable state could not be read or written, or refused a write.
#[derive(Debug, thiserror::Error)]
pub enum DurableError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("format: {0}")]
    Format(#[from] FormatError),
    #[error("{0} is locked by another process")]
    Locked(String),
    #[error("{what} is corrupt: {reason}")]
    Corrupt { what: String, reason: String },
    #[error("{what} belongs to another chain or sequencer")]
    ChainMismatch { what: String },
    #[error(
        "signing guard refuses height {height}: it recorded {recorded_height} with header {} \
         and was asked for header {}",
        crate::hash::hex(recorded),
        crate::hash::hex(requested)
    )]
    GuardConflict {
        height: u64,
        recorded_height: u64,
        recorded: Hash,
        requested: Hash,
    },
    #[error("block store already holds a different block at height {height}")]
    BlockConflict { height: u64 },
    #[error("the relation log holds different hashes for height {height}")]
    RelationsConflict { height: u64 },
    #[error("block store expected height {expected}, got {found}")]
    Height { expected: u64, found: u64 },
}

impl DurableError {
    pub(crate) fn corrupt(what: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Corrupt {
            what: what.into(),
            reason: reason.into(),
        }
    }
}

/// `sync_data` on `file`, timed.
pub(crate) fn timed_sync(file: &File) -> std::io::Result<Duration> {
    let started = Instant::now();
    file.sync_data()?;
    Ok(started.elapsed())
}

/// fsync a directory, so a created or renamed entry in it is durable.
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Take an exclusive advisory lock on `file` for as long as it stays open.
pub(crate) fn lock_exclusive(file: &File, what: &Path) -> Result<(), DurableError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => {
            Err(DurableError::Locked(what.display().to_string()))
        }
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}
