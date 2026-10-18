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

//! The signing guard (ADR 0006 decision 4, "Signing guard").
//!
//! One file, kept beside the sequencer key and **exclusively locked while open**: the lock is the
//! key's lock file, so only the process holding it signs. Layout:
//!
//! ```text
//! file   = magic(16) || chain(64) || record*
//! magic  = "rw/v1/sig-guard\n"
//! chain  = genesis_root(32) || sequencer_address(20) || SHA-256(magic || genesis_root || address)[0..12]
//! record = height_be64 || header_hash(32) || SHA-256("rw/v1/guard" || height_be64 || header_hash)[0..8]
//! ```
//!
//! Records are 48 bytes, appended and fsynced **before** the key signs, with strictly increasing
//! heights; the last is the guard's record. [`SigningGuard::authorize`] refuses any height at or
//! below the record unless the guard holds that height with the identical `header_hash` (a
//! re-sign, which RFC 6979 makes byte-identical). A partial or damaged last record is a torn
//! append and is dropped (its signature was never made: signing waits for the fsync); damage
//! before the last record is corruption.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{DurableError, StoreChain, lock_exclusive, sync_dir, timed_sync};
use crate::hash::{Hash, sha256};
use crate::sign::Address;

const MAGIC: &[u8; 16] = b"rw/v1/sig-guard\n";
const CHAIN_LEN: usize = 64;
const HEADER_LEN: usize = MAGIC.len() + CHAIN_LEN;
const RECORD_LEN: usize = 48;
const RECORD_DOMAIN: &[u8] = b"rw/v1/guard";

fn chain_bytes(chain: &StoreChain) -> [u8; CHAIN_LEN] {
    let mut out = [0u8; CHAIN_LEN];
    out[..32].copy_from_slice(&chain.genesis_root);
    out[32..52].copy_from_slice(&chain.sequencer.0);
    let check = sha256(&[MAGIC, &chain.genesis_root, &chain.sequencer.0]);
    out[52..].copy_from_slice(&check[..12]);
    out
}

fn record_bytes(height: u64, hash: &Hash) -> [u8; RECORD_LEN] {
    let mut out = [0u8; RECORD_LEN];
    out[..8].copy_from_slice(&height.to_be_bytes());
    out[8..40].copy_from_slice(hash);
    let check = sha256(&[RECORD_DOMAIN, &height.to_be_bytes(), hash]);
    out[40..].copy_from_slice(&check[..8]);
    out
}

fn decode_record(raw: &[u8]) -> Option<(u64, Hash)> {
    let height = u64::from_be_bytes(raw.get(..8)?.try_into().ok()?);
    let hash: Hash = raw.get(8..40)?.try_into().ok()?;
    (raw.len() == RECORD_LEN && raw == record_bytes(height, &hash)).then_some((height, hash))
}

/// What [`SigningGuard::authorize`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authorization {
    /// A new record was written and fsynced (in this time).
    Recorded(Duration),
    /// The guard already holds this height with this hash: a re-sign.
    Identical,
}

/// The persisted record of signed headers. See the module documentation.
#[derive(Debug)]
pub struct SigningGuard {
    path: PathBuf,
    file: File,
    chain: StoreChain,
    /// Every recorded `(height, header_hash)`, heights increasing.
    records: Vec<(u64, Hash)>,
}

impl SigningGuard {
    /// Open the guard at `path` for `chain`, creating it if absent, and lock it. Refused if
    /// another process holds it or it belongs to another chain or key.
    pub fn open(path: impl AsRef<Path>, chain: StoreChain) -> Result<Self, DurableError> {
        let path = path.as_ref().to_path_buf();
        let what = || path.display().to_string();
        let created = !path.exists();
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .append(true)
            .open(&path)?;
        lock_exclusive(&file, &path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if bytes.len() < HEADER_LEN {
            let mut header = MAGIC.to_vec();
            header.extend_from_slice(&chain_bytes(&chain));
            if !header.starts_with(&bytes) && !bytes.is_empty() {
                return Err(DurableError::corrupt(what(), "damaged header"));
            }
            // New, or torn while being created.
            file.set_len(0)?;
            file.write_all(&header)?;
            file.sync_all()?;
            if created && let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                sync_dir(dir)?;
            }
            bytes = header;
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(DurableError::corrupt(what(), "no magic"));
        }
        if bytes[MAGIC.len()..HEADER_LEN] != chain_bytes(&chain) {
            let mut root = [0u8; 32];
            root.copy_from_slice(&bytes[MAGIC.len()..MAGIC.len() + 32]);
            let mut address = [0u8; 20];
            address.copy_from_slice(&bytes[MAGIC.len() + 32..MAGIC.len() + 52]);
            let stored = StoreChain {
                genesis_root: root,
                sequencer: Address(address),
            };
            if bytes[MAGIC.len()..HEADER_LEN] == chain_bytes(&stored) {
                return Err(DurableError::ChainMismatch { what: what() });
            }
            return Err(DurableError::corrupt(what(), "damaged header"));
        }
        let body = &bytes[HEADER_LEN..];
        let chunks: Vec<&[u8]> = body.chunks(RECORD_LEN).collect();
        let mut records: Vec<(u64, Hash)> = Vec::with_capacity(chunks.len());
        for (i, chunk) in chunks.iter().enumerate() {
            match decode_record(chunk) {
                Some(record) => {
                    if records.last().is_some_and(|(h, _)| *h >= record.0) {
                        return Err(DurableError::corrupt(
                            what(),
                            format!("record {i} does not increase the height"),
                        ));
                    }
                    records.push(record);
                }
                None if i + 1 == chunks.len() => break,
                None => {
                    return Err(DurableError::corrupt(
                        what(),
                        format!("record {i} is damaged"),
                    ));
                }
            }
        }
        let valid = (HEADER_LEN + records.len() * RECORD_LEN) as u64;
        if valid != bytes.len() as u64 {
            file.set_len(valid)?;
            file.sync_all()?;
        }
        Ok(Self {
            path,
            file,
            chain,
            records,
        })
    }

    /// The guard file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The chain the guard was opened for.
    #[must_use]
    pub fn chain(&self) -> StoreChain {
        self.chain
    }

    /// The guard's record: the highest `(height, header_hash)` it allowed.
    #[must_use]
    pub fn last(&self) -> Option<(u64, Hash)> {
        self.records.last().copied()
    }

    /// Allow signing `header_hash` at `height`: record it and fsync, or accept an identical
    /// re-sign. Refuses any other header at or below the record.
    pub fn authorize(
        &mut self,
        height: u64,
        header_hash: &Hash,
    ) -> Result<Authorization, DurableError> {
        if let Some((last_height, last_hash)) = self.last()
            && height <= last_height
        {
            let found = self
                .records
                .binary_search_by_key(&height, |(h, _)| *h)
                .ok()
                .map(|i| self.records[i]);
            return match found {
                Some((_, hash)) if &hash == header_hash => Ok(Authorization::Identical),
                Some((h, hash)) => Err(DurableError::GuardConflict {
                    height,
                    recorded_height: h,
                    recorded: hash,
                    requested: *header_hash,
                }),
                None => Err(DurableError::GuardConflict {
                    height,
                    recorded_height: last_height,
                    recorded: last_hash,
                    requested: *header_hash,
                }),
            };
        }
        self.file.write_all(&record_bytes(height, header_hash))?;
        let took = timed_sync(&self.file)?;
        self.records.push((height, *header_hash));
        Ok(Authorization::Recorded(took))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain() -> StoreChain {
        StoreChain {
            genesis_root: [7; 32],
            sequencer: Address([1; 20]),
        }
    }

    fn guard(dir: &Path) -> SigningGuard {
        SigningGuard::open(dir.join("seq.guard"), chain()).unwrap()
    }

    #[test]
    fn a_second_header_at_a_recorded_height_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut g = guard(dir.path());
        assert!(matches!(
            g.authorize(1, &[1; 32]),
            Ok(Authorization::Recorded(_))
        ));
        assert!(matches!(
            g.authorize(1, &[2; 32]),
            Err(DurableError::GuardConflict { height: 1, .. })
        ));
    }

    #[test]
    fn the_identical_header_may_be_signed_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut g = guard(dir.path());
        g.authorize(1, &[1; 32]).unwrap();
        g.authorize(2, &[2; 32]).unwrap();
        assert_eq!(g.authorize(1, &[1; 32]).unwrap(), Authorization::Identical);
    }

    #[test]
    fn a_height_below_the_record_that_was_never_recorded_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut g = guard(dir.path());
        g.authorize(5, &[5; 32]).unwrap();
        assert!(g.authorize(3, &[3; 32]).is_err());
    }

    #[test]
    fn the_record_survives_a_reopen_and_still_refuses() {
        let dir = tempfile::tempdir().unwrap();
        guard(dir.path()).authorize(1, &[1; 32]).unwrap();
        let mut g = guard(dir.path());
        assert_eq!(g.last(), Some((1, [1; 32])));
        assert!(g.authorize(1, &[9; 32]).is_err());
    }

    #[test]
    fn the_guard_is_locked_while_open() {
        let dir = tempfile::tempdir().unwrap();
        let _held = guard(dir.path());
        assert!(matches!(
            SigningGuard::open(dir.path().join("seq.guard"), chain()),
            Err(DurableError::Locked(_))
        ));
    }

    #[test]
    fn another_chain_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        drop(guard(dir.path()));
        let other = StoreChain {
            genesis_root: [8; 32],
            ..chain()
        };
        assert!(matches!(
            SigningGuard::open(dir.path().join("seq.guard"), other),
            Err(DurableError::ChainMismatch { .. })
        ));
    }

    #[test]
    fn a_torn_record_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut g = guard(dir.path());
            g.authorize(1, &[1; 32]).unwrap();
            g.authorize(2, &[2; 32]).unwrap();
        }
        let path = dir.path().join("seq.guard");
        let len = std::fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len - 7)
            .unwrap();
        assert_eq!(guard(dir.path()).last(), Some((1, [1; 32])));
    }
}
