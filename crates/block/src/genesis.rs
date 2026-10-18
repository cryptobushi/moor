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

//! The genesis record: everything a verifier needs to rebuild block 0 (fork API request R4;
//! spec `docs/spec/block-format-v0.md` §13).
//!
//! The genesis root depends on the core objdef tree that was imported, the feature flags the
//! world ran with, the genesis set-up (the principals bound to wallets before block 1), the
//! envelope domain salt and, for anything a verb can observe about the build, the fork commit. The
//! record carries those as data next to the genesis root, so a verifier needs no out-of-band
//! configuration beyond the core files themselves, which the record pins by content hash.
//!
//! Encoding: one canonical CBOR array (the block format's profile), published as `genesis.cbor`
//! in the sink directory and kept in the sequencer's state directory:
//!
//! ```text
//! genesis = [ "rw/v1/genesis", 1,
//!             genesis_root(32), sequencer(20), fork_commit(text),
//!             core_hash(32), core_files: [[path(text), sha256(32)], ...],
//!             features: [[name(text), 0|1], ...],
//!             principals: [[player(int), wallet(20)], ...],
//!             domain_salt(32) ]
//! ```
//!
//! `core_files` is sorted by path bytes; `features` by name; `principals` in the order applied.
//! `core_hash = SHA-256("rw/v1/core" || canonical CBOR of core_files)`.

use std::fs;
use std::path::Path;

use crate::cbor::{CborError, Decoder, Encoder};
use crate::error::FormatError;
use crate::hash::{Hash, sha256};
use crate::sign::Address;

/// The record's domain tag, its first element.
pub const GENESIS_TAG: &str = "rw/v1/genesis";
/// The record's version, its second element.
pub const GENESIS_VERSION: u64 = 1;
/// The file name in a sink or state directory.
pub const GENESIS_FILE: &str = "genesis.cbor";

const CORE_DOMAIN: &[u8] = b"rw/v1/core";
/// The most core files a record may list.
const MAX_CORE_FILES: usize = 1 << 20;

/// One core file: its path under the core directory (`/` separated) and its SHA-256.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreFile {
    pub path: String,
    pub sha256: Hash,
}

/// A genesis wallet binding: `player` is bound to `wallet` before block 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Principal {
    pub player: i32,
    pub wallet: Address,
}

/// The genesis set-up as data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisRecord {
    /// The state root the set-up produces (block 0's state root).
    pub genesis_root: Hash,
    /// The sequencer's address.
    pub sequencer: Address,
    /// The full git commit of the fork that built the sequencer.
    pub fork_commit: String,
    /// The core objdef import manifest, sorted by path.
    pub core_files: Vec<CoreFile>,
    /// Feature flags by name, sorted by name.
    pub features: Vec<(String, bool)>,
    /// Genesis wallet bindings, in the order applied.
    pub principals: Vec<Principal>,
    /// The envelope domain salt (ADR 0005 decision 2).
    pub domain_salt: Hash,
}

/// Hash of the `core_files` manifest.
#[must_use]
pub fn core_hash(files: &[CoreFile]) -> Hash {
    let mut e = Encoder::new();
    encode_files(&mut e, files);
    sha256(&[CORE_DOMAIN, &e.into_bytes()])
}

fn encode_files(e: &mut Encoder, files: &[CoreFile]) {
    e.array(files.len());
    for f in files {
        e.array(2);
        e.text(&f.path);
        e.bytes(&f.sha256);
    }
}

/// The manifest of a core directory: every regular file below `dir` whose name (and whose
/// directories' names) do not start with `.`, sorted by path.
pub fn core_manifest(dir: &Path) -> std::io::Result<Vec<CoreFile>> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<CoreFile>) -> std::io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let kind = fs::metadata(entry.path())?;
            if kind.is_dir() {
                walk(&entry.path(), &path, out)?;
            } else if kind.is_file() {
                out.push(CoreFile {
                    sha256: sha256(&[&fs::read(entry.path())?]),
                    path,
                });
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, "", &mut out)?;
    out.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    Ok(out)
}

impl GenesisRecord {
    /// The hash of this record's core manifest.
    #[must_use]
    pub fn core_hash(&self) -> Hash {
        core_hash(&self.core_files)
    }

    /// The canonical bytes of `genesis.cbor`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(10);
        e.text(GENESIS_TAG);
        e.uint(GENESIS_VERSION);
        e.bytes(&self.genesis_root);
        e.bytes(&self.sequencer.0);
        e.text(&self.fork_commit);
        e.bytes(&self.core_hash());
        encode_files(&mut e, &self.core_files);
        e.array(self.features.len());
        for (name, on) in &self.features {
            e.array(2);
            e.text(name);
            e.uint(u64::from(*on));
        }
        e.array(self.principals.len());
        for p in &self.principals {
            e.array(2);
            e.int(i64::from(p.player));
            e.bytes(&p.wallet.0);
        }
        e.bytes(&self.domain_salt);
        e.into_bytes()
    }

    /// Decode and check a record: tag, version, sort order and the manifest hash.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut d = Decoder::new(bytes);
        d.array_of(10)?;
        if d.text()? != GENESIS_TAG {
            return Err(FormatError::Tag {
                expected: GENESIS_TAG,
            });
        }
        let version = d.uint()?;
        if version != GENESIS_VERSION {
            return Err(FormatError::Version {
                expected: GENESIS_VERSION,
                found: version,
            });
        }
        let genesis_root = d.bytes_fixed()?;
        let sequencer = Address(d.bytes_fixed()?);
        let fork_commit = d.text()?.to_owned();
        let stated_core_hash: Hash = d.bytes_fixed()?;
        let n = d.array()?;
        if n > MAX_CORE_FILES {
            return Err(CborError::Range(d.position()).into());
        }
        let mut core_files = Vec::with_capacity(n);
        for _ in 0..n {
            d.array_of(2)?;
            let path = d.text()?.to_owned();
            core_files.push(CoreFile {
                path,
                sha256: d.bytes_fixed()?,
            });
        }
        let sorted = |a: &[u8], b: &[u8]| a < b;
        if !core_files
            .windows(2)
            .all(|w| sorted(w[0].path.as_bytes(), w[1].path.as_bytes()))
        {
            return Err(FormatError::Genesis(
                "core files are not sorted by path".into(),
            ));
        }
        if core_hash(&core_files) != stated_core_hash {
            return Err(FormatError::Genesis(
                "core_hash is not the manifest's hash".into(),
            ));
        }
        let n = d.array()?;
        let mut features = Vec::with_capacity(n.min(256));
        for _ in 0..n {
            d.array_of(2)?;
            let name = d.text()?.to_owned();
            let on = match d.uint()? {
                0 => false,
                1 => true,
                other => {
                    return Err(FormatError::Genesis(format!(
                        "feature {name} has value {other}, not 0 or 1"
                    )));
                }
            };
            features.push((name, on));
        }
        if !features.windows(2).all(|w| w[0].0 < w[1].0) {
            return Err(FormatError::Genesis(
                "features are not sorted by name".into(),
            ));
        }
        let n = d.array()?;
        let mut principals = Vec::with_capacity(n.min(256));
        for _ in 0..n {
            d.array_of(2)?;
            let player = i32::try_from(d.int()?)
                .map_err(|_| FormatError::Genesis("principal out of range".into()))?;
            principals.push(Principal {
                player,
                wallet: Address(d.bytes_fixed()?),
            });
        }
        let domain_salt = d.bytes_fixed()?;
        d.finish()?;
        Ok(Self {
            genesis_root,
            sequencer,
            fork_commit,
            core_files,
            features,
            principals,
            domain_salt,
        })
    }

    /// Compare this manifest with the files under `dir`: `Ok(())` when they are the same set with
    /// the same hashes, otherwise the first difference.
    pub fn check_core_dir(&self, dir: &Path) -> Result<(), String> {
        let actual = core_manifest(dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
        let (mut want, mut have) = (self.core_files.iter().peekable(), actual.iter().peekable());
        loop {
            match (want.peek(), have.peek()) {
                (None, None) => break,
                (Some(w), Some(h)) if w.path == h.path => {
                    if w.sha256 != h.sha256 {
                        return Err(format!("{} differs from the pinned core", w.path));
                    }
                    want.next();
                    have.next();
                }
                (Some(w), h) if h.is_none_or(|h| w.path < h.path) => {
                    return Err(format!("{} is missing from {}", w.path, dir.display()));
                }
                (_, Some(h)) => {
                    return Err(format!("{} is not in the pinned core manifest", h.path));
                }
                (Some(w), None) => {
                    return Err(format!("{} is missing from {}", w.path, dir.display()));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GenesisRecord {
        GenesisRecord {
            genesis_root: [7; 32],
            sequencer: Address([9; 20]),
            fork_commit: "0123456789abcdef0123456789abcdef01234567".into(),
            core_files: vec![
                CoreFile {
                    path: "a.moo".into(),
                    sha256: [1; 32],
                },
                CoreFile {
                    path: "sub/b.moo".into(),
                    sha256: [2; 32],
                },
            ],
            features: vec![
                ("custom_errors".into(), true),
                ("flyweight_type".into(), false),
            ],
            principals: vec![Principal {
                player: 2,
                wallet: Address([3; 20]),
            }],
            domain_salt: [4; 32],
        }
    }

    #[test]
    fn a_record_round_trips() {
        let record = sample();
        assert_eq!(GenesisRecord::decode(&record.encode()).unwrap(), record);
    }

    #[test]
    fn the_encoding_is_stable() {
        assert_eq!(sample().encode(), sample().encode());
    }

    #[test]
    fn a_changed_manifest_entry_is_refused_by_the_core_hash() {
        let mut bytes = sample().encode();
        // The first core file hash is 32 bytes of 0x01; flip one.
        let at = bytes.windows(32).position(|w| w == [1u8; 32]).unwrap();
        bytes[at] ^= 0xff;
        assert!(matches!(
            GenesisRecord::decode(&bytes),
            Err(FormatError::Genesis(_))
        ));
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert!(GenesisRecord::decode(&bytes).is_err());
    }

    #[test]
    fn the_manifest_of_a_directory_skips_hidden_entries_and_sorts_by_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join("b.moo"), b"b").unwrap();
        fs::write(dir.path().join("a.moo"), b"a").unwrap();
        fs::write(dir.path().join("sub/c.moo"), b"c").unwrap();
        fs::write(dir.path().join(".git/x"), b"x").unwrap();
        fs::write(dir.path().join(".hidden"), b"x").unwrap();
        let paths: Vec<_> = core_manifest(dir.path())
            .unwrap()
            .into_iter()
            .map(|f| f.path)
            .collect();
        assert_eq!(paths, ["a.moo", "b.moo", "sub/c.moo"]);
    }

    #[test]
    fn check_core_dir_names_the_first_difference() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.moo"), b"a").unwrap();
        let mut record = sample();
        record.core_files = core_manifest(dir.path()).unwrap();
        assert_eq!(record.check_core_dir(dir.path()), Ok(()));
        fs::write(dir.path().join("a.moo"), b"changed").unwrap();
        assert!(
            record
                .check_core_dir(dir.path())
                .unwrap_err()
                .contains("a.moo differs")
        );
        fs::write(dir.path().join("a.moo"), b"a").unwrap();
        fs::write(dir.path().join("z.moo"), b"z").unwrap();
        assert!(
            record
                .check_core_dir(dir.path())
                .unwrap_err()
                .contains("z.moo is not in")
        );
    }
}
