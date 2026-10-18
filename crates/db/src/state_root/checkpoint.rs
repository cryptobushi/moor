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

//! Checkpoints (RuneWorld ADR 0006 decision 7): the canonical state encoding at a sealed height,
//! written as one file that restores into an empty database with the identical state root.
//!
//! # File format (checkpoint format 1, state encoding 1)
//!
//! ```text
//! file   = header || relation_1 || ... || relation_n      ; a CBOR sequence, nothing after it
//! header = ["rw/v1/checkpoint", 1, 1, height, state_root, header_hash, fork_commit]
//! ```
//!
//! - `relation_i` is the canonical encoding of the i-th relation of [`super::RELATIONS`], exactly
//!   as hashed into the state root (`[[key, value], ...]`, entries in bytewise key order).
//! - The checkpoint's hash is the state root recomputed from the relations: `SHA-256` of each
//!   relation gives its relation hash, and the hashes combine as in [`StateRoot::from_relations`].
//!   A checkpoint is valid only if that root equals `state_root` in its header; the header's
//!   `height` and `header_hash` say which sealed block it claims to be the state after, and a
//!   reader checks them against its own chain (the signed header at `height` carries the root).
//! - `fork_commit` (text) is the fork build that wrote it; informative.
//!
//! [`Checkpoint::parse`] checks the whole file (canonical CBOR, key order, the root) without a
//! database. [`crate::TxDB::import_checkpoint`] loads a parsed checkpoint into an empty database and
//! checks the root of the result again.

use super::{
    RELATIONS, STATE_VERSION, StateRoot, StateRootError, canonical_relation_from,
    cbor::{CborError, Decoder, Encoder},
    hex,
};
use crate::engine::moor_db::{SEQUENCE_COUNT, WorldStateSnapshot};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Domain separation string, the first element of the header.
pub const CHECKPOINT_DOMAIN: &str = "rw/v1/checkpoint";
/// Version of the checkpoint file layout (the header and the framing).
pub const CHECKPOINT_FORMAT: u64 = 1;
/// File extension of checkpoint files in a [`CheckpointDir`].
pub const CHECKPOINT_EXTENSION: &str = "rwcp";

/// Why a checkpoint could not be written, read or restored.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("malformed checkpoint: {0}")]
    Malformed(String),
    #[error("unsupported checkpoint: format {format}, state encoding {state}")]
    Version { format: u64, state: u64 },
    #[error(
        "the checkpoint's relations hash to {}, its header says {}",
        hex(.computed),
        hex(.header)
    )]
    RootMismatch {
        header: [u8; 32],
        computed: [u8; 32],
    },
    #[error("the checkpoint is the state after height {height}, not {expected}")]
    WrongHeight { height: u64, expected: u64 },
    #[error("the database is not empty; a checkpoint restores only into an empty database")]
    NotEmpty,
    #[error("restoring relation {relation}: {detail}")]
    Restore {
        relation: &'static str,
        detail: String,
    },
    #[error(
        "the restored database has root {}, the checkpoint {}",
        hex(.restored),
        hex(.expected)
    )]
    RestoredRoot {
        expected: [u8; 32],
        restored: [u8; 32],
    },
    #[error("encoding: {0}")]
    Encoding(#[from] StateRootError),
}

fn malformed(context: &str, e: CborError) -> CheckpointError {
    CheckpointError::Malformed(format!("{context}: {e}"))
}

/// What a checkpoint claims to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointHeader {
    /// The sealed height whose state this is (0 = genesis).
    pub height: u64,
    /// The state root at `height`; the relations must hash to it.
    pub state_root: [u8; 32],
    /// `header_hash` of the block at `height` (all zero at genesis).
    pub header_hash: [u8; 32],
    /// The fork commit that wrote the checkpoint (informative).
    pub fork_commit: String,
}

impl CheckpointHeader {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(7);
        e.text(CHECKPOINT_DOMAIN);
        e.uint(CHECKPOINT_FORMAT);
        e.uint(STATE_VERSION);
        e.uint(self.height);
        e.bytes(&self.state_root);
        e.bytes(&self.header_hash);
        e.text(&self.fork_commit);
        e.into_bytes()
    }

    fn decode(d: &mut Decoder<'_>) -> Result<Self, CheckpointError> {
        let m = |e| malformed("header", e);
        d.array_of(7).map_err(m)?;
        if d.text().map_err(m)? != CHECKPOINT_DOMAIN {
            return Err(CheckpointError::Malformed(
                "not a RuneWorld checkpoint (domain string)".into(),
            ));
        }
        let format = d.uint().map_err(m)?;
        let state = d.uint().map_err(m)?;
        if format != CHECKPOINT_FORMAT || state != STATE_VERSION {
            return Err(CheckpointError::Version { format, state });
        }
        let height = d.uint().map_err(m)?;
        let hash32 = |d: &mut Decoder<'_>, what: &str| -> Result<[u8; 32], CheckpointError> {
            <[u8; 32]>::try_from(d.bytes().map_err(m)?)
                .map_err(|_| CheckpointError::Malformed(format!("{what} is not 32 bytes")))
        };
        let state_root = hash32(d, "state_root")?;
        let header_hash = hash32(d, "header_hash")?;
        let fork_commit = d.text().map_err(m)?.to_string();
        Ok(Self {
            height,
            state_root,
            header_hash,
            fork_commit,
        })
    }
}

/// A checkpoint file, parsed and verified: canonical form, key order, root.
#[derive(Clone, Debug)]
pub struct Checkpoint<'a> {
    pub header: CheckpointHeader,
    /// The root recomputed from the relations (equal to `header.state_root`).
    pub root: StateRoot,
    /// The raw canonical encoding of each relation, in [`RELATIONS`] order.
    relations: Vec<&'a [u8]>,
}

impl<'a> Checkpoint<'a> {
    /// Parse and verify `bytes`. Fails unless the relations are canonical, their entries are in
    /// strictly increasing key order, nothing follows them, and they hash to the header's root.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CheckpointError> {
        let mut d = Decoder::new(bytes);
        let header = CheckpointHeader::decode(&mut d)?;
        let mut relations = Vec::with_capacity(RELATIONS.len());
        let mut digests = Vec::with_capacity(RELATIONS.len());
        for name in RELATIONS {
            let raw = d.item().map_err(|e| malformed(name, e))?;
            let entries = check_relation(name, raw)?;
            digests.push(super::RelationDigest {
                name,
                hash: Sha256::digest(raw).into(),
                entries,
            });
            relations.push(raw);
        }
        d.finish()
            .map_err(|e| malformed("after the last relation", e))?;
        let root = StateRoot::from_relations(digests);
        if root.root != header.state_root {
            return Err(CheckpointError::RootMismatch {
                header: header.state_root,
                computed: root.root,
            });
        }
        Ok(Self {
            header,
            root,
            relations,
        })
    }

    /// The raw canonical encoding of relation `name`.
    #[must_use]
    pub fn relation(&self, name: &str) -> Option<&'a [u8]> {
        RELATIONS
            .iter()
            .position(|n| *n == name)
            .map(|i| self.relations[i])
    }
}

/// Check one relation's shape: `[[key, value], ...]` with strictly increasing key bytes. The item
/// is already known to be canonical CBOR. Returns the entry count.
fn check_relation(name: &str, raw: &[u8]) -> Result<u64, CheckpointError> {
    let m = |e| malformed(name, e);
    let mut d = Decoder::new(raw);
    let n = d.array().map_err(m)?;
    let mut previous: Option<&[u8]> = None;
    for _ in 0..n {
        d.array_of(2).map_err(m)?;
        let at = d.position();
        let key = d.item().map_err(m)?;
        if previous.is_some_and(|p| p >= key) {
            return Err(CheckpointError::Malformed(format!(
                "{name}: entry key at byte {at} is not above the previous key"
            )));
        }
        previous = Some(key);
        d.item().map_err(m)?;
    }
    d.finish().map_err(m)?;
    Ok(n as u64)
}

/// The world state at a block boundary, held for writing a checkpoint later: the published
/// snapshot (immutable) and the sequence values beside it. Capturing is O(1); encoding is
/// O(state) and can happen on another thread while blocks continue.
#[derive(Clone)]
pub struct CheckpointCapture {
    pub(crate) snapshot: Arc<WorldStateSnapshot>,
    pub(crate) sequences: [i64; SEQUENCE_COUNT],
}

impl CheckpointCapture {
    /// The captured state's root.
    pub fn state_root(&self) -> Result<StateRoot, StateRootError> {
        let relations = RELATIONS
            .iter()
            .map(|name| {
                canonical_relation_from(&self.snapshot, &self.sequences, name).map(|r| r.digest())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(StateRoot::from_relations(relations))
    }

    /// The checkpoint file for this state as the state after block `height` (whose header hash is
    /// `header_hash`), and its header.
    pub fn encode(
        &self,
        height: u64,
        header_hash: [u8; 32],
        fork_commit: &str,
    ) -> Result<(CheckpointHeader, Vec<u8>), StateRootError> {
        let relations = RELATIONS
            .iter()
            .map(|name| canonical_relation_from(&self.snapshot, &self.sequences, name))
            .collect::<Result<Vec<_>, _>>()?;
        let root = StateRoot::from_relations(relations.iter().map(|r| r.digest()).collect());
        let header = CheckpointHeader {
            height,
            state_root: root.root,
            header_hash,
            fork_commit: fork_commit.to_string(),
        };
        let mut out = header.encode();
        for relation in &relations {
            out.extend_from_slice(&relation.encode());
        }
        Ok((header, out))
    }
}

/// A verified checkpoint read from a [`CheckpointDir`].
#[derive(Clone, Debug)]
pub struct StoredCheckpoint {
    pub path: PathBuf,
    pub header: CheckpointHeader,
    pub bytes: Vec<u8>,
}

impl StoredCheckpoint {
    /// Parse again (cheap relative to a restore) to restore from it.
    pub fn checkpoint(&self) -> Result<Checkpoint<'_>, CheckpointError> {
        Checkpoint::parse(&self.bytes)
    }
}

/// Read and verify the checkpoint file at `path`.
pub fn read_checkpoint(path: &Path) -> Result<StoredCheckpoint, CheckpointError> {
    let bytes = fs::read(path)?;
    let header = Checkpoint::parse(&bytes)?.header;
    Ok(StoredCheckpoint {
        path: path.to_path_buf(),
        header,
        bytes,
    })
}

/// A directory of checkpoint files named `<height:012>.rwcp`.
#[derive(Clone, Debug)]
pub struct CheckpointDir {
    dir: PathBuf,
}

impl CheckpointDir {
    /// Open (creating) the directory.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Where the checkpoint at `height` lives.
    #[must_use]
    pub fn path_for(&self, height: u64) -> PathBuf {
        self.dir
            .join(format!("{height:012}.{CHECKPOINT_EXTENSION}"))
    }

    /// Write a checkpoint file atomically (temporary file, fsync, rename, directory fsync).
    pub fn write(&self, header: &CheckpointHeader, bytes: &[u8]) -> io::Result<PathBuf> {
        let path = self.path_for(header.height);
        let tmp = self
            .dir
            .join(format!(".{:012}.{CHECKPOINT_EXTENSION}.tmp", header.height));
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        if let Ok(dir) = fs::File::open(&self.dir) {
            // Directory fsync makes the rename durable; not every platform supports it.
            let _ = dir.sync_all();
        }
        Ok(path)
    }

    /// Heights of the checkpoint files present, ascending. Other files are ignored.
    pub fn heights(&self) -> io::Result<Vec<u64>> {
        let mut heights: Vec<u64> = fs::read_dir(&self.dir)?
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name();
                let name = name.to_str()?;
                let stem = name.strip_suffix(&format!(".{CHECKPOINT_EXTENSION}"))?;
                (stem.len() == 12 && stem.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| stem.parse().ok())
                    .flatten()
            })
            .collect();
        heights.sort_unstable();
        Ok(heights)
    }

    /// Remove all but the newest `keep` checkpoints. Returns the heights removed.
    pub fn prune(&self, keep: usize) -> io::Result<Vec<u64>> {
        let heights = self.heights()?;
        let excess = heights.len().saturating_sub(keep);
        let removed = heights[..excess].to_vec();
        for h in &removed {
            fs::remove_file(self.path_for(*h))?;
        }
        Ok(removed)
    }

    /// The newest checkpoint that verifies and that `accept` accepts (typically: its height is a
    /// sealed block whose state root is the checkpoint's). Checkpoints that fail to read or verify
    /// are reported through `on_rejected` and skipped.
    pub fn newest_verified(
        &self,
        mut accept: impl FnMut(&CheckpointHeader) -> bool,
        mut on_rejected: impl FnMut(u64, &CheckpointError),
    ) -> io::Result<Option<StoredCheckpoint>> {
        for height in self.heights()?.into_iter().rev() {
            match read_checkpoint(&self.path_for(height)) {
                Ok(stored) if stored.header.height != height => on_rejected(
                    height,
                    &CheckpointError::WrongHeight {
                        height: stored.header.height,
                        expected: height,
                    },
                ),
                Ok(stored) if accept(&stored.header) => return Ok(Some(stored)),
                Ok(_) => {}
                Err(e) => on_rejected(height, &e),
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnonymousObjectMetadata, DatabaseConfig,
        engine::{MoorDB, moor_db::WorldStateTransaction},
    };
    use moor_common::{
        model::{CommitResult, ObjAttrs, ObjectKind, VerbArgsSpec, VerbFlag},
        util::BitEnum,
    };
    use moor_var::{
        AnonymousObjid, NOTHING, Obj, Symbol, program::ProgramType, program::program::Program,
        v_float, v_int, v_list, v_map, v_obj, v_str, v_sym,
    };

    fn commit(tx: WorldStateTransaction) {
        assert!(matches!(tx.commit().unwrap(), CommitResult::Success { .. }));
    }

    /// A small world touching every relation: objects, locations, a verb, properties of several
    /// types, metadata of all three kinds, `last_move`, anonymous metadata and the sequences.
    fn populated() -> Arc<MoorDB> {
        let (db, _) = MoorDB::try_open(None, DatabaseConfig::default()).unwrap();
        let mut tx = db.start_transaction();
        let objs: Vec<Obj> = (0..4)
            .map(|i| {
                tx.create_object(
                    ObjectKind::NextObjid,
                    ObjAttrs::new(NOTHING, NOTHING, NOTHING, BitEnum::new(), &format!("O{i}")),
                )
                .unwrap()
            })
            .collect();
        tx.set_object_parent(&objs[1], &objs[0]).unwrap();
        tx.set_object_location(&objs[1], &objs[0]).unwrap();
        tx.set_object_location(&objs[2], &objs[0]).unwrap();
        tx.set_last_move(&objs[1], NOTHING).unwrap();
        let prop = tx
            .define_property(
                &objs[0],
                &objs[0],
                Symbol::mk("Value"),
                &objs[0],
                BitEnum::new(),
                Some(v_map(&[
                    (v_sym(Symbol::mk("b")), v_list(&[v_int(1), v_float(-0.5)])),
                    (v_str("A"), v_obj(objs[3])),
                ])),
            )
            .unwrap();
        tx.set_property(&objs[1], prop, v_str("Inherited, overridden"))
            .unwrap();
        tx.add_object_verb(
            &objs[0],
            &objs[0],
            &[Symbol::mk("look"), Symbol::mk("l*")],
            ProgramType::MooR(Program::new()),
            BitEnum::new_with(VerbFlag::Read) | VerbFlag::Exec,
            VerbArgsSpec::this_none_this(),
        )
        .unwrap();
        tx.set_object_metadata(&objs[0], Symbol::mk("Colour"), v_str("Red"))
            .unwrap();
        tx.set_property_metadata(&objs[0], prop, Symbol::mk("doc"), v_int(7))
            .unwrap();
        let anon = Obj::mk_anonymous(AnonymousObjid(5));
        tx.anonymous_object_metadata
            .insert(anon, AnonymousObjectMetadata::from_micros(10, 20))
            .unwrap();
        commit(tx);
        db.sequences.increment(1);
        db
    }

    fn export(db: &MoorDB, height: u64) -> (CheckpointHeader, Vec<u8>) {
        db.capture_checkpoint()
            .encode(height, [height as u8; 32], "test")
            .unwrap()
    }

    #[test]
    fn export_import_gives_the_same_root_and_bytes() {
        let db = populated();
        let root = db.state_root().unwrap();
        let (header, bytes) = export(&db, 7);
        assert_eq!(header.state_root, root.root);
        let checkpoint = Checkpoint::parse(&bytes).unwrap();
        assert_eq!(checkpoint.root, root);

        let dir = tempfile::tempdir().unwrap();
        let restored = {
            let (fresh, is_fresh) =
                MoorDB::try_open(Some(dir.path()), DatabaseConfig::default()).unwrap();
            assert!(is_fresh);
            let restored = fresh.restore_checkpoint(&checkpoint).unwrap();
            assert_eq!(restored, root);
            // Exporting the restored database gives the same file.
            assert_eq!(export(&fresh, 7).1, bytes);
            fresh.stop().unwrap();
            restored
        };
        // And so does reopening it from disk.
        let (reopened, fresh) =
            MoorDB::try_open(Some(dir.path()), DatabaseConfig::default()).unwrap();
        assert!(!fresh);
        assert_eq!(reopened.state_root().unwrap(), restored);
        assert_eq!(reopened.sequences.values(), db.sequences.values());
    }

    /// Found by S1-5: Fjall storage loses the sign of `-0.0` (the stored FlatBuffer omits a float
    /// equal to its 0.0 default), so a database holding `-0.0` has a different state root after a
    /// reopen than before. The checkpoint keeps it; the engine's storage does not.
    #[test]
    #[ignore = "known storage bug: -0.0 reads back as 0.0 after a reopen"]
    fn negative_zero_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let before = {
            let (db, _) = MoorDB::try_open(Some(dir.path()), DatabaseConfig::default()).unwrap();
            let mut tx = db.start_transaction();
            let o = tx
                .create_object(ObjectKind::NextObjid, ObjAttrs::default())
                .unwrap();
            tx.define_property(
                &o,
                &o,
                Symbol::mk("z"),
                &o,
                BitEnum::new(),
                Some(v_float(-0.0)),
            )
            .unwrap();
            commit(tx);
            let root = db.state_root().unwrap();
            db.stop().unwrap();
            root
        };
        let (db, _) = MoorDB::try_open(Some(dir.path()), DatabaseConfig::default()).unwrap();
        assert_eq!(db.state_root().unwrap(), before);
    }

    #[test]
    fn a_restored_database_keeps_working() {
        let db = populated();
        let (_, bytes) = export(&db, 1);
        let (fresh, _) = MoorDB::try_open(None, DatabaseConfig::default()).unwrap();
        fresh
            .restore_checkpoint(&Checkpoint::parse(&bytes).unwrap())
            .unwrap();
        for target in [&db, &fresh] {
            let mut tx = target.start_transaction();
            let o = tx
                .create_object(ObjectKind::NextObjid, ObjAttrs::default())
                .unwrap();
            assert_eq!(o, Obj::mk_id(4), "the object counter came back");
            tx.set_object_location(&o, &Obj::mk_id(0)).unwrap();
            commit(tx);
        }
        assert_eq!(db.state_root().unwrap(), fresh.state_root().unwrap());
    }

    #[test]
    fn the_empty_world_round_trips() {
        let (db, _) = MoorDB::try_open(None, DatabaseConfig::default()).unwrap();
        let (header, bytes) = export(&db, 0);
        assert_eq!(
            hex(&header.state_root),
            "61bdca7e9b9c830c63bd4a7ff18caa509ee7dd2fdd2bf01b841d1c1c61fce256"
        );
        let (fresh, _) = MoorDB::try_open(None, DatabaseConfig::default()).unwrap();
        let restored = fresh
            .restore_checkpoint(&Checkpoint::parse(&bytes).unwrap())
            .unwrap();
        assert_eq!(restored.root, header.state_root);
    }

    #[test]
    fn a_flipped_byte_is_rejected() {
        let db = populated();
        let (header, bytes) = export(&db, 3);
        let body = header.encode().len();
        // Every byte of the relations is covered: flip a sample across the body.
        for at in (body..bytes.len()).step_by(7) {
            let mut bad = bytes.clone();
            bad[at] ^= 0x01;
            assert!(Checkpoint::parse(&bad).is_err(), "byte {at} accepted");
        }
    }

    #[test]
    fn a_header_with_another_root_is_rejected() {
        let db = populated();
        let (mut header, bytes) = export(&db, 3);
        let body = bytes[header.encode().len()..].to_vec();
        header.state_root[0] ^= 1;
        let mut forged = header.encode();
        forged.extend_from_slice(&body);
        assert!(matches!(
            Checkpoint::parse(&forged),
            Err(CheckpointError::RootMismatch { .. })
        ));
    }

    #[test]
    fn truncated_and_extended_files_are_rejected() {
        let db = populated();
        let (_, bytes) = export(&db, 3);
        assert!(Checkpoint::parse(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(Checkpoint::parse(&longer).is_err());
    }

    #[test]
    fn restore_refuses_a_database_that_is_not_empty() {
        let db = populated();
        let (_, bytes) = export(&db, 3);
        assert!(matches!(
            db.restore_checkpoint(&Checkpoint::parse(&bytes).unwrap()),
            Err(CheckpointError::NotEmpty)
        ));
    }

    #[test]
    fn checkpoint_dir_keeps_the_newest_and_skips_bad_files() {
        let db = populated();
        let dir = tempfile::tempdir().unwrap();
        let cps = CheckpointDir::open(dir.path().join("cp")).unwrap();
        for h in [10, 20, 30] {
            let (header, bytes) = export(&db, h);
            cps.write(&header, &bytes).unwrap();
        }
        std::fs::write(cps.path().join("notes.txt"), "x").unwrap();
        assert_eq!(cps.heights().unwrap(), [10, 20, 30]);
        // Corrupt the newest; it is skipped and reported.
        let newest = cps.path_for(30);
        let mut bytes = std::fs::read(&newest).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&newest, bytes).unwrap();
        let mut rejected = Vec::new();
        let found = cps
            .newest_verified(|_| true, |h, _| rejected.push(h))
            .unwrap()
            .unwrap();
        assert_eq!((found.header.height, rejected), (20, vec![30]));
        // The predicate can refuse one (e.g. its root is not the chain's at that height).
        let found = cps
            .newest_verified(|h| h.height < 20, |_, _| {})
            .unwrap()
            .unwrap();
        assert_eq!(found.header.height, 10);
        assert_eq!(cps.prune(2).unwrap(), [10]);
        assert_eq!(cps.heights().unwrap(), [20, 30]);
    }
}
