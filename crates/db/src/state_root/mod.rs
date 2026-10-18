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

//! Canonical state encoding and state root, version 1 (phase 1: a full O(state) hash).
//!
//! The state root commits to the logical world database: every relation, plus the sequences, in
//! a canonical CBOR encoding (RFC 8949 §4.2.1). It never covers storage metadata (Fjall
//! transaction timestamps, record chains, on-disk bytes) or events. Specified in RuneWorld
//! `docs/spec/state-root-v0.md`.
//!
//! # Layout
//!
//! - A relation is a CBOR array of `[key, value]` entries in bytewise order of the encoded keys.
//!   Its *relation hash* is SHA-256 of that array.
//! - `state_root = SHA-256(header || pair_1 || ... || pair_n)`, a CBOR sequence where
//!   `header = ["rw/v1/state", 1, n]` and `pair_i = [name_i, relation_hash_i]` in [`RELATIONS`]
//!   order.
//!
//! New relations are appended to [`RELATIONS`] by name (and bump [`STATE_VERSION`]); a test fails
//! if the database defines a relation this list does not cover.

pub mod cbor;
pub mod values;

use crate::engine::moor_db::{SEQUENCE_COUNT, SequenceState, WorldStateSnapshot};
use crate::tx::{RelationCodomain, RelationDomain, RelationIndex};
use cbor::{CborError, Encoder};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Domain separation string, the first element of the root header.
pub const STATE_DOMAIN: &str = "rw/v1/state";
/// Version of the encoding and of the relation list.
pub const STATE_VERSION: u64 = 1;

/// The relations the root covers, in root order. `sequences` is the counter keyspace, encoded as a
/// relation from sequence index to value.
pub const RELATIONS: [&str; 14] = [
    "object_location",
    "object_parent",
    "object_flags",
    "object_owner",
    "object_name",
    "object_verbdefs",
    "object_verbs",
    "object_propdefs",
    "object_propvalues",
    "object_propflags",
    "entity_metadata",
    "object_last_move",
    "anonymous_object_metadata",
    "sequences",
];

/// Why a root or a dump could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum StateRootError {
    #[error("unknown relation {0:?}")]
    UnknownRelation(String),
    #[error("cannot encode relation {relation}: {source}")]
    Encoding {
        relation: &'static str,
        #[source]
        source: CborError,
    },
}

/// One relation's contribution to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationDigest {
    pub name: &'static str,
    /// SHA-256 of the relation's canonical encoding.
    pub hash: [u8; 32],
    pub entries: u64,
}

/// The state root and the per-relation hashes that feed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateRoot {
    pub root: [u8; 32],
    /// In [`RELATIONS`] order.
    pub relations: Vec<RelationDigest>,
}

impl StateRoot {
    /// Combine relation digests (in [`RELATIONS`] order) into the root.
    #[must_use]
    pub fn from_relations(relations: Vec<RelationDigest>) -> Self {
        let mut hasher = Sha256::new();
        let mut header = Encoder::new();
        header.array(3);
        header.text(STATE_DOMAIN);
        header.uint(STATE_VERSION);
        header.uint(relations.len() as u64);
        hasher.update(header.as_bytes());
        for r in &relations {
            let mut pair = Encoder::new();
            pair.array(2);
            pair.text(r.name);
            pair.bytes(&r.hash);
            hasher.update(pair.as_bytes());
        }
        Self {
            root: hasher.finalize().into(),
            relations,
        }
    }

    #[must_use]
    pub fn root_hex(&self) -> String {
        hex(&self.root)
    }

    /// The first relation whose hash differs from `other`'s, by root order.
    #[must_use]
    pub fn first_difference(&self, other: &StateRoot) -> Option<&'static str> {
        self.relations
            .iter()
            .zip(&other.relations)
            .find(|(a, b)| a != b)
            .map(|(a, _)| a.name)
    }
}

/// Lower-case hex of `bytes`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The canonical encoding of one relation: its entries as encoded `(key, value)` pairs, sorted by
/// key bytes. This is the dump endpoint's payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalRelation {
    pub name: &'static str,
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl CanonicalRelation {
    fn new(
        name: &'static str,
        mut entries: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Self, StateRootError> {
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        if entries.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(StateRootError::Encoding {
                relation: name,
                source: CborError::Invalid("two entries encode to the same key".into()),
            });
        }
        Ok(Self { name, entries })
    }

    fn array_head(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(self.entries.len());
        e.into_bytes()
    }

    /// The full canonical bytes: `[[key, value], ...]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let size = self
            .entries
            .iter()
            .map(|(k, v)| 1 + k.len() + v.len())
            .sum::<usize>();
        let mut out = Vec::with_capacity(size + 9);
        out.extend_from_slice(&self.array_head());
        for (k, v) in &self.entries {
            out.push(0x82);
            out.extend_from_slice(k);
            out.extend_from_slice(v);
        }
        out
    }

    /// SHA-256 of [`Self::encode`], computed without materialising it.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.array_head());
        for (k, v) in &self.entries {
            hasher.update([0x82]);
            hasher.update(k);
            hasher.update(v);
        }
        hasher.finalize().into()
    }

    #[must_use]
    pub fn digest(&self) -> RelationDigest {
        RelationDigest {
            name: self.name,
            hash: self.hash(),
            entries: self.entries.len() as u64,
        }
    }

    /// One line per entry, `key => value` in diagnostic notation, in canonical order.
    pub fn diagnostic_lines(&self, abbreviate: bool) -> Result<Vec<String>, CborError> {
        self.entries
            .iter()
            .map(|(k, v)| {
                Ok(format!(
                    "{} => {}",
                    cbor::diagnostic(k, abbreviate)?,
                    cbor::diagnostic(v, abbreviate)?
                ))
            })
            .collect()
    }
}

type Encode<T> = fn(&mut Encoder, &T) -> Result<(), CborError>;

fn entries<D, C>(
    name: &'static str,
    index: &dyn RelationIndex<D, C>,
    key: Encode<D>,
    value: Encode<C>,
) -> Result<CanonicalRelation, StateRootError>
where
    D: RelationDomain,
    C: RelationCodomain,
{
    let wrap = |source| StateRootError::Encoding {
        relation: name,
        source,
    };
    let mut out = Vec::with_capacity(index.len());
    for (d, entry) in index.iter() {
        let mut k = Encoder::new();
        key(&mut k, d).map_err(wrap)?;
        let mut v = Encoder::new();
        value(&mut v, &entry.value).map_err(wrap)?;
        out.push((k.into_bytes(), v.into_bytes()));
    }
    CanonicalRelation::new(name, out)
}

fn obj_key(e: &mut Encoder, o: &moor_var::Obj) -> Result<(), CborError> {
    values::obj(e, o);
    Ok(())
}

fn obj_uuid_key(e: &mut Encoder, k: &crate::ObjAndUUIDHolder) -> Result<(), CborError> {
    e.array(2);
    values::obj(e, &k.obj());
    values::uuid(e, &k.uuid());
    Ok(())
}

/// `entity_metadata` key: `[object, kind, uuid, key]`, kind 0 object, 1 property, 2 verb; the uuid
/// is 16 zero bytes for object metadata. The key symbol is case-folded, as the storage key is, so
/// the encoding survives a reload from disk.
fn metadata_key(e: &mut Encoder, k: &crate::EntityMetadataKey) -> Result<(), CborError> {
    e.array(4);
    values::obj(e, &k.obj());
    let kind = if k.is_object() {
        0
    } else if k.is_property() {
        1
    } else if k.is_verb() {
        2
    } else {
        return Err(CborError::Invalid("unknown metadata kind".into()));
    };
    e.uint(kind);
    let id = k.uuid().unwrap_or_default();
    values::uuid(e, &id);
    e.text(&k.key().to_folded_case());
    Ok(())
}

fn var_value(e: &mut Encoder, v: &moor_var::Var) -> Result<(), CborError> {
    values::var(e, v)
}

/// `anonymous_object_metadata` value: `[created_micros, last_accessed_micros]`.
fn anonymous_metadata(
    e: &mut Encoder,
    m: &crate::AnonymousObjectMetadata,
) -> Result<(), CborError> {
    let micros = |t: std::time::SystemTime| {
        t.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_micros()).ok())
            .ok_or_else(|| CborError::Invalid("anonymous metadata time out of range".into()))
    };
    e.array(2);
    e.uint(micros(m.created_time())?);
    e.uint(micros(m.last_accessed_time())?);
    Ok(())
}

/// Encode one relation of `snapshot` (or the sequences).
pub(crate) fn canonical_relation(
    snapshot: &WorldStateSnapshot,
    sequences: &SequenceState,
    name: &str,
) -> Result<CanonicalRelation, StateRootError> {
    let s = snapshot;
    match name {
        "object_location" => entries(
            "object_location",
            s.object_location.as_ref(),
            obj_key,
            obj_key,
        ),
        "object_parent" => entries("object_parent", s.object_parent.as_ref(), obj_key, obj_key),
        "object_flags" => entries("object_flags", s.object_flags.as_ref(), obj_key, |e, f| {
            values::flags(e, f);
            Ok(())
        }),
        "object_owner" => entries("object_owner", s.object_owner.as_ref(), obj_key, obj_key),
        "object_name" => entries("object_name", s.object_name.as_ref(), obj_key, |e, n| {
            e.text(&n.0);
            Ok(())
        }),
        "object_verbdefs" => entries(
            "object_verbdefs",
            s.object_verbdefs.as_ref(),
            obj_key,
            values::verbdefs,
        ),
        "object_verbs" => entries(
            "object_verbs",
            s.object_verbs.as_ref(),
            obj_uuid_key,
            values::program_type,
        ),
        "object_propdefs" => entries(
            "object_propdefs",
            s.object_propdefs.as_ref(),
            obj_key,
            |e, p| {
                values::propdefs(e, p);
                Ok(())
            },
        ),
        "object_propvalues" => entries(
            "object_propvalues",
            s.object_propvalues.as_ref(),
            obj_uuid_key,
            var_value,
        ),
        "object_propflags" => entries(
            "object_propflags",
            s.object_propflags.as_ref(),
            obj_uuid_key,
            |e, p| {
                values::propperms(e, p);
                Ok(())
            },
        ),
        "entity_metadata" => entries(
            "entity_metadata",
            s.entity_metadata.as_ref(),
            metadata_key,
            var_value,
        ),
        "object_last_move" => entries(
            "object_last_move",
            s.object_last_move.as_ref(),
            obj_key,
            var_value,
        ),
        "anonymous_object_metadata" => entries(
            "anonymous_object_metadata",
            s.anonymous_object_metadata.as_ref(),
            obj_key,
            anonymous_metadata,
        ),
        "sequences" => {
            // Every slot, including never-used ones (value -1): the slot count is part of v1.
            let entries = (0..SEQUENCE_COUNT)
                .map(|i| {
                    let mut k = Encoder::new();
                    k.uint(i as u64);
                    let mut v = Encoder::new();
                    v.int(sequences.load(i));
                    (k.into_bytes(), v.into_bytes())
                })
                .collect();
            CanonicalRelation::new("sequences", entries)
        }
        other => Err(StateRootError::UnknownRelation(other.to_string())),
    }
}

/// Canonical size of one `[key, value]` pair: the pair head plus both encodings.
fn pair_size<D, C>(d: &D, c: &C, key: Encode<D>, value: Encode<C>) -> i64 {
    let mut k = Encoder::new();
    let mut v = Encoder::new();
    // An unencodable value counts as zero: sizes are a measurement, not a commitment.
    let _ = key(&mut k, d);
    let _ = value(&mut v, c);
    1 + k.as_bytes().len() as i64 + v.as_bytes().len() as i64
}

/// Add one relation's working set to `out`: for each written key, the pair size after the write
/// minus the pair size the transaction started from, attributed to `owner(key)`. With `existence`,
/// also counts rows created (an insert with no base row) and deleted.
fn relation_delta<D, C>(
    ws: &crate::tx::WorkingSet<D, C>,
    key: Encode<D>,
    value: Encode<C>,
    owner: fn(&D) -> moor_var::Obj,
    existence: bool,
    out: &mut crate::commit_meter::CommitDelta,
) where
    D: RelationDomain,
    C: RelationCodomain,
{
    use crate::tx::OpType;
    for (d, op) in ws.tuples_ref() {
        let before = ws
            .base_value(d)
            .map_or(0, |(_, c)| pair_size(d, &c, key, value));
        let (after, existed_after) = match &op.operation {
            OpType::Insert(c) | OpType::Update(c) => (pair_size(d, c, key, value), true),
            OpType::Delete => (0, false),
        };
        out.add_storage(owner(d), after - before);
        if existence {
            let existed_before = ws.base_value(d).is_some();
            match (existed_before, existed_after) {
                (false, true) => out.created += 1,
                (true, false) => out.recycled += 1,
                _ => {}
            }
        }
    }
}

/// The net canonical-size change of a transaction's write set, by object, and the objects it
/// created and recycled. `sequences` is not included (fixed slot count, value sizes only).
pub(crate) fn working_set_delta(
    ws: &crate::engine::moor_db::WorkingSets,
) -> crate::commit_meter::CommitDelta {
    let mut out = crate::commit_meter::CommitDelta::default();
    let obj_owner: fn(&moor_var::Obj) -> moor_var::Obj = |o| *o;
    let uuid_owner: fn(&crate::ObjAndUUIDHolder) -> moor_var::Obj = |k| k.obj();
    let meta_owner: fn(&crate::EntityMetadataKey) -> moor_var::Obj = |k| k.obj();
    let o = &mut out;
    relation_delta(&ws.object_location, obj_key, obj_key, obj_owner, false, o);
    relation_delta(&ws.object_parent, obj_key, obj_key, obj_owner, false, o);
    relation_delta(
        &ws.object_flags,
        obj_key,
        |e, f| {
            values::flags(e, f);
            Ok(())
        },
        obj_owner,
        true,
        o,
    );
    relation_delta(&ws.object_owner, obj_key, obj_key, obj_owner, false, o);
    relation_delta(
        &ws.object_name,
        obj_key,
        |e, n| {
            e.text(&n.0);
            Ok(())
        },
        obj_owner,
        false,
        o,
    );
    relation_delta(
        &ws.object_verbdefs,
        obj_key,
        values::verbdefs,
        obj_owner,
        false,
        o,
    );
    relation_delta(
        &ws.object_verbs,
        obj_uuid_key,
        values::program_type,
        uuid_owner,
        false,
        o,
    );
    relation_delta(
        &ws.object_propdefs,
        obj_key,
        |e, p| {
            values::propdefs(e, p);
            Ok(())
        },
        obj_owner,
        false,
        o,
    );
    relation_delta(
        &ws.object_propvalues,
        obj_uuid_key,
        var_value,
        uuid_owner,
        false,
        o,
    );
    relation_delta(
        &ws.object_propflags,
        obj_uuid_key,
        |e, p| {
            values::propperms(e, p);
            Ok(())
        },
        uuid_owner,
        false,
        o,
    );
    relation_delta(
        &ws.entity_metadata,
        metadata_key,
        var_value,
        meta_owner,
        false,
        o,
    );
    relation_delta(
        &ws.object_last_move,
        obj_key,
        var_value,
        obj_owner,
        false,
        o,
    );
    relation_delta(
        &ws.anonymous_object_metadata,
        obj_key,
        anonymous_metadata,
        obj_owner,
        false,
        o,
    );
    out
}

/// The root over every relation of `snapshot`.
pub(crate) fn state_root(
    snapshot: &WorldStateSnapshot,
    sequences: &SequenceState,
) -> Result<StateRoot, StateRootError> {
    let relations = RELATIONS
        .iter()
        .map(|name| canonical_relation(snapshot, sequences, name).map(|r| r.digest()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StateRoot::from_relations(relations))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DatabaseConfig, DatabaseRelation, engine::MoorDB};
    use moor_common::{
        model::{CommitResult, ObjAttrs, ObjectKind},
        util::BitEnum,
    };
    use moor_var::{NOTHING, Obj, Symbol, v_int, v_str};
    use std::sync::Arc;

    fn commit(tx: crate::engine::moor_db::WorldStateTransaction) {
        assert!(matches!(tx.commit().unwrap(), CommitResult::Success { .. }));
    }

    fn create(db: &Arc<MoorDB>, n: usize) -> Vec<Obj> {
        let mut tx = db.start_transaction();
        let objs = (0..n)
            .map(|i| {
                tx.create_object(
                    ObjectKind::NextObjid,
                    ObjAttrs::new(NOTHING, NOTHING, NOTHING, BitEnum::new(), &format!("o{i}")),
                )
                .unwrap()
            })
            .collect();
        commit(tx);
        objs
    }

    #[test]
    fn relation_list_covers_every_database_relation() {
        let mut expected: Vec<&str> = DatabaseRelation::ALL.iter().map(|r| r.as_str()).collect();
        expected.push("sequences");
        assert_eq!(RELATIONS.to_vec(), expected);
    }

    #[test]
    fn root_is_independent_of_the_order_writes_happened_in() {
        let roots: Vec<StateRoot> = [[0usize, 1], [1, 0]]
            .iter()
            .map(|order| {
                let (db, _) = MoorDB::try_open(None, DatabaseConfig::default()).unwrap();
                let objs = create(&db, 3);
                for &i in order {
                    let mut tx = db.start_transaction();
                    tx.set_object_location(&objs[i], &objs[2]).unwrap();
                    commit(tx);
                }
                db.state_root().unwrap()
            })
            .collect();
        assert_eq!(roots[0], roots[1]);
    }

    #[test]
    fn a_property_write_changes_exactly_one_relation_hash() {
        let (db, _) = MoorDB::try_open(None, DatabaseConfig::default()).unwrap();
        let objs = create(&db, 1);
        let mut tx = db.start_transaction();
        let prop = tx
            .define_property(
                &objs[0],
                &objs[0],
                Symbol::mk("p"),
                &objs[0],
                BitEnum::new(),
                Some(v_int(1)),
            )
            .unwrap();
        commit(tx);
        let before = db.state_root().unwrap();
        let mut tx = db.start_transaction();
        tx.set_property(&objs[0], prop, v_int(2)).unwrap();
        commit(tx);
        let after = db.state_root().unwrap();
        assert_ne!(before.root, after.root);
        let changed: Vec<_> = before
            .relations
            .iter()
            .zip(&after.relations)
            .filter(|(a, b)| a != b)
            .map(|(a, _)| a.name)
            .collect();
        assert_eq!(changed, ["object_propvalues"]);
    }

    #[test]
    fn root_survives_a_reopen_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let before = {
            let (db, _) = MoorDB::try_open(Some(dir.path()), DatabaseConfig::default()).unwrap();
            let objs = create(&db, 2);
            let mut tx = db.start_transaction();
            tx.set_object_location(&objs[0], &objs[1]).unwrap();
            let prop = tx
                .define_property(
                    &objs[1],
                    &objs[1],
                    Symbol::mk("Desc"),
                    &objs[1],
                    BitEnum::new(),
                    Some(v_str("x")),
                )
                .unwrap();
            commit(tx);
            // Two more writes to the same property: storage keeps a record chain, the root must not.
            for v in ["y", "z"] {
                let mut tx = db.start_transaction();
                tx.set_property(&objs[1], prop, v_str(v)).unwrap();
                commit(tx);
            }
            let root = db.state_root().unwrap();
            db.stop().unwrap();
            root
        };
        let (db, fresh) = MoorDB::try_open(Some(dir.path()), DatabaseConfig::default()).unwrap();
        assert!(!fresh);
        assert_eq!(db.state_root().unwrap(), before);
    }

    #[test]
    fn dump_of_a_relation_hashes_to_its_digest() {
        let (db, _) = MoorDB::try_open(None, DatabaseConfig::default()).unwrap();
        create(&db, 2);
        let root = db.state_root().unwrap();
        for digest in &root.relations {
            let dump = db.canonical_relation(digest.name).unwrap();
            let bytes = dump.encode();
            let hash: [u8; 32] = Sha256::digest(&bytes).into();
            assert_eq!(hash, digest.hash, "{}", digest.name);
            assert_eq!(dump.entries.len() as u64, digest.entries);
            let mut d = cbor::Decoder::new(&bytes);
            d.item().unwrap();
            d.finish().unwrap();
        }
        assert!(db.canonical_relation("no_such_relation").is_err());
    }
}

/// Test vectors published in RuneWorld `docs/spec/state-root-v0.md`. A change here is a change
/// to the state encoding and needs a new [`STATE_VERSION`].
#[cfg(test)]
mod spec_vectors {
    use super::*;
    use crate::{DatabaseConfig, engine::MoorDB};
    use moor_var::{
        E_PERM, Obj, Symbol, v_error, v_float, v_int, v_list, v_map, v_obj, v_str, v_sym,
    };

    fn var_hex(v: &moor_var::Var) -> String {
        let mut e = Encoder::new();
        values::var(&mut e, v).unwrap();
        hex(e.as_bytes())
    }

    #[test]
    fn var_vectors() {
        let cases = [
            (v_int(5), "820205"),
            (v_int(-1), "820220"),
            (v_str("hi"), "8204626869"),
            (v_obj(Obj::mk_id(-1)), "820520"),
            (v_obj(Obj::mk_id(42)), "8205182a"),
            (v_float(1.5), "82031b3ff8000000000000"),
            (v_list(&[v_int(1), v_str("x")]), "820782820201820461 78"),
            (v_sym(Symbol::mk("Foo")), "820963466f6f"),
            (v_error(E_PERM.into()), "840603f6f6"),
            (
                v_map(&[(v_sym(Symbol::mk("a")), v_int(2)), (v_str("b"), v_int(1))]),
                "8208a282046162820201820961618202 02",
            ),
        ];
        for (v, want) in cases {
            assert_eq!(var_hex(&v), want.replace(' ', ""), "{v:?}");
        }
    }

    #[test]
    fn relation_and_root_vectors() {
        // An empty relation is the empty array 0x80.
        let empty = CanonicalRelation::new("object_last_move", vec![]).unwrap();
        assert_eq!(
            hex(&empty.hash()),
            "76be8b528d0075f7aae98d6fa57a6d3c83ae480a8469e668d7b0af968995ac71"
        );

        // object_name with #1 "Root" and #0 "System": sorted by key bytes (0x00 < 0x01).
        let mut entries = Vec::new();
        for (id, name) in [(1, "Root"), (0, "System")] {
            let mut k = Encoder::new();
            values::obj(&mut k, &Obj::mk_id(id));
            let mut v = Encoder::new();
            v.text(name);
            entries.push((k.into_bytes(), v.into_bytes()));
        }
        let names = CanonicalRelation::new("object_name", entries).unwrap();
        assert_eq!(
            hex(&names.encode()),
            "82820066 53797374656d 820164526f6f74".replace(' ', "")
        );
        assert_eq!(
            hex(&names.hash()),
            "13a1fe3ec28e4f8455a4c28f6112d81ac3fcc09122f475fd2716d3d80a2af157"
        );

        // The root of a freshly opened, empty database: 13 empty relations and 15 sequences at -1.
        let (db, _) = MoorDB::try_open(None, DatabaseConfig::default()).unwrap();
        let root = db.state_root().unwrap();
        let sequences = db.canonical_relation("sequences").unwrap();
        assert_eq!(
            hex(&sequences.encode()),
            "8f820020820120820220820320820420820520820620820720820820820920820a20820b20820c20820d20820e20"
        );
        assert_eq!(
            root.root_hex(),
            "61bdca7e9b9c830c63bd4a7ff18caa509ee7dd2fdd2bf01b841d1c1c61fce256"
        );
    }
}
