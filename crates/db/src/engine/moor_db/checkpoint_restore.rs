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

//! Checkpoint capture and restore (RuneWorld ADR 0006 decision 7): the inverse of the canonical
//! state encoding, loaded into an empty database in one transaction.

use super::{MoorDB, SEQUENCE_COUNT};
use crate::{
    AnonymousObjectMetadata, EntityMetadataKey, ObjAndUUIDHolder, StringHolder,
    provider::Provider,
    state_root::{
        RELATIONS, StateRoot,
        cbor::{CborError, Decoder},
        checkpoint::{Checkpoint, CheckpointCapture, CheckpointError},
        values,
    },
    tx::{RelationCodomain, RelationDomain, RelationTransaction},
};
use moor_common::model::{CommitResult, ObjFlag};
use moor_var::Obj;
use std::sync::Arc;
use uuid::Uuid;

type Decode<T> = fn(&mut Decoder<'_>) -> Result<T, CborError>;

fn obj(d: &mut Decoder<'_>) -> Result<Obj, CborError> {
    values::decode_obj(d)
}

fn obj_uuid(d: &mut Decoder<'_>) -> Result<ObjAndUUIDHolder, CborError> {
    d.array_of(2)?;
    let o = values::decode_obj(d)?;
    Ok(ObjAndUUIDHolder::new(&o, values::decode_uuid(d)?))
}

/// `[object, kind, uuid, folded key]`; kind 0 object (uuid all zero), 1 property, 2 verb.
fn metadata_key(d: &mut Decoder<'_>) -> Result<EntityMetadataKey, CborError> {
    d.array_of(4)?;
    let o = values::decode_obj(d)?;
    let kind = d.uint()?;
    let id = values::decode_uuid(d)?;
    let key = moor_var::Symbol::mk(d.text()?);
    match kind {
        0 if id == Uuid::nil() => Ok(EntityMetadataKey::object(o, key)),
        1 => Ok(EntityMetadataKey::property(o, id, key)),
        2 => Ok(EntityMetadataKey::verb(o, id, key)),
        _ => Err(CborError::Invalid(format!("bad metadata key kind {kind}"))),
    }
}

fn anonymous_metadata(d: &mut Decoder<'_>) -> Result<AnonymousObjectMetadata, CborError> {
    d.array_of(2)?;
    let created = d.uint()?;
    let accessed = d.uint()?;
    Ok(AnonymousObjectMetadata::from_micros(
        u128::from(created),
        u128::from(accessed),
    ))
}

/// Insert every entry of one relation's canonical encoding. The checkpoint was parsed, so keys
/// are known to be distinct and the database empty: no duplicate checks are needed.
fn restore_relation<D, C, P>(
    rel: &mut RelationTransaction<D, C, P>,
    name: &'static str,
    raw: &[u8],
    key: Decode<D>,
    value: Decode<C>,
) -> Result<u64, CheckpointError>
where
    D: RelationDomain,
    C: RelationCodomain,
    P: Provider<D, C>,
{
    let fail = |detail: String| CheckpointError::Restore {
        relation: name,
        detail,
    };
    let mut d = Decoder::new(raw);
    let n = d.array().map_err(|e| fail(e.to_string()))?;
    for i in 0..n {
        let entry = (|| {
            d.array_of(2)?;
            let k = key(&mut d)?;
            let v = value(&mut d)?;
            Ok::<_, CborError>((k, v))
        })()
        .map_err(|e| fail(format!("entry {i}: {e}")))?;
        rel.insert_guaranteed_unique(entry.0, entry.1)
            .map_err(|e| fail(format!("entry {i}: {e:?}")))?;
    }
    d.finish().map_err(|e| fail(e.to_string()))?;
    Ok(n as u64)
}

/// The 15 sequence slots: `[[0, v0], [1, v1], ...]`, every slot present.
fn decode_sequences(raw: &[u8]) -> Result<[i64; SEQUENCE_COUNT], CheckpointError> {
    let fail = |detail: String| CheckpointError::Restore {
        relation: "sequences",
        detail,
    };
    let mut d = Decoder::new(raw);
    let n = d.array().map_err(|e| fail(e.to_string()))?;
    if n != SEQUENCE_COUNT {
        return Err(fail(format!("{n} slots, expected {SEQUENCE_COUNT}")));
    }
    let mut out = [0i64; SEQUENCE_COUNT];
    for (i, slot) in out.iter_mut().enumerate() {
        let (index, value) = (|| {
            d.array_of(2)?;
            Ok::<_, CborError>((d.uint()?, d.int()?))
        })()
        .map_err(|e| fail(e.to_string()))?;
        if index != i as u64 {
            return Err(fail(format!("slot {index} where {i} was expected")));
        }
        *slot = value;
    }
    d.finish().map_err(|e| fail(e.to_string()))?;
    Ok(out)
}

impl MoorDB {
    /// Hold the current published state for a checkpoint. Call at a quiescent point (a block
    /// boundary): the sequences are read beside the snapshot.
    pub(crate) fn capture_checkpoint(&self) -> CheckpointCapture {
        CheckpointCapture {
            snapshot: self.snapshot_planes.load_root(),
            sequences: self.sequences.values(),
        }
    }

    fn is_empty(&self) -> bool {
        let s = self.snapshot_planes.load_root();
        s.object_location.is_empty()
            && s.object_parent.is_empty()
            && s.object_flags.is_empty()
            && s.object_owner.is_empty()
            && s.object_name.is_empty()
            && s.object_verbdefs.is_empty()
            && s.object_verbs.is_empty()
            && s.object_propdefs.is_empty()
            && s.object_propvalues.is_empty()
            && s.object_propflags.is_empty()
            && s.entity_metadata.is_empty()
            && s.object_last_move.is_empty()
            && s.anonymous_object_metadata.is_empty()
            && self.sequences.values().iter().all(|v| *v == -1)
    }

    /// Load `checkpoint` into this database, which must be empty, in one transaction, and wait
    /// until Fjall holds it. Returns the restored root, which must equal the checkpoint's.
    pub(crate) fn restore_checkpoint(
        self: &Arc<Self>,
        checkpoint: &Checkpoint<'_>,
    ) -> Result<StateRoot, CheckpointError> {
        if !self.is_empty() {
            return Err(CheckpointError::NotEmpty);
        }
        let raw = |name: &str| {
            checkpoint
                .relation(name)
                .ok_or_else(|| CheckpointError::Malformed(format!("no relation {name}")))
        };
        let mut tx = self.start_transaction();
        restore_relation(
            &mut tx.object_location,
            "object_location",
            raw("object_location")?,
            obj,
            obj,
        )?;
        restore_relation(
            &mut tx.object_parent,
            "object_parent",
            raw("object_parent")?,
            obj,
            obj,
        )?;
        restore_relation(
            &mut tx.object_flags,
            "object_flags",
            raw("object_flags")?,
            obj,
            values::decode_flags::<ObjFlag>,
        )?;
        restore_relation(
            &mut tx.object_owner,
            "object_owner",
            raw("object_owner")?,
            obj,
            obj,
        )?;
        restore_relation(
            &mut tx.object_name,
            "object_name",
            raw("object_name")?,
            obj,
            |d| Ok(StringHolder(d.text()?.to_string())),
        )?;
        restore_relation(
            &mut tx.object_verbdefs,
            "object_verbdefs",
            raw("object_verbdefs")?,
            obj,
            values::decode_verbdefs,
        )?;
        restore_relation(
            &mut tx.object_verbs,
            "object_verbs",
            raw("object_verbs")?,
            obj_uuid,
            values::decode_program_type,
        )?;
        restore_relation(
            &mut tx.object_propdefs,
            "object_propdefs",
            raw("object_propdefs")?,
            obj,
            values::decode_propdefs,
        )?;
        restore_relation(
            &mut tx.object_propvalues,
            "object_propvalues",
            raw("object_propvalues")?,
            obj_uuid,
            values::decode_var,
        )?;
        restore_relation(
            &mut tx.object_propflags,
            "object_propflags",
            raw("object_propflags")?,
            obj_uuid,
            values::decode_propperms,
        )?;
        restore_relation(
            &mut tx.entity_metadata,
            "entity_metadata",
            raw("entity_metadata")?,
            metadata_key,
            values::decode_var,
        )?;
        restore_relation(
            &mut tx.object_last_move,
            "object_last_move",
            raw("object_last_move")?,
            obj,
            values::decode_var,
        )?;
        restore_relation(
            &mut tx.anonymous_object_metadata,
            "anonymous_object_metadata",
            raw("anonymous_object_metadata")?,
            obj,
            anonymous_metadata,
        )?;
        debug_assert_eq!(RELATIONS.len(), 14, "restore covers every relation");
        let sequences = decode_sequences(raw("sequences")?)?;
        self.sequences.restore(&sequences);
        let commit_failed = |detail: String| CheckpointError::Restore {
            relation: "commit",
            detail,
        };
        match tx.commit() {
            Ok(CommitResult::Success { .. }) => {}
            Ok(other) => return Err(commit_failed(format!("{other:?}"))),
            Err(e) => return Err(commit_failed(e.to_string())),
        }
        // A world with no relation entries commits nothing, so its sequences would wait for the
        // next write: persist them directly (the same values the commit writes otherwise).
        for (i, value) in sequences.iter().enumerate() {
            self.sequences_partition
                .insert(i.to_le_bytes(), value.to_le_bytes())
                .map_err(|e| commit_failed(format!("sequence {i}: {e}")))?;
        }
        self.wait_for_persistence().map_err(commit_failed)?;
        self.mark_all_fully_loaded();
        let restored = self.state_root()?;
        if restored.root != checkpoint.header.state_root {
            return Err(CheckpointError::RestoredRoot {
                expected: checkpoint.header.state_root,
                restored: restored.root,
            });
        }
        Ok(restored)
    }
}
