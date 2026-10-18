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

//! RuneWorld block format v1 (ADR 0006 decisions 3 and 5; spec `docs/spec/block-format-v0.md` in
//! the runeworld repo).
//!
//! - [`BlockHeader`] / [`SignedHeader`]: the header and its secp256k1 seal. `header_hash` is the
//!   SHA-256 of the canonical header without the signature.
//! - [`CommandBatch`]: the ordered inputs of a block, envelopes carried verbatim.
//! - [`EventBatch`]: the ordered committed events of a block.
//! - [`Meter`]: the engine's per-input measurement, event entry `[5, meter]` (ADR 0007).
//! - [`merkle`]: RFC 6962 roots and inclusion proofs for `commands_root` and `events_root`.
//! - [`Segment`]: the published, zstd-compressed run of consecutive blocks.
//! - [`DaSink`] and [`FileSink`]: where segments are published, with the receipt time of each.
//! - [`GenesisRecord`]: the genesis set-up as data, published next to block 0.
//! - [`durable`]: the sequencer's input journal, local block store and signing guard.
//!
//! Everything is RFC 8949 §4.2.1 deterministic CBOR ([`cbor`]), so two sequencers given the same
//! inputs produce the same bytes. This crate has no MOO dependency: envelopes and events are opaque
//! byte strings whose meaning belongs to the fork's admission step and event encoding.

pub mod cbor;
mod command;
pub mod durable;
mod error;
mod event;
mod file_sink;
pub mod genesis;
mod hash;
mod header;
pub mod merkle;
mod meter;
mod segment;
mod sign;
mod sink;

pub use command::{
    CommandBatch, CommandEntry, MAX_COMMAND_BATCH_BYTES, MAX_COMMANDS_PER_BLOCK,
    MAX_ENVELOPE_BYTES, SequencerInput, SequencerInputKind,
};
pub use error::FormatError;
pub use event::{EventBatch, EventEntry, EventId};
pub use file_sink::{EventPolicy, FileSink};
pub use hash::{EMPTY_ROOT, Hash, hex, sha256, unhex};
pub use header::{BLOCK_VERSION, BlockHeader, GENESIS_PARENT_HASH, SignedHeader, seed_for};
pub use merkle::InclusionProof;
pub use meter::{METER_EVENT_TAG, Meter, MeterKind, MeterOutcome};
pub use segment::{
    Block, ChainTip, MAX_SEGMENT_BLOCKS, MAX_SEGMENT_PAYLOAD_BYTES, SEGMENT_TAG, SealedBlock,
    Segment, ZSTD_LEVEL,
};
pub use sign::{
    Address, ChainParams, HeaderSignature, SequencerKey, SignatureError, signing_digest,
};
pub use genesis::{CoreFile, GENESIS_FILE, GenesisRecord, Principal, core_hash, core_manifest};
pub use sink::{DaSink, PublishedSegment, PublishedTip, Receipt, SinkError};
