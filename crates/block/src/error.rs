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

//! Why bytes or values are not a valid block, batch or segment.

use crate::cbor::CborError;
use crate::sign::SignatureError;

/// A block-format rule a value or its encoding breaks.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    #[error("CBOR: {0}")]
    Cbor(#[from] CborError),
    #[error("signature: {0}")]
    Signature(#[from] SignatureError),
    #[error("expected the tag {expected:?}")]
    Tag { expected: &'static str },
    #[error("format version {found} is not {expected}")]
    Version { expected: u64, found: u64 },
    #[error("unknown command entry type {0}")]
    UnknownCommandType(u64),
    #[error("unknown sequencer input kind {0}")]
    UnknownSequencerInput(u64),
    #[error("object number {0} is out of range")]
    ObjectRange(i64),
    #[error("an envelope may not be empty")]
    EmptyEnvelope,
    #[error("envelope of {0} bytes exceeds the limit")]
    EnvelopeTooLarge(usize),
    #[error("{0} commands exceed the per-block limit")]
    TooManyCommands(usize),
    #[error("command batch of {0} bytes exceeds the per-block limit")]
    CommandBatchTooLarge(usize),
    #[error("event at position {position} has seq {found}")]
    EventSeq { position: u64, found: u64 },
    #[error("event {seq} has a lower command index than the event before it")]
    EventCommandOrder { seq: u64 },
    #[error("event {seq} names command {command_index}, but the block has {commands} commands")]
    EventCommandIndex {
        seq: u64,
        command_index: u64,
        commands: usize,
    },
    #[error("block height {found}, expected {expected}")]
    Height { expected: u64, found: u64 },
    #[error("block {height}: parent_hash is not the previous header hash")]
    ParentHash { height: u64 },
    #[error("block {height}: seed does not follow the seed rule")]
    Seed { height: u64 },
    #[error("block {height}: timestamp decreases")]
    TimestampDecreases { height: u64 },
    #[error("block {height}: timestamp overflows")]
    TimestampOverflow { height: u64 },
    #[error("block {height}: commands_root does not match the command batch")]
    CommandsRoot { height: u64 },
    #[error("block {height}: events_root does not match the event batch")]
    EventsRoot { height: u64 },
    #[error("block {height}: an empty block must use the compact form")]
    NonCanonicalEmptyBlock { height: u64 },
    #[error("a segment needs at least one block")]
    EmptySegment,
    #[error("a segment of {0} blocks exceeds the limit")]
    SegmentTooLong(usize),
    #[error("{found} event batches for {expected} blocks")]
    EventBatchCount { expected: usize, found: usize },
    #[error("height {height} is outside the segment")]
    OutsideSegment { height: u64 },
    #[error("the segment's tip signature does not sign its tip")]
    TipSignature,
    #[error("zstd: {0}")]
    Compression(String),
    #[error("genesis record: {0}")]
    Genesis(String),
}
