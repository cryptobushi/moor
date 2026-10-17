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

//! Blocks and segments: the published form (ADR 0006 decision 3, "Published form").
//!
//! A segment is a run of consecutive blocks. Its payload is one canonical CBOR array:
//!
//! ```text
//! [ "rw/v1/segment", version,
//!   prev_height, prev_hash, prev_timestamp, prev_state_root,   ; the tip before the first block
//!   [block...],
//!   tip_sig,                                                  ; the last block's signature only
//!   [event_batch...] | null ]                                 ; one batch per block, or none
//!
//! block = ts_delta                                            ; compact empty block
//!       | [ts_delta, events_root, state_root, [command...]]   ; any other block
//! ```
//!
//! `parent_hash`, `seed` and `commands_root` are omitted: each is recomputed from the previous
//! block and the block's own commands, so the tip signature covers every block through the hash
//! chain. An empty block (no commands, empty `events_root`, unchanged `state_root`) must use the
//! compact form, so every segment has exactly one payload. The published bytes are the payload
//! compressed as a single zstd frame at [`ZSTD_LEVEL`].

use crate::cbor::{Decoder, Encoder};
use crate::command::CommandBatch;
use crate::error::FormatError;
use crate::event::EventBatch;
use crate::hash::{EMPTY_ROOT, Hash, sha256};
use crate::header::{BLOCK_VERSION, BlockHeader, GENESIS_PARENT_HASH, SignedHeader, seed_for};
use crate::sign::{ChainParams, HeaderSignature, SequencerKey};

/// The first element of every segment payload.
pub const SEGMENT_TAG: &str = "rw/v1/segment";

/// At most this many blocks per segment (one hour of 1 s blocks).
pub const MAX_SEGMENT_BLOCKS: usize = 3_600;

/// Decompression refuses payloads larger than this.
pub const MAX_SEGMENT_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;

/// The zstd compression level of published segments. Single-threaded, no dictionary, content
/// size recorded, no checksum: with the pinned libzstd the bytes are a function of the payload.
pub const ZSTD_LEVEL: i32 = 19;

const MAJOR_UNSIGNED: u8 = 0;

/// The chain as of one sealed block: what the next block links to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChainTip {
    pub height: u64,
    /// `header_hash` of the block at `height` ([`GENESIS_PARENT_HASH`] at height 0).
    pub hash: Hash,
    pub timestamp: u64,
    pub state_root: Hash,
}

impl ChainTip {
    /// Before block 1: height 0, zero hash, timestamp 0, the genesis state root.
    #[must_use]
    pub fn genesis(genesis_root: &Hash) -> Self {
        Self {
            height: 0,
            hash: GENESIS_PARENT_HASH,
            timestamp: 0,
            state_root: *genesis_root,
        }
    }

    /// The tip after the block with this header.
    #[must_use]
    pub fn of(header: &BlockHeader) -> Self {
        Self {
            height: header.height,
            hash: header.hash(),
            timestamp: header.timestamp,
            state_root: header.state_root,
        }
    }

    /// The header of the next block, filling in the derived fields.
    #[must_use]
    pub fn next_header(
        &self,
        timestamp: u64,
        commands_root: Hash,
        events_root: Hash,
        state_root: Hash,
    ) -> BlockHeader {
        let height = self.height + 1;
        BlockHeader {
            version: BLOCK_VERSION,
            height,
            parent_hash: self.hash,
            timestamp,
            seed: seed_for(&self.state_root, height),
            commands_root,
            events_root,
            state_root,
        }
    }

    /// Check that `header` follows this tip: version, height, parent hash, timestamp, seed.
    pub fn check_next(&self, header: &BlockHeader) -> Result<(), FormatError> {
        let height = self.height + 1;
        if header.version != BLOCK_VERSION {
            return Err(FormatError::Version {
                expected: BLOCK_VERSION,
                found: header.version,
            });
        }
        if header.height != height {
            return Err(FormatError::Height {
                expected: height,
                found: header.height,
            });
        }
        if header.parent_hash != self.hash {
            return Err(FormatError::ParentHash { height });
        }
        if header.timestamp < self.timestamp {
            return Err(FormatError::TimestampDecreases { height });
        }
        if header.seed != seed_for(&self.state_root, height) {
            return Err(FormatError::Seed { height });
        }
        Ok(())
    }
}

/// An unsigned block: header and command batch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Block {
    pub header: BlockHeader,
    pub commands: CommandBatch,
}

impl Block {
    /// Check the block follows `prev` and its `commands_root` matches its commands.
    pub fn check(&self, prev: &ChainTip) -> Result<(), FormatError> {
        prev.check_next(&self.header)?;
        if self.header.commands_root != self.commands.root() {
            return Err(FormatError::CommandsRoot {
                height: self.header.height,
            });
        }
        Ok(())
    }

    /// Whether this block is empty in the sense of the compact form.
    #[must_use]
    pub fn is_empty_after(&self, prev: &ChainTip) -> bool {
        self.commands.is_empty()
            && self.header.events_root == EMPTY_ROOT
            && self.header.state_root == prev.state_root
    }
}

/// A sealed block as the sequencer holds it: signed header, commands and events.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SealedBlock {
    pub header: SignedHeader,
    pub commands: CommandBatch,
    pub events: EventBatch,
}

impl SealedBlock {
    /// Build and sign the block after `prev`.
    pub fn seal(
        prev: &ChainTip,
        timestamp: u64,
        commands: CommandBatch,
        events: EventBatch,
        state_root: Hash,
        key: &SequencerKey,
        genesis_root: &Hash,
    ) -> Result<Self, FormatError> {
        let header = prev.next_header(timestamp, commands.root(), events.root(), state_root);
        let block = Self {
            header: header.sign(key, genesis_root)?,
            commands,
            events,
        };
        block.check(prev)?;
        Ok(block)
    }

    /// Check linkage to `prev` and both batch roots (not the signature).
    pub fn check(&self, prev: &ChainTip) -> Result<(), FormatError> {
        let height = self.header.header.height;
        prev.check_next(&self.header.header)?;
        if self.header.header.commands_root != self.commands.root() {
            return Err(FormatError::CommandsRoot { height });
        }
        if self.header.header.events_root != self.events.root() {
            return Err(FormatError::EventsRoot { height });
        }
        self.events.check_against(self.commands.len())
    }

    /// [`Self::check`] plus the signature.
    pub fn verify(&self, prev: &ChainTip, params: &ChainParams) -> Result<(), FormatError> {
        self.check(prev)?;
        Ok(self.header.verify(params)?)
    }

    #[must_use]
    pub fn tip(&self) -> ChainTip {
        ChainTip::of(&self.header.header)
    }

    /// The local block-store encoding: `[signed_header, commands, events]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3);
        self.header.encode_into(&mut e);
        self.commands.encode_into(&mut e);
        self.events.encode_into(&mut e);
        e.into_bytes()
    }

    /// Decode the local block-store encoding. Checks everything but linkage and the signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut d = Decoder::new(bytes);
        d.array_of(3)?;
        let header = SignedHeader::decode_from(&mut d)?;
        let commands = CommandBatch::decode_from(&mut d)?;
        let events = EventBatch::decode_from(&mut d)?;
        d.finish()?;
        let height = header.header.height;
        if header.header.commands_root != commands.root() {
            return Err(FormatError::CommandsRoot { height });
        }
        if header.header.events_root != events.root() {
            return Err(FormatError::EventsRoot { height });
        }
        events.check_against(commands.len())?;
        Ok(Self {
            header,
            commands,
            events,
        })
    }
}

/// A run of consecutive blocks, the unit a [`crate::DaSink`] publishes. Always valid: every
/// constructor checks the chain from `prev` to the tip, the command roots, and the event roots
/// when events are carried. The tip signature is checked against a sequencer by [`Self::verify`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Segment {
    prev: ChainTip,
    blocks: Vec<Block>,
    tip_signature: HeaderSignature,
    events: Option<Vec<EventBatch>>,
}

impl Segment {
    /// A segment from unsigned blocks, the tip's signature and optionally the event batches.
    pub fn new(
        prev: ChainTip,
        blocks: Vec<Block>,
        tip_signature: HeaderSignature,
        events: Option<Vec<EventBatch>>,
    ) -> Result<Self, FormatError> {
        if blocks.is_empty() {
            return Err(FormatError::EmptySegment);
        }
        if blocks.len() > MAX_SEGMENT_BLOCKS {
            return Err(FormatError::SegmentTooLong(blocks.len()));
        }
        let mut tip = prev;
        for block in &blocks {
            block.check(&tip)?;
            tip = ChainTip::of(&block.header);
        }
        if let Some(batches) = &events {
            if batches.len() != blocks.len() {
                return Err(FormatError::EventBatchCount {
                    expected: blocks.len(),
                    found: batches.len(),
                });
            }
            for (block, batch) in blocks.iter().zip(batches) {
                if block.header.events_root != batch.root() {
                    return Err(FormatError::EventsRoot {
                        height: block.header.height,
                    });
                }
                batch.check_against(block.commands.len())?;
            }
        }
        Ok(Self {
            prev,
            blocks,
            tip_signature,
            events,
        })
    }

    /// A segment from consecutive sealed blocks following `prev`, keeping the tip's signature.
    pub fn from_sealed(
        prev: ChainTip,
        sealed: &[SealedBlock],
        include_events: bool,
    ) -> Result<Self, FormatError> {
        let tip = sealed.last().ok_or(FormatError::EmptySegment)?;
        let blocks = sealed
            .iter()
            .map(|b| Block {
                header: b.header.header,
                commands: b.commands.clone(),
            })
            .collect();
        let events = include_events.then(|| sealed.iter().map(|b| b.events.clone()).collect());
        Self::new(prev, blocks, tip.header.sequencer_sig, events)
    }

    /// The tip before the first block.
    #[must_use]
    pub fn prev(&self) -> &ChainTip {
        &self.prev
    }

    #[must_use]
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    #[must_use]
    pub fn events(&self) -> Option<&[EventBatch]> {
        self.events.as_deref()
    }

    #[must_use]
    pub fn tip_signature(&self) -> &HeaderSignature {
        &self.tip_signature
    }

    #[must_use]
    pub fn first_height(&self) -> u64 {
        self.prev.height + 1
    }

    #[must_use]
    pub fn tip_height(&self) -> u64 {
        self.prev.height + self.blocks.len() as u64
    }

    /// The tip's header with its signature.
    #[must_use]
    pub fn tip_header(&self) -> SignedHeader {
        SignedHeader {
            header: self.last().header,
            sequencer_sig: self.tip_signature,
        }
    }

    /// The chain tip after this segment.
    #[must_use]
    pub fn tip(&self) -> ChainTip {
        ChainTip::of(&self.last().header)
    }

    fn last(&self) -> &Block {
        // Non-empty by construction.
        &self.blocks[self.blocks.len() - 1]
    }

    /// The block at `height`.
    #[must_use]
    pub fn block(&self, height: u64) -> Option<&Block> {
        let index = usize::try_from(height.checked_sub(self.first_height())?).ok()?;
        self.blocks.get(index)
    }

    /// Check that the chain's sequencer signed the tip, which covers every block.
    pub fn verify(&self, params: &ChainParams) -> Result<(), FormatError> {
        self.tip_signature
            .verify(params, &self.last().header.hash())
            .map_err(|_| FormatError::TipSignature)
    }

    /// The same segment without event batches (what a remote sink publishes).
    #[must_use]
    pub fn without_events(&self) -> Self {
        Self {
            events: None,
            ..self.clone()
        }
    }

    /// The blocks from `height` to the tip, as a segment of their own.
    pub fn suffix_from(&self, height: u64) -> Result<Self, FormatError> {
        if height <= self.first_height() {
            return if height == self.first_height() {
                Ok(self.clone())
            } else {
                Err(FormatError::OutsideSegment { height })
            };
        }
        if height > self.tip_height() {
            return Err(FormatError::OutsideSegment { height });
        }
        let skip = (height - self.first_height()) as usize;
        Ok(Self {
            prev: ChainTip::of(&self.blocks[skip - 1].header),
            blocks: self.blocks[skip..].to_vec(),
            tip_signature: self.tip_signature,
            events: self.events.as_ref().map(|e| e[skip..].to_vec()),
        })
    }

    /// The canonical CBOR payload.
    #[must_use]
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(9);
        e.text(SEGMENT_TAG);
        e.uint(BLOCK_VERSION);
        e.uint(self.prev.height);
        e.bytes(&self.prev.hash);
        e.uint(self.prev.timestamp);
        e.bytes(&self.prev.state_root);
        e.array(self.blocks.len());
        let mut tip = self.prev;
        for block in &self.blocks {
            let delta = block.header.timestamp - tip.timestamp;
            if block.is_empty_after(&tip) {
                e.uint(delta);
            } else {
                e.array(4);
                e.uint(delta);
                e.bytes(&block.header.events_root);
                e.bytes(&block.header.state_root);
                block.commands.encode_into(&mut e);
            }
            tip = ChainTip::of(&block.header);
        }
        e.bytes(self.tip_signature.as_bytes());
        match &self.events {
            None => e.null(),
            Some(batches) => {
                e.array(batches.len());
                for batch in batches {
                    batch.encode_into(&mut e);
                }
            }
        }
        e.into_bytes()
    }

    /// SHA-256 of the payload: the segment's identity, independent of compression.
    #[must_use]
    pub fn payload_hash(&self) -> Hash {
        sha256(&[&self.encode_payload()])
    }

    /// Decode and fully check a payload (not the tip signature's signer).
    pub fn decode_payload(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut d = Decoder::new(bytes);
        d.array_of(9)?;
        if d.text()? != SEGMENT_TAG {
            return Err(FormatError::Tag {
                expected: SEGMENT_TAG,
            });
        }
        let version = d.uint()?;
        if version != BLOCK_VERSION {
            return Err(FormatError::Version {
                expected: BLOCK_VERSION,
                found: version,
            });
        }
        let prev = ChainTip {
            height: d.uint()?,
            hash: d.bytes_fixed()?,
            timestamp: d.uint()?,
            state_root: d.bytes_fixed()?,
        };
        let n = d.array()?;
        if n > MAX_SEGMENT_BLOCKS {
            return Err(FormatError::SegmentTooLong(n));
        }
        let mut blocks = Vec::with_capacity(n);
        let mut tip = prev;
        for _ in 0..n {
            let height = tip.height + 1;
            let block = if d.peek_major()? == MAJOR_UNSIGNED {
                let timestamp = add_delta(&tip, d.uint()?)?;
                Block {
                    header: tip.next_header(timestamp, EMPTY_ROOT, EMPTY_ROOT, tip.state_root),
                    commands: CommandBatch::empty(),
                }
            } else {
                d.array_of(4)?;
                let timestamp = add_delta(&tip, d.uint()?)?;
                let events_root = d.bytes_fixed()?;
                let state_root = d.bytes_fixed()?;
                let commands = CommandBatch::decode_from(&mut d)?;
                let block = Block {
                    header: tip.next_header(timestamp, commands.root(), events_root, state_root),
                    commands,
                };
                if block.is_empty_after(&tip) {
                    return Err(FormatError::NonCanonicalEmptyBlock { height });
                }
                block
            };
            tip = ChainTip::of(&block.header);
            blocks.push(block);
        }
        let tip_signature = HeaderSignature::from_bytes(d.bytes_fixed()?)?;
        let events = if d.null()? {
            None
        } else {
            let count = d.array()?;
            Some(
                (0..count)
                    .map(|_| EventBatch::decode_from(&mut d))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        };
        d.finish()?;
        Self::new(prev, blocks, tip_signature, events)
    }

    /// The published bytes: the payload as one zstd frame.
    pub fn to_bytes(&self) -> Result<Vec<u8>, FormatError> {
        zstd::bulk::compress(&self.encode_payload(), ZSTD_LEVEL)
            .map_err(|e| FormatError::Compression(e.to_string()))
    }

    /// Decompress one zstd frame and decode the payload with full checks.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FormatError> {
        Self::decode_payload(&decompress(bytes)?)
    }
}

fn add_delta(tip: &ChainTip, delta: u64) -> Result<u64, FormatError> {
    tip.timestamp
        .checked_add(delta)
        .ok_or(FormatError::TimestampOverflow {
            height: tip.height + 1,
        })
}

/// Decompress exactly one zstd frame that records its content size, within the payload limit.
fn decompress(bytes: &[u8]) -> Result<Vec<u8>, FormatError> {
    let error = |what: &str| FormatError::Compression(what.to_string());
    let frame = zstd::zstd_safe::find_frame_compressed_size(bytes)
        .map_err(|_| error("not a zstd frame"))?;
    if frame != bytes.len() {
        return Err(error("bytes after the zstd frame"));
    }
    let size = zstd::zstd_safe::get_frame_content_size(bytes)
        .ok()
        .flatten()
        .ok_or_else(|| error("frame does not record its content size"))?;
    let size = usize::try_from(size)
        .ok()
        .filter(|s| *s <= MAX_SEGMENT_PAYLOAD_BYTES)
        .ok_or_else(|| error("payload exceeds the segment limit"))?;
    let payload = zstd::bulk::decompress(bytes, size).map_err(|e| error(&e.to_string()))?;
    if payload.len() != size {
        return Err(error("payload size differs from the frame header"));
    }
    Ok(payload)
}
