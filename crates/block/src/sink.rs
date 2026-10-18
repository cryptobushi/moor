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

//! Where sealed blocks are published (ADR 0006 decision 5).

use crate::error::FormatError;
use crate::genesis::GenesisRecord;
use crate::hash::Hash;
use crate::segment::Segment;

/// Proof of publication of a segment's blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub first_height: u64,
    pub tip_height: u64,
    /// `header_hash` of the tip.
    pub tip_hash: Hash,
    /// Where the sink holds the tip: a file name, a blob id, a transaction.
    pub location: String,
    /// SHA-256 of the stored bytes at `location`.
    pub digest: Hash,
    /// Size of the stored bytes at `location`.
    pub bytes: u64,
    /// Receipt time the sink attests, in seconds, if it attests one (the replayer's
    /// `timestamp <= receipt + 5 s` check). A `FileSink` records its own write time, which
    /// is not an attestation by anyone else but is the sink's receipt; a remote sink attests
    /// its inclusion time.
    pub attested_time: Option<u64>,
    /// `false` when every block was already published (an idempotent re-publish).
    pub fresh: bool,
}

/// A published segment as read back, with the receipt time the sink holds for it (fork API
/// request R1: ADR 0006 decision 1, the replayer's `timestamp <= receipt + 5 s` check).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedSegment {
    /// The segment.
    pub segment: Segment,
    /// When the sink received it, in seconds, if it has a time. `None` for a segment published
    /// before the sink recorded receipts.
    pub receipt_time: Option<u64>,
}

impl std::ops::Deref for PublishedSegment {
    type Target = Segment;
    fn deref(&self) -> &Segment {
        &self.segment
    }
}

/// The published tip and when the sink received it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishedTip {
    /// The highest published height; 0 when nothing is published.
    pub height: u64,
    /// Receipt time of the segment holding the tip, if the sink has one.
    pub receipt_time: Option<u64>,
}

/// Why a sink refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("format: {0}")]
    Format(#[from] FormatError),
    #[error("segment starts at {first}, but the published tip is {tip}")]
    OutOfOrder { first: u64, tip: u64 },
    #[error("segment does not extend the published chain at height {height}")]
    Discontinuous { height: u64 },
    #[error("height {height} is already published with a different header")]
    Conflict { height: u64 },
    #[error("this sink stores event batches and the segment has none")]
    MissingEvents,
    #[error("the sink is locked by another process")]
    Locked,
    #[error("the sink's store is corrupt: {0}")]
    Corrupt(String),
    #[error("invalid range {from}..={to}")]
    Range { from: u64, to: u64 },
    #[error("the sink was opened read-only")]
    ReadOnly,
    #[error("the sink already holds a different genesis record")]
    GenesisConflict,
    #[error("the genesis record does not belong to this chain: {0}")]
    GenesisMismatch(String),
}

/// A DA sink: publishes segments in height order, immutably.
pub trait DaSink {
    /// Publish `segment`. Must extend the published chain; heights already published are accepted
    /// again only with identical headers (idempotent per height), and a segment that overlaps the
    /// tip publishes only its new blocks.
    fn publish(&mut self, segment: &Segment) -> Result<Receipt, SinkError>;

    /// The highest published height and its receipt time.
    fn published_tip_info(&self) -> Result<PublishedTip, SinkError>;

    /// The highest published height; 0 when nothing is published.
    fn published_tip(&self) -> Result<u64, SinkError> {
        Ok(self.published_tip_info()?.height)
    }

    /// The published segments holding heights `from..=to` (whole segments, in order), each with
    /// the receipt time the sink holds for it. Heights past the tip are simply absent.
    fn read(&self, from: u64, to: u64) -> Result<Vec<PublishedSegment>, SinkError>;

    /// Publish a checkpoint (ADR 0006 decision 7): `bytes` is the checkpoint file of the state
    /// after the published block at `height`, whose state root is `state_root`. The sink checks
    /// that the block is published with that root; it does not parse the file (a reader verifies
    /// it against the chain). Idempotent per height. A sink that carries no checkpoints returns
    /// `Ok(None)` (the default).
    fn publish_checkpoint(
        &mut self,
        _height: u64,
        _state_root: &Hash,
        _bytes: &[u8],
    ) -> Result<Option<Receipt>, SinkError> {
        Ok(None)
    }

    /// Heights of the checkpoints the sink holds, ascending.
    fn checkpoint_heights(&self) -> Result<Vec<u64>, SinkError> {
        Ok(Vec::new())
    }

    /// The checkpoint file published at `height`, if the sink holds one.
    fn read_checkpoint(&self, _height: u64) -> Result<Option<Vec<u8>>, SinkError> {
        Ok(None)
    }

    /// The genesis record published next to block 0 (fork API request R4), if the sink holds one.
    fn genesis(&self) -> Result<Option<GenesisRecord>, SinkError> {
        Ok(None)
    }
}
