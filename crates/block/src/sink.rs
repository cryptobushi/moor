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
    /// `timestamp <= receipt + 5 s` check). `FileSink` attests none.
    pub attested_time: Option<u64>,
    /// `false` when every block was already published (an idempotent re-publish).
    pub fresh: bool,
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
}

/// A DA sink: publishes segments in height order, immutably.
pub trait DaSink {
    /// Publish `segment`. Must extend the published chain; heights already published are accepted
    /// again only with identical headers (idempotent per height), and a segment that overlaps the
    /// tip publishes only its new blocks.
    fn publish(&mut self, segment: &Segment) -> Result<Receipt, SinkError>;

    /// The highest published height; 0 when nothing is published.
    fn published_tip(&self) -> Result<u64, SinkError>;

    /// The published segments holding heights `from..=to` (whole segments, in order). Heights past
    /// the tip are simply absent.
    fn read(&self, from: u64, to: u64) -> Result<Vec<Segment>, SinkError>;
}
