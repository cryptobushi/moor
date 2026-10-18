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

//! `FileSink`: the local DA sink (dev, replay, and the node's event-batch store).
//!
//! Layout of a sink directory:
//!
//! - `segments/<first:012>-<tip:012>.rwseg`: one file per published segment, the exact bytes of
//!   [`Segment::to_bytes`]. Written to a `.tmp` name, fsynced, renamed, directory fsynced. Never
//!   modified afterwards.
//! - `index`: a 16-byte magic, then one 168-byte record per segment, appended and fsynced after
//!   the segment file: `first_be64 || tip_be64 || tip_timestamp_be64 || file_len_be64 ||
//!   tip_hash || tip_state_root || file_sha256 || receipt_time_be64 || SHA-256(the preceding 136
//!   bytes)`. `receipt_time` is the wall-clock second the sink received the segment (0: unknown).
//!   The first format (magic `rw/v1/fsink-idx`, 160-byte records, no receipt time) is read, and
//!   rewritten as the current one when a writable open finds it.
//! - `checkpoints/<height:012>.rwcp`: published checkpoints (ADR 0006 decision 7), each the state
//!   after the published block at its height. Written like segments; not indexed (the file is
//!   self-verifying against the chain's state root at its height).
//! - `genesis.cbor`: the genesis record ([`GenesisRecord`]), written once, next to the index.
//! - `LOCK`: held with an exclusive lock while the sink is open for writing. A sink opened with
//!   [`FileSink::open_read_only`] takes no lock and writes nothing.
//!
//! A crash can leave a torn last index record (dropped on open) or a segment file the index does
//! not list (overwritten when that range is published again). The index is the source of truth.

use crate::genesis::{GENESIS_FILE, GenesisRecord};
use crate::hash::{Hash, sha256};
use crate::header::GENESIS_PARENT_HASH;
use crate::segment::{ChainTip, Segment};
use crate::sink::{DaSink, PublishedSegment, PublishedTip, Receipt, SinkError};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const INDEX_MAGIC: &[u8; 16] = b"rw/v2/fsink-idx\n";
const INDEX_MAGIC_V1: &[u8; 16] = b"rw/v1/fsink-idx\n";
const RECORD_LEN: usize = 168;
const RECORD_BODY: usize = 136;
const RECORD_LEN_V1: usize = 160;
const RECORD_BODY_V1: usize = 128;
const SEGMENTS: &str = "segments";
const CHECKPOINTS: &str = "checkpoints";
const CHECKPOINT_EXTENSION: &str = "rwcp";

/// Whether a sink requires segments to carry event batches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventPolicy {
    /// The node's own sink: event batches live only here (ADR 0001 amendment 9), so a segment
    /// without them is refused.
    Require,
    /// A mirror of a remote sink, which carries no events.
    Optional,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IndexRecord {
    first: u64,
    tip: u64,
    tip_timestamp: u64,
    file_len: u64,
    tip_hash: Hash,
    tip_state_root: Hash,
    digest: Hash,
    /// Wall-clock second the sink received the segment; 0 when unknown (a v1 record).
    receipt_time: u64,
}

impl IndexRecord {
    fn encode(&self) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        out[0..8].copy_from_slice(&self.first.to_be_bytes());
        out[8..16].copy_from_slice(&self.tip.to_be_bytes());
        out[16..24].copy_from_slice(&self.tip_timestamp.to_be_bytes());
        out[24..32].copy_from_slice(&self.file_len.to_be_bytes());
        out[32..64].copy_from_slice(&self.tip_hash);
        out[64..96].copy_from_slice(&self.tip_state_root);
        out[96..128].copy_from_slice(&self.digest);
        out[128..136].copy_from_slice(&self.receipt_time.to_be_bytes());
        let check = sha256(&[&out[..RECORD_BODY]]);
        out[RECORD_BODY..].copy_from_slice(&check);
        out
    }

    /// `None` if the checksum does not match. `v1` records have no receipt time.
    fn decode(raw: &[u8], v1: bool) -> Option<Self> {
        let (len, body) = if v1 {
            (RECORD_LEN_V1, RECORD_BODY_V1)
        } else {
            (RECORD_LEN, RECORD_BODY)
        };
        if raw.len() != len || sha256(&[&raw[..body]])[..] != raw[body..] {
            return None;
        }
        let u64_at = |at: usize| u64::from_be_bytes(raw[at..at + 8].try_into().unwrap_or([0; 8]));
        let hash_at = |at: usize| raw[at..at + 32].try_into().unwrap_or([0; 32]);
        Some(Self {
            first: u64_at(0),
            tip: u64_at(8),
            tip_timestamp: u64_at(16),
            file_len: u64_at(24),
            tip_hash: hash_at(32),
            tip_state_root: hash_at(64),
            digest: hash_at(96),
            receipt_time: if v1 { 0 } else { u64_at(128) },
        })
    }

    fn file_name(&self) -> String {
        segment_file_name(self.first, self.tip)
    }

    fn receipt_time(&self) -> Option<u64> {
        (self.receipt_time != 0).then_some(self.receipt_time)
    }

    fn chain_tip(&self) -> ChainTip {
        ChainTip {
            height: self.tip,
            hash: self.tip_hash,
            timestamp: self.tip_timestamp,
            state_root: self.tip_state_root,
        }
    }
}

fn segment_file_name(first: u64, tip: u64) -> String {
    format!("{first:012}-{tip:012}.rwseg")
}

/// Append-only segment files plus an index. See the module documentation for the layout.
#[derive(Debug)]
pub struct FileSink {
    dir: PathBuf,
    policy: EventPolicy,
    /// `None` when opened read-only.
    index: Option<File>,
    records: Vec<IndexRecord>,
    _lock: Option<File>,
    clock: fn() -> u64,
}

/// Wall-clock seconds since the Unix epoch (the default receipt clock).
fn wall_clock_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl FileSink {
    /// Open (creating if needed) the sink in `dir`, taking its lock and recovering a torn index.
    pub fn open(dir: impl AsRef<Path>, policy: EventPolicy) -> Result<Self, SinkError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(dir.join(SEGMENTS))?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("LOCK"))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(SinkError::Locked),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        migrate_v1_index(&dir)?;
        let mut index = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(dir.join("index"))?;
        let records = load_index(&mut index, true)?;
        let sink = Self {
            dir,
            policy,
            index: Some(index),
            records,
            _lock: Some(lock),
            clock: wall_clock_secs,
        };
        sink.check_last_file()?;
        sink.remove_temporaries()?;
        Ok(sink)
    }

    /// Open an existing sink for reading only (fork API request R2): no lock is taken, nothing is
    /// created, truncated or removed, and [`DaSink::publish`] is refused. Safe beside a running
    /// writer: it appends a segment file (renamed into place whole) before its index record, so
    /// the index this reads, torn tail ignored, lists only complete segments. The view is the
    /// index as it was at open; open again to see later segments.
    pub fn open_read_only(dir: impl AsRef<Path>, policy: EventPolicy) -> Result<Self, SinkError> {
        let dir = dir.as_ref().to_path_buf();
        let mut index = File::open(dir.join("index"))?;
        let records = load_index(&mut index, false)?;
        let sink = Self {
            dir,
            policy,
            index: None,
            records,
            _lock: None,
            clock: wall_clock_secs,
        };
        sink.check_last_file()?;
        Ok(sink)
    }

    /// Use `clock` (seconds) for receipt times instead of the wall clock (tests that compare
    /// sinks byte for byte).
    #[must_use]
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    /// Whether this sink was opened read-only.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.index.is_none()
    }

    /// Publish the genesis record next to block 0 (fork API request R4). Accepted again only when
    /// identical, and only if it names the root the chain starts from.
    pub fn put_genesis(&mut self, record: &GenesisRecord) -> Result<(), SinkError> {
        if self.is_read_only() {
            return Err(SinkError::ReadOnly);
        }
        if let Some(existing) = self.genesis()? {
            return if existing == *record {
                Ok(())
            } else {
                Err(SinkError::GenesisConflict)
            };
        }
        if let Some(first) = self.records.first() {
            let first_segment = self.read_record(first)?;
            if first_segment.prev().state_root != record.genesis_root {
                return Err(SinkError::GenesisMismatch(
                    "its genesis_root is not the first segment's previous state root".into(),
                ));
            }
        }
        let path = self.dir.join(GENESIS_FILE);
        let tmp = self.dir.join(format!("{GENESIS_FILE}.tmp"));
        {
            let mut file = File::create(&tmp)?;
            file.write_all(&record.encode())?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// The sink's directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The published chain tip, `None` when nothing is published.
    #[must_use]
    pub fn tip(&self) -> Option<ChainTip> {
        self.records.last().map(IndexRecord::chain_tip)
    }

    fn segment_path(&self, name: &str) -> PathBuf {
        self.dir.join(SEGMENTS).join(name)
    }

    fn check_last_file(&self) -> Result<(), SinkError> {
        if let Some(record) = self.records.last() {
            let len = fs::metadata(self.segment_path(&record.file_name()))
                .map_err(|e| SinkError::Corrupt(format!("{}: {e}", record.file_name())))?
                .len();
            if len != record.file_len {
                return Err(SinkError::Corrupt(format!(
                    "{} is {len} bytes, the index says {}",
                    record.file_name(),
                    record.file_len
                )));
            }
        }
        Ok(())
    }

    fn remove_temporaries(&self) -> Result<(), SinkError> {
        let _ = fs::remove_file(self.dir.join(format!("{GENESIS_FILE}.tmp")));
        for entry in fs::read_dir(self.dir.join(SEGMENTS))? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "tmp") {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    /// The record holding `height`.
    fn record_at(&self, height: u64) -> Option<&IndexRecord> {
        let i = self.records.partition_point(|r| r.tip < height);
        self.records.get(i).filter(|r| r.first <= height)
    }

    fn read_record(&self, record: &IndexRecord) -> Result<Segment, SinkError> {
        let name = record.file_name();
        let mut bytes = Vec::new();
        File::open(self.segment_path(&name))?.read_to_end(&mut bytes)?;
        if bytes.len() as u64 != record.file_len || sha256(&[&bytes]) != record.digest {
            return Err(SinkError::Corrupt(format!(
                "{name} does not match its index record"
            )));
        }
        let segment =
            Segment::from_bytes(&bytes).map_err(|e| SinkError::Corrupt(format!("{name}: {e}")))?;
        if segment.first_height() != record.first
            || segment.tip().hash != record.tip_hash
            || segment.tip_height() != record.tip
        {
            return Err(SinkError::Corrupt(format!(
                "{name} is not the indexed range"
            )));
        }
        Ok(segment)
    }

    fn receipt(record: &IndexRecord, first_height: u64, fresh: bool) -> Receipt {
        Receipt {
            first_height,
            tip_height: record.tip,
            tip_hash: record.tip_hash,
            location: record.file_name(),
            digest: record.digest,
            bytes: record.file_len,
            attested_time: record.receipt_time(),
            fresh,
        }
    }

    /// Check the heights of `segment` up to `tip` against what is stored.
    fn check_overlap(&self, segment: &Segment, tip: u64) -> Result<(), SinkError> {
        let last = segment.tip_height().min(tip);
        for stored in self.read(segment.first_height(), last)? {
            for block in stored.segment.blocks() {
                let height = block.header.height;
                if let Some(ours) = segment.block(height).filter(|_| height <= last)
                    && ours.header != block.header
                {
                    return Err(SinkError::Conflict { height });
                }
            }
        }
        Ok(())
    }

    fn write(&mut self, segment: &Segment) -> Result<Receipt, SinkError> {
        let bytes = segment.to_bytes()?;
        let tip = segment.tip();
        let record = IndexRecord {
            first: segment.first_height(),
            tip: tip.height,
            tip_timestamp: tip.timestamp,
            file_len: bytes.len() as u64,
            tip_hash: tip.hash,
            tip_state_root: tip.state_root,
            digest: sha256(&[&bytes]),
            // Never 0, which means "unknown".
            receipt_time: (self.clock)().max(1),
        };
        let name = record.file_name();
        let path = self.segment_path(&name);
        let tmp = self.segment_path(&format!("{name}.tmp"));
        {
            let mut file = File::create(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        File::open(self.dir.join(SEGMENTS))?.sync_all()?;
        let index = self.index.as_mut().ok_or(SinkError::ReadOnly)?;
        index.write_all(&record.encode())?;
        index.sync_all()?;
        self.records.push(record);
        Ok(Self::receipt(&record, record.first, true))
    }
}

impl DaSink for FileSink {
    fn publish(&mut self, segment: &Segment) -> Result<Receipt, SinkError> {
        if self.is_read_only() {
            return Err(SinkError::ReadOnly);
        }
        if self.policy == EventPolicy::Require && segment.events().is_none() {
            return Err(SinkError::MissingEvents);
        }
        let tip = self.published_tip()?;
        let first = segment.first_height();
        if first > tip + 1 {
            return Err(SinkError::OutOfOrder { first, tip });
        }
        if first <= tip {
            self.check_overlap(segment, tip)?;
            if segment.tip_height() <= tip {
                let record = self
                    .record_at(segment.tip_height())
                    .ok_or_else(|| SinkError::Corrupt("index has a gap".into()))?;
                return Ok(Self::receipt(record, first, false));
            }
            return self.write(&segment.suffix_from(tip + 1)?);
        }
        let continues = match self.tip() {
            Some(current) => *segment.prev() == current,
            None => segment.prev().hash == GENESIS_PARENT_HASH && segment.prev().timestamp == 0,
        };
        if !continues {
            return Err(SinkError::Discontinuous { height: first });
        }
        self.write(segment)
    }

    fn published_tip_info(&self) -> Result<PublishedTip, SinkError> {
        Ok(self.records.last().map_or(
            PublishedTip {
                height: 0,
                receipt_time: None,
            },
            |r| PublishedTip {
                height: r.tip,
                receipt_time: r.receipt_time(),
            },
        ))
    }

    fn genesis(&self) -> Result<Option<GenesisRecord>, SinkError> {
        match fs::read(self.dir.join(GENESIS_FILE)) {
            Ok(bytes) => {
                Ok(Some(GenesisRecord::decode(&bytes).map_err(|e| {
                    SinkError::Corrupt(format!("{GENESIS_FILE}: {e}"))
                })?))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn read(&self, from: u64, to: u64) -> Result<Vec<PublishedSegment>, SinkError> {
        if from == 0 || from > to {
            return Err(SinkError::Range { from, to });
        }
        let start = self.records.partition_point(|r| r.tip < from);
        self.records[start..]
            .iter()
            .take_while(|r| r.first <= to)
            .map(|r| {
                Ok(PublishedSegment {
                    segment: self.read_record(r)?,
                    receipt_time: r.receipt_time(),
                })
            })
            .collect()
    }

    fn publish_checkpoint(
        &mut self,
        height: u64,
        state_root: &Hash,
        bytes: &[u8],
    ) -> Result<Option<Receipt>, SinkError> {
        let header = self
            .read(height.max(1), height)?
            .into_iter()
            .find_map(|s| s.segment.block(height).map(|b| b.header))
            .filter(|_| height > 0)
            .ok_or(SinkError::OutOfOrder {
                first: height,
                tip: self.published_tip()?,
            })?;
        if header.state_root != *state_root {
            return Err(SinkError::Conflict { height });
        }
        let dir = self.dir.join(CHECKPOINTS);
        fs::create_dir_all(&dir)?;
        let name = checkpoint_file_name(height);
        let path = dir.join(&name);
        let receipt = |fresh| Receipt {
            first_height: height,
            tip_height: height,
            tip_hash: header.hash(),
            location: format!("{CHECKPOINTS}/{name}"),
            digest: sha256(&[bytes]),
            bytes: bytes.len() as u64,
            attested_time: None,
            fresh,
        };
        if let Ok(existing) = fs::read(&path) {
            if existing == bytes {
                return Ok(Some(receipt(false)));
            }
            return Err(SinkError::Conflict { height });
        }
        let tmp = dir.join(format!("{name}.tmp"));
        {
            let mut file = File::create(&tmp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        File::open(&dir)?.sync_all()?;
        Ok(Some(receipt(true)))
    }

    fn checkpoint_heights(&self) -> Result<Vec<u64>, SinkError> {
        let dir = self.dir.join(CHECKPOINTS);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut heights: Vec<u64> = fs::read_dir(dir)?
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let stem = name.strip_suffix(&format!(".{CHECKPOINT_EXTENSION}"))?;
                (stem.len() == 12).then(|| stem.parse().ok()).flatten()
            })
            .collect();
        heights.sort_unstable();
        Ok(heights)
    }

    fn read_checkpoint(&self, height: u64) -> Result<Option<Vec<u8>>, SinkError> {
        match fs::read(
            self.dir
                .join(CHECKPOINTS)
                .join(checkpoint_file_name(height)),
        ) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

fn checkpoint_file_name(height: u64) -> String {
    format!("{height:012}.{CHECKPOINT_EXTENSION}")
}

/// Rewrite a first-format index (no receipt times) as the current format, atomically. Receipt
/// times of those segments stay unknown.
fn migrate_v1_index(dir: &Path) -> Result<(), SinkError> {
    let path = dir.join("index");
    let Ok(bytes) = fs::read(&path) else {
        return Ok(());
    };
    if bytes.len() < INDEX_MAGIC_V1.len() || &bytes[..INDEX_MAGIC_V1.len()] != INDEX_MAGIC_V1 {
        return Ok(());
    }
    let mut records = Vec::new();
    let chunks: Vec<&[u8]> = bytes[INDEX_MAGIC_V1.len()..]
        .chunks(RECORD_LEN_V1)
        .collect();
    for (i, chunk) in chunks.iter().enumerate() {
        match IndexRecord::decode(chunk, true) {
            Some(record) => records.push(record),
            // Only the last append can be torn.
            None if i + 1 == chunks.len() => break,
            None => return Err(SinkError::Corrupt(format!("index record {i} is damaged"))),
        }
    }
    let tmp = dir.join("index.tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(INDEX_MAGIC)?;
        for record in &records {
            file.write_all(&record.encode())?;
        }
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Read the index, dropping a torn tail (cutting it off from the file when `repair`), and check
/// its records chain.
fn load_index(index: &mut File, repair: bool) -> Result<Vec<IndexRecord>, SinkError> {
    let mut bytes = Vec::new();
    index.read_to_end(&mut bytes)?;
    if bytes.len() < INDEX_MAGIC.len() {
        if !INDEX_MAGIC.starts_with(&bytes) && !INDEX_MAGIC_V1.starts_with(&bytes) {
            return Err(SinkError::Corrupt("index has no magic".into()));
        }
        if repair {
            // New, or torn while writing the magic.
            index.set_len(0)?;
            index.write_all(INDEX_MAGIC)?;
            index.sync_all()?;
        }
        return Ok(Vec::new());
    }
    let v1 = match &bytes[..INDEX_MAGIC.len()] {
        m if m == INDEX_MAGIC => false,
        m if m == INDEX_MAGIC_V1 => true,
        _ => return Err(SinkError::Corrupt("index has no magic".into())),
    };
    let record_len = if v1 { RECORD_LEN_V1 } else { RECORD_LEN };
    let body = &bytes[INDEX_MAGIC.len()..];
    let chunks: Vec<&[u8]> = body.chunks(record_len).collect();
    let mut records: Vec<IndexRecord> = Vec::with_capacity(chunks.len());
    for (i, chunk) in chunks.iter().enumerate() {
        match IndexRecord::decode(chunk, v1) {
            Some(record) => records.push(record),
            // Only the last append can be torn.
            None if i + 1 == chunks.len() => break,
            None => return Err(SinkError::Corrupt(format!("index record {i} is damaged"))),
        }
    }
    let mut expected = 1;
    for record in &records {
        if record.first != expected || record.tip < record.first {
            return Err(SinkError::Corrupt(format!(
                "index record for {}..={} does not follow height {}",
                record.first,
                record.tip,
                expected - 1
            )));
        }
        expected = record.tip + 1;
    }
    if repair && !v1 {
        let valid_len = (INDEX_MAGIC.len() + records.len() * RECORD_LEN) as u64;
        if valid_len != bytes.len() as u64 {
            index.set_len(valid_len)?;
            index.sync_all()?;
        }
    }
    Ok(records)
}
