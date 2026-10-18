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

//! `FileSink`: ordering, idempotency, refusal, persistence, torn-index recovery.

mod common;

use common::*;
use moor_block::{
    ChainTip, CoreFile, DaSink, EventPolicy, FileSink, GenesisRecord, Principal, PublishedSegment,
    SealedBlock, Segment, SinkError,
};
use std::fs::OpenOptions;
use std::io::Write as _;

fn sealed(n: usize) -> Vec<SealedBlock> {
    let specs: Vec<BlockSpec> = (0..n)
        .map(|i| {
            if i % 3 == 0 {
                typical_block(2, &i.to_string())
            } else {
                BlockSpec::empty(1)
            }
        })
        .collect();
    seal_chain(ChainTip::genesis(&genesis_root()), &specs)
}

/// Segment of `sealed[from-1..to]` (heights `from..=to`).
fn segment(sealed: &[SealedBlock], from: usize, to: usize, events: bool) -> Segment {
    let prev = if from == 1 {
        ChainTip::genesis(&genesis_root())
    } else {
        sealed[from - 2].tip()
    };
    Segment::from_sealed(prev, &sealed[from - 1..to], events).unwrap()
}

fn plain(read: Vec<PublishedSegment>) -> Vec<Segment> {
    read.into_iter().map(|p| p.segment).collect()
}

fn open(dir: &tempfile::TempDir) -> FileSink {
    FileSink::open(dir.path(), EventPolicy::Require).unwrap()
}

#[test]
fn publishes_and_reads_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let chain = sealed(9);
    let segments = [
        segment(&chain, 1, 3, true),
        segment(&chain, 4, 7, true),
        segment(&chain, 8, 9, true),
    ];
    for s in &segments {
        sink.publish(s).unwrap();
    }
    assert_eq!(plain(sink.read(1, 9).unwrap()), segments);
}

#[test]
fn published_tip_advances() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let chain = sealed(5);
    let before = sink.published_tip().unwrap();
    sink.publish(&segment(&chain, 1, 5, true)).unwrap();
    assert_eq!((before, sink.published_tip().unwrap()), (0, 5));
}

#[test]
fn read_returns_whole_overlapping_segments() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let chain = sealed(9);
    for (a, b) in [(1, 3), (4, 7), (8, 9)] {
        sink.publish(&segment(&chain, a, b, true)).unwrap();
    }
    let ranges: Vec<(u64, u64)> = sink
        .read(5, 8)
        .unwrap()
        .iter()
        .map(|s| (s.first_height(), s.tip_height()))
        .collect();
    assert_eq!(ranges, [(4, 7), (8, 9)]);
}

#[test]
fn read_past_the_tip_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    sink.publish(&segment(&sealed(3), 1, 3, true)).unwrap();
    assert!(sink.read(4, 10).unwrap().is_empty());
}

#[test]
fn refuses_a_gap() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let chain = sealed(6);
    sink.publish(&segment(&chain, 1, 2, true)).unwrap();
    assert!(matches!(
        sink.publish(&segment(&chain, 4, 6, true)),
        Err(SinkError::OutOfOrder { first: 4, tip: 2 })
    ));
}

#[test]
fn refuses_a_first_segment_not_at_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    assert!(matches!(
        sink.publish(&segment(&sealed(4), 2, 4, true)),
        Err(SinkError::OutOfOrder { first: 2, tip: 0 })
    ));
}

#[test]
fn republishing_the_same_segment_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let s = segment(&sealed(4), 1, 4, true);
    let first = sink.publish(&s).unwrap();
    let again = sink.publish(&s).unwrap();
    assert_eq!(
        again,
        moor_block::Receipt {
            fresh: false,
            ..first
        }
    );
}

#[test]
fn republishing_a_sub_range_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let chain = sealed(6);
    sink.publish(&segment(&chain, 1, 6, true)).unwrap();
    let receipt = sink.publish(&segment(&chain, 2, 4, true)).unwrap();
    assert_eq!((receipt.fresh, sink.published_tip().unwrap()), (false, 6));
}

#[test]
fn overlapping_segment_publishes_only_new_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let chain = sealed(8);
    sink.publish(&segment(&chain, 1, 4, true)).unwrap();
    let receipt = sink.publish(&segment(&chain, 3, 8, true)).unwrap();
    let ranges: Vec<(u64, u64)> = sink
        .read(1, 8)
        .unwrap()
        .iter()
        .map(|s| (s.first_height(), s.tip_height()))
        .collect();
    assert_eq!((receipt.fresh, ranges), (true, vec![(1, 4), (5, 8)]));
}

#[test]
fn refuses_a_conflicting_header_at_a_published_height() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let chain = sealed(4);
    sink.publish(&segment(&chain, 1, 4, true)).unwrap();
    // A fork: same block 1, different block 2.
    let mut specs = vec![typical_block(2, "0"), typical_block(1, "fork")];
    specs[1].dt = 1;
    let fork = seal_chain(ChainTip::genesis(&genesis_root()), &specs);
    assert!(matches!(
        sink.publish(
            &Segment::from_sealed(ChainTip::genesis(&genesis_root()), &fork, true).unwrap()
        ),
        Err(SinkError::Conflict { height: 2 })
    ));
}

#[test]
fn refuses_a_segment_that_does_not_extend_the_tip() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let chain = sealed(2);
    sink.publish(&segment(&chain, 1, 1, true)).unwrap();
    // Block 2 of a different chain.
    let other = seal_chain(
        ChainTip::genesis(&genesis_root()),
        &[typical_block(1, "other"), BlockSpec::empty(1)],
    );
    assert!(matches!(
        sink.publish(&segment(&other, 2, 2, true)),
        Err(SinkError::Discontinuous { height: 2 })
    ));
}

#[test]
fn require_policy_refuses_segments_without_events() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    assert!(matches!(
        sink.publish(&segment(&sealed(2), 1, 2, false)),
        Err(SinkError::MissingEvents)
    ));
}

#[test]
fn optional_policy_stores_segments_without_events() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = FileSink::open(dir.path(), EventPolicy::Optional).unwrap();
    let s = segment(&sealed(2), 1, 2, false);
    sink.publish(&s).unwrap();
    assert_eq!(plain(sink.read(1, 2).unwrap()), vec![s]);
}

#[test]
fn reopened_sink_keeps_its_tip_and_segments() {
    let dir = tempfile::tempdir().unwrap();
    let chain = sealed(5);
    let s = segment(&chain, 1, 5, true);
    open(&dir).publish(&s).unwrap();
    let sink = open(&dir);
    assert_eq!(
        (sink.tip(), plain(sink.read(1, 5).unwrap())),
        (Some(chain[4].tip()), vec![s])
    );
}

#[test]
fn second_open_is_locked_out() {
    let dir = tempfile::tempdir().unwrap();
    let _sink = open(&dir);
    assert!(matches!(
        FileSink::open(dir.path(), EventPolicy::Require),
        Err(SinkError::Locked)
    ));
}

#[test]
fn torn_index_tail_is_dropped_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let chain = sealed(4);
    open(&dir).publish(&segment(&chain, 1, 2, true)).unwrap();
    // A crash halfway through appending the next record.
    OpenOptions::new()
        .append(true)
        .open(dir.path().join("index"))
        .unwrap()
        .write_all(&[0xab; 70])
        .unwrap();
    let mut sink = open(&dir);
    sink.publish(&segment(&chain, 3, 4, true)).unwrap();
    assert_eq!(sink.published_tip().unwrap(), 4);
}

#[test]
fn tampered_segment_file_is_reported_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let receipt = sink.publish(&segment(&sealed(3), 1, 3, true)).unwrap();
    let path = dir.path().join("segments").join(&receipt.location);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(matches!(sink.read(1, 3), Err(SinkError::Corrupt(_))));
}

#[test]
fn receipt_digest_is_the_file_hash() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let receipt = sink.publish(&segment(&sealed(3), 1, 3, true)).unwrap();
    let bytes = std::fs::read(dir.path().join("segments").join(&receipt.location)).unwrap();
    assert_eq!(receipt.digest, moor_block::sha256(&[&bytes]));
}

#[test]
fn checkpoints_publish_after_their_block_and_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let chain = sealed(6);
    let root = chain[3].header.header.state_root;
    // Height 4 is not published yet.
    assert!(sink.publish_checkpoint(4, &root, b"cp").is_err());
    sink.publish(&segment(&chain, 1, 6, true)).unwrap();
    let receipt = sink.publish_checkpoint(4, &root, b"cp").unwrap().unwrap();
    assert!(receipt.fresh);
    assert_eq!(receipt.tip_hash, chain[3].header.header.hash());
    assert_eq!(receipt.location, "checkpoints/000000000004.rwcp");
    // Idempotent; a different file at the same height conflicts.
    assert!(
        !sink
            .publish_checkpoint(4, &root, b"cp")
            .unwrap()
            .unwrap()
            .fresh
    );
    assert!(matches!(
        sink.publish_checkpoint(4, &root, b"other"),
        Err(SinkError::Conflict { height: 4 })
    ));
    assert_eq!(sink.checkpoint_heights().unwrap(), [4]);
    assert_eq!(
        sink.read_checkpoint(4).unwrap().as_deref(),
        Some(&b"cp"[..])
    );
    assert_eq!(sink.read_checkpoint(5).unwrap(), None);
}

#[test]
fn a_checkpoint_with_another_root_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let chain = sealed(3);
    sink.publish(&segment(&chain, 1, 3, true)).unwrap();
    let mut root = chain[1].header.header.state_root;
    root[0] ^= 1;
    assert!(matches!(
        sink.publish_checkpoint(2, &root, b"cp"),
        Err(SinkError::Conflict { height: 2 })
    ));
    assert!(sink.checkpoint_heights().unwrap().is_empty());
}

fn fixed_clock() -> u64 {
    1_700_000_000
}

#[test]
fn read_returns_the_receipt_time_of_each_segment() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir).with_clock(fixed_clock);
    let chain = sealed(4);
    let receipt = sink.publish(&segment(&chain, 1, 2, true)).unwrap();
    sink.publish(&segment(&chain, 3, 4, true)).unwrap();
    let times: Vec<_> = sink
        .read(1, 4)
        .unwrap()
        .iter()
        .map(|p| p.receipt_time)
        .collect();
    assert_eq!(
        (receipt.attested_time, times),
        (Some(1_700_000_000), vec![Some(1_700_000_000); 2])
    );
}

#[test]
fn the_default_receipt_time_is_the_write_time() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    sink.publish(&segment(&sealed(2), 1, 2, true)).unwrap();
    let got = sink.read(1, 2).unwrap()[0].receipt_time.unwrap();
    assert!(got >= before && got <= before + 5, "{got} vs {before}");
}

#[test]
fn published_tip_info_carries_the_tip_segments_receipt_time() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir).with_clock(fixed_clock);
    assert_eq!(sink.published_tip_info().unwrap().receipt_time, None);
    sink.publish(&segment(&sealed(3), 1, 3, true)).unwrap();
    let tip = sink.published_tip_info().unwrap();
    assert_eq!((tip.height, tip.receipt_time), (3, Some(1_700_000_000)));
}

#[test]
fn an_idempotent_republish_reports_the_original_receipt_time() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir).with_clock(fixed_clock);
    let chain = sealed(3);
    sink.publish(&segment(&chain, 1, 3, true)).unwrap();
    let sink = sink.with_clock(|| 1_800_000_000);
    let mut sink = sink;
    let receipt = sink.publish(&segment(&chain, 1, 3, true)).unwrap();
    assert_eq!((receipt.fresh, receipt.attested_time), (false, Some(1_700_000_000)));
}

#[test]
fn a_first_format_index_is_read_without_receipt_times_and_migrated_on_a_writable_open() {
    let dir = tempfile::tempdir().unwrap();
    let chain = sealed(4);
    open(&dir)
        .with_clock(fixed_clock)
        .publish(&segment(&chain, 1, 2, true))
        .unwrap();
    // Rewrite the index as the first format: v1 magic, 160-byte records without receipt time.
    let path = dir.path().join("index");
    let bytes = std::fs::read(&path).unwrap();
    let mut v1 = b"rw/v1/fsink-idx\n".to_vec();
    let mut record = bytes[16..16 + 128].to_vec();
    let check = moor_block::sha256(&[&record]);
    record.extend_from_slice(&check);
    v1.extend_from_slice(&record);
    std::fs::write(&path, &v1).unwrap();
    let ro = FileSink::open_read_only(dir.path(), EventPolicy::Require).unwrap();
    assert_eq!(ro.read(1, 2).unwrap()[0].receipt_time, None);
    assert_eq!(std::fs::read(&path).unwrap(), v1, "a read-only open writes nothing");
    let mut sink = open(&dir).with_clock(fixed_clock);
    assert_eq!(sink.published_tip().unwrap(), 2);
    sink.publish(&segment(&chain, 3, 4, true)).unwrap();
    let times: Vec<_> = sink.read(1, 4).unwrap().iter().map(|p| p.receipt_time).collect();
    assert_eq!(times, vec![None, Some(1_700_000_000)]);
}

#[test]
fn a_read_only_open_takes_no_lock_and_sees_published_segments() {
    let dir = tempfile::tempdir().unwrap();
    let mut writer = open(&dir);
    let chain = sealed(4);
    writer.publish(&segment(&chain, 1, 4, true)).unwrap();
    let reader = FileSink::open_read_only(dir.path(), EventPolicy::Require).unwrap();
    assert!(reader.is_read_only());
    assert_eq!(reader.published_tip().unwrap(), 4);
    assert_eq!(reader.read(1, 4).unwrap().len(), 1);
}

#[test]
fn a_read_only_open_beside_a_writer_sees_only_complete_segments() {
    let dir = tempfile::tempdir().unwrap();
    let mut writer = open(&dir);
    let chain = sealed(4);
    writer.publish(&segment(&chain, 1, 2, true)).unwrap();
    // The writer is mid-append: a torn next index record.
    OpenOptions::new()
        .append(true)
        .open(dir.path().join("index"))
        .unwrap()
        .write_all(&[0xab; 70])
        .unwrap();
    let reader = FileSink::open_read_only(dir.path(), EventPolicy::Require).unwrap();
    assert_eq!(reader.published_tip().unwrap(), 2);
}

#[test]
fn a_read_only_open_does_not_modify_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    open(&dir).publish(&segment(&sealed(3), 1, 3, true)).unwrap();
    // A torn tail and a stray temporary: a writable open would repair both.
    let index = dir.path().join("index");
    OpenOptions::new().append(true).open(&index).unwrap().write_all(&[1; 9]).unwrap();
    let tmp = dir.path().join("segments").join("x.tmp");
    std::fs::write(&tmp, b"x").unwrap();
    let before = std::fs::read(&index).unwrap();
    let _reader = FileSink::open_read_only(dir.path(), EventPolicy::Require).unwrap();
    assert_eq!(std::fs::read(&index).unwrap(), before);
    assert!(tmp.exists());
    assert!(!dir.path().join("LOCK").metadata().is_err(), "the writer's lock file is untouched");
}

#[test]
fn a_read_only_open_of_a_missing_sink_is_an_error_and_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope");
    assert!(FileSink::open_read_only(&missing, EventPolicy::Require).is_err());
    assert!(!missing.exists());
}

#[test]
fn a_read_only_sink_refuses_to_publish() {
    let dir = tempfile::tempdir().unwrap();
    let chain = sealed(2);
    open(&dir).publish(&segment(&chain, 1, 1, true)).unwrap();
    let mut reader = FileSink::open_read_only(dir.path(), EventPolicy::Require).unwrap();
    assert!(matches!(
        reader.publish(&segment(&chain, 2, 2, true)),
        Err(SinkError::ReadOnly)
    ));
}

fn genesis_record(root: [u8; 32]) -> GenesisRecord {
    GenesisRecord {
        genesis_root: root,
        sequencer: moor_block::Address([5; 20]),
        fork_commit: "abc".into(),
        core_files: vec![CoreFile {
            path: "a.moo".into(),
            sha256: [1; 32],
        }],
        features: vec![("custom_errors".into(), true)],
        principals: vec![Principal {
            player: 2,
            wallet: moor_block::Address([6; 20]),
        }],
        domain_salt: [0; 32],
    }
}

#[test]
fn the_genesis_record_is_published_beside_block_zero_and_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    assert_eq!(sink.genesis().unwrap(), None);
    let record = genesis_record(genesis_root());
    sink.put_genesis(&record).unwrap();
    drop(sink);
    let reader = FileSink::open_read_only(dir.path(), EventPolicy::Require).unwrap();
    assert_eq!(reader.genesis().unwrap(), Some(record));
}

#[test]
fn the_genesis_record_is_idempotent_and_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    let record = genesis_record(genesis_root());
    sink.put_genesis(&record).unwrap();
    sink.put_genesis(&record).unwrap();
    let mut other = record.clone();
    other.fork_commit = "def".into();
    assert!(matches!(sink.put_genesis(&other), Err(SinkError::GenesisConflict)));
}

#[test]
fn a_genesis_record_for_another_root_is_refused_once_blocks_exist() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = open(&dir);
    sink.publish(&segment(&sealed(2), 1, 2, true)).unwrap();
    assert!(matches!(
        sink.put_genesis(&genesis_record([9; 32])),
        Err(SinkError::GenesisMismatch(_))
    ));
    sink.put_genesis(&genesis_record(genesis_root())).unwrap();
}
