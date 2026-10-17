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
use moor_block::{ChainTip, DaSink, EventPolicy, FileSink, SealedBlock, Segment, SinkError};
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
    assert_eq!(sink.read(1, 9).unwrap(), segments);
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
    assert_eq!(sink.read(1, 2).unwrap(), vec![s]);
}

#[test]
fn reopened_sink_keeps_its_tip_and_segments() {
    let dir = tempfile::tempdir().unwrap();
    let chain = sealed(5);
    let s = segment(&chain, 1, 5, true);
    open(&dir).publish(&s).unwrap();
    let sink = open(&dir);
    assert_eq!(
        (sink.tip(), sink.read(1, 5).unwrap()),
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
