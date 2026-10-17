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

//! Round trips, inclusion proofs, signatures and segment checks.

mod common;

use common::*;
use moor_block::{
    Block, BlockHeader, ChainParams, ChainTip, CommandBatch, CommandEntry, EMPTY_ROOT, EventBatch,
    EventEntry, FormatError, SealedBlock, Segment, SignedHeader, cbor::Encoder,
};

fn chain() -> Vec<SealedBlock> {
    let specs = vec![
        typical_block(3, "1"),
        BlockSpec::empty(1),
        BlockSpec::empty(2),
        BlockSpec {
            dt: 1,
            commands: vec![disconnect(12)],
            events: vec![],
            state: Some(state("4")),
        },
        typical_block(5, "5"),
    ];
    seal_chain(ChainTip::genesis(&genesis_root()), &specs)
}

fn params() -> ChainParams {
    ChainParams {
        genesis_root: genesis_root(),
        sequencer: key().address(),
    }
}

#[test]
fn command_entry_round_trips() {
    for entry in [
        CommandEntry::Envelope(envelope(1, 1, "go west")),
        disconnect(-1),
        disconnect(i32::MAX),
    ] {
        assert_eq!(CommandEntry::decode(&entry.encode()), Ok(entry));
    }
}

#[test]
fn command_batch_round_trips() {
    let batch = chain()[0].commands.clone();
    assert_eq!(CommandBatch::decode(&batch.encode()), Ok(batch));
}

#[test]
fn event_entry_round_trips() {
    let entry = EventEntry {
        seq: 7,
        command_index: 3,
        recipient: -1,
        event: event_bytes(4, "hi"),
    };
    assert_eq!(EventEntry::decode(&entry.encode()), Ok(entry));
}

#[test]
fn event_batch_round_trips() {
    let batch = chain()[4].events.clone();
    assert_eq!(EventBatch::decode(&batch.encode()), Ok(batch));
}

#[test]
fn header_round_trips() {
    let header = chain()[2].header.header;
    assert_eq!(BlockHeader::decode(&header.encode()), Ok(header));
}

#[test]
fn signed_header_round_trips() {
    let header = chain()[3].header;
    assert_eq!(SignedHeader::decode(&header.encode()), Ok(header));
}

#[test]
fn sealed_block_round_trips() {
    let block = chain()[0].clone();
    assert_eq!(SealedBlock::decode(&block.encode()), Ok(block));
}

#[test]
fn segment_payload_round_trips() {
    let segment = Segment::from_sealed(ChainTip::genesis(&genesis_root()), &chain(), true).unwrap();
    assert_eq!(
        Segment::decode_payload(&segment.encode_payload()),
        Ok(segment)
    );
}

#[test]
fn segment_bytes_round_trip() {
    let segment = Segment::from_sealed(ChainTip::genesis(&genesis_root()), &chain(), true).unwrap();
    assert_eq!(
        Segment::from_bytes(&segment.to_bytes().unwrap()),
        Ok(segment)
    );
}

#[test]
fn segment_without_events_round_trips() {
    let segment =
        Segment::from_sealed(ChainTip::genesis(&genesis_root()), &chain(), false).unwrap();
    assert_eq!(
        Segment::from_bytes(&segment.to_bytes().unwrap()),
        Ok(segment)
    );
}

#[test]
fn decoded_segment_reconstructs_every_header() {
    let sealed = chain();
    let segment = Segment::from_sealed(ChainTip::genesis(&genesis_root()), &sealed, false).unwrap();
    let decoded = Segment::from_bytes(&segment.to_bytes().unwrap()).unwrap();
    let headers: Vec<_> = decoded.blocks().iter().map(|b| b.header).collect();
    let expected: Vec<_> = sealed.iter().map(|b| b.header.header).collect();
    assert_eq!(headers, expected);
}

#[test]
fn segment_tip_signature_verifies() {
    let segment =
        Segment::from_sealed(ChainTip::genesis(&genesis_root()), &chain(), false).unwrap();
    assert_eq!(segment.verify(&params()), Ok(()));
}

#[test]
fn segment_from_another_sequencer_fails_verification() {
    let segment =
        Segment::from_sealed(ChainTip::genesis(&genesis_root()), &chain(), false).unwrap();
    let other = ChainParams {
        sequencer: moor_block::SequencerKey::from_secret(&[0x22; 32])
            .unwrap()
            .address(),
        ..params()
    };
    assert_eq!(segment.verify(&other), Err(FormatError::TipSignature));
}

#[test]
fn every_sealed_header_signature_recovers_the_sequencer() {
    for block in chain() {
        assert_eq!(
            block
                .header
                .sequencer_sig
                .recover(&genesis_root(), &block.header.hash()),
            Ok(key().address())
        );
    }
}

#[test]
fn falsified_state_root_breaks_the_tip_signature() {
    // ADR 0006 exit (b) at the format level: rewrite one state root, keep the old signature.
    let sealed = chain();
    let segment = Segment::from_sealed(ChainTip::genesis(&genesis_root()), &sealed, false).unwrap();
    let mut blocks = segment.blocks().to_vec();
    let mut prev = ChainTip::genesis(&genesis_root());
    for (i, block) in blocks.iter_mut().enumerate() {
        let state_root = if i == 0 {
            state("forged")
        } else {
            block.header.state_root
        };
        block.header = prev.next_header(
            block.header.timestamp,
            block.header.commands_root,
            block.header.events_root,
            state_root,
        );
        prev = ChainTip::of(&block.header);
    }
    let forged = Segment::new(*segment.prev(), blocks, *segment.tip_signature(), None).unwrap();
    assert_eq!(forged.verify(&params()), Err(FormatError::TipSignature));
}

#[test]
fn every_command_has_a_verifying_inclusion_proof() {
    for block in chain() {
        let root = block.header.header.commands_root;
        for (i, entry) in block.commands.entries().iter().enumerate() {
            let proof = block.commands.proof(i).unwrap();
            assert!(proof.verify(&root, &entry.encode()), "command {i}");
        }
    }
}

#[test]
fn every_event_has_a_verifying_inclusion_proof() {
    for block in chain() {
        let root = block.header.header.events_root;
        for entry in block.events.entries() {
            let proof = block.events.proof(entry.seq).unwrap();
            assert!(proof.verify(&root, &entry.encode()), "event {}", entry.seq);
        }
    }
}

#[test]
fn single_command_proof_is_empty_and_verifies() {
    let block = &chain()[3];
    let proof = block.commands.proof(0).unwrap();
    assert!(
        proof.path.is_empty()
            && proof.verify(&block.header.header.commands_root, &disconnect(12).encode())
    );
}

#[test]
fn odd_counts_prove_every_event() {
    for n in [1usize, 3, 5, 7, 9, 13] {
        let mut batch = EventBatch::empty();
        for i in 0..n {
            batch.push(1, 4, vec![i as u8; 3]).unwrap();
        }
        let root = batch.root();
        assert!(
            batch
                .entries()
                .iter()
                .all(|e| batch.proof(e.seq).unwrap().verify(&root, &e.encode())),
            "n = {n}"
        );
    }
}

#[test]
fn a_command_proof_does_not_prove_a_substituted_command() {
    let block = &chain()[0];
    let proof = block.commands.proof(1).unwrap();
    let forged = CommandEntry::Envelope(envelope(2, 2, "give sword to thief"));
    assert!(!proof.verify(&block.header.header.commands_root, &forged.encode()));
}

#[test]
fn empty_blocks_use_one_byte() {
    let sealed = seal_chain(
        ChainTip::genesis(&genesis_root()),
        &[typical_block(1, "a"), BlockSpec::empty(1)],
    );
    let one =
        Segment::from_sealed(ChainTip::genesis(&genesis_root()), &sealed[..1], false).unwrap();
    let two = Segment::from_sealed(ChainTip::genesis(&genesis_root()), &sealed, false).unwrap();
    assert_eq!(two.encode_payload().len() - one.encode_payload().len(), 1);
}

#[test]
fn non_compact_empty_block_is_refused() {
    let sealed = seal_chain(ChainTip::genesis(&genesis_root()), &[BlockSpec::empty(5)]);
    let segment = Segment::from_sealed(ChainTip::genesis(&genesis_root()), &sealed, false).unwrap();
    // Re-encode the one empty block in the full form by hand.
    let payload = segment.encode_payload();
    let mut e = Encoder::new();
    e.array(4);
    e.uint(5);
    e.bytes(&EMPTY_ROOT);
    e.bytes(&genesis_root());
    e.array(0);
    let full = e.into_bytes();
    // The blocks array `81 05` follows tag, version and the 4 prev fields (86 bytes).
    let at = 86;
    assert_eq!(payload[at..at + 2], [0x81, 0x05]);
    let mut forged = payload[..at + 1].to_vec();
    forged.extend_from_slice(&full);
    forged.extend_from_slice(&payload[at + 2..]);
    assert_eq!(
        Segment::decode_payload(&forged),
        Err(FormatError::NonCanonicalEmptyBlock { height: 1 })
    );
}

#[test]
fn segment_refuses_a_gap_in_heights() {
    let sealed = chain();
    let blocks: Vec<Block> = [&sealed[0], &sealed[2]]
        .iter()
        .map(|b| Block {
            header: b.header.header,
            commands: b.commands.clone(),
        })
        .collect();
    assert!(matches!(
        Segment::new(
            ChainTip::genesis(&genesis_root()),
            blocks,
            sealed[2].header.sequencer_sig,
            None
        ),
        Err(FormatError::Height {
            expected: 2,
            found: 3
        })
    ));
}

#[test]
fn segment_refuses_mismatched_events() {
    let sealed = chain();
    let segment = Segment::from_sealed(ChainTip::genesis(&genesis_root()), &sealed, false).unwrap();
    let mut events: Vec<EventBatch> = sealed.iter().map(|b| b.events.clone()).collect();
    events.swap(0, 4);
    assert_eq!(
        Segment::new(
            *segment.prev(),
            segment.blocks().to_vec(),
            *segment.tip_signature(),
            Some(events)
        ),
        Err(FormatError::EventsRoot { height: 1 })
    );
}

#[test]
fn seal_refuses_a_decreasing_timestamp() {
    let sealed = chain();
    let tip = sealed[4].tip();
    assert_eq!(
        SealedBlock::seal(
            &tip,
            tip.timestamp - 1,
            CommandBatch::empty(),
            EventBatch::empty(),
            tip.state_root,
            &key(),
            &genesis_root(),
        ),
        Err(FormatError::TimestampDecreases { height: 6 })
    );
}

#[test]
fn seal_refuses_events_naming_a_missing_command() {
    let mut events = EventBatch::empty();
    events.push(2, 4, vec![1]).unwrap();
    let genesis = ChainTip::genesis(&genesis_root());
    assert!(matches!(
        SealedBlock::seal(
            &genesis,
            1,
            CommandBatch::new(vec![disconnect(4)]).unwrap(),
            events,
            state("x"),
            &key(),
            &genesis_root()
        ),
        Err(FormatError::EventCommandIndex { .. })
    ));
}

#[test]
fn trailing_bytes_after_the_zstd_frame_are_refused() {
    let segment =
        Segment::from_sealed(ChainTip::genesis(&genesis_root()), &chain(), false).unwrap();
    let mut bytes = segment.to_bytes().unwrap();
    bytes.push(0);
    assert!(matches!(
        Segment::from_bytes(&bytes),
        Err(FormatError::Compression(_))
    ));
}

#[test]
fn suffix_keeps_the_tip_and_links_to_the_block_before() {
    let sealed = chain();
    let segment = Segment::from_sealed(ChainTip::genesis(&genesis_root()), &sealed, true).unwrap();
    let suffix = segment.suffix_from(3).unwrap();
    assert_eq!(
        (
            suffix.first_height(),
            *suffix.prev(),
            suffix.verify(&params())
        ),
        (3, sealed[1].tip(), Ok(()))
    );
}

/// Sizes for the report (`cargo test -p moor-block --test blocks sizes -- --nocapture`).
#[test]
fn sizes() {
    let genesis = ChainTip::genesis(&genesis_root());
    let empty = seal_chain(genesis, &[BlockSpec::empty(1)]);
    let typical = seal_chain(genesis, &[typical_block(10, "t")]);
    let header = typical[0].header.encode().len();
    let one_empty = Segment::from_sealed(genesis, &empty, false).unwrap();
    let one_typical = Segment::from_sealed(genesis, &typical, false).unwrap();
    let one_typical_ev = Segment::from_sealed(genesis, &typical, true).unwrap();
    println!(
        "signed header: {header} B; sealed empty block (store form): {} B",
        empty[0].encode().len()
    );
    println!(
        "typical block (10 commands, 20 events) store form: {} B; commands {} B; events {} B",
        typical[0].encode().len(),
        typical[0].commands.encode().len(),
        typical[0].events.encode().len()
    );
    println!(
        "segment of 1 empty block: payload {} B, zstd {} B",
        one_empty.encode_payload().len(),
        one_empty.to_bytes().unwrap().len()
    );
    println!(
        "segment of 1 typical block: payload {} B (with events {} B), zstd {} B (with events {} B)",
        one_typical.encode_payload().len(),
        one_typical_ev.encode_payload().len(),
        one_typical.to_bytes().unwrap().len(),
        one_typical_ev.to_bytes().unwrap().len()
    );
    // One minute: 60 blocks, a quarter of them carrying 10 commands, the rest empty.
    let specs: Vec<BlockSpec> = (0..60)
        .map(|i| {
            if i % 4 == 0 {
                typical_block(10, &i.to_string())
            } else {
                BlockSpec::empty(1)
            }
        })
        .collect();
    let minute = seal_chain(genesis, &specs);
    let seg = Segment::from_sealed(genesis, &minute, false).unwrap();
    let seg_ev = Segment::from_sealed(genesis, &minute, true).unwrap();
    println!(
        "segment of 60 blocks (15 x 10 commands, 45 empty): payload {} B (with events {} B), zstd {} B (with events {} B)",
        seg.encode_payload().len(),
        seg_ev.encode_payload().len(),
        seg.to_bytes().unwrap().len(),
        seg_ev.to_bytes().unwrap().len()
    );
    // An idle hour.
    let idle = seal_chain(genesis, &vec![BlockSpec::empty(1); 3600]);
    let idle_seg = Segment::from_sealed(genesis, &idle, false).unwrap();
    println!(
        "segment of 3600 empty blocks: payload {} B, zstd {} B",
        idle_seg.encode_payload().len(),
        idle_seg.to_bytes().unwrap().len()
    );
    let start = std::time::Instant::now();
    let bytes = seg_ev.to_bytes().unwrap();
    let compress = start.elapsed();
    let start = std::time::Instant::now();
    let _ = Segment::from_bytes(&bytes).unwrap();
    println!(
        "60-block segment with events: compress {compress:?}, decode+check {:?}",
        start.elapsed()
    );
}
