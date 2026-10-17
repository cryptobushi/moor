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

//! Two independent encoders given the same inputs produce byte-identical segments.
//!
//! Encoder A is the crate (seal each block, build the segment, compress). Encoder B is written
//! here from the spec alone: its own CBOR heads, Merkle tree, header hash, seed rule and payload
//! layout, then zstd at the spec's level. Only the ECDSA signer and SHA-256 are shared.

mod common;

use common::*;
use moor_block::{
    ChainTip, CommandEntry, EMPTY_ROOT, Hash, Segment, SequencerInputKind, ZSTD_LEVEL, sha256,
};
use proptest::prelude::*;

/// Encoder B.
mod spec {
    use super::*;

    pub fn head(out: &mut Vec<u8>, major: u8, n: u64) {
        let m = major << 5;
        match n {
            0..=23 => out.push(m | n as u8),
            24..=0xff => out.extend([m | 24, n as u8]),
            0x100..=0xffff => {
                out.push(m | 25);
                out.extend((n as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push(m | 26);
                out.extend((n as u32).to_be_bytes());
            }
            _ => {
                out.push(m | 27);
                out.extend(n.to_be_bytes());
            }
        }
    }

    pub fn int(out: &mut Vec<u8>, n: i64) {
        if n >= 0 {
            head(out, 0, n as u64);
        } else {
            head(out, 1, (-1 - n) as u64);
        }
    }

    pub fn bstr(out: &mut Vec<u8>, b: &[u8]) {
        head(out, 2, b.len() as u64);
        out.extend_from_slice(b);
    }

    pub fn command(e: &CommandEntry) -> Vec<u8> {
        let mut out = vec![0x82];
        match e {
            CommandEntry::Envelope(b) => {
                out.push(0x00);
                bstr(&mut out, b);
            }
            CommandEntry::Sequencer(s) => {
                assert_eq!(s.kind, SequencerInputKind::Disconnected);
                out.extend([0x01, 0x82, 0x00]);
                int(&mut out, i64::from(s.player));
            }
        }
        out
    }

    pub fn event(seq: u64, ci: u64, recipient: i32, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0x84];
        head(&mut out, 0, seq);
        head(&mut out, 0, ci);
        int(&mut out, i64::from(recipient));
        bstr(&mut out, bytes);
        out
    }

    pub fn mth(leaves: &[Vec<u8>]) -> Hash {
        match leaves.len() {
            0 => sha256(&[]),
            1 => sha256(&[&[0], &leaves[0]]),
            n => {
                let mut k = 1;
                while k * 2 < n {
                    k *= 2;
                }
                sha256(&[&[1], &mth(&leaves[..k]), &mth(&leaves[k..])])
            }
        }
    }

    pub struct Out {
        pub payload: Vec<u8>,
        pub bytes: Vec<u8>,
    }

    /// Encode the chain from genesis, as the spec describes it.
    pub fn encode(specs: &[BlockSpec], with_events: bool) -> Out {
        let genesis = genesis_root();
        let (mut hash, mut ts, mut root) = ([0u8; 32], 0u64, genesis);
        let mut blocks = Vec::new();
        let mut batches = Vec::new();
        for (i, spec) in specs.iter().enumerate() {
            let height = i as u64 + 1;
            let commands: Vec<Vec<u8>> = spec.commands.iter().map(command).collect();
            let events: Vec<Vec<u8>> = spec
                .events
                .iter()
                .enumerate()
                .map(|(seq, (ci, r, b))| event(seq as u64, *ci, *r, b))
                .collect();
            let state = spec.state.unwrap_or(root);
            let events_root = mth(&events);
            let mut header = vec![0x88, 0x01];
            head(&mut header, 0, height);
            bstr(&mut header, &hash);
            head(&mut header, 0, ts + spec.dt);
            bstr(
                &mut header,
                &sha256(&[b"rw/v1/seed", &root, &height.to_be_bytes()]),
            );
            bstr(&mut header, &mth(&commands));
            bstr(&mut header, &events_root);
            bstr(&mut header, &state);
            let mut block = Vec::new();
            if commands.is_empty() && events_root == EMPTY_ROOT && state == root {
                head(&mut block, 0, spec.dt);
            } else {
                block.push(0x84);
                head(&mut block, 0, spec.dt);
                bstr(&mut block, &events_root);
                bstr(&mut block, &state);
                head(&mut block, 4, commands.len() as u64);
                commands.iter().for_each(|c| block.extend(c));
            }
            blocks.push(block);
            let mut batch = Vec::new();
            head(&mut batch, 4, events.len() as u64);
            events.iter().for_each(|e| batch.extend(e));
            batches.push(batch);
            hash = sha256(&[&header]);
            ts += spec.dt;
            root = state;
        }
        let sig = key().sign(&genesis, &hash).unwrap();
        let mut p = vec![0x89];
        head(&mut p, 3, 13);
        p.extend(b"rw/v1/segment");
        p.extend([0x01, 0x00]);
        bstr(&mut p, &[0; 32]);
        p.push(0x00);
        bstr(&mut p, &genesis);
        head(&mut p, 4, blocks.len() as u64);
        blocks.iter().for_each(|b| p.extend(b));
        bstr(&mut p, sig.as_bytes());
        if with_events {
            head(&mut p, 4, batches.len() as u64);
            batches.iter().for_each(|b| p.extend(b));
        } else {
            p.push(0xf6);
        }
        let bytes = zstd::bulk::compress(&p, ZSTD_LEVEL).unwrap();
        Out { payload: p, bytes }
    }
}

fn entry() -> impl Strategy<Value = CommandEntry> {
    prop_oneof![
        3 => prop::collection::vec(any::<u8>(), 1..300).prop_map(CommandEntry::Envelope),
        1 => any::<i32>().prop_map(disconnect),
    ]
}

fn block_spec() -> impl Strategy<Value = BlockSpec> {
    (
        0u64..4,
        prop::collection::vec(entry(), 0..6),
        prop::collection::vec(
            (
                any::<u8>(),
                any::<i32>(),
                prop::collection::vec(any::<u8>(), 0..64),
            ),
            0..8,
        ),
        prop::option::of(any::<[u8; 32]>()),
        any::<bool>(),
    )
        .prop_map(|(dt, commands, raw_events, state, idle)| {
            if idle {
                return BlockSpec::empty(dt);
            }
            let n = commands.len() as u64;
            // Command indices in 0..=n, non-decreasing.
            let mut cis: Vec<u64> = raw_events
                .iter()
                .map(|(c, _, _)| u64::from(*c) % (n + 1))
                .collect();
            cis.sort_unstable();
            let events = cis
                .into_iter()
                .zip(raw_events)
                .map(|(ci, (_, r, b))| (ci, r, b))
                .collect();
            BlockSpec {
                dt,
                commands,
                events,
                state,
            }
        })
}

fn encoder_a(specs: &[BlockSpec], with_events: bool) -> Segment {
    let genesis = ChainTip::genesis(&genesis_root());
    Segment::from_sealed(genesis, &seal_chain(genesis, specs), with_events).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn independent_encoders_produce_identical_segments(
        specs in prop::collection::vec(block_spec(), 1..12),
        with_events in any::<bool>(),
    ) {
        let a = encoder_a(&specs, with_events);
        let b = spec::encode(&specs, with_events);
        prop_assert_eq!(a.encode_payload(), b.payload);
        prop_assert_eq!(a.to_bytes().unwrap(), b.bytes);
    }

    #[test]
    fn decoding_and_reencoding_is_the_identity(
        specs in prop::collection::vec(block_spec(), 1..12),
        with_events in any::<bool>(),
    ) {
        let bytes = encoder_a(&specs, with_events).to_bytes().unwrap();
        prop_assert_eq!(Segment::from_bytes(&bytes).unwrap().to_bytes().unwrap(), bytes);
    }

    #[test]
    fn two_sequencers_seal_identical_blocks(specs in prop::collection::vec(block_spec(), 1..12)) {
        let genesis = ChainTip::genesis(&genesis_root());
        let one: Vec<Vec<u8>> = seal_chain(genesis, &specs).iter().map(|b| b.encode()).collect();
        let two: Vec<Vec<u8>> = seal_chain(genesis, &specs).iter().map(|b| b.encode()).collect();
        prop_assert_eq!(one, two);
    }
}
