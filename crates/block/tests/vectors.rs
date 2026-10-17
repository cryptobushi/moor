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

//! The spec's test vectors (`docs/spec/block-format-v0.md` §9). The hashes, encodings and the
//! uncompressed payload were recomputed independently in Python from the spec; the signature
//! matches Foundry `cast wallet sign --no-hash` byte for byte.

mod common;

use common::*;
use moor_block::{
    ChainTip, CommandBatch, CommandEntry, EventBatch, SealedBlock, Segment, hex, seed_for,
    signing_digest,
};

const TIMESTAMP: u64 = 1_760_000_000;

fn e1() -> CommandEntry {
    CommandEntry::Envelope(envelope(1, 1, "go west"))
}

fn commands() -> CommandBatch {
    CommandBatch::new(vec![e1(), disconnect(4)]).unwrap()
}

fn events() -> EventBatch {
    let mut batch = EventBatch::empty();
    batch.push(1, 4, b"You go west.".to_vec()).unwrap();
    batch.push(2, 4, vec![]).unwrap();
    batch
}

fn chain() -> Vec<SealedBlock> {
    let genesis = ChainTip::genesis(&genesis_root());
    let b1 = SealedBlock::seal(
        &genesis,
        TIMESTAMP,
        commands(),
        events(),
        state("1"),
        &key(),
        &genesis_root(),
    )
    .unwrap();
    let mut out = vec![b1];
    for (dt, cmds, st) in [
        (1, vec![], None),
        (1, vec![], None),
        (2, vec![disconnect(4)], Some(state("4"))),
    ] {
        let tip = out.last().unwrap().tip();
        let block = SealedBlock::seal(
            &tip,
            tip.timestamp + dt,
            CommandBatch::new(cmds).unwrap(),
            EventBatch::empty(),
            st.unwrap_or(tip.state_root),
            &key(),
            &genesis_root(),
        )
        .unwrap();
        out.push(block);
    }
    out
}

fn segment(with_events: bool) -> Segment {
    Segment::from_sealed(ChainTip::genesis(&genesis_root()), &chain(), with_events).unwrap()
}

const E1: &str = "82005850000000000101002007676f207765737401264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c";
const COMMANDS_ROOT: &str = "73e2a2ce9975204bded10c8b0cc21f086825831d2d62cfdb5102c27037067a71";
const EVENTS_ROOT: &str = "cf631952247594ac4dbd4085d5c63a56f7967b81daab8ed66af54107c848cba8";
const SEED_1: &str = "19d4a7bba241d17fb94c84425cc92f3224dafbe79977480668d4151c012256d6";
const HEADER_1: &str = "880101582000000000000000000000000000000000000000000000000000000000000000001a68e77800582019d4a7bba241d17fb94c84425cc92f3224dafbe79977480668d4151c012256d6582073e2a2ce9975204bded10c8b0cc21f086825831d2d62cfdb5102c27037067a715820cf631952247594ac4dbd4085d5c63a56f7967b81daab8ed66af54107c848cba858202780e2d008eba4f8b30ac02f5ec0a66ce5285a29bb2d1a6c0164ea2c7dd17544";
const HASH_1: &str = "df9f7c4e473610aa9b79c3c318a9e9576a7a50e12d531dd5980b80c8cfa17edc";
const DIGEST_1: &str = "eb54bd23af95c41b9992411dcad8797cbb083bf7679da11d2b463df30647e576";
const SIG_1: &str = "706a0e5cdb353cc7aba2f0ee4495cf090a8d85add11f093dc5240c73e4501f10006ef9766912f20c9f730976f951c548dff4c057d07e37392101d4e75d2a69a31c";
const ADDRESS: &str = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
const HASHES: [&str; 4] = [
    HASH_1,
    "3e4cb19bf5b4663dddbcf5c1719f6be48259b0fd0f3e90151f4a432e46e87397",
    "7347a00a7916410274773d45010b0f2b618b2ff089b2f40f45193a9bb9046d53",
    "39b33fca7ef884f4c9ab72b4b1f579a262535e192fd6e160101ac5dec080ce2b",
];
const SIG_4: &str = "231ec03522a0177051327612cb23146f620e6abc82d12701ac7257e53ade03d55466e5a19885d38a254b8728e64b7e9ff240ba8f6bef51119ff08626fc6b4c941c";
const PAYLOAD: &str = "896d72772f76312f7365676d656e7401005820000000000000000000000000000000000000000000000000000000000000000000582061bdca7e9b9c830c63bd4a7ff18caa509ee7dd2fdd2bf01b841d1c1c61fce25684841a68e778005820cf631952247594ac4dbd4085d5c63a56f7967b81daab8ed66af54107c848cba858202780e2d008eba4f8b30ac02f5ec0a66ce5285a29bb2d1a6c0164ea2c7dd175448282005850000000000101002007676f207765737401264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c8201820004010184025820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85558208dcd5901529429313d9b3b1e50aaa6e3c0a7e91ba78f77ebe0aaaa4605c0f28c8182018200045841231ec03522a0177051327612cb23146f620e6abc82d12701ac7257e53ade03d55466e5a19885d38a254b8728e64b7e9ff240ba8f6bef51119ff08626fc6b4c941cf6";
const PAYLOAD_HASH: &str = "defc9a78026378170f87e3b5955586aab720b59dee27f1cebd0d7955543b7b79";
const PAYLOAD_EVENTS_HASH: &str =
    "4862d8b9af19f542f7bfc27735df3325e36b8570ce551d389b51674242e2e9a0";
/// libzstd 1.5.7 (zstd-sys 2.1.2), level 19: informative, pinned by `Cargo.lock`.
const ZSTD_SHA256: &str = "4357c810026e61059ef97749710848a83958110ef64b1ee4b023fc00624e403c";

#[test]
fn envelope_entry_vector() {
    assert_eq!(hex(&e1().encode()), E1);
}

#[test]
fn sequencer_input_entry_vector() {
    assert_eq!(hex(&disconnect(4).encode()), "8201820004");
}

#[test]
fn event_entry_vectors() {
    let encoded: Vec<String> = events()
        .entries()
        .iter()
        .map(|e| hex(&e.encode()))
        .collect();
    assert_eq!(
        encoded,
        ["840001044c596f7520676f20776573742e", "8401020440"]
    );
}

#[test]
fn commands_root_vector() {
    assert_eq!(hex(&commands().root()), COMMANDS_ROOT);
}

#[test]
fn events_root_vector() {
    assert_eq!(hex(&events().root()), EVENTS_ROOT);
}

#[test]
fn seed_vector() {
    assert_eq!(hex(&seed_for(&genesis_root(), 1)), SEED_1);
}

#[test]
fn header_vector() {
    assert_eq!(hex(&chain()[0].header.header.encode()), HEADER_1);
}

#[test]
fn header_hash_vectors() {
    let hashes: Vec<String> = chain().iter().map(|b| hex(&b.header.hash())).collect();
    assert_eq!(hashes, HASHES);
}

#[test]
fn signing_digest_vector() {
    assert_eq!(
        hex(&signing_digest(&genesis_root(), &chain()[0].header.hash())),
        DIGEST_1
    );
}

#[test]
fn signature_vectors_match_cast() {
    let c = chain();
    assert_eq!(
        [
            hex(c[0].header.sequencer_sig.as_bytes()),
            hex(c[3].header.sequencer_sig.as_bytes())
        ],
        [SIG_1, SIG_4]
    );
}

#[test]
fn sequencer_address_vector() {
    assert_eq!(key().address().to_string(), ADDRESS);
}

#[test]
fn signed_header_is_header_fields_plus_signature() {
    let expected = format!("89{}5841{SIG_1}", &HEADER_1[2..]);
    assert_eq!(hex(&chain()[0].header.encode()), expected);
}

#[test]
fn segment_payload_vector() {
    assert_eq!(hex(&segment(false).encode_payload()), PAYLOAD);
}

#[test]
fn segment_payload_hash_vectors() {
    assert_eq!(
        [
            hex(&segment(false).payload_hash()),
            hex(&segment(true).payload_hash())
        ],
        [PAYLOAD_HASH, PAYLOAD_EVENTS_HASH]
    );
}

#[test]
fn segment_vector_decodes_to_the_chain() {
    let payload = moor_block::unhex(PAYLOAD).unwrap();
    assert_eq!(Segment::decode_payload(&payload), Ok(segment(false)));
}

#[test]
fn compressed_segment_vector() {
    let bytes = segment(false).to_bytes().unwrap();
    assert_eq!(hex(&moor_block::sha256(&[&bytes])), ZSTD_SHA256);
}
