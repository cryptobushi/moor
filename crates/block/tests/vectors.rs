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
const HEADER_1: &str = "880201582000000000000000000000000000000000000000000000000000000000000000001a68e77800582019d4a7bba241d17fb94c84425cc92f3224dafbe79977480668d4151c012256d6582073e2a2ce9975204bded10c8b0cc21f086825831d2d62cfdb5102c27037067a715820cf631952247594ac4dbd4085d5c63a56f7967b81daab8ed66af54107c848cba858202780e2d008eba4f8b30ac02f5ec0a66ce5285a29bb2d1a6c0164ea2c7dd17544";
const HASH_1: &str = "d54746915062c7d40bd853ff50392d794d57a7165c9c885a9360e4d114d4cc9c";
const DIGEST_1: &str = "a5462f807713f16d072737c960551dd0962d24f70073e81905af3dc71a2ecf93";
const SIG_1: &str = "f248019c73186dd095b12e8e8948afed49c54d3c572fe989b8438268ce5ec51743878b11354c5b45b4752dd292b570475d525f6430c496cb36562039aebd7f121b";
const ADDRESS: &str = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
const HASHES: [&str; 4] = [
    HASH_1,
    "4f724f9e1a35859c9d025bb7a44eb997b362bcb5a4d17873a5358d5bd9e0b5a8",
    "1b827fe152607ddd7cdcd0c27492cb5acf26577695a4588666d3d8133475fe6e",
    "92110eb177aaaf05d45c456b4c553d3ce2734d35bf940104cfc1766306440905",
];
const SIG_4: &str = "fe0cfc401c3fd3bd4eb3af93704ac47d3587f1c2a058cb5c69ba1b055cad85b64f2a9f3803d2d4037f3ca01e666f55452e09633d34831b2e1bf7136c10b662b91c";
const PAYLOAD: &str = "896d72772f76312f7365676d656e7402005820000000000000000000000000000000000000000000000000000000000000000000582061bdca7e9b9c830c63bd4a7ff18caa509ee7dd2fdd2bf01b841d1c1c61fce25684841a68e778005820cf631952247594ac4dbd4085d5c63a56f7967b81daab8ed66af54107c848cba858202780e2d008eba4f8b30ac02f5ec0a66ce5285a29bb2d1a6c0164ea2c7dd175448282005850000000000101002007676f207765737401264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c8201820004010184025820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85558208dcd5901529429313d9b3b1e50aaa6e3c0a7e91ba78f77ebe0aaaa4605c0f28c8182018200045841fe0cfc401c3fd3bd4eb3af93704ac47d3587f1c2a058cb5c69ba1b055cad85b64f2a9f3803d2d4037f3ca01e666f55452e09633d34831b2e1bf7136c10b662b91cf6";
const PAYLOAD_HASH: &str = "75b6ab420f4414c0134fc55219fe3b8f6a8a08d3211e51343ec1ebc31a0fc9cf";
const PAYLOAD_EVENTS_HASH: &str =
    "49a713763e442d06346c14649227e97f9b3a4c1ab434841b8e5f52da9e7fa68e";
/// libzstd 1.5.7 (zstd-sys 2.1.2), level 19: informative, pinned by `Cargo.lock`.
const ZSTD_SHA256: &str = "0952f6773eefd8d4412ed61c5b7188217e77f9860e202e750312b1c529282810";

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

#[test]
fn meter_event_vectors() {
    use moor_block::{Meter, MeterKind, MeterOutcome};
    let m1 = Meter {
        kind: MeterKind::Command,
        world: 7,
        ticks: 1234,
        tasks: 2,
        log_bytes: 80,
        events: 3,
        event_bytes: 200,
        objects_created: 1,
        objects_recycled: 0,
        storage_delta: -42,
        policy_ticks: 0,
        outcome: MeterOutcome::Ok,
    };
    let m2 = Meter {
        world: -1,
        ticks: 60_000,
        tasks: 3,
        events: 0,
        event_bytes: 0,
        objects_created: 0,
        storage_delta: 0,
        policy_ticks: 25,
        outcome: MeterOutcome::TickCeiling,
        ..m1
    };
    assert_eq!(hex(&m1.encode_event()), "82058c00071904d20218500318c8010038290000");
    assert_eq!(hex(&m2.encode_event()), "82058c002019ea600318500000000000181902");
}
