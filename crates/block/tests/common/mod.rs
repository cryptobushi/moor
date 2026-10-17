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

//! Shared fixtures: a test sequencer key, a genesis root, and realistic-looking inputs.

#![allow(dead_code)]

use moor_block::{
    ChainTip, CommandBatch, CommandEntry, EventBatch, Hash, SealedBlock, SequencerInput,
    SequencerInputKind, SequencerKey, sha256, unhex,
};

/// The S0-5 root of a fresh, empty DB (spec `state-root-v0.md` §8), used as a genesis root.
pub fn genesis_root() -> Hash {
    hash32("61bdca7e9b9c830c63bd4a7ff18caa509ee7dd2fdd2bf01b841d1c1c61fce256")
}

/// Test-only sequencer secret: 32 bytes of 0x11.
pub fn key() -> SequencerKey {
    SequencerKey::from_secret(&[0x11; 32]).unwrap()
}

pub fn hash32(text: &str) -> Hash {
    unhex(text).unwrap().try_into().unwrap()
}

/// A state root standing in for the fork's at `label`.
pub fn state(label: &str) -> Hash {
    sha256(&[b"state ", label.as_bytes()])
}

/// An ADR 0005 command envelope's shape (80 bytes for "go west"): kind, session, nonce, expiry,
/// text length, text, a 64-byte signature. The block format carries it verbatim; the signature
/// bytes here are a fixed pattern, not a real signature.
pub fn envelope(session: u32, nonce: u8, text: &str) -> Vec<u8> {
    let mut out = vec![0x00];
    out.extend_from_slice(&session.to_be_bytes());
    out.push(nonce & 0x7f);
    out.extend_from_slice(&0x0020u16.to_be_bytes());
    out.push(text.len() as u8);
    out.extend_from_slice(text.as_bytes());
    out.extend((0..64u8).map(|i| i.wrapping_mul(37).wrapping_add(nonce)));
    out
}

pub fn disconnect(player: i32) -> CommandEntry {
    CommandEntry::Sequencer(SequencerInput {
        kind: SequencerInputKind::Disconnected,
        player,
    })
}

/// What a block contains before sealing.
#[derive(Clone, Debug)]
pub struct BlockSpec {
    pub dt: u64,
    pub commands: Vec<CommandEntry>,
    /// `(command_index, recipient, event bytes)`.
    pub events: Vec<(u64, i32, Vec<u8>)>,
    /// `None`: state unchanged.
    pub state: Option<Hash>,
}

impl BlockSpec {
    pub fn empty(dt: u64) -> Self {
        Self {
            dt,
            commands: vec![],
            events: vec![],
            state: None,
        }
    }
}

/// Seal `specs` after `prev`, as a sequencer would.
pub fn seal_chain(prev: ChainTip, specs: &[BlockSpec]) -> Vec<SealedBlock> {
    let key = key();
    let mut tip = prev;
    specs
        .iter()
        .map(|spec| {
            let mut events = EventBatch::empty();
            for (ci, recipient, bytes) in &spec.events {
                events.push(*ci, *recipient, bytes.clone()).unwrap();
            }
            let block = SealedBlock::seal(
                &tip,
                tip.timestamp + spec.dt,
                CommandBatch::new(spec.commands.clone()).unwrap(),
                events,
                spec.state.unwrap_or(tip.state_root),
                &key,
                &genesis_root(),
            )
            .unwrap();
            tip = block.tip();
            block
        })
        .collect()
}

/// A narrative event of `len` bytes for `player`, standing in for the fork's encoding.
pub fn event_bytes(player: i32, text: &str) -> Vec<u8> {
    format!("{{\"narrative\":{{\"player\":{player},\"text\":\"{text}\"}}}}").into_bytes()
}

/// An envelope of the same shape whose signature bytes are pseudo-random (as real Ed25519
/// signatures are), so compression measurements are not flattered.
pub fn signed_envelope(session: u32, nonce: u8, text: &str, salt: &str) -> Vec<u8> {
    let mut out = envelope(session, nonce, text);
    let n = out.len();
    let a = sha256(&[salt.as_bytes(), &session.to_be_bytes(), b"a"]);
    let b = sha256(&[salt.as_bytes(), &session.to_be_bytes(), b"b"]);
    out[n - 64..n - 32].copy_from_slice(&a);
    out[n - 32..].copy_from_slice(&b);
    out
}

/// A "typical" block: `n` players each send a short command, each gets two events.
pub fn typical_block(n: usize, label: &str) -> BlockSpec {
    let verbs = [
        "go west",
        "look",
        "take sword",
        "say hello there",
        "inventory",
    ];
    let commands = (0..n)
        .map(|i| {
            CommandEntry::Envelope(signed_envelope(
                i as u32 + 1,
                (i % 100) as u8 + 1,
                verbs[i % 5],
                label,
            ))
        })
        .collect();
    let events = (0..n)
        .flat_map(|i| {
            let ci = i as u64 + 1;
            let player = 10 + i as i32;
            [
                (ci, player, event_bytes(player, "You go west.")),
                (
                    ci,
                    player,
                    event_bytes(player, "Meadow. Exits: east, north."),
                ),
            ]
        })
        .collect();
    BlockSpec {
        dt: 1,
        commands,
        events,
        state: Some(state(label)),
    }
}
