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
//! Deterministic mode: the only source of time, randomness and generated identifiers when the
//! daemon runs as a state transition function (STF).
//!
//! In this mode the world sees a *block context* instead of the host: a height, a timestamp in whole
//! seconds and a 32-byte seed, all supplied by the driver. The driver also advances a *command
//! index* before each command. Everything below is a pure function of
//! `(height, timestamp, seed, command index, per-purpose counter)`.
//!
//! # Derivations (version 1)
//!
//! All hashing is SHA-256. SHA-256 was chosen over a ChaCha stream because every verifier we may
//! need (a RISC-V machine, an onchain fraud-proof VM) already has it, it is in this workspace's
//! dependency tree, and its output is specified bit for bit. The `rand` crates only promise value
//! stability inside one version, which is not enough for a verification contract.
//!
//! * Command key: `K = HMAC-SHA256(key = seed, msg = "moor-det/v1/rng" || command_le64)`.
//! * Random stream for that command: block `i` is `HMAC-SHA256(key = K, msg = i_le64)`, read as four
//!   little-endian `u64` words in order (HMAC in counter mode, as in HKDF-Expand).
//! * Bounded integers use rejection sampling on whole `u64` words, so there is no modulo bias and
//!   the number of words consumed is itself deterministic.
//! * Identifiers: `SHA-256("moor-det/v1/id" || domain || height_le64 || command_le64 || counter_le64)`,
//!   truncated to 16 bytes with the UUID version (8, custom) and variant bits set. Each
//!   [`IdDomain`] has its own counter, which restarts at zero for every command, so activity in one
//!   domain (for example narrative events) never shifts ids in another (for example `uuid()`).
//!
//! Command index 0 is the block prologue: world loading and anything else that runs before the
//! first command of a block. The first command of a block has index 1.
//!
//! # Process-global state
//!
//! The context lives in a process-wide cell, because time, ids and `last_move` are needed deep in
//! the database and event layers that have no handle on the scheduler. This matches the audit's
//! finding that the STF is one instance per process (DA section 3). Enable it with
//! [`configure`] from the kernel's `Config`, never from the environment.

use std::{
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const RNG_LABEL: &[u8] = b"moor-det/v1/rng";
const ID_LABEL: &[u8] = b"moor-det/v1/id";

/// The per-block inputs the driver supplies. See `GLOSSARY.md`, "Block context".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlockContext {
    /// Block height. Increments by one per block.
    pub height: u64,
    /// Block time in whole seconds since the Unix epoch. Never decreases.
    pub timestamp: u64,
    /// Block seed, the root of every random stream in the block. Written as 64 hex digits in
    /// configuration files.
    #[serde(with = "hex_seed")]
    pub seed: [u8; 32],
}

/// Serde adapter for the seed: 64 hexadecimal digits.
mod hex_seed {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(seed: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() != 64 || !text.is_ascii() {
            return Err(D::Error::custom("seed must be 64 hexadecimal digits"));
        }
        let mut seed = [0u8; 32];
        for (byte, pair) in seed.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
            let pair = std::str::from_utf8(pair).map_err(D::Error::custom)?;
            *byte = u8::from_str_radix(pair, 16).map_err(D::Error::custom)?;
        }
        Ok(seed)
    }
}

/// Whether the process runs in deterministic mode. This is a configuration value, separate from
/// any development shortcut switch. It is a struct with every key always present so that the
/// daemon's configuration file loader, which rejects keys missing from the defaults, accepts it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeterministicMode {
    /// Off (the default) is stock behaviour: wall clock, OS randomness.
    pub enabled: bool,
    /// The block context in force until the driver sets the first block.
    pub genesis: BlockContext,
    /// Salt of the envelope signing domain (RuneWorld ADR 0005 decision 2): the genesis state root
    /// once one is defined (S0-5). All zero until then. Written as 64 hex digits.
    #[serde(with = "hex_seed")]
    pub domain_salt: [u8; 32],
}

impl DeterministicMode {
    /// Deterministic mode starting in the all-zero block context.
    #[must_use]
    pub fn on() -> Self {
        Self {
            enabled: true,
            genesis: BlockContext::default(),
            domain_salt: [0; 32],
        }
    }

    #[must_use]
    pub fn is_on(&self) -> bool {
        self.enabled
    }
}

/// Independent counters for generated identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdDomain {
    /// `uuid()` results.
    Uuid = 0,
    /// Verb and property definition ids (storage keys).
    Definition = 1,
    /// Narrative event ids.
    Event = 2,
}

const ID_DOMAINS: usize = 3;

/// A snapshot of the active context, as seen by MOO code through `block_context()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandContext {
    pub block: BlockContext,
    /// 0 in the block prologue, 1 for the first command of the block.
    pub command: u64,
}

/// A deterministic stream of `u64` words keyed by `(seed, command index)`.
#[derive(Clone, Debug)]
pub struct RngStream {
    key: [u8; 32],
    block: u64,
    words: [u64; 4],
    next: usize,
}

impl RngStream {
    /// The stream for one command of a block.
    #[must_use]
    pub fn new(seed: &[u8; 32], command: u64) -> Self {
        let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC accepts any key length");
        mac.update(RNG_LABEL);
        mac.update(&command.to_le_bytes());
        Self {
            key: mac.finalize().into_bytes().into(),
            block: 0,
            words: [0; 4],
            next: 4,
        }
    }

    fn refill(&mut self) {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(&self.block.to_le_bytes());
        let out: [u8; 32] = mac.finalize().into_bytes().into();
        for (word, chunk) in self.words.iter_mut().zip(out.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*chunk);
        }
        self.block += 1;
        self.next = 0;
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        if self.next == self.words.len() {
            self.refill();
        }
        let word = self.words[self.next];
        self.next += 1;
        word
    }

    /// A uniform value in `0..n`, by rejection sampling. `n` must be non-zero.
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "below(0)");
        // Largest multiple of n that fits in u64; words at or above it are rejected.
        let zone = (u64::MAX / n) * n;
        loop {
            let word = self.next_u64();
            if word < zone {
                return word % n;
            }
        }
    }

    /// A uniform value in `lo..=hi`. `lo <= hi` is required.
    pub fn range_inclusive(&mut self, lo: i64, hi: i64) -> i64 {
        assert!(lo <= hi, "empty range");
        let span = hi.wrapping_sub(lo) as u64;
        match span.checked_add(1) {
            Some(n) => lo.wrapping_add(self.below(n) as i64),
            // The full i64 range: every word is valid.
            None => self.next_u64() as i64,
        }
    }

    /// Fill `out` with stream bytes, eight per word, little-endian.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

/// The identifier for `(domain, height, command, counter)`. See the module docs.
#[must_use]
pub fn derive_id(domain: IdDomain, height: u64, command: u64, counter: u64) -> Uuid {
    let mut hash = Sha256::new();
    hash.update(ID_LABEL);
    hash.update([domain as u8]);
    hash.update(height.to_le_bytes());
    hash.update(command.to_le_bytes());
    hash.update(counter.to_le_bytes());
    let digest = hash.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes).into_uuid()
}

struct State {
    context: CommandContext,
    rng: RngStream,
    counters: [u64; ID_DOMAINS],
}

impl State {
    fn new(block: BlockContext, command: u64) -> Self {
        Self {
            context: CommandContext { block, command },
            rng: RngStream::new(&block.seed, command),
            counters: [0; ID_DOMAINS],
        }
    }
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static STATE: Mutex<Option<State>> = Mutex::new(None);

fn state() -> MutexGuard<'static, Option<State>> {
    // The state is plain data, so a poisoned lock is still consistent.
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Apply `mode` to this process. An off mode leaves a running deterministic mode untouched, and
/// so does a second call while it is already on: a driver may configure before loading the world
/// (so definition ids are derived) and the scheduler configures again when it starts, which must
/// not rewind the counters. Use [`disable`] to turn the mode off explicitly.
pub fn configure(mode: &DeterministicMode) {
    if mode.is_on() && !is_enabled() {
        *state() = Some(State::new(mode.genesis, 0));
        ENABLED.store(true, Ordering::SeqCst);
    }
}

/// Turn deterministic mode off. Intended for tests.
pub fn disable() {
    ENABLED.store(false, Ordering::SeqCst);
    *state() = None;
}

/// True when this process runs in deterministic mode.
#[inline]
#[must_use]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Start a new block: set the context, restart at the block prologue (command 0) and reset the
/// random stream and id counters. No effect when deterministic mode is off.
pub fn set_block(block: BlockContext) {
    if let Some(state) = state().as_mut() {
        *state = State::new(block, 0);
    }
}

/// Advance to the next command of the block and restart its random stream and id counters.
/// Returns the new command index (1 for the first command), or `None` when the mode is off.
pub fn next_command() -> Option<u64> {
    let mut guard = state();
    let state = guard.as_mut()?;
    let command = state.context.command + 1;
    *state = State::new(state.context.block, command);
    Some(command)
}

/// The active block and command, or `None` when the mode is off.
#[must_use]
pub fn current() -> Option<CommandContext> {
    state().as_ref().map(|s| s.context)
}

/// Seconds since the Unix epoch: block time in deterministic mode, else the wall clock.
#[must_use]
pub fn now_secs() -> u64 {
    match current() {
        Some(ctx) => ctx.block.timestamp,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    }
}

/// `now_secs` as a `SystemTime`. In deterministic mode there is no sub-second part.
#[must_use]
pub fn now_system() -> SystemTime {
    match current() {
        Some(ctx) => UNIX_EPOCH + Duration::from_secs(ctx.block.timestamp),
        None => SystemTime::now(),
    }
}

/// Run `f` on the current command's random stream. `None` when the mode is off.
pub fn with_rng<T>(f: impl FnOnce(&mut RngStream) -> T) -> Option<T> {
    state().as_mut().map(|s| f(&mut s.rng))
}

/// The next identifier in `domain`, or `None` when the mode is off.
pub fn next_id(domain: IdDomain) -> Option<Uuid> {
    let mut guard = state();
    let state = guard.as_mut()?;
    let counter = &mut state.counters[domain as usize];
    let id = derive_id(
        domain,
        state.context.block.height,
        state.context.command,
        *counter,
    );
    *counter += 1;
    Some(id)
}

/// A time-ordered id for narrative events: `Uuid::now_v7()` normally, derived in deterministic mode.
#[must_use]
pub fn event_id() -> Uuid {
    next_id(IdDomain::Event).unwrap_or_else(Uuid::now_v7)
}

/// A definition id for a verb or property: `Uuid::new_v4()` normally, derived in deterministic mode.
#[must_use]
pub fn definition_id() -> Uuid {
    next_id(IdDomain::Definition).unwrap_or_else(Uuid::new_v4)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7; 32];

    fn words(seed: &[u8; 32], command: u64, n: usize) -> Vec<u64> {
        let mut s = RngStream::new(seed, command);
        (0..n).map(|_| s.next_u64()).collect()
    }

    #[test]
    fn stream_is_repeatable() {
        assert_eq!(words(&SEED, 3, 9), words(&SEED, 3, 9));
    }

    #[test]
    fn stream_differs_by_command() {
        assert_ne!(words(&SEED, 1, 4), words(&SEED, 2, 4));
    }

    #[test]
    fn stream_differs_by_seed() {
        assert_ne!(words(&SEED, 1, 4), words(&[8; 32], 1, 4));
    }

    #[test]
    fn stream_matches_golden_vector() {
        // Pins derivation version 1. A change here changes world semantics and needs a new
        // label (v2), not an edit of this vector.
        assert_eq!(
            words(&SEED, 1, 2),
            vec![GOLDEN_WORDS[0], GOLDEN_WORDS[1]],
            "stream derivation changed"
        );
    }

    #[test]
    fn seed_round_trips_as_hex() {
        let ctx = BlockContext {
            height: 3,
            timestamp: 9,
            seed: [0xab; 32],
        };
        let text = serde_json::to_string(&ctx).unwrap();
        assert!(text.contains(&"ab".repeat(32)));
        assert_eq!(serde_json::from_str::<BlockContext>(&text).unwrap(), ctx);
    }

    #[test]
    fn short_seed_is_rejected() {
        assert!(serde_json::from_str::<BlockContext>(r#"{"seed":"abcd"}"#).is_err());
    }

    #[test]
    fn mode_reads_from_a_partial_object() {
        let mode: DeterministicMode =
            serde_json::from_str(r#"{"enabled":true,"genesis":{"height":2}}"#).unwrap();
        assert_eq!(mode.genesis.height, 2);
        assert!(mode.is_on());
    }

    #[test]
    fn mode_defaults_to_off() {
        assert!(!DeterministicMode::default().is_on());
    }

    #[test]
    fn below_stays_in_range() {
        let mut s = RngStream::new(&SEED, 1);
        assert!((0..1000).all(|_| s.below(6) < 6));
    }

    #[test]
    fn range_inclusive_covers_both_ends() {
        let mut s = RngStream::new(&SEED, 1);
        let draws: Vec<i64> = (0..500).map(|_| s.range_inclusive(5, 7)).collect();
        assert!(
            draws.contains(&5) && draws.contains(&7) && draws.iter().all(|d| (5..=7).contains(d))
        );
    }

    #[test]
    fn range_inclusive_accepts_the_full_i64_range() {
        let mut s = RngStream::new(&SEED, 1);
        let _ = s.range_inclusive(i64::MIN, i64::MAX);
    }

    #[test]
    fn fill_bytes_is_the_word_stream_in_little_endian() {
        let mut bytes = [0u8; 12];
        RngStream::new(&SEED, 1).fill_bytes(&mut bytes);
        let w = words(&SEED, 1, 2);
        assert_eq!(&bytes[..8], &w[0].to_le_bytes());
        assert_eq!(&bytes[8..], &w[1].to_le_bytes()[..4]);
    }

    #[test]
    fn stream_crosses_the_hmac_block_boundary() {
        // Four words per HMAC block; the fifth word comes from block 1.
        let w = words(&SEED, 1, 5);
        assert_ne!(w[4], w[0]);
    }

    #[test]
    fn ids_are_repeatable() {
        assert_eq!(
            derive_id(IdDomain::Uuid, 5, 2, 0),
            derive_id(IdDomain::Uuid, 5, 2, 0)
        );
    }

    #[test]
    fn ids_differ_by_every_input() {
        let base = derive_id(IdDomain::Uuid, 5, 2, 0);
        assert_ne!(base, derive_id(IdDomain::Definition, 5, 2, 0));
        assert_ne!(base, derive_id(IdDomain::Uuid, 6, 2, 0));
        assert_ne!(base, derive_id(IdDomain::Uuid, 5, 3, 0));
        assert_ne!(base, derive_id(IdDomain::Uuid, 5, 2, 1));
    }

    #[test]
    fn ids_carry_version_8_and_rfc_variant() {
        let id = derive_id(IdDomain::Event, 1, 1, 1);
        assert_eq!(id.get_version_num(), 8);
        assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
    }

    #[test]
    fn ids_match_golden_vector() {
        assert_eq!(derive_id(IdDomain::Uuid, 1, 1, 0).to_string(), GOLDEN_ID);
    }

    const GOLDEN_WORDS: [u64; 2] = [5892142076226692195, 1342175277956641647];
    const GOLDEN_ID: &str = "39a12b72-54e3-85d3-89bd-bba8ab6bfba5";
}
