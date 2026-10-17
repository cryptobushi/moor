//! Opt-in deterministic provider (SPIKE). When enabled, wall-clock time, random numbers and
//! time-based UUIDs come from a per-block context set by the driver instead of the OS. When not
//! enabled every function falls through to the normal behaviour.

use std::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use uuid::Uuid;

static ENABLED: AtomicBool = AtomicBool::new(false);
static BLOCK_SECS: AtomicU64 = AtomicU64::new(0);
static RNG_STATE: AtomicU64 = AtomicU64::new(0);

const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

/// Turn the deterministic provider on and set the block context.
pub fn enable(block_secs: u64, seed: u64) {
    ENABLED.store(true, Ordering::SeqCst);
    set_block(block_secs, seed);
}

/// Set the block context: the clock value and the RNG stream seed for the next batch of inputs.
pub fn set_block(block_secs: u64, seed: u64) {
    BLOCK_SECS.store(block_secs, Ordering::SeqCst);
    RNG_STATE.store(seed, Ordering::SeqCst);
}

#[inline]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Seconds since the epoch: the block clock when enabled, else the wall clock.
pub fn now_secs() -> u64 {
    if is_enabled() {
        BLOCK_SECS.load(Ordering::SeqCst)
    } else {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

pub fn now_system() -> SystemTime {
    if is_enabled() {
        UNIX_EPOCH + Duration::from_secs(BLOCK_SECS.load(Ordering::SeqCst))
    } else {
        SystemTime::now()
    }
}

/// Next value of the seeded splitmix64 stream, or `None` when the provider is disabled.
pub fn next_u64() -> Option<u64> {
    if !is_enabled() {
        return None;
    }
    let mut z = RNG_STATE.fetch_add(GAMMA, Ordering::SeqCst).wrapping_add(GAMMA);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    Some(z ^ (z >> 31))
}

/// Uniform-ish integer in `lo..=hi` from the seeded stream (modulo bias accepted in the spike).
pub fn random_range(lo: i64, hi: i64) -> Option<i64> {
    let r = next_u64()?;
    let span = (hi as i128 - lo as i128 + 1) as u128;
    Some((lo as i128 + (r as u128 % span) as i128) as i64)
}

/// A v7-shaped UUID from the seeded stream when enabled, else `Uuid::now_v7()`.
pub fn uuid_v7() -> Uuid {
    match (next_u64(), next_u64()) {
        (Some(a), Some(b)) => uuid::Builder::from_unix_timestamp_millis(
            BLOCK_SECS.load(Ordering::SeqCst) * 1000,
            &{
                let mut bytes = [0u8; 10];
                bytes[..8].copy_from_slice(&a.to_be_bytes());
                bytes[8..].copy_from_slice(&b.to_be_bytes()[..2]);
                bytes
            },
        )
        .into_uuid(),
        _ => Uuid::now_v7(),
    }
}
