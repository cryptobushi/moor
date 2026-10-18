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

//! fsync latency of the durable writes (ADR 0006 "fsync per command ... Measured"). Ignored by
//! default; run with
//! `cargo test -p moor-block --release --test durable_fsync -- --ignored --nocapture`.
//! `RW_FSYNC_DIR` picks the directory (default: a temporary directory), so the disk under test
//! can be chosen. On macOS `sync_data` is `fcntl(F_FULLFSYNC)`; on Linux it is `fdatasync`.

use std::time::Duration;

use moor_block::{
    ChainTip, CommandBatch, CommandEntry, EventBatch, SequencerKey,
    durable::{Authorization, BlockStore, Journal, SigningGuard, StoreChain},
};

fn quantiles(name: &str, mut samples: Vec<Duration>) {
    samples.sort();
    let q = |p: f64| {
        let i = ((samples.len() as f64 * p).ceil() as usize).clamp(1, samples.len()) - 1;
        samples[i].as_secs_f64() * 1000.0
    };
    println!(
        "{name}: n={} p50={:.3} ms p95={:.3} ms p99={:.3} ms max={:.3} ms",
        samples.len(),
        q(0.50),
        q(0.95),
        q(0.99),
        q(1.0)
    );
}

#[test]
#[ignore = "measurement; run explicitly"]
fn fsync_latency_of_journal_store_and_guard() {
    let base = std::env::var_os("RW_FSYNC_DIR").map(std::path::PathBuf::from);
    let dir = match &base {
        Some(path) => tempfile::tempdir_in(path).unwrap(),
        None => tempfile::tempdir().unwrap(),
    };
    println!("directory: {}", dir.path().display());
    let n: usize = std::env::var("RW_FSYNC_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000);

    // One 86-byte command entry per group commit, as the sequencer journals a single input.
    let entry = CommandEntry::Envelope(vec![0x5a; 80]);
    let (mut journal, _) = Journal::open(dir.path().join("journal")).unwrap();
    journal.append_open(1, 1, &[0; 32]).unwrap();
    let samples = (0..n)
        .map(|i| {
            journal
                .append_inputs(1, i as u64 + 1, std::slice::from_ref(&entry))
                .unwrap()
        })
        .collect();
    quantiles("journal input (1 entry)", samples);

    // A group commit of 16 entries.
    let group = vec![entry.clone(); 16];
    let (mut journal16, _) = Journal::open(dir.path().join("journal16")).unwrap();
    journal16.append_open(1, 1, &[0; 32]).unwrap();
    let samples = (0..n / 4)
        .map(|i| {
            journal16
                .append_inputs(1, i as u64 * 16 + 1, &group)
                .unwrap()
        })
        .collect();
    quantiles("journal group (16 entries)", samples);

    let key = SequencerKey::from_secret(&[0x11; 32]).unwrap();
    let chain = StoreChain {
        genesis_root: [7; 32],
        sequencer: key.address(),
    };
    let mut store = BlockStore::open(dir.path().join("blocks")).unwrap();
    store.init_chain(chain).unwrap();
    let mut guard = SigningGuard::open(dir.path().join("sequencer.guard"), chain).unwrap();
    let mut tip = ChainTip::genesis(&chain.genesis_root);
    let commands = CommandBatch::new(vec![entry; 10]).unwrap();
    let events = EventBatch::new(vec![]).unwrap();
    let (mut store_samples, mut guard_samples) = (Vec::new(), Vec::new());
    for i in 0..n / 2 {
        let header = tip.next_header(i as u64, commands.root(), events.root(), [9; 32]);
        store_samples.push(
            store
                .put_unsigned(&header, &commands, &events)
                .unwrap()
                .unwrap(),
        );
        match guard.authorize(header.height, &header.hash()).unwrap() {
            Authorization::Recorded(took) => guard_samples.push(took),
            Authorization::Identical => unreachable!("new heights"),
        }
        let sig = header
            .sign(&key, &chain.genesis_root)
            .unwrap()
            .sequencer_sig;
        store.put_signature(header.height, &sig).unwrap();
        tip = ChainTip::of(&header);
    }
    quantiles("block store unsigned block (10 commands)", store_samples);
    quantiles("signing guard record", guard_samples);
}
