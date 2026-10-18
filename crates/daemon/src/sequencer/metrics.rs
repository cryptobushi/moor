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

//! Sequencer measurement hooks (ADR 0006 "Emitted measurements"; S1-7 formalises them).
//!
//! Counters and latency samples are kept per reporting window and logged as one JSON line
//! (`target: "rw_sequencer_metrics"`) every `window` blocks and at shutdown:
//!
//! - bytes per command (command batch), per event (event batch), per block (header + command
//!   batch, and compressed segment bytes as the DA sink reports them);
//! - blocks/s, commands/s, empty-block share;
//! - p50/p95 receipt to soft confirmation (the input's `submit` returned, so every event it
//!   produced has been handed to the hosts' publisher) and receipt to seal notice;
//! - p50/p95 `end_block` time (root time included) and inter-block pause (from the end of one
//!   block's input window to the next block's opening).

use std::time::{Duration, Instant};

use serde_json::json;
use tracing::info;

/// Latency samples for one window.
#[derive(Default)]
struct Samples(Vec<Duration>);

impl Samples {
    fn push(&mut self, d: Duration) {
        self.0.push(d);
    }

    /// The `q` quantile (nearest rank), in milliseconds with microsecond precision.
    fn quantile_ms(&mut self, q: f64) -> Option<f64> {
        if self.0.is_empty() {
            return None;
        }
        self.0.sort_unstable();
        let rank = ((q * self.0.len() as f64).ceil() as usize).clamp(1, self.0.len());
        Some(self.0[rank - 1].as_micros() as f64 / 1000.0)
    }

    fn max_ms(&self) -> Option<f64> {
        self.0.iter().max().map(|d| d.as_micros() as f64 / 1000.0)
    }
}

#[derive(Default)]
struct Window {
    blocks: u64,
    empty_blocks: u64,
    commands: u64,
    events: u64,
    command_bytes: u64,
    event_bytes: u64,
    header_bytes: u64,
    segment_bytes: u64,
    segment_blocks: u64,
    soft_confirm: Samples,
    seal_notice: Samples,
    end_block: Samples,
    pause: Samples,
    queue_wait: Samples,
}

/// The sequencer's metrics. Owned by the block thread; the DA thread reports through
/// [`Metrics::record_segment`] via the block thread's channel.
pub struct Metrics {
    window: Window,
    total: Window,
    window_blocks: u64,
    window_started: Instant,
    started: Instant,
}

impl Metrics {
    #[must_use]
    pub fn new(window_blocks: u64) -> Self {
        Self {
            window: Window::default(),
            total: Window::default(),
            window_blocks: window_blocks.max(1),
            window_started: Instant::now(),
            started: Instant::now(),
        }
    }

    /// An input finished: queued at `received`, taken from the queue at `taken`, soft-confirmed
    /// (its `submit` returned) at `done`.
    pub fn record_input(&mut self, received: Instant, taken: Instant, done: Instant) {
        let latency = done.saturating_duration_since(received);
        let wait = taken.saturating_duration_since(received);
        self.window.soft_confirm.push(latency);
        self.total.soft_confirm.push(latency);
        self.window.queue_wait.push(wait);
        self.total.queue_wait.push(wait);
    }

    /// A block was sealed and its notice sent at `notice_at`; `received` are its inputs' receipt
    /// times.
    #[allow(clippy::too_many_arguments)]
    pub fn record_block(
        &mut self,
        commands: usize,
        events: usize,
        command_bytes: usize,
        event_bytes: usize,
        header_bytes: usize,
        end_block: Duration,
        notice_at: Instant,
        received: &[Instant],
    ) {
        for w in [&mut self.window, &mut self.total] {
            w.blocks += 1;
            w.empty_blocks += u64::from(commands == 0 && events == 0);
            w.commands += commands as u64;
            w.events += events as u64;
            w.command_bytes += command_bytes as u64;
            w.event_bytes += event_bytes as u64;
            w.header_bytes += header_bytes as u64;
            w.end_block.push(end_block);
            for r in received {
                w.seal_notice.push(notice_at.saturating_duration_since(*r));
            }
        }
    }

    /// The pause between one block's input window closing and the next block opening.
    pub fn record_pause(&mut self, pause: Duration) {
        self.window.pause.push(pause);
        self.total.pause.push(pause);
    }

    /// A segment of `blocks` blocks was published as `bytes` compressed bytes.
    pub fn record_segment(&mut self, blocks: u64, bytes: u64) {
        for w in [&mut self.window, &mut self.total] {
            w.segment_blocks += blocks;
            w.segment_bytes += bytes;
        }
    }

    /// Log the window if it is full.
    pub fn maybe_report(&mut self, height: u64) {
        if self.window.blocks >= self.window_blocks {
            let elapsed = self.window_started.elapsed();
            let mut window = std::mem::take(&mut self.window);
            log_summary("window", height, elapsed, &mut window);
            self.window_started = Instant::now();
        }
    }

    /// Log everything since start.
    pub fn report_total(&mut self, height: u64) {
        let elapsed = self.started.elapsed();
        log_summary("total", height, elapsed, &mut self.total);
    }
}

fn per(numerator: u64, denominator: u64) -> Option<f64> {
    (denominator > 0).then(|| numerator as f64 / denominator as f64)
}

fn log_summary(scope: &str, height: u64, elapsed: Duration, w: &mut Window) {
    let secs = elapsed.as_secs_f64().max(f64::EPSILON);
    let summary = json!({
        "scope": scope,
        "height": height,
        "seconds": secs,
        "blocks": w.blocks,
        "empty_blocks": w.empty_blocks,
        "empty_share": per(w.empty_blocks, w.blocks),
        "commands": w.commands,
        "events": w.events,
        "blocks_per_s": w.blocks as f64 / secs,
        "commands_per_s": w.commands as f64 / secs,
        "bytes_per_command": per(w.command_bytes, w.commands),
        "bytes_per_event": per(w.event_bytes, w.events),
        "bytes_per_block_uncompressed": per(w.header_bytes + w.command_bytes, w.blocks),
        "segment_bytes_per_block": per(w.segment_bytes, w.segment_blocks),
        "soft_confirm_ms": {
            "n": w.soft_confirm.0.len(),
            "p50": w.soft_confirm.quantile_ms(0.50),
            "p95": w.soft_confirm.quantile_ms(0.95),
            "max": w.soft_confirm.max_ms(),
        },
        "queue_wait_ms": {
            "p50": w.queue_wait.quantile_ms(0.50),
            "p95": w.queue_wait.quantile_ms(0.95),
        },
        "seal_notice_ms": {
            "n": w.seal_notice.0.len(),
            "p50": w.seal_notice.quantile_ms(0.50),
            "p95": w.seal_notice.quantile_ms(0.95),
            "max": w.seal_notice.max_ms(),
        },
        "end_block_ms": {
            "p50": w.end_block.quantile_ms(0.50),
            "p95": w.end_block.quantile_ms(0.95),
            "max": w.end_block.max_ms(),
        },
        "pause_ms": {
            "p50": w.pause.quantile_ms(0.50),
            "p95": w.pause.quantile_ms(0.95),
            "max": w.pause.max_ms(),
        },
    });
    info!(target: "rw_sequencer_metrics", "{summary}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_use_nearest_rank() {
        let mut s = Samples::default();
        for ms in 1..=20 {
            s.push(Duration::from_millis(ms));
        }
        assert_eq!(
            (s.quantile_ms(0.5), s.quantile_ms(0.95)),
            (Some(10.0), Some(19.0))
        );
    }

    #[test]
    fn empty_samples_have_no_quantile() {
        assert_eq!(Samples::default().quantile_ms(0.5), None);
    }
}
