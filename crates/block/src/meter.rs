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

//! The engine's per-input measurement (RuneWorld ADR 0007 decision 2) and its event encoding.
//!
//! A [`Meter`] is recorded in the event batch as the entry kind `[5, meter]` after the input's
//! other events (block format version 2, spec `block-format-v0.md` §12.2). The event byte string
//! of such an entry is exactly [`Meter::encode_event`].
//!
//! ```text
//! event = [5, meter]
//! meter = [kind, world, ticks, tasks, log_bytes, events, event_bytes,
//!          objects_created, objects_recycled, storage_delta, policy_ticks, outcome]
//! ```
//!
//! Every field is a CBOR integer in the shortest form; `world` and `storage_delta` may be
//! negative (`world` is an object number, so `-1` is `#-1`).

use crate::cbor::{CborError, Decoder, Encoder};

/// The tag of a meter entry in the `event` array.
pub const METER_EVENT_TAG: u64 = 5;

/// Fields of a meter (the length of its array).
const FIELDS: usize = 12;

/// What kind of input was measured (ADR 0007 ratification note 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MeterKind {
    Command = 0,
    Connect = 1,
    Create = 2,
    Build = 3,
    Revoke = 4,
    Sequencer = 5,
}

impl MeterKind {
    fn from_code(code: u64) -> Result<Self, CborError> {
        Ok(match code {
            0 => Self::Command,
            1 => Self::Connect,
            2 => Self::Create,
            3 => Self::Build,
            4 => Self::Revoke,
            5 => Self::Sequencer,
            _ => return Err(CborError::Range(0)),
        })
    }

    /// The symbol a charge hook sees in `meter['kind]`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Connect => "connect",
            Self::Create => "create",
            Self::Build => "build",
            Self::Revoke => "revoke",
            Self::Sequencer => "sequencer",
        }
    }
}

/// How the input ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MeterOutcome {
    /// It ran to completion (a task that raised an error and committed is still `Ok`: the MOO
    /// semantics of a failed command are not the engine's concern).
    Ok = 0,
    /// Nothing ran: admission rejected the envelope, or a task was cancelled without finishing.
    Aborted = 1,
    /// The command exceeded its tick ceiling and was rolled back.
    TickCeiling = 2,
    /// The charge hook denied the reservation.
    Denied = 3,
}

impl MeterOutcome {
    fn from_code(code: u64) -> Result<Self, CborError> {
        Ok(match code {
            0 => Self::Ok,
            1 => Self::Aborted,
            2 => Self::TickCeiling,
            3 => Self::Denied,
            _ => return Err(CborError::Range(0)),
        })
    }

    /// The symbol a charge hook sees in `meter['outcome]`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Aborted => "aborted",
            Self::TickCeiling => "tick_ceiling",
            Self::Denied => "denied",
        }
    }
}

/// One input's measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Meter {
    pub kind: MeterKind,
    /// The charged world: the player's current world at admission, else `#0`. An object number.
    pub world: i32,
    /// VM ticks summed over every task sharing the command index (not `policy_ticks`).
    pub ticks: u64,
    /// Jobs run: the input's task, `fork (0)` children, forced input and wakes.
    pub tasks: u64,
    /// Envelope wire bytes in the command batch (0 for an input that is not an envelope).
    pub log_bytes: u64,
    /// Events the input added to the batch (this entry excluded) and their canonical bytes.
    pub events: u64,
    pub event_bytes: u64,
    /// Objects whose existence committed or ended in this input's transactions.
    pub objects_created: u64,
    pub objects_recycled: u64,
    /// Net change in canonical (state encoding) bytes of the committed writes.
    pub storage_delta: i64,
    /// Ticks spent inside the charge hook at `'reserve`.
    pub policy_ticks: u64,
    pub outcome: MeterOutcome,
}

impl Meter {
    /// An all-zero meter of `kind` for `world`.
    #[must_use]
    pub fn new(kind: MeterKind, world: i32) -> Self {
        Self {
            kind,
            world,
            ticks: 0,
            tasks: 0,
            log_bytes: 0,
            events: 0,
            event_bytes: 0,
            objects_created: 0,
            objects_recycled: 0,
            storage_delta: 0,
            policy_ticks: 0,
            outcome: MeterOutcome::Ok,
        }
    }

    pub fn encode_into(&self, e: &mut Encoder) {
        e.array(FIELDS);
        e.uint(self.kind as u64);
        e.int(i64::from(self.world));
        e.uint(self.ticks);
        e.uint(self.tasks);
        e.uint(self.log_bytes);
        e.uint(self.events);
        e.uint(self.event_bytes);
        e.uint(self.objects_created);
        e.uint(self.objects_recycled);
        e.int(self.storage_delta);
        e.uint(self.policy_ticks);
        e.uint(self.outcome as u64);
    }

    /// The canonical encoding of the meter array alone.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_into(&mut e);
        e.into_bytes()
    }

    /// The `event` byte string of a meter batch entry: `[5, meter]`.
    #[must_use]
    pub fn encode_event(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2);
        e.uint(METER_EVENT_TAG);
        self.encode_into(&mut e);
        e.into_bytes()
    }

    pub fn decode_from(d: &mut Decoder) -> Result<Self, CborError> {
        d.array_of(FIELDS)?;
        let kind = MeterKind::from_code(d.uint()?)?;
        let world = d.int()?;
        let world = i32::try_from(world).map_err(|_| CborError::Range(d.position()))?;
        let ticks = d.uint()?;
        let tasks = d.uint()?;
        let log_bytes = d.uint()?;
        let events = d.uint()?;
        let event_bytes = d.uint()?;
        let objects_created = d.uint()?;
        let objects_recycled = d.uint()?;
        let storage_delta = d.int()?;
        let policy_ticks = d.uint()?;
        let outcome = MeterOutcome::from_code(d.uint()?)?;
        Ok(Self {
            kind,
            world,
            ticks,
            tasks,
            log_bytes,
            events,
            event_bytes,
            objects_created,
            objects_recycled,
            storage_delta,
            policy_ticks,
            outcome,
        })
    }

    /// Decode exactly one meter array.
    pub fn decode(bytes: &[u8]) -> Result<Self, CborError> {
        let mut d = Decoder::new(bytes);
        let meter = Self::decode_from(&mut d)?;
        d.finish()?;
        Ok(meter)
    }

    /// Decode a meter batch entry's `event` bytes. `Ok(None)` when they are another event kind.
    pub fn decode_event(bytes: &[u8]) -> Result<Option<Self>, CborError> {
        let mut d = Decoder::new(bytes);
        d.array_of(2)?;
        if d.uint()? != METER_EVENT_TAG {
            return Ok(None);
        }
        let meter = Self::decode_from(&mut d)?;
        d.finish()?;
        Ok(Some(meter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Meter {
        Meter {
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
        }
    }

    #[test]
    fn meter_round_trips() {
        let m = sample();
        assert_eq!(Meter::decode(&m.encode()), Ok(m));
        assert_eq!(Meter::decode_event(&m.encode_event()), Ok(Some(m)));
    }

    #[test]
    fn another_event_kind_is_not_a_meter() {
        assert_eq!(
            Meter::decode_event(&[0x82, 0x02, 0x60]),
            Ok(None)
        );
    }

    #[test]
    fn unknown_codes_and_trailing_bytes_are_rejected() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert!(Meter::decode(&bytes).is_err());
        let mut bytes = sample().encode();
        bytes[1] = 9;
        assert!(Meter::decode(&bytes).is_err());
    }
}
