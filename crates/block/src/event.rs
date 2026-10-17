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

//! The event batch: a block's ordered committed events (ADR 0001 decision 4, S0-4 ordering).

use crate::cbor::{Decoder, Encoder};
use crate::error::FormatError;
use crate::hash::Hash;
use crate::merkle::{self, InclusionProof};

/// An event's id: `(height, seq)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId {
    pub height: u64,
    pub seq: u64,
}

/// One event batch entry, encoded `[seq, command_index, recipient, event]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventEntry {
    /// Position in the block's batch, from 0.
    pub seq: u64,
    /// The input that caused it (from 1), or 0 for work outside any input.
    pub command_index: u64,
    /// The recipient player's object number.
    pub recipient: i32,
    /// The fork's canonical encoding of the event; opaque here.
    pub event: Vec<u8>,
}

impl EventEntry {
    pub(crate) fn encode_into(&self, e: &mut Encoder) {
        e.array(4);
        e.uint(self.seq);
        e.uint(self.command_index);
        e.int(i64::from(self.recipient));
        e.bytes(&self.event);
    }

    /// The canonical encoding: the Merkle leaf input.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_into(&mut e);
        e.into_bytes()
    }

    pub(crate) fn decode_from(d: &mut Decoder) -> Result<Self, FormatError> {
        d.array_of(4)?;
        let seq = d.uint()?;
        let command_index = d.uint()?;
        let recipient = d.int()?;
        let recipient =
            i32::try_from(recipient).map_err(|_| FormatError::ObjectRange(recipient))?;
        let event = d.bytes()?.to_vec();
        Ok(Self {
            seq,
            command_index,
            recipient,
            event,
        })
    }

    /// Decode exactly one entry.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut d = Decoder::new(bytes);
        let entry = Self::decode_from(&mut d)?;
        d.finish()?;
        Ok(entry)
    }
}

/// A block's events in `seq` order. Invariants: `seq` is the position, and `command_index` never
/// decreases (events of an input, and of tasks it forked, precede the next input's).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct EventBatch {
    entries: Vec<EventEntry>,
}

impl EventBatch {
    /// A batch from entries, checked.
    pub fn new(entries: Vec<EventEntry>) -> Result<Self, FormatError> {
        let batch = Self { entries };
        batch.check()?;
        Ok(batch)
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Append an event, numbering it. Fails if `command_index` goes backwards.
    pub fn push(
        &mut self,
        command_index: u64,
        recipient: i32,
        event: Vec<u8>,
    ) -> Result<(), FormatError> {
        let seq = self.entries.len() as u64;
        if self
            .entries
            .last()
            .is_some_and(|last| last.command_index > command_index)
        {
            return Err(FormatError::EventCommandOrder { seq });
        }
        self.entries.push(EventEntry {
            seq,
            command_index,
            recipient,
            event,
        });
        Ok(())
    }

    #[must_use]
    pub fn entries(&self) -> &[EventEntry] {
        &self.entries
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn check(&self) -> Result<(), FormatError> {
        let mut previous = 0;
        for (position, entry) in self.entries.iter().enumerate() {
            let position = position as u64;
            if entry.seq != position {
                return Err(FormatError::EventSeq {
                    position,
                    found: entry.seq,
                });
            }
            if entry.command_index < previous {
                return Err(FormatError::EventCommandOrder { seq: entry.seq });
            }
            previous = entry.command_index;
        }
        Ok(())
    }

    /// Check that every event names an input of a block with `commands` inputs (or none).
    pub fn check_against(&self, commands: usize) -> Result<(), FormatError> {
        match self.entries.last() {
            Some(last) if last.command_index > commands as u64 => {
                Err(FormatError::EventCommandIndex {
                    seq: last.seq,
                    command_index: last.command_index,
                    commands,
                })
            }
            _ => Ok(()),
        }
    }

    fn encoded_entries(&self) -> Vec<Vec<u8>> {
        self.entries.iter().map(EventEntry::encode).collect()
    }

    /// `events_root`: the RFC 6962 root over the encoded entries.
    #[must_use]
    pub fn root(&self) -> Hash {
        merkle::root(&self.encoded_entries())
    }

    /// An inclusion proof for the event with `seq`.
    #[must_use]
    pub fn proof(&self, seq: u64) -> Option<InclusionProof> {
        InclusionProof::generate(&self.encoded_entries(), usize::try_from(seq).ok()?)
    }

    pub(crate) fn encode_into(&self, e: &mut Encoder) {
        e.array(self.entries.len());
        for entry in &self.entries {
            entry.encode_into(e);
        }
    }

    /// The canonical encoding: an array of entries.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_into(&mut e);
        e.into_bytes()
    }

    pub(crate) fn decode_from(d: &mut Decoder) -> Result<Self, FormatError> {
        let n = d.array()?;
        let entries = (0..n)
            .map(|_| EventEntry::decode_from(d))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(entries)
    }

    /// Decode exactly one batch.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut d = Decoder::new(bytes);
        let batch = Self::decode_from(&mut d)?;
        d.finish()?;
        Ok(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seq: u64, command_index: u64) -> EventEntry {
        EventEntry {
            seq,
            command_index,
            recipient: 3,
            event: vec![0xee],
        }
    }

    #[test]
    fn seq_must_be_the_position() {
        assert_eq!(
            EventBatch::new(vec![entry(0, 1), entry(2, 1)]),
            Err(FormatError::EventSeq {
                position: 1,
                found: 2
            })
        );
    }

    #[test]
    fn command_index_may_not_decrease() {
        assert_eq!(
            EventBatch::new(vec![entry(0, 2), entry(1, 1)]),
            Err(FormatError::EventCommandOrder { seq: 1 })
        );
    }

    #[test]
    fn push_numbers_events() {
        let mut batch = EventBatch::empty();
        batch.push(1, 3, vec![0xee]).unwrap();
        batch.push(1, 3, vec![0xee]).unwrap();
        assert_eq!(batch.entries(), &[entry(0, 1), entry(1, 1)]);
    }

    #[test]
    fn events_must_name_an_input_of_the_block() {
        let batch = EventBatch::new(vec![entry(0, 3)]).unwrap();
        assert!(batch.check_against(2).is_err());
    }
}
