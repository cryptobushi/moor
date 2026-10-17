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

//! The command batch: a block's ordered inputs (ADR 0006 decision 3).

use crate::cbor::{Decoder, Encoder};
use crate::error::FormatError;
use crate::hash::Hash;
use crate::merkle::{self, InclusionProof};

/// At most this many inputs per block (ADR 0006 decision 1, "Limits").
pub const MAX_COMMANDS_PER_BLOCK: usize = 2_048;

/// At most this many bytes of encoded command batch per block (ADR 0006 decision 1).
pub const MAX_COMMAND_BATCH_BYTES: usize = 512 * 1024;

/// A bound on one envelope's bytes. ADR 0005 envelopes are at most about 1.1 KB (1 KiB of text
/// plus headers and signature); this cap only bounds parsing. Whether the bytes are a valid
/// envelope is the admission step's question, not the block format's: an undecodable envelope is a
/// rejected input in a valid block.
pub const MAX_ENVELOPE_BYTES: usize = 2_048;

const TYPE_ENVELOPE: u64 = 0;
const TYPE_SEQUENCER_INPUT: u64 = 1;

/// What a sequencer input does. Version 1 has one kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SequencerInputKind {
    /// The player's connection went away (detach, ping timeout, cap overflow). Runs only
    /// `player:disfunc()` (ADR 0005 decision 6).
    Disconnected = 0,
}

impl SequencerInputKind {
    fn from_code(code: u64) -> Result<Self, FormatError> {
        match code {
            0 => Ok(Self::Disconnected),
            other => Err(FormatError::UnknownSequencerInput(other)),
        }
    }
}

/// An input with no player signature and no player authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SequencerInput {
    pub kind: SequencerInputKind,
    /// The player's object number (`#N` as `N`, as in the state encoding).
    pub player: i32,
}

/// One command batch entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CommandEntry {
    /// ADR 0005 envelope wire bytes, verbatim: `[0, bytes]`.
    Envelope(Vec<u8>),
    /// A sequencer input: `[1, [kind, player]]`.
    Sequencer(SequencerInput),
}

impl CommandEntry {
    /// Check the per-entry limits.
    pub fn check(&self) -> Result<(), FormatError> {
        match self {
            Self::Envelope(bytes) if bytes.is_empty() => Err(FormatError::EmptyEnvelope),
            Self::Envelope(bytes) if bytes.len() > MAX_ENVELOPE_BYTES => {
                Err(FormatError::EnvelopeTooLarge(bytes.len()))
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn encode_into(&self, e: &mut Encoder) {
        e.array(2);
        match self {
            Self::Envelope(bytes) => {
                e.uint(TYPE_ENVELOPE);
                e.bytes(bytes);
            }
            Self::Sequencer(input) => {
                e.uint(TYPE_SEQUENCER_INPUT);
                e.array(2);
                e.uint(input.kind as u64);
                e.int(i64::from(input.player));
            }
        }
    }

    /// The canonical encoding: the Merkle leaf input.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_into(&mut e);
        e.into_bytes()
    }

    pub(crate) fn decode_from(d: &mut Decoder) -> Result<Self, FormatError> {
        d.array_of(2)?;
        let entry = match d.uint()? {
            TYPE_ENVELOPE => Self::Envelope(d.bytes()?.to_vec()),
            TYPE_SEQUENCER_INPUT => {
                d.array_of(2)?;
                let kind = SequencerInputKind::from_code(d.uint()?)?;
                let player = d.int()?;
                let player = i32::try_from(player).map_err(|_| FormatError::ObjectRange(player))?;
                Self::Sequencer(SequencerInput { kind, player })
            }
            other => return Err(FormatError::UnknownCommandType(other)),
        };
        entry.check()?;
        Ok(entry)
    }

    /// Decode exactly one entry.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut d = Decoder::new(bytes);
        let entry = Self::decode_from(&mut d)?;
        d.finish()?;
        Ok(entry)
    }
}

/// A block's ordered inputs. The entry at position `k` (from 0) has command index `k + 1`: the
/// fork's block driver numbers inputs from 1 and uses 0 for work outside any input.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CommandBatch {
    entries: Vec<CommandEntry>,
}

impl CommandBatch {
    /// A batch, checked against the per-entry and per-block limits.
    pub fn new(entries: Vec<CommandEntry>) -> Result<Self, FormatError> {
        let batch = Self { entries };
        batch.check()?;
        Ok(batch)
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn entries(&self) -> &[CommandEntry] {
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

    /// The entry with command index `command_index` (from 1).
    #[must_use]
    pub fn by_command_index(&self, command_index: u64) -> Option<&CommandEntry> {
        let position = usize::try_from(command_index.checked_sub(1)?).ok()?;
        self.entries.get(position)
    }

    fn check(&self) -> Result<(), FormatError> {
        if self.entries.len() > MAX_COMMANDS_PER_BLOCK {
            return Err(FormatError::TooManyCommands(self.entries.len()));
        }
        self.entries.iter().try_for_each(CommandEntry::check)?;
        let size = self.encode().len();
        if size > MAX_COMMAND_BATCH_BYTES {
            return Err(FormatError::CommandBatchTooLarge(size));
        }
        Ok(())
    }

    fn encoded_entries(&self) -> Vec<Vec<u8>> {
        self.entries.iter().map(CommandEntry::encode).collect()
    }

    /// `commands_root`: the RFC 6962 root over the encoded entries.
    #[must_use]
    pub fn root(&self) -> Hash {
        merkle::root(&self.encoded_entries())
    }

    /// An inclusion proof for the entry at `position` (from 0; command index `position + 1`).
    #[must_use]
    pub fn proof(&self, position: usize) -> Option<InclusionProof> {
        InclusionProof::generate(&self.encoded_entries(), position)
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
        let start = d.position();
        let n = d.array()?;
        if n > MAX_COMMANDS_PER_BLOCK {
            return Err(FormatError::TooManyCommands(n));
        }
        let entries = (0..n)
            .map(|_| CommandEntry::decode_from(d))
            .collect::<Result<Vec<_>, _>>()?;
        let size = d.position() - start;
        if size > MAX_COMMAND_BATCH_BYTES {
            return Err(FormatError::CommandBatchTooLarge(size));
        }
        Ok(Self { entries })
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

    #[test]
    fn command_index_is_position_plus_one() {
        let batch = CommandBatch::new(vec![
            CommandEntry::Envelope(vec![1]),
            CommandEntry::Envelope(vec![2]),
        ])
        .unwrap();
        assert_eq!(
            (batch.by_command_index(0), batch.by_command_index(2)),
            (None, Some(&CommandEntry::Envelope(vec![2])))
        );
    }

    #[test]
    fn empty_envelope_is_refused() {
        assert_eq!(
            CommandBatch::new(vec![CommandEntry::Envelope(vec![])]),
            Err(FormatError::EmptyEnvelope)
        );
    }

    #[test]
    fn too_many_commands_are_refused() {
        let entries = vec![CommandEntry::Envelope(vec![0]); MAX_COMMANDS_PER_BLOCK + 1];
        assert_eq!(
            CommandBatch::new(entries),
            Err(FormatError::TooManyCommands(MAX_COMMANDS_PER_BLOCK + 1))
        );
    }

    #[test]
    fn oversized_batch_is_refused() {
        let entries = vec![CommandEntry::Envelope(vec![0; MAX_ENVELOPE_BYTES]); 300];
        assert!(matches!(
            CommandBatch::new(entries),
            Err(FormatError::CommandBatchTooLarge(_))
        ));
    }

    #[test]
    fn unknown_sequencer_input_kind_is_refused() {
        // [1, [7, 3]]
        assert_eq!(
            CommandEntry::decode(&[0x82, 0x01, 0x82, 0x07, 0x03]),
            Err(FormatError::UnknownSequencerInput(7))
        );
    }

    #[test]
    fn unknown_entry_type_is_refused() {
        // [2, h'00']
        assert_eq!(
            CommandEntry::decode(&[0x82, 0x02, 0x41, 0x00]),
            Err(FormatError::UnknownCommandType(2))
        );
    }
}
