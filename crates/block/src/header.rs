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

//! The block header (ADR 0006 decision 3).

use crate::cbor::{Decoder, Encoder};
use crate::error::FormatError;
use crate::hash::{Hash, sha256};
use crate::sign::{ChainParams, HeaderSignature, SequencerKey, SignatureError};

/// The block format version this crate writes and reads.
pub const BLOCK_VERSION: u64 = 2;

/// `parent_hash` of block 1.
pub const GENESIS_PARENT_HASH: Hash = [0; 32];

const SEED_DOMAIN: &[u8] = b"rw/v1/seed";

/// The seed of block `height`: `SHA-256("rw/v1/seed" || state_root_{height-1} || height_be64)`
/// (ADR 0006 decision 1; `state_root_0` is the genesis root).
#[must_use]
pub fn seed_for(previous_state_root: &Hash, height: u64) -> Hash {
    sha256(&[SEED_DOMAIN, previous_state_root, &height.to_be_bytes()])
}

/// A header without its signature. Encoded as the array
/// `[version, height, parent_hash, timestamp, seed, commands_root, events_root, state_root]`;
/// `header_hash` is the SHA-256 of that encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockHeader {
    pub version: u64,
    pub height: u64,
    pub parent_hash: Hash,
    /// Whole seconds; never decreases.
    pub timestamp: u64,
    pub seed: Hash,
    pub commands_root: Hash,
    pub events_root: Hash,
    pub state_root: Hash,
}

impl BlockHeader {
    pub(crate) fn encode_fields(&self, e: &mut Encoder) {
        e.uint(self.version);
        e.uint(self.height);
        e.bytes(&self.parent_hash);
        e.uint(self.timestamp);
        e.bytes(&self.seed);
        e.bytes(&self.commands_root);
        e.bytes(&self.events_root);
        e.bytes(&self.state_root);
    }

    /// The canonical encoding of the unsigned header.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(8);
        self.encode_fields(&mut e);
        e.into_bytes()
    }

    /// `header_hash`.
    #[must_use]
    pub fn hash(&self) -> Hash {
        sha256(&[&self.encode()])
    }

    fn decode_fields(d: &mut Decoder) -> Result<Self, FormatError> {
        let version = d.uint()?;
        if version != BLOCK_VERSION {
            return Err(FormatError::Version {
                expected: BLOCK_VERSION,
                found: version,
            });
        }
        Ok(Self {
            version,
            height: d.uint()?,
            parent_hash: d.bytes_fixed()?,
            timestamp: d.uint()?,
            seed: d.bytes_fixed()?,
            commands_root: d.bytes_fixed()?,
            events_root: d.bytes_fixed()?,
            state_root: d.bytes_fixed()?,
        })
    }

    pub(crate) fn decode_from(d: &mut Decoder) -> Result<Self, FormatError> {
        d.array_of(8)?;
        Self::decode_fields(d)
    }

    /// Decode an unsigned header.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut d = Decoder::new(bytes);
        let header = Self::decode_from(&mut d)?;
        d.finish()?;
        Ok(header)
    }

    /// Seal: sign this header.
    pub fn sign(
        &self,
        key: &SequencerKey,
        genesis_root: &Hash,
    ) -> Result<SignedHeader, SignatureError> {
        Ok(SignedHeader {
            header: *self,
            sequencer_sig: key.sign(genesis_root, &self.hash())?,
        })
    }
}

/// ADR 0006's `BlockHeader{..., sequencer_sig}`: the header with its signature, encoded as the
/// nine-element array `[version, ..., state_root, sequencer_sig]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SignedHeader {
    pub header: BlockHeader,
    pub sequencer_sig: HeaderSignature,
}

impl SignedHeader {
    /// `header_hash` (the signature is not covered).
    #[must_use]
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Check that the chain's sequencer signed this header.
    pub fn verify(&self, params: &ChainParams) -> Result<(), SignatureError> {
        self.sequencer_sig.verify(params, &self.hash())
    }

    pub(crate) fn encode_into(&self, e: &mut Encoder) {
        e.array(9);
        self.header.encode_fields(e);
        e.bytes(self.sequencer_sig.as_bytes());
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_into(&mut e);
        e.into_bytes()
    }

    pub(crate) fn decode_from(d: &mut Decoder) -> Result<Self, FormatError> {
        d.array_of(9)?;
        let header = BlockHeader::decode_fields(d)?;
        let sequencer_sig = HeaderSignature::from_bytes(d.bytes_fixed()?)?;
        Ok(Self {
            header,
            sequencer_sig,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut d = Decoder::new(bytes);
        let header = Self::decode_from(&mut d)?;
        d.finish()?;
        Ok(header)
    }
}
