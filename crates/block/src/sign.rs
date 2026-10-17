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

//! The sequencer's header signature (ADR 0006 decision 3, ratification note 6).
//!
//! secp256k1 ECDSA with RFC 6979 deterministic nonces and low `s`, over
//! `SHA-256("rw/v1/header" || genesis_root || header_hash)`. The signature is `r || s || v`,
//! 65 bytes, `v` in {27, 28}, so `ecrecover(digest, v, r, s)` returns the sequencer's address and
//! an equivocation proof (two signatures at one height) is cheap to check onchain. Re-signing the
//! same header gives the same bytes.

use crate::hash::{Hash, hex, sha256};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest as _, Keccak256};
use std::fmt;

const HEADER_DOMAIN: &[u8] = b"rw/v1/header";

/// The digest the sequencer signs for a header.
#[must_use]
pub fn signing_digest(genesis_root: &Hash, header_hash: &Hash) -> Hash {
    sha256(&[HEADER_DOMAIN, genesis_root, header_hash])
}

/// An Ethereum-style address: the low 20 bytes of `keccak256(uncompressed public key)`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 20]);

impl Address {
    fn of(key: &VerifyingKey) -> Self {
        let point = key.to_encoded_point(false);
        let digest: [u8; 32] = Keccak256::digest(&point.as_bytes()[1..]).into();
        let mut out = [0u8; 20];
        out.copy_from_slice(&digest[12..]);
        Self(out)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex(&self.0))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex(&self.0))
    }
}

/// What a verifier needs besides the published bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainParams {
    /// The genesis state root; domain-separates signatures between deployments.
    pub genesis_root: Hash,
    /// The sequencer's address.
    pub sequencer: Address,
}

/// Why a signature is malformed or wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("v must be 27 or 28")]
    BadRecoveryId,
    #[error("r or s is zero or not below the curve order")]
    BadScalars,
    #[error("s is not in the lower half of the curve order")]
    HighS,
    #[error("no key recovers from this signature")]
    Unrecoverable,
    #[error("signed by {found}, expected {expected}")]
    WrongSigner { expected: Address, found: Address },
    #[error("signing failed")]
    Signing,
}

/// A canonical header signature: `r || s || v`, low `s`, `v` in {27, 28}.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeaderSignature([u8; 65]);

impl HeaderSignature {
    /// Check that the bytes are a canonical signature (scalars in range, low `s`, `v` 27 or 28).
    pub fn from_bytes(bytes: [u8; 65]) -> Result<Self, SignatureError> {
        let sig = Self(bytes);
        sig.parts()?;
        Ok(sig)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }

    fn parts(&self) -> Result<(Signature, RecoveryId), SignatureError> {
        let recid = match self.0[64] {
            27 => RecoveryId::from_byte(0),
            28 => RecoveryId::from_byte(1),
            _ => None,
        }
        .ok_or(SignatureError::BadRecoveryId)?;
        let sig = Signature::from_slice(&self.0[..64]).map_err(|_| SignatureError::BadScalars)?;
        if sig.normalize_s().is_some() {
            return Err(SignatureError::HighS);
        }
        Ok((sig, recid))
    }

    /// `ecrecover`: the address whose key signed `header_hash` under `genesis_root`.
    pub fn recover(
        &self,
        genesis_root: &Hash,
        header_hash: &Hash,
    ) -> Result<Address, SignatureError> {
        let (sig, recid) = self.parts()?;
        let digest = signing_digest(genesis_root, header_hash);
        let key = VerifyingKey::recover_from_prehash(&digest, &sig, recid)
            .map_err(|_| SignatureError::Unrecoverable)?;
        Ok(Address::of(&key))
    }

    /// Check that the chain's sequencer signed `header_hash`.
    pub fn verify(&self, params: &ChainParams, header_hash: &Hash) -> Result<(), SignatureError> {
        let found = self.recover(&params.genesis_root, header_hash)?;
        if found != params.sequencer {
            return Err(SignatureError::WrongSigner {
                expected: params.sequencer,
                found,
            });
        }
        Ok(())
    }
}

impl fmt::Debug for HeaderSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HeaderSignature({})", hex(&self.0))
    }
}

/// The sequencer's signing key (operator-held in Stage 1).
pub struct SequencerKey {
    key: SigningKey,
}

impl SequencerKey {
    /// From a 32-byte secp256k1 secret. `None` if the bytes are not a valid scalar.
    #[must_use]
    pub fn from_secret(secret: &[u8; 32]) -> Option<Self> {
        SigningKey::from_bytes(secret.into())
            .ok()
            .map(|key| Self { key })
    }

    #[must_use]
    pub fn address(&self) -> Address {
        Address::of(self.key.verifying_key())
    }

    /// Sign `header_hash` under `genesis_root`. Deterministic (RFC 6979), low `s`.
    pub fn sign(
        &self,
        genesis_root: &Hash,
        header_hash: &Hash,
    ) -> Result<HeaderSignature, SignatureError> {
        let digest = signing_digest(genesis_root, header_hash);
        let (sig, recid) = self
            .key
            .sign_prehash_recoverable(&digest)
            .map_err(|_| SignatureError::Signing)?;
        // `is_x_reduced` recovery ids (2, 3) occur with probability ~2^-128 and have no `v`.
        if recid.is_x_reduced() {
            return Err(SignatureError::Signing);
        }
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = 27 + recid.to_byte();
        HeaderSignature::from_bytes(out)
    }
}

impl fmt::Debug for SequencerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SequencerKey({})", self.address())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SequencerKey {
        SequencerKey::from_secret(&[0x11; 32]).unwrap()
    }

    #[test]
    fn signature_recovers_the_signer() {
        let sig = key().sign(&[1; 32], &[2; 32]).unwrap();
        assert_eq!(sig.recover(&[1; 32], &[2; 32]), Ok(key().address()));
    }

    #[test]
    fn resigning_is_byte_identical() {
        assert_eq!(
            key().sign(&[1; 32], &[2; 32]).unwrap(),
            key().sign(&[1; 32], &[2; 32]).unwrap()
        );
    }

    #[test]
    fn signature_under_another_genesis_does_not_verify() {
        let params = ChainParams {
            genesis_root: [9; 32],
            sequencer: key().address(),
        };
        let sig = key().sign(&[1; 32], &[2; 32]).unwrap();
        assert!(matches!(
            sig.verify(&params, &[2; 32]),
            Err(SignatureError::WrongSigner { .. })
        ));
    }

    #[test]
    fn high_s_is_refused() {
        let sig = key().sign(&[1; 32], &[2; 32]).unwrap();
        // s' = n - s, with v flipped: the malleated twin.
        let s = Signature::from_slice(&sig.as_bytes()[..64]).unwrap().s();
        let high = (-*s).to_bytes();
        let mut bytes = *sig.as_bytes();
        bytes[32..64].copy_from_slice(&high);
        bytes[64] = 55 - bytes[64];
        assert_eq!(
            HeaderSignature::from_bytes(bytes),
            Err(SignatureError::HighS)
        );
    }

    #[test]
    fn v_must_be_27_or_28() {
        let mut bytes = *key().sign(&[1; 32], &[2; 32]).unwrap().as_bytes();
        bytes[64] -= 27;
        assert_eq!(
            HeaderSignature::from_bytes(bytes),
            Err(SignatureError::BadRecoveryId)
        );
    }
}
