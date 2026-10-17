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

//! Signed envelopes: the wire form of every player input in deterministic mode (RuneWorld
//! ADR 0005, decisions 2 and 4).
//!
//! A *wallet* (secp256k1 EOA) signs an EIP-712 [`Delegation`] to an Ed25519 *session key* once;
//! the session key signs every [`Envelope`]. This module is pure: encoding, digests and signature
//! checks. The admission step that consults world state lives in the kernel.
//!
//! # Envelope wire format (version 1)
//!
//! | Field | Bytes | Encoding |
//! |---|---|---|
//! | `kind` | 1 | [`EnvelopeKind`] as `u8` |
//! | `session` | 4 | big-endian `u32`; 0 for `delegate` and `revoke_all` |
//! | `nonce` | 1-4 | unsigned LEB128, minimal, `< 2^28`; 0 for `delegate` and `revoke_all` |
//! | `expiry` | 2 | big-endian `u16`: the low 16 bits of the absolute expiry height |
//! | `text_len` | 1-2 | unsigned LEB128, minimal, `<= 1024` |
//! | `text` | `text_len` | command line (UTF-8), empty, or a binary payload (see below) |
//! | `signature` | 64 | Ed25519 over [`envelope_digest`]; all zero for `revoke_all` |
//!
//! The absolute expiry height is recovered by [`expiry_height`]: the unique height congruent to
//! the field modulo 2^16 in `(current - 2^15, current + 2^15]`.
//!
//! # Signed preimage
//!
//! `SHA-256("RuneWorld/envelope/v1" || domain_separator || player_be64 || session_pubkey ||
//! kind || nonce_be64 || expiry_height_be64 || text_len_be32 || text)`, signed with Ed25519 and
//! verified under ZIP-215 rules. `player` is `Obj::as_u64()` of the session's player (`#-1` for a
//! `delegate`, whose player may not exist yet). The domain separator is the EIP-712 one, so a
//! single domain `(name "RuneWorld", version "1", salt)` binds both signatures to a deployment.
//!
//! # Binary payloads
//!
//! - `delegate`: `session_key(32) || box_key(32) || scope_be32 || expires_be64 || nonce_be64 ||
//!   create(1) || wallet_signature(65)`, 150 bytes. The Ed25519 signature is by the delegated
//!   session key (proof of possession).
//! - `revoke_all`: `nonce_be64 || wallet_signature(65)`, 73 bytes.
//! - `revoke`: empty (revoke the signing session) or the decimal index of another session of the
//!   same player.
//!
//! Wallet signatures are `r(32) || s(32) || v(1)` with `v` in `{0, 1, 27, 28}` and low `s`
//! (EIP-2), over the EIP-712 digest of [`Delegation`] or [`RevokeAll`].

use ed25519_zebra::{Signature as EdSignature, SigningKey as EdSigningKey, VerificationKey};
use k256::ecdsa::{RecoveryId, Signature as EcSignature, SigningKey as EcSigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use std::fmt;

/// Largest `text` an envelope may carry (ADR 0005 decision 4: 1 KiB for `play`).
pub const MAX_TEXT_BYTES: usize = 1024;
/// Largest envelope nonce: four LEB128 bytes carry 28 bits.
pub const MAX_NONCE: u32 = (1 << 28) - 1;
/// Bytes in a `delegate` payload.
pub const DELEGATION_PAYLOAD_BYTES: usize = 32 + 32 + 4 + 8 + 8 + 1 + 65;
/// Bytes in a `revoke_all` payload.
pub const REVOKE_ALL_PAYLOAD_BYTES: usize = 8 + 65;
/// EIP-712 domain name.
pub const DOMAIN_NAME: &str = "RuneWorld";
/// EIP-712 domain version. Becomes "2" when the settlement ADR adds `chainId`.
pub const DOMAIN_VERSION: &str = "1";

const PREIMAGE_TAG: &[u8] = b"RuneWorld/envelope/v1";
const DOMAIN_TYPE: &[u8] = b"EIP712Domain(string name,string version,bytes32 salt)";
const DELEGATION_TYPE: &[u8] = b"Delegation(bytes32 session_key,bytes32 box_key,uint32 scope,uint64 expires,uint64 nonce,bool create)";
const REVOKE_ALL_TYPE: &[u8] = b"RevokeAll(uint64 nonce)";

/// Session scope bits (ADR 0005 decision 2). Scope gates envelope kinds only.
pub mod scope {
    /// Ordinary commands.
    pub const PLAY: u32 = 1 << 0;
    /// Deploy-shaped authoring (shape set by the deploy ADR).
    pub const BUILD: u32 = 1 << 1;
    /// Every defined bit.
    pub const ALL: u32 = PLAY | BUILD;
}

/// What an envelope asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum EnvelopeKind {
    /// A command line, signed by a session key with `play` scope.
    Command = 0,
    /// Attach a connection to the session's player. Empty text.
    Connect = 1,
    /// Register a session key; the payload carries the wallet-signed [`Delegation`].
    Delegate = 2,
    /// Revoke one session of the signer's player.
    Revoke = 3,
    /// Revoke every session of a wallet's player; the payload carries a wallet-signed
    /// [`RevokeAll`].
    RevokeAll = 4,
}

impl EnvelopeKind {
    /// The kind for a wire byte.
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Command,
            1 => Self::Connect,
            2 => Self::Delegate,
            3 => Self::Revoke,
            4 => Self::RevokeAll,
            _ => return None,
        })
    }

    /// The name used in logs and events.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Connect => "connect",
            Self::Delegate => "delegate",
            Self::Revoke => "revoke",
            Self::RevokeAll => "revoke_all",
        }
    }

    /// The scope bits of which a session needs at least one to sign this kind, or `None` for
    /// kinds that are not signed by a session key.
    #[must_use]
    pub fn required_scope(self) -> Option<u32> {
        match self {
            Self::Command => Some(scope::PLAY),
            Self::Connect | Self::Revoke => Some(scope::ALL),
            Self::Delegate | Self::RevokeAll => None,
        }
    }
}

impl fmt::Display for EnvelopeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why bytes are not a well-formed envelope or payload.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("envelope truncated")]
    Truncated,
    #[error("unknown envelope kind {0}")]
    UnknownKind(u8),
    #[error("non-minimal or oversized varint")]
    BadVarint,
    #[error("text is {0} bytes, more than {MAX_TEXT_BYTES}")]
    TextTooLong(usize),
    #[error("{0} trailing bytes")]
    Trailing(usize),
    #[error("payload is {got} bytes, expected {expected}")]
    PayloadLength { expected: usize, got: usize },
    #[error("create flag must be 0 or 1")]
    BadCreateFlag,
}

/// A signed log entry (glossary: *Envelope*).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub kind: EnvelopeKind,
    /// Session index assigned at delegation; 0 when the kind is not session-signed.
    pub session: u32,
    /// Per-session nonce, strictly increasing, gaps allowed.
    pub nonce: u32,
    /// Low 16 bits of the last block height the envelope is valid at.
    pub expiry: u16,
    pub text: Vec<u8>,
    pub signature: [u8; 64],
}

fn put_varint(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Read a minimal LEB128 value of at most `max_bytes` bytes.
fn get_varint(bytes: &[u8], pos: &mut usize, max_bytes: usize) -> Result<u32, DecodeError> {
    let mut value: u32 = 0;
    for i in 0..max_bytes {
        let byte = *bytes.get(*pos).ok_or(DecodeError::Truncated)?;
        *pos += 1;
        value |= u32::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            // A zero final byte after the first is an overlong encoding.
            if i > 0 && byte == 0 {
                return Err(DecodeError::BadVarint);
            }
            return Ok(value);
        }
    }
    Err(DecodeError::BadVarint)
}

fn take<'a>(bytes: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], DecodeError> {
    let end = pos.checked_add(n).ok_or(DecodeError::Truncated)?;
    let slice = bytes.get(*pos..end).ok_or(DecodeError::Truncated)?;
    *pos = end;
    Ok(slice)
}

fn array<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    out
}

impl Envelope {
    /// The wire bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4 + 4 + 2 + 2 + self.text.len() + 64);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.session.to_be_bytes());
        put_varint(&mut out, self.nonce);
        out.extend_from_slice(&self.expiry.to_be_bytes());
        put_varint(&mut out, self.text.len() as u32);
        out.extend_from_slice(&self.text);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse wire bytes. The whole input must be one envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut pos = 0;
        let kind_byte = take(bytes, &mut pos, 1)?[0];
        let kind = EnvelopeKind::from_byte(kind_byte).ok_or(DecodeError::UnknownKind(kind_byte))?;
        let session = u32::from_be_bytes(array(take(bytes, &mut pos, 4)?));
        let nonce = get_varint(bytes, &mut pos, 4)?;
        let expiry = u16::from_be_bytes(array(take(bytes, &mut pos, 2)?));
        let text_len = get_varint(bytes, &mut pos, 2)? as usize;
        if text_len > MAX_TEXT_BYTES {
            return Err(DecodeError::TextTooLong(text_len));
        }
        let text = take(bytes, &mut pos, text_len)?.to_vec();
        let signature = array(take(bytes, &mut pos, 64)?);
        if pos != bytes.len() {
            return Err(DecodeError::Trailing(bytes.len() - pos));
        }
        Ok(Self {
            kind,
            session,
            nonce,
            expiry,
            text,
            signature,
        })
    }

    /// The wire `expiry` field for an absolute expiry height.
    #[must_use]
    pub fn expiry_field(expiry_height: u64) -> u16 {
        (expiry_height & 0xffff) as u16
    }
}

/// The absolute expiry height for a wire field seen at block height `current`: the unique height
/// congruent to `field` modulo 2^16 in `(current - 2^15, current + 2^15]`. `None` when that height
/// would be negative, which only happens in the first 2^15 blocks and means "already expired".
#[must_use]
pub fn expiry_height(current: u64, field: u16) -> Option<u64> {
    const WINDOW: i128 = 1 << 16;
    const HALF: i128 = 1 << 15;
    let current = i128::from(current);
    let mut candidate = current - current.rem_euclid(WINDOW) + i128::from(field);
    if candidate > current + HALF {
        candidate -= WINDOW;
    } else if candidate <= current - HALF {
        candidate += WINDOW;
    }
    u64::try_from(candidate).ok()
}

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// The signing domain (ADR 0005 decision 2): name "RuneWorld", version "1", and a salt that is the
/// genesis state root once S0-5 defines one. No `chainId` until the settlement ADR.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Domain {
    pub salt: [u8; 32],
}

impl Domain {
    #[must_use]
    pub fn new(salt: [u8; 32]) -> Self {
        Self { salt }
    }

    /// EIP-712 `domainSeparator`:
    /// `keccak256(typeHash || keccak256(name) || keccak256(version) || salt)`.
    #[must_use]
    pub fn separator(&self) -> [u8; 32] {
        keccak(&[
            &keccak(&[DOMAIN_TYPE]),
            &keccak(&[DOMAIN_NAME.as_bytes()]),
            &keccak(&[DOMAIN_VERSION.as_bytes()]),
            &self.salt,
        ])
    }

    fn typed_digest(&self, struct_hash: &[u8; 32]) -> [u8; 32] {
        keccak(&[&[0x19, 0x01], &self.separator(), struct_hash])
    }
}

/// The digest a session key signs (see the module docs).
#[must_use]
pub fn envelope_digest(
    domain: &Domain,
    player: u64,
    session_pubkey: &[u8; 32],
    kind: EnvelopeKind,
    nonce: u64,
    expiry_height: u64,
    text: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PREIMAGE_TAG);
    h.update(domain.separator());
    h.update(player.to_be_bytes());
    h.update(session_pubkey);
    h.update([kind as u8]);
    h.update(nonce.to_be_bytes());
    h.update(expiry_height.to_be_bytes());
    h.update((text.len() as u32).to_be_bytes());
    h.update(text);
    h.finalize().into()
}

/// Ed25519 verification under ZIP-215 rules (cofactored equation; non-canonical point encodings
/// accepted; `s` must be canonical). True when `signature` is valid for `digest`.
#[must_use]
pub fn verify_session_signature(
    session_pubkey: &[u8; 32],
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    let Ok(key) = VerificationKey::try_from(*session_pubkey) else {
        return false;
    };
    key.verify(&EdSignature::from_bytes(signature), digest)
        .is_ok()
}

/// A 20-byte Ethereum address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// Lower-case `0x`-prefixed hex, as stored in `$player.wallet`.
    #[must_use]
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex(&self.0))
    }

    /// Parse `0x` + 40 hex digits (either case).
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        let digits = text.strip_prefix("0x")?;
        unhex::<20>(digits).map(Self)
    }

    /// The placeholder player name: `w-` and the first 8 hex digits (ADR 0005 decision 5).
    #[must_use]
    pub fn placeholder_name(&self) -> String {
        format!("w-{}", &hex(&self.0)[..8])
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse exactly `N` bytes of hex (no prefix).
#[must_use]
pub fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let pair = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// Parse any even-length hex string.
#[must_use]
pub fn unhex_vec(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// Why a wallet signature does not yield an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WalletSignatureError {
    #[error("v must be 0, 1, 27 or 28")]
    BadRecoveryId,
    #[error("r or s out of range")]
    BadScalars,
    #[error("s is not in the lower half of the curve order (EIP-2)")]
    HighS,
    #[error("no key recovers from this signature")]
    Unrecoverable,
}

/// The address whose key produced `signature` over `digest` (`ecrecover`). Rejects high `s`.
pub fn recover_wallet(
    digest: &[u8; 32],
    signature: &[u8; 65],
) -> Result<Address, WalletSignatureError> {
    let recid = match signature[64] {
        0 | 27 => 0,
        1 | 28 => 1,
        _ => return Err(WalletSignatureError::BadRecoveryId),
    };
    let sig =
        EcSignature::from_slice(&signature[..64]).map_err(|_| WalletSignatureError::BadScalars)?;
    if sig.normalize_s().is_some() {
        return Err(WalletSignatureError::HighS);
    }
    let recid = RecoveryId::from_byte(recid).ok_or(WalletSignatureError::BadRecoveryId)?;
    let key = VerifyingKey::recover_from_prehash(digest, &sig, recid)
        .map_err(|_| WalletSignatureError::Unrecoverable)?;
    Ok(address_of(&key))
}

fn address_of(key: &VerifyingKey) -> Address {
    let point = key.to_encoded_point(false);
    let hash = keccak(&[&point.as_bytes()[1..]]);
    Address(array(&hash[12..]))
}

/// The EIP-712 typed message a wallet signs to authorise a session key (ADR 0005 decision 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delegation {
    /// Ed25519 public key of the session.
    pub session_key: [u8; 32],
    /// X25519 public key for private messages.
    pub box_key: [u8; 32],
    /// [`scope`] bits.
    pub scope: u32,
    /// Block timestamp (seconds) at which the session stops being valid.
    pub expires: u64,
    /// Per-wallet nonce, strictly increasing.
    pub nonce: u64,
    /// Mint a `$player` for a wallet that has none.
    pub create: bool,
}

impl Delegation {
    /// `hashStruct(Delegation)`.
    #[must_use]
    pub fn struct_hash(&self) -> [u8; 32] {
        keccak(&[
            &keccak(&[DELEGATION_TYPE]),
            &self.session_key,
            &self.box_key,
            &word_u64(u64::from(self.scope)),
            &word_u64(self.expires),
            &word_u64(self.nonce),
            &word_u64(u64::from(self.create)),
        ])
    }

    /// The digest the wallet signs (`eth_signTypedData_v4`).
    #[must_use]
    pub fn digest(&self, domain: &Domain) -> [u8; 32] {
        domain.typed_digest(&self.struct_hash())
    }
}

/// A `delegate` payload: the delegation and the wallet's signature over it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegationPayload {
    pub delegation: Delegation,
    pub wallet_signature: [u8; 65],
}

impl DelegationPayload {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let d = &self.delegation;
        let mut out = Vec::with_capacity(DELEGATION_PAYLOAD_BYTES);
        out.extend_from_slice(&d.session_key);
        out.extend_from_slice(&d.box_key);
        out.extend_from_slice(&d.scope.to_be_bytes());
        out.extend_from_slice(&d.expires.to_be_bytes());
        out.extend_from_slice(&d.nonce.to_be_bytes());
        out.push(u8::from(d.create));
        out.extend_from_slice(&self.wallet_signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != DELEGATION_PAYLOAD_BYTES {
            return Err(DecodeError::PayloadLength {
                expected: DELEGATION_PAYLOAD_BYTES,
                got: bytes.len(),
            });
        }
        let create = match bytes[84] {
            0 => false,
            1 => true,
            _ => return Err(DecodeError::BadCreateFlag),
        };
        Ok(Self {
            delegation: Delegation {
                session_key: array(&bytes[0..32]),
                box_key: array(&bytes[32..64]),
                scope: u32::from_be_bytes(array(&bytes[64..68])),
                expires: u64::from_be_bytes(array(&bytes[68..76])),
                nonce: u64::from_be_bytes(array(&bytes[76..84])),
                create,
            },
            wallet_signature: array(&bytes[85..150]),
        })
    }
}

/// The EIP-712 typed message a wallet signs to revoke every session of its player. Not named in
/// ADR 0005; added because `revoke_all` must be signed by the root, not by a possibly compromised
/// session key. It consumes the same per-wallet nonce as [`Delegation`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevokeAll {
    pub nonce: u64,
}

impl RevokeAll {
    #[must_use]
    pub fn struct_hash(&self) -> [u8; 32] {
        keccak(&[&keccak(&[REVOKE_ALL_TYPE]), &word_u64(self.nonce)])
    }

    #[must_use]
    pub fn digest(&self, domain: &Domain) -> [u8; 32] {
        domain.typed_digest(&self.struct_hash())
    }
}

/// A `revoke_all` payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevokeAllPayload {
    pub revoke: RevokeAll,
    pub wallet_signature: [u8; 65],
}

impl RevokeAllPayload {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REVOKE_ALL_PAYLOAD_BYTES);
        out.extend_from_slice(&self.revoke.nonce.to_be_bytes());
        out.extend_from_slice(&self.wallet_signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != REVOKE_ALL_PAYLOAD_BYTES {
            return Err(DecodeError::PayloadLength {
                expected: REVOKE_ALL_PAYLOAD_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self {
            revoke: RevokeAll {
                nonce: u64::from_be_bytes(array(&bytes[0..8])),
            },
            wallet_signature: array(&bytes[8..73]),
        })
    }
}

/// A session key that signs envelopes (hosts, tests, the replay harness).
pub struct SessionSigner {
    key: EdSigningKey,
}

impl SessionSigner {
    /// From a 32-byte Ed25519 seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            key: EdSigningKey::from(seed),
        }
    }

    /// The public key, as delegated.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        VerificationKey::from(&self.key).into()
    }

    /// Sign a digest.
    #[must_use]
    pub fn sign_digest(&self, digest: &[u8; 32]) -> [u8; 64] {
        self.key.sign(digest).to_bytes()
    }

    /// A signed session envelope for `player` (`Obj::as_u64`).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn envelope(
        &self,
        domain: &Domain,
        player: u64,
        kind: EnvelopeKind,
        session: u32,
        nonce: u32,
        expiry_height: u64,
        text: Vec<u8>,
    ) -> Envelope {
        let digest = envelope_digest(
            domain,
            player,
            &self.public_key(),
            kind,
            u64::from(nonce),
            expiry_height,
            &text,
        );
        Envelope {
            kind,
            session,
            nonce,
            expiry: Envelope::expiry_field(expiry_height),
            text,
            signature: self.sign_digest(&digest),
        }
    }
}

/// A wallet key that signs EIP-712 messages (tests and the replay harness; real wallets sign
/// through `eth_signTypedData_v4`).
pub struct WalletSigner {
    key: EcSigningKey,
}

impl WalletSigner {
    /// From a 32-byte secp256k1 secret. `None` if the bytes are not a valid scalar.
    #[must_use]
    pub fn from_secret(secret: [u8; 32]) -> Option<Self> {
        EcSigningKey::from_bytes(&secret.into())
            .ok()
            .map(|key| Self { key })
    }

    #[must_use]
    pub fn address(&self) -> Address {
        address_of(self.key.verifying_key())
    }

    /// `r || s || v` with `v` in {27, 28} and low `s`, as wallets return.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 65], WalletSignatureError> {
        let (sig, recid) = self
            .key
            .sign_prehash_recoverable(digest)
            .map_err(|_| WalletSignatureError::BadScalars)?;
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = 27 + recid.to_byte();
        Ok(out)
    }

    /// A signed `delegate` envelope. The session signer proves possession of the delegated key.
    pub fn delegate(
        &self,
        domain: &Domain,
        session: &SessionSigner,
        delegation: Delegation,
        expiry_height: u64,
    ) -> Result<Envelope, WalletSignatureError> {
        let wallet_signature = self.sign_digest(&delegation.digest(domain))?;
        let text = DelegationPayload {
            delegation,
            wallet_signature,
        }
        .encode();
        let nothing = moor_var::NOTHING.as_u64();
        let digest = envelope_digest(
            domain,
            nothing,
            &delegation.session_key,
            EnvelopeKind::Delegate,
            0,
            expiry_height,
            &text,
        );
        Ok(Envelope {
            kind: EnvelopeKind::Delegate,
            session: 0,
            nonce: 0,
            expiry: Envelope::expiry_field(expiry_height),
            text,
            signature: session.sign_digest(&digest),
        })
    }

    /// A signed `revoke_all` envelope.
    pub fn revoke_all(
        &self,
        domain: &Domain,
        nonce: u64,
        expiry_height: u64,
    ) -> Result<Envelope, WalletSignatureError> {
        let revoke = RevokeAll { nonce };
        let wallet_signature = self.sign_digest(&revoke.digest(domain))?;
        Ok(Envelope {
            kind: EnvelopeKind::RevokeAll,
            session: 0,
            nonce: 0,
            expiry: Envelope::expiry_field(expiry_height),
            text: RevokeAllPayload {
                revoke,
                wallet_signature,
            }
            .encode(),
            signature: [0; 64],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: Domain = Domain { salt: [0; 32] };

    fn wallet() -> WalletSigner {
        WalletSigner::from_secret([0x11; 32]).unwrap()
    }

    fn session() -> SessionSigner {
        SessionSigner::from_seed([0x22; 32])
    }

    fn delegation() -> Delegation {
        Delegation {
            session_key: session().public_key(),
            box_key: [0x33; 32],
            scope: scope::PLAY,
            expires: 1_700_086_400,
            nonce: 1,
            create: true,
        }
    }

    #[test]
    fn envelope_round_trips() {
        let env = session().envelope(
            &DOMAIN,
            5,
            EnvelopeKind::Command,
            3,
            300,
            70_000,
            b"look".to_vec(),
        );
        assert_eq!(Envelope::decode(&env.encode()), Ok(env));
    }

    #[test]
    fn typical_command_envelope_is_80_bytes() {
        // 1 + 4 + 1 + 2 + 1 + 7 + 64: the 64-byte signature and 4-byte index dominate.
        let env = session().envelope(
            &DOMAIN,
            5,
            EnvelopeKind::Command,
            1,
            1,
            10,
            b"go west".to_vec(),
        );
        assert_eq!(env.encode().len(), 80);
    }

    #[test]
    fn nonce_varint_takes_at_most_four_bytes() {
        let env = session().envelope(&DOMAIN, 5, EnvelopeKind::Command, 1, MAX_NONCE, 10, vec![]);
        assert_eq!(env.encode().len(), 1 + 4 + 4 + 2 + 1 + 64);
    }

    #[test]
    fn overlong_varint_is_rejected() {
        let mut bytes = session()
            .envelope(&DOMAIN, 5, EnvelopeKind::Command, 1, 1, 10, vec![])
            .encode();
        // nonce 1 encoded as 0x81 0x00
        bytes.splice(5..6, [0x81, 0x00]);
        assert_eq!(Envelope::decode(&bytes), Err(DecodeError::BadVarint));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = session()
            .envelope(&DOMAIN, 5, EnvelopeKind::Command, 1, 1, 10, vec![])
            .encode();
        bytes.push(0);
        assert_eq!(Envelope::decode(&bytes), Err(DecodeError::Trailing(1)));
    }

    #[test]
    fn oversized_text_is_rejected() {
        let mut env = session().envelope(&DOMAIN, 5, EnvelopeKind::Command, 1, 1, 10, vec![]);
        env.text = vec![b'x'; MAX_TEXT_BYTES + 1];
        assert_eq!(
            Envelope::decode(&env.encode()),
            Err(DecodeError::TextTooLong(MAX_TEXT_BYTES + 1))
        );
    }

    #[test]
    fn session_signature_verifies() {
        let s = session();
        let env = s.envelope(
            &DOMAIN,
            5,
            EnvelopeKind::Command,
            1,
            7,
            10,
            b"look".to_vec(),
        );
        let digest = envelope_digest(&DOMAIN, 5, &s.public_key(), env.kind, 7, 10, b"look");
        assert!(verify_session_signature(
            &s.public_key(),
            &digest,
            &env.signature
        ));
    }

    #[test]
    fn session_signature_is_bound_to_the_player() {
        let s = session();
        let env = s.envelope(
            &DOMAIN,
            5,
            EnvelopeKind::Command,
            1,
            7,
            10,
            b"look".to_vec(),
        );
        let digest = envelope_digest(&DOMAIN, 6, &s.public_key(), env.kind, 7, 10, b"look");
        assert!(!verify_session_signature(
            &s.public_key(),
            &digest,
            &env.signature
        ));
    }

    #[test]
    fn session_signature_is_bound_to_the_domain_salt() {
        let s = session();
        let env = s.envelope(
            &DOMAIN,
            5,
            EnvelopeKind::Command,
            1,
            7,
            10,
            b"look".to_vec(),
        );
        let other = Domain::new([1; 32]);
        let digest = envelope_digest(&other, 5, &s.public_key(), env.kind, 7, 10, b"look");
        assert!(!verify_session_signature(
            &s.public_key(),
            &digest,
            &env.signature
        ));
    }

    #[test]
    fn wallet_signature_recovers_the_address() {
        let w = wallet();
        let digest = delegation().digest(&DOMAIN);
        let sig = w.sign_digest(&digest).unwrap();
        assert_eq!(recover_wallet(&digest, &sig), Ok(w.address()));
    }

    #[test]
    fn high_s_wallet_signature_is_rejected() {
        let w = wallet();
        let digest = delegation().digest(&DOMAIN);
        let mut sig = w.sign_digest(&digest).unwrap();
        // s' = n - s, v flipped: the same point, the malleable twin.
        let s = EcSignature::from_slice(&sig[..64]).unwrap();
        let (r, s_scalar) = s.split_scalars();
        let high = EcSignature::from_scalars(r.to_bytes(), (-*s_scalar).to_bytes()).unwrap();
        sig[..64].copy_from_slice(&high.to_bytes());
        sig[64] = if sig[64] == 27 { 28 } else { 27 };
        assert_eq!(
            recover_wallet(&digest, &sig),
            Err(WalletSignatureError::HighS)
        );
    }

    #[test]
    fn delegation_payload_round_trips() {
        let payload = DelegationPayload {
            delegation: delegation(),
            wallet_signature: [9; 65],
        };
        assert_eq!(DelegationPayload::decode(&payload.encode()), Ok(payload));
    }

    #[test]
    fn delegate_envelope_is_225_bytes() {
        let env = wallet()
            .delegate(&DOMAIN, &session(), delegation(), 100)
            .unwrap();
        assert_eq!(env.encode().len(), 1 + 4 + 1 + 2 + 2 + 150 + 64);
    }

    #[test]
    fn expiry_height_recovers_nearby_heights() {
        for (current, target) in [
            (0, 0),
            (10, 40),
            (70_000, 70_100),
            (70_000, 65_536),
            (65_535, 65_600),
        ] {
            assert_eq!(
                expiry_height(current, Envelope::expiry_field(target)),
                Some(target),
                "{current} -> {target}"
            );
        }
    }

    #[test]
    fn expiry_height_outside_the_window_wraps() {
        // The window is (current - 2^15, current + 2^15]: a height 40,000 blocks back is read as
        // 25,536 ahead. Signers therefore never set an expiry more than 2^15 blocks ahead, and
        // a sequencer holding an envelope 2^15 blocks gains nothing it could not get by
        // including it on time.
        assert_eq!(
            expiry_height(100_000, Envelope::expiry_field(60_000)),
            Some(125_536)
        );
    }

    #[test]
    fn expiry_height_before_genesis_is_none() {
        assert_eq!(expiry_height(5, 0xffff), None);
    }

    #[test]
    fn address_hex_round_trips() {
        let a = wallet().address();
        assert_eq!(Address::from_hex(&a.to_hex()), Some(a));
    }

    // Golden vectors, cross-checked with Foundry `cast` (see the S0-8 report): secret 0x11..11,
    // salt zero, delegation() above.
    #[test]
    fn wallet_address_matches_cast() {
        assert_eq!(wallet().address().to_hex(), GOLDEN_ADDRESS);
    }

    #[test]
    fn delegation_digest_matches_cast() {
        assert_eq!(hex(&delegation().digest(&DOMAIN)), GOLDEN_DELEGATION_DIGEST);
    }

    #[test]
    fn delegation_signature_matches_cast() {
        let sig = wallet().sign_digest(&delegation().digest(&DOMAIN)).unwrap();
        assert_eq!(hex(&sig), GOLDEN_DELEGATION_SIGNATURE);
    }

    #[test]
    fn domain_separator_matches_cast() {
        assert_eq!(hex(&DOMAIN.separator()), GOLDEN_SEPARATOR);
    }

    // Independent: SHA-256 of the preimage in Python, Ed25519 signature by Node's crypto (the same
    // primitive WebCrypto exposes), session seed 0x22..22.
    #[test]
    fn command_envelope_matches_independent_implementation() {
        let env = session().envelope(
            &DOMAIN,
            5,
            EnvelopeKind::Command,
            1,
            7,
            10,
            b"look".to_vec(),
        );
        let digest = envelope_digest(
            &DOMAIN,
            5,
            &session().public_key(),
            env.kind,
            7,
            10,
            b"look",
        );
        assert_eq!(
            (
                hex(&session().public_key()),
                hex(&digest),
                hex(&env.signature)
            ),
            (
                GOLDEN_SESSION_KEY.to_string(),
                GOLDEN_COMMAND_DIGEST.to_string(),
                GOLDEN_COMMAND_SIGNATURE.to_string()
            )
        );
    }

    const GOLDEN_ADDRESS: &str = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
    const GOLDEN_SEPARATOR: &str =
        "b1454b3e05ff5da1fee31a4374c6a1a038feac2900a95178fc0e924c679503fa";
    const GOLDEN_DELEGATION_DIGEST: &str =
        "cdeccda09dad9023a2078a1295574a44e34dc6268b7ffc8e611df86f50204cbf";
    const GOLDEN_DELEGATION_SIGNATURE: &str = "8a2fe23c21ac017eeb0f1ae66a1a885a2d80a5c897277039b5eb2a9b52b728a4554755759a6d24b469c0562c51a5cf03c1613fb415476d4ce2c6f4e693d223ef1c";
    const GOLDEN_SESSION_KEY: &str =
        "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";
    const GOLDEN_COMMAND_DIGEST: &str =
        "eecc0ebde0040a372550dd15e52b07914cf77b2319c5a39ea1de6a042c907781";
    const GOLDEN_COMMAND_SIGNATURE: &str = "ff640b5943531fce4ee473dabeb129951ba40b2434afe78d1f246a483754d3d84e276b88845e2a7cbdd3a3aafe52825f56754ec68820633e6b5ed2996864f406";
}
