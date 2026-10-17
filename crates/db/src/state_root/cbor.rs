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

//! The subset of RFC 8949 CBOR the state encoding uses, written and read under the §4.2.1 core
//! deterministic rules: every head in its shortest form, definite lengths only, and map keys in
//! bytewise lexicographic order of their encodings.
//!
//! Only major types 0 (unsigned), 1 (negative), 2 (bytes), 3 (text), 4 (array), 5 (map) and the
//! simple values `false`, `true` and `null` occur. There are no tags and no floats: a MOO float is
//! carried as the unsigned integer of its IEEE 754 bits, so float canonicalisation never arises.
//! The decoder rejects anything else, including a non-shortest head, so decoding is also a
//! canonical-form check.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_SIMPLE: u8 = 7;

const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;

/// Why a byte string is not a canonical item of the subset.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CborError {
    #[error("unexpected end of input at byte {0}")]
    Truncated(usize),
    #[error("non-shortest head at byte {0}")]
    NotShortest(usize),
    #[error("unsupported initial byte {byte:#04x} at byte {at}")]
    Unsupported { at: usize, byte: u8 },
    #[error("expected {expected} at byte {at}")]
    Unexpected { at: usize, expected: &'static str },
    #[error("map keys out of canonical order at byte {0}")]
    KeyOrder(usize),
    #[error("text is not UTF-8 at byte {0}")]
    Utf8(usize),
    #[error("integer out of range at byte {0}")]
    Range(usize),
    #[error("{0} trailing bytes")]
    Trailing(usize),
    #[error("invalid value: {0}")]
    Invalid(String),
}

/// Appends canonical CBOR items to a buffer.
#[derive(Default, Debug)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    fn head(&mut self, major: u8, n: u64) {
        let major = major << 5;
        if n < 24 {
            self.buf.push(major | n as u8);
        } else if n <= u64::from(u8::MAX) {
            self.buf.extend_from_slice(&[major | 24, n as u8]);
        } else if n <= u64::from(u16::MAX) {
            self.buf.push(major | 25);
            self.buf.extend_from_slice(&(n as u16).to_be_bytes());
        } else if n <= u64::from(u32::MAX) {
            self.buf.push(major | 26);
            self.buf.extend_from_slice(&(n as u32).to_be_bytes());
        } else {
            self.buf.push(major | 27);
            self.buf.extend_from_slice(&n.to_be_bytes());
        }
    }

    pub fn uint(&mut self, n: u64) {
        self.head(MAJOR_UNSIGNED, n);
    }

    pub fn int(&mut self, n: i64) {
        if n >= 0 {
            self.head(MAJOR_UNSIGNED, n as u64);
        } else {
            // -1 - n, computed without overflow for i64::MIN.
            self.head(MAJOR_NEGATIVE, !(n as u64));
        }
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.head(MAJOR_BYTES, b.len() as u64);
        self.buf.extend_from_slice(b);
    }

    pub fn text(&mut self, s: &str) {
        self.head(MAJOR_TEXT, s.len() as u64);
        self.buf.extend_from_slice(s.as_bytes());
    }

    pub fn array(&mut self, len: usize) {
        self.head(MAJOR_ARRAY, len as u64);
    }

    pub fn map(&mut self, len: usize) {
        self.head(MAJOR_MAP, len as u64);
    }

    pub fn bool(&mut self, b: bool) {
        self.buf
            .push((MAJOR_SIMPLE << 5) | if b { SIMPLE_TRUE } else { SIMPLE_FALSE });
    }

    pub fn null(&mut self) {
        self.buf.push((MAJOR_SIMPLE << 5) | SIMPLE_NULL);
    }

    /// Append an item that is already canonical CBOR.
    pub fn raw(&mut self, item: &[u8]) {
        self.buf.extend_from_slice(item);
    }

    /// Write a map from already-encoded `(key, value)` pairs, sorting them into canonical key order.
    /// Duplicate keys are an error.
    pub fn map_of_encoded(&mut self, mut pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), CborError> {
        pairs.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        if pairs.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(CborError::Invalid("duplicate map key".into()));
        }
        self.map(pairs.len());
        for (k, v) in pairs {
            self.raw(&k);
            self.raw(&v);
        }
        Ok(())
    }
}

/// Reads canonical CBOR items from a buffer.
#[derive(Clone)]
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Fail unless every byte was consumed.
    pub fn finish(&self) -> Result<(), CborError> {
        match self.buf.len() - self.pos {
            0 => Ok(()),
            n => Err(CborError::Trailing(n)),
        }
    }

    /// The major type of the next item, without consuming it.
    pub fn peek_major(&self) -> Result<u8, CborError> {
        Ok(self.peek()? >> 5)
    }

    fn peek(&self) -> Result<u8, CborError> {
        self.buf
            .get(self.pos)
            .copied()
            .ok_or(CborError::Truncated(self.pos))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.buf.len())
            .ok_or(CborError::Truncated(self.pos))?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// The next head: `(major, argument)`. Rejects indefinite lengths and non-shortest forms.
    fn head(&mut self) -> Result<(u8, u64), CborError> {
        let at = self.pos;
        let initial = self.take(1)?[0];
        let major = initial >> 5;
        let info = initial & 0x1f;
        if major == MAJOR_SIMPLE {
            return Ok((major, u64::from(info)));
        }
        let n = match info {
            0..=23 => return Ok((major, u64::from(info))),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().expect("2 bytes"),
            )),
            26 => u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().expect("4 bytes"),
            )),
            27 => u64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")),
            _ => return Err(CborError::Unsupported { at, byte: initial }),
        };
        let shortest = match info {
            24 => n >= 24,
            25 => n > u64::from(u8::MAX),
            26 => n > u64::from(u16::MAX),
            _ => n > u64::from(u32::MAX),
        };
        if !shortest {
            return Err(CborError::NotShortest(at));
        }
        Ok((major, n))
    }

    fn expect(&mut self, major: u8, expected: &'static str) -> Result<u64, CborError> {
        let at = self.pos;
        let (m, n) = self.head()?;
        if m != major {
            return Err(CborError::Unexpected { at, expected });
        }
        Ok(n)
    }

    pub fn uint(&mut self) -> Result<u64, CborError> {
        self.expect(MAJOR_UNSIGNED, "unsigned integer")
    }

    pub fn int(&mut self) -> Result<i64, CborError> {
        let at = self.pos;
        match self.head()? {
            (MAJOR_UNSIGNED, n) => i64::try_from(n).map_err(|_| CborError::Range(at)),
            (MAJOR_NEGATIVE, n) => i64::try_from(n)
                .map(|n| -1 - n)
                .map_err(|_| CborError::Range(at)),
            _ => Err(CborError::Unexpected {
                at,
                expected: "integer",
            }),
        }
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], CborError> {
        let n = self.expect(MAJOR_BYTES, "byte string")?;
        self.take(usize::try_from(n).map_err(|_| CborError::Range(self.pos))?)
    }

    pub fn text(&mut self) -> Result<&'a str, CborError> {
        let n = self.expect(MAJOR_TEXT, "text string")?;
        let at = self.pos;
        let raw = self.take(usize::try_from(n).map_err(|_| CborError::Range(at))?)?;
        std::str::from_utf8(raw).map_err(|_| CborError::Utf8(at))
    }

    pub fn array(&mut self) -> Result<usize, CborError> {
        let n = self.expect(MAJOR_ARRAY, "array")?;
        usize::try_from(n).map_err(|_| CborError::Range(self.pos))
    }

    /// An array that must have exactly `len` elements.
    pub fn array_of(&mut self, len: usize) -> Result<(), CborError> {
        let at = self.pos;
        if self.array()? != len {
            return Err(CborError::Unexpected {
                at,
                expected: "array of the expected length",
            });
        }
        Ok(())
    }

    pub fn map(&mut self) -> Result<usize, CborError> {
        let n = self.expect(MAJOR_MAP, "map")?;
        usize::try_from(n).map_err(|_| CborError::Range(self.pos))
    }

    pub fn bool(&mut self) -> Result<bool, CborError> {
        let at = self.pos;
        match self.head()? {
            (MAJOR_SIMPLE, n) if n == u64::from(SIMPLE_FALSE) => Ok(false),
            (MAJOR_SIMPLE, n) if n == u64::from(SIMPLE_TRUE) => Ok(true),
            _ => Err(CborError::Unexpected {
                at,
                expected: "bool",
            }),
        }
    }

    /// Consume a `null` if one is next. Returns whether it did.
    pub fn null(&mut self) -> Result<bool, CborError> {
        if self.peek()? == (MAJOR_SIMPLE << 5) | SIMPLE_NULL {
            self.pos += 1;
            return Ok(true);
        }
        Ok(false)
    }

    /// The raw bytes of the next complete item, after checking it is canonical.
    pub fn item(&mut self) -> Result<&'a [u8], CborError> {
        let start = self.pos;
        self.skip()?;
        Ok(&self.buf[start..self.pos])
    }

    fn skip(&mut self) -> Result<(), CborError> {
        let at = self.pos;
        let (major, n) = self.head()?;
        match major {
            MAJOR_UNSIGNED | MAJOR_NEGATIVE => Ok(()),
            MAJOR_BYTES => self
                .take(usize::try_from(n).map_err(|_| CborError::Range(at))?)
                .map(|_| ()),
            MAJOR_TEXT => {
                let raw = self.take(usize::try_from(n).map_err(|_| CborError::Range(at))?)?;
                std::str::from_utf8(raw)
                    .map(|_| ())
                    .map_err(|_| CborError::Utf8(at))
            }
            MAJOR_ARRAY => (0..n).try_for_each(|_| self.skip()),
            MAJOR_MAP => {
                let mut previous: Option<&[u8]> = None;
                for _ in 0..n {
                    let key_at = self.pos;
                    let key = self.item()?;
                    if previous.is_some_and(|p| p >= key) {
                        return Err(CborError::KeyOrder(key_at));
                    }
                    previous = Some(key);
                    self.skip()?;
                }
                Ok(())
            }
            MAJOR_SIMPLE
                if [SIMPLE_FALSE, SIMPLE_TRUE, SIMPLE_NULL]
                    .iter()
                    .any(|s| u64::from(*s) == n) =>
            {
                Ok(())
            }
            _ => Err(CborError::Unsupported {
                at,
                byte: self.buf[at],
            }),
        }
    }
}

/// Byte strings longer than this are shown by length and digest in abbreviated diagnostics.
pub const ABBREVIATE_BYTES_OVER: usize = 32;

/// RFC 8949 §8 diagnostic notation for one canonical item. With `abbreviate`, a byte string longer
/// than [`ABBREVIATE_BYTES_OVER`] is shown as `<N bytes sha256:...>` (16 hex digits of the digest),
/// which is not diagnostic notation but keeps program bodies readable in dumps.
pub fn diagnostic(item: &[u8], abbreviate: bool) -> Result<String, CborError> {
    let mut out = String::new();
    let mut d = Decoder::new(item);
    diag_item(&mut d, abbreviate, &mut out)?;
    d.finish()?;
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn diag_item(d: &mut Decoder<'_>, abbreviate: bool, out: &mut String) -> Result<(), CborError> {
    let at = d.pos;
    let initial = d.peek()?;
    match initial >> 5 {
        MAJOR_UNSIGNED => {
            let _ = write!(out, "{}", d.uint()?);
        }
        MAJOR_NEGATIVE => {
            let (_, n) = d.head()?;
            let _ = write!(out, "{}", -1 - i128::from(n));
        }
        MAJOR_BYTES => {
            let b = d.bytes()?;
            if abbreviate && b.len() > ABBREVIATE_BYTES_OVER {
                let digest = Sha256::digest(b);
                let _ = write!(out, "<{} bytes sha256:{}>", b.len(), &hex(&digest)[..16]);
            } else {
                let _ = write!(out, "h'{}'", hex(b));
            }
        }
        MAJOR_TEXT => {
            let t = d.text()?;
            out.push('"');
            for c in t.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        MAJOR_ARRAY => {
            let n = d.array()?;
            out.push('[');
            for i in 0..n {
                if i > 0 {
                    out.push_str(", ");
                }
                diag_item(d, abbreviate, out)?;
            }
            out.push(']');
        }
        MAJOR_MAP => {
            let n = d.map()?;
            out.push('{');
            for i in 0..n {
                if i > 0 {
                    out.push_str(", ");
                }
                diag_item(d, abbreviate, out)?;
                out.push_str(": ");
                diag_item(d, abbreviate, out)?;
            }
            out.push('}');
        }
        MAJOR_SIMPLE => {
            if d.null()? {
                out.push_str("null");
            } else {
                let _ = write!(out, "{}", d.bool()?);
            }
        }
        _ => {
            return Err(CborError::Unsupported { at, byte: initial });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(f: impl FnOnce(&mut Encoder)) -> Vec<u8> {
        let mut e = Encoder::new();
        f(&mut e);
        e.into_bytes()
    }

    #[test]
    fn integers_use_the_shortest_head() {
        // RFC 8949 Appendix A vectors.
        assert_eq!(enc(|e| e.uint(0)), [0x00]);
        assert_eq!(enc(|e| e.uint(23)), [0x17]);
        assert_eq!(enc(|e| e.uint(24)), [0x18, 0x18]);
        assert_eq!(enc(|e| e.uint(1000)), [0x19, 0x03, 0xe8]);
        assert_eq!(enc(|e| e.uint(1_000_000)), [0x1a, 0x00, 0x0f, 0x42, 0x40]);
        assert_eq!(
            enc(|e| e.uint(u64::MAX)),
            [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(enc(|e| e.int(-1)), [0x20]);
        assert_eq!(enc(|e| e.int(-1000)), [0x39, 0x03, 0xe7]);
        assert_eq!(
            enc(|e| e.int(i64::MIN)),
            [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(enc(|e| e.text("IETF")), [0x64, 0x49, 0x45, 0x54, 0x46]);
    }

    #[test]
    fn decoder_round_trips_extreme_integers() {
        for n in [
            0,
            23,
            24,
            255,
            256,
            65_535,
            65_536,
            i64::MAX,
            -1,
            -24,
            -25,
            i64::MIN,
        ] {
            let bytes = enc(|e| e.int(n));
            let mut d = Decoder::new(&bytes);
            assert_eq!(d.int().unwrap(), n);
            d.finish().unwrap();
        }
    }

    #[test]
    fn decoder_rejects_a_non_shortest_head() {
        assert_eq!(
            Decoder::new(&[0x18, 0x05]).uint(),
            Err(CborError::NotShortest(0))
        );
    }

    #[test]
    fn decoder_rejects_unsorted_map_keys() {
        let bytes = [0xa2, 0x02, 0x00, 0x01, 0x00];
        assert_eq!(Decoder::new(&bytes).item(), Err(CborError::KeyOrder(3)));
    }

    #[test]
    fn map_of_encoded_sorts_keys_bytewise() {
        let pairs = vec![
            (enc(|e| e.text("b")), enc(|e| e.uint(2))),
            (enc(|e| e.uint(100)), enc(|e| e.uint(1))),
            (enc(|e| e.text("a")), enc(|e| e.uint(3))),
        ];
        let bytes = enc(|e| e.map_of_encoded(pairs).unwrap());
        assert_eq!(
            diagnostic(&bytes, false).unwrap(),
            "{100: 1, \"a\": 3, \"b\": 2}"
        );
    }

    #[test]
    fn diagnostic_abbreviates_long_byte_strings() {
        let bytes = enc(|e| e.bytes(&[7; 40]));
        assert!(
            diagnostic(&bytes, true)
                .unwrap()
                .starts_with("<40 bytes sha256:")
        );
        assert!(diagnostic(&bytes, false).unwrap().starts_with("h'0707"));
    }
}
