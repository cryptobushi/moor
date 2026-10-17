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

//! The subset of RFC 8949 CBOR the block format uses, written and read under the §4.2.1 core
//! deterministic rules: every head in its shortest form and definite lengths only.
//!
//! Only major types 0 (unsigned), 1 (negative), 2 (bytes), 3 (text), 4 (array) and the simple
//! value `null` occur. The block format has no maps, tags or floats. The decoder rejects anything
//! else, including a non-shortest head, so decoding is also a canonical-form check. The same rules
//! as the state encoding (`moor_db::state_root::cbor`, spec `state-root-v0.md` §2); this copy
//! keeps the crate free of the DB.

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_SIMPLE: u8 = 7;

/// The initial byte of `null`.
pub const NULL: u8 = 0xf6;

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
    #[error("text is not UTF-8 at byte {0}")]
    Utf8(usize),
    #[error("integer out of range at byte {0}")]
    Range(usize),
    #[error("{0} trailing bytes")]
    Trailing(usize),
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
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn head(&mut self, major: u8, n: u64) {
        let major = major << 5;
        if n < 24 {
            self.buf.push(major | n as u8);
        } else if let Ok(n) = u8::try_from(n) {
            self.buf.extend_from_slice(&[major | 24, n]);
        } else if let Ok(n) = u16::try_from(n) {
            self.buf.push(major | 25);
            self.buf.extend_from_slice(&n.to_be_bytes());
        } else if let Ok(n) = u32::try_from(n) {
            self.buf.push(major | 26);
            self.buf.extend_from_slice(&n.to_be_bytes());
        } else {
            self.buf.push(major | 27);
            self.buf.extend_from_slice(&n.to_be_bytes());
        }
    }

    pub fn uint(&mut self, n: u64) {
        self.head(MAJOR_UNSIGNED, n);
    }

    pub fn int(&mut self, n: i64) {
        match u64::try_from(n) {
            Ok(n) => self.head(MAJOR_UNSIGNED, n),
            // -1 - n, without overflow for i64::MIN.
            Err(_) => self.head(MAJOR_NEGATIVE, !(n as u64)),
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

    pub fn null(&mut self) {
        self.buf.push(NULL);
    }

    /// Append an item that is already canonical CBOR.
    pub fn raw(&mut self, item: &[u8]) {
        self.buf.extend_from_slice(item);
    }
}

/// Reads canonical CBOR items from a buffer.
#[derive(Clone, Debug)]
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

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
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
            25 => u64::from(u16::from_be_bytes(self.take_array()?)),
            26 => u64::from(u32::from_be_bytes(self.take_array()?)),
            27 => u64::from_be_bytes(self.take_array()?),
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

    fn length(&self, n: u64, at: usize) -> Result<usize, CborError> {
        usize::try_from(n).map_err(|_| CborError::Range(at))
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
        let at = self.pos;
        let n = self.expect(MAJOR_BYTES, "byte string")?;
        let n = self.length(n, at)?;
        self.take(n)
    }

    /// A byte string of exactly `N` bytes.
    pub fn bytes_fixed<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        let at = self.pos;
        let raw = self.bytes()?;
        let mut out = [0u8; N];
        if raw.len() != N {
            return Err(CborError::Unexpected {
                at,
                expected: "byte string of the expected length",
            });
        }
        out.copy_from_slice(raw);
        Ok(out)
    }

    pub fn text(&mut self) -> Result<&'a str, CborError> {
        let at = self.pos;
        let n = self.expect(MAJOR_TEXT, "text string")?;
        let n = self.length(n, at)?;
        let start = self.pos;
        let raw = self.take(n)?;
        std::str::from_utf8(raw).map_err(|_| CborError::Utf8(start))
    }

    pub fn array(&mut self) -> Result<usize, CborError> {
        let at = self.pos;
        let n = self.expect(MAJOR_ARRAY, "array")?;
        // An element is at least one byte, which bounds allocation by the input size.
        let n = self.length(n, at)?;
        if n > self.buf.len() - self.pos {
            return Err(CborError::Truncated(at));
        }
        Ok(n)
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

    /// Consume a `null` if one is next. Returns whether it did.
    pub fn null(&mut self) -> Result<bool, CborError> {
        if self.peek()? == NULL {
            self.pos += 1;
            return Ok(true);
        }
        Ok(false)
    }
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
    fn heads_are_shortest() {
        assert_eq!(enc(|e| e.uint(23)), [0x17]);
        assert_eq!(enc(|e| e.uint(24)), [0x18, 0x18]);
        assert_eq!(enc(|e| e.uint(256)), [0x19, 0x01, 0x00]);
        assert_eq!(enc(|e| e.uint(65_536)), [0x1a, 0, 1, 0, 0]);
        assert_eq!(enc(|e| e.uint(1 << 32)), [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(enc(|e| e.int(-1)), [0x20]);
        assert_eq!(
            enc(|e| e.int(i64::MIN)),
            [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn decoder_rejects_non_shortest_heads() {
        assert_eq!(
            Decoder::new(&[0x18, 0x17]).uint(),
            Err(CborError::NotShortest(0))
        );
    }

    #[test]
    fn decoder_rejects_indefinite_arrays() {
        assert!(matches!(
            Decoder::new(&[0x9f, 0xff]).array(),
            Err(CborError::Unsupported { .. })
        ));
    }

    #[test]
    fn decoder_rejects_array_lengths_beyond_the_input() {
        assert_eq!(
            Decoder::new(&[0x9a, 0xff, 0xff, 0xff, 0xff]).array(),
            Err(CborError::Truncated(0))
        );
    }

    #[test]
    fn integers_round_trip() {
        for n in [0, 1, -1, 23, 24, -24, -25, i64::MAX, i64::MIN, 1 << 40] {
            let bytes = enc(|e| e.int(n));
            let mut d = Decoder::new(&bytes);
            assert_eq!(d.int(), Ok(n));
            assert_eq!(d.finish(), Ok(()));
        }
    }
}
