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

//! Record framing for the journal and the block store.
//!
//! ```text
//! record = len_be32 || payload || check
//! check  = SHA-256("rw/v1/record" || len_be32 || payload)[0..8]
//! ```
//!
//! Records are only appended. A crash can leave the last record incomplete (shorter than its
//! length says), or, after a power loss, with garbage or zeros where its bytes should be. Both
//! are a **torn tail** and are cut off on open. A record whose check fails while further
//! non-zero bytes follow is **corruption**: something other than an append damaged the file.

use std::ops::Range;

use crate::hash::sha256;

const DOMAIN: &[u8] = b"rw/v1/record";
/// Length prefix and check bytes around each payload.
pub const OVERHEAD: usize = 4 + 8;

fn check(len: &[u8; 4], payload: &[u8]) -> [u8; 8] {
    let digest = sha256(&[DOMAIN, len, payload]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Frame `payload` as one record.
#[must_use]
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len())
        .expect("record payloads are far below 4 GiB")
        .to_be_bytes();
    let mut out = Vec::with_capacity(payload.len() + OVERHEAD);
    out.extend_from_slice(&len);
    out.extend_from_slice(payload);
    out.extend_from_slice(&check(&len, payload));
    out
}

/// The records found in a file body.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// Payload byte ranges, in order.
    pub payloads: Vec<Range<usize>>,
    /// Where the valid records end; bytes after this are a torn tail.
    pub valid_len: usize,
}

/// Read the records of `bytes` from `start`. `Err` names the offset of a damaged record that is
/// not the tail.
pub fn scan(bytes: &[u8], start: usize) -> Result<Scan, String> {
    let mut scan = Scan {
        payloads: Vec::new(),
        valid_len: start,
    };
    let mut at = start;
    while at < bytes.len() {
        let rest = &bytes[at..];
        if rest.len() < OVERHEAD {
            break;
        }
        let len: [u8; 4] = rest[..4].try_into().unwrap_or([0; 4]);
        let n = u32::from_be_bytes(len) as usize;
        let Some(end) = n.checked_add(OVERHEAD).filter(|end| *end <= rest.len()) else {
            // Shorter than its length: an append cut short.
            break;
        };
        let payload = &rest[4..4 + n];
        if rest[4 + n..end] != check(&len, payload) {
            let after = &rest[end..];
            if after.iter().all(|b| *b == 0) || rest.iter().all(|b| *b == 0) {
                break;
            }
            return Err(format!("record at byte {at} fails its check"));
        }
        scan.payloads.push(at + 4..at + 4 + n);
        at += end;
        scan.valid_len = at;
    }
    Ok(scan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(payloads: &[&[u8]]) -> Vec<u8> {
        payloads.iter().flat_map(|p| frame(p)).collect()
    }

    #[test]
    fn records_round_trip() {
        let bytes = file(&[b"one", b"", b"three"]);
        let scan = scan(&bytes, 0).unwrap();
        let got: Vec<&[u8]> = scan.payloads.iter().map(|r| &bytes[r.clone()]).collect();
        assert_eq!(got, vec![&b"one"[..], b"", b"three"]);
        assert_eq!(scan.valid_len, bytes.len());
    }

    #[test]
    fn a_cut_short_last_record_is_a_torn_tail() {
        let mut bytes = file(&[b"one", b"two"]);
        let whole = bytes.len();
        bytes.truncate(whole - 3);
        let scan = scan(&bytes, 0).unwrap();
        assert_eq!(
            (scan.payloads.len(), scan.valid_len),
            (1, frame(b"one").len())
        );
    }

    #[test]
    fn a_zeroed_last_record_is_a_torn_tail() {
        let mut bytes = file(&[b"one"]);
        let keep = bytes.len();
        bytes.extend_from_slice(&[0u8; 40]);
        let scan = scan(&bytes, 0).unwrap();
        assert_eq!((scan.payloads.len(), scan.valid_len), (1, keep));
    }

    #[test]
    fn a_damaged_last_record_is_a_torn_tail() {
        let mut bytes = file(&[b"one", b"two"]);
        let last = bytes.len() - 9;
        bytes[last] ^= 1;
        assert_eq!(scan(&bytes, 0).unwrap().payloads.len(), 1);
    }

    #[test]
    fn a_damaged_middle_record_is_corruption() {
        let mut bytes = file(&[b"one", b"two", b"three"]);
        bytes[5] ^= 1;
        assert!(scan(&bytes, 0).is_err());
    }
}
