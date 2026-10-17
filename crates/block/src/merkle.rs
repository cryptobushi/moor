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

//! RFC 6962 (§2.1) binary Merkle trees over SHA-256, as used for `commands_root` and
//! `events_root`.
//!
//! - leaf: `H(0x00 || entry)`, where `entry` is the canonical CBOR encoding of one batch entry;
//! - node: `H(0x01 || left || right)`;
//! - empty list: `H("")` ([`EMPTY_ROOT`]);
//! - a list of `n > 1` leaves splits at `k`, the largest power of two smaller than `n`.
//!
//! Inclusion proofs are RFC 6962 audit paths (`PATH(m, D[n])`), verified with the RFC 9162
//! §2.1.3.2 algorithm, so they interoperate with Certificate Transparency tooling.

use crate::hash::{EMPTY_ROOT, Hash, sha256};

/// The leaf hash of one encoded entry.
#[must_use]
pub fn leaf_hash(entry: &[u8]) -> Hash {
    sha256(&[&[0x00], entry])
}

/// The hash of an interior node.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256(&[&[0x01], left, right])
}

/// The root over encoded entries, in order.
#[must_use]
pub fn root<T: AsRef<[u8]>>(entries: &[T]) -> Hash {
    let leaves: Vec<Hash> = entries.iter().map(|e| leaf_hash(e.as_ref())).collect();
    root_of_leaves(&leaves)
}

/// The root over already-computed leaf hashes.
#[must_use]
pub fn root_of_leaves(leaves: &[Hash]) -> Hash {
    match leaves {
        [] => EMPTY_ROOT,
        [leaf] => *leaf,
        _ => {
            let k = split(leaves.len());
            node_hash(&root_of_leaves(&leaves[..k]), &root_of_leaves(&leaves[k..]))
        }
    }
}

/// The largest power of two smaller than `n` (`n >= 2`).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// An inclusion proof for the entry at `index` in a list of `size` entries: the RFC 6962 audit
/// path, bottom-up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub index: u64,
    pub size: u64,
    pub path: Vec<Hash>,
}

impl InclusionProof {
    /// Proof for entry `index` of `entries`. `None` if `index` is out of range.
    #[must_use]
    pub fn generate<T: AsRef<[u8]>>(entries: &[T], index: usize) -> Option<Self> {
        let leaves: Vec<Hash> = entries.iter().map(|e| leaf_hash(e.as_ref())).collect();
        Self::from_leaves(&leaves, index)
    }

    /// Proof for leaf `index` of `leaves`. `None` if `index` is out of range.
    #[must_use]
    pub fn from_leaves(leaves: &[Hash], index: usize) -> Option<Self> {
        if index >= leaves.len() {
            return None;
        }
        let mut path = Vec::new();
        audit_path(index, leaves, &mut path);
        Some(Self {
            index: index as u64,
            size: leaves.len() as u64,
            path,
        })
    }

    /// The root this proof and `entry` (the encoded entry, not its leaf hash) imply, or `None` if
    /// the proof is malformed for its `index` and `size`.
    #[must_use]
    pub fn implied_root(&self, entry: &[u8]) -> Option<Hash> {
        if self.index >= self.size {
            return None;
        }
        let mut f = self.index;
        let mut s = self.size - 1;
        let mut r = leaf_hash(entry);
        for p in &self.path {
            if s == 0 {
                return None;
            }
            if f & 1 == 1 || f == s {
                r = node_hash(p, &r);
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            } else {
                r = node_hash(&r, p);
            }
            f >>= 1;
            s >>= 1;
        }
        (s == 0).then_some(r)
    }

    /// Whether `entry` is at `index` in a list of `size` entries with root `root`.
    #[must_use]
    pub fn verify(&self, root: &Hash, entry: &[u8]) -> bool {
        self.implied_root(entry).is_some_and(|r| &r == root)
    }
}

/// `PATH(m, D[n])`, RFC 6962 §2.1.1, appended bottom-up.
fn audit_path(m: usize, leaves: &[Hash], out: &mut Vec<Hash>) {
    if leaves.len() <= 1 {
        return;
    }
    let k = split(leaves.len());
    if m < k {
        audit_path(m, &leaves[..k], out);
        out.push(root_of_leaves(&leaves[k..]));
    } else {
        audit_path(m - k, &leaves[k..], out);
        out.push(root_of_leaves(&leaves[..k]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{hex, unhex};

    /// The Certificate Transparency reference inputs (RFC 6962 test data, also used by
    /// `transparency-dev/merkle`).
    fn ct_leaves() -> Vec<Vec<u8>> {
        [
            "",
            "00",
            "10",
            "2021",
            "3031",
            "40414243",
            "5051525354555657",
            "606162636465666768696a6b6c6d6e6f",
        ]
        .iter()
        .map(|h| unhex(h).unwrap())
        .collect()
    }

    #[test]
    fn root_matches_the_certificate_transparency_reference_roots() {
        let leaves = ct_leaves();
        let expected = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        for (n, want) in expected.iter().enumerate() {
            assert_eq!(hex(&root(&leaves[..=n])), *want, "size {}", n + 1);
        }
    }

    #[test]
    fn empty_root_is_hash_of_nothing() {
        assert_eq!(root::<&[u8]>(&[]), EMPTY_ROOT);
    }

    #[test]
    fn every_proof_verifies_for_every_size_up_to_33() {
        for size in 1..=33usize {
            let entries: Vec<Vec<u8>> = (0..size).map(|i| vec![i as u8, 0xaa]).collect();
            let r = root(&entries);
            for (i, entry) in entries.iter().enumerate() {
                let proof = InclusionProof::generate(&entries, i).unwrap();
                assert!(proof.verify(&r, entry), "size {size} index {i}");
            }
        }
    }

    #[test]
    fn a_proof_does_not_verify_another_entry() {
        let entries: Vec<Vec<u8>> = (0..7u8).map(|i| vec![i]).collect();
        let r = root(&entries);
        let proof = InclusionProof::generate(&entries, 3).unwrap();
        assert!(!proof.verify(&r, &[4]));
    }

    #[test]
    fn a_proof_with_a_wrong_index_fails() {
        let entries: Vec<Vec<u8>> = (0..7u8).map(|i| vec![i]).collect();
        let r = root(&entries);
        let mut proof = InclusionProof::generate(&entries, 3).unwrap();
        proof.index = 2;
        assert!(!proof.verify(&r, &[3]));
    }

    #[test]
    fn a_truncated_or_extended_proof_fails() {
        let entries: Vec<Vec<u8>> = (0..7u8).map(|i| vec![i]).collect();
        let r = root(&entries);
        let proof = InclusionProof::generate(&entries, 5).unwrap();
        let mut short = proof.clone();
        short.path.pop();
        let mut long = proof;
        long.path.push([0; 32]);
        assert_eq!(
            (short.verify(&r, &[5]), long.verify(&r, &[5])),
            (false, false)
        );
    }

    #[test]
    fn out_of_range_index_has_no_proof() {
        assert_eq!(InclusionProof::generate(&[[1u8]], 1), None);
    }
}
