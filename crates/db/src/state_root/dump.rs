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

//! Dump directories (spec `block-format-v0.md` §14): the canonical state at a height as files a
//! verifier can diff against its own, the format `rw-replayer --state-ref` reads.
//!
//! A dump directory holds `relations.json` (`{height, state_root, relations: [{name, hash,
//! entries}]}`) and one `<relation>.entries` file per relation: one line per entry, `<key hex>
//! <value hex>`, in canonical (key byte) order.

use super::{CanonicalRelation, StateRoot, hex};
use std::{
    fs,
    io::{BufWriter, Write as _},
    path::Path,
};

/// The `.entries` text of a relation: one `<key hex> <value hex>` line per entry.
pub fn write_entries(out: &mut impl std::io::Write, relation: &CanonicalRelation) -> std::io::Result<()> {
    for (k, v) in &relation.entries {
        writeln!(out, "{} {}", hex(k), hex(v))?;
    }
    Ok(())
}

/// The `relations.json` text for `root` after block `height`.
#[must_use]
pub fn manifest_json(height: u64, root: &StateRoot) -> String {
    let relations: Vec<String> = root
        .relations
        .iter()
        .map(|r| {
            format!(
                "{{\"name\":\"{}\",\"hash\":\"{}\",\"entries\":{}}}",
                r.name,
                hex(&r.hash),
                r.entries
            )
        })
        .collect();
    format!(
        "{{\"height\":{height},\"state_root\":\"{}\",\"relations\":[{}]}}\n",
        root.root_hex(),
        relations.join(",")
    )
}

/// Write a dump of `relations` (every relation of the state, in any order) after block `height`
/// into `dir`, creating it.
pub fn write_dump(
    dir: &Path,
    height: u64,
    root: &StateRoot,
    relations: &[CanonicalRelation],
) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    for relation in relations {
        let mut out = BufWriter::new(fs::File::create(
            dir.join(format!("{}.entries", relation.name)),
        )?);
        write_entries(&mut out, relation)?;
        out.flush()?;
    }
    fs::write(dir.join("relations.json"), manifest_json(height, root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_root::RelationDigest;

    #[test]
    fn a_dump_has_one_line_per_entry_and_a_manifest_naming_the_root() {
        let relation = CanonicalRelation {
            name: "object_flags",
            entries: vec![(vec![1], vec![0x18, 7]), (vec![2], vec![3])],
        };
        let root = StateRoot::from_relations(vec![RelationDigest {
            name: "object_flags",
            hash: relation.hash(),
            entries: 2,
        }]);
        let dir = tempfile::tempdir().unwrap();
        write_dump(dir.path(), 9, &root, &[relation]).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("object_flags.entries")).unwrap(),
            "01 1807\n02 03\n"
        );
        let manifest = fs::read_to_string(dir.path().join("relations.json")).unwrap();
        assert!(manifest.starts_with("{\"height\":9,\"state_root\":\""));
        assert!(manifest.contains(&root.root_hex()));
    }
}
