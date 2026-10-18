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

//! The sequencer's local block store (ADR 0006 decision 4, "Seal" steps 1 and 3).
//!
//! Directory layout: `blocks.rwb` and `LOCK` (exclusive lock while open). `blocks.rwb` is the
//! 16-byte magic `rw/v1/blocks\0\0\0\0` followed by framed records ([`super::record`]):
//!
//! ```text
//! chain     = [0, 1, genesis_root(32), sequencer(20)]          ; first record, once
//! unsigned  = [1, header, command_batch, event_batch]          ; header: the 8-field unsigned header
//! signature = [2, height, sequencer_sig(65)]
//! ```
//!
//! `unsigned` records are fsynced before the signing guard is written; `signature` records are
//! not fsynced (signing is deterministic, so a lost signature is re-made byte for byte under the
//! guard's identical-hash rule). Blocks are consecutive from height 1; block `h + 1` is written
//! only after block `h` is signed, so at most the last block is unsigned. On open the store checks
//! the chain linkage, both batch roots of every block and the last signature.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{DurableError, lock_exclusive, record, sync_dir, timed_sync};
use crate::cbor::{Decoder, Encoder};
use crate::command::CommandBatch;
use crate::event::EventBatch;
use crate::hash::Hash;
use crate::header::{BlockHeader, SignedHeader};
use crate::segment::{ChainTip, SealedBlock};
use crate::sign::{Address, ChainParams, HeaderSignature};

const MAGIC: &[u8; 16] = b"rw/v1/blocks\0\0\0\0";
const FILE: &str = "blocks.rwb";
const CHAIN: u64 = 0;
const UNSIGNED: u64 = 1;
const SIGNATURE: u64 = 2;
const STORE_VERSION: u64 = 1;

/// The chain a store belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreChain {
    pub genesis_root: Hash,
    pub sequencer: Address,
}

impl StoreChain {
    #[must_use]
    pub fn params(&self) -> ChainParams {
        ChainParams {
            genesis_root: self.genesis_root,
            sequencer: self.sequencer,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    header: BlockHeader,
    sig: Option<HeaderSignature>,
    /// Payload range of the `unsigned` record.
    offset: u64,
    len: usize,
}

/// A stored block: its header, batches and signature if it has one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBlock {
    pub header: BlockHeader,
    pub commands: CommandBatch,
    pub events: EventBatch,
    pub sig: Option<HeaderSignature>,
}

impl StoredBlock {
    /// The sealed block, if signed.
    #[must_use]
    pub fn sealed(self) -> Option<SealedBlock> {
        let sig = self.sig?;
        Some(SealedBlock {
            header: SignedHeader {
                header: self.header,
                sequencer_sig: sig,
            },
            commands: self.commands,
            events: self.events,
        })
    }
}

/// The local block store. See the module documentation for the format.
#[derive(Debug)]
pub struct BlockStore {
    path: PathBuf,
    file: File,
    len: u64,
    chain: Option<StoreChain>,
    blocks: Vec<Entry>,
    _lock: File,
}

fn encode_unsigned(header: &BlockHeader, commands: &CommandBatch, events: &EventBatch) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(4);
    e.uint(UNSIGNED);
    e.raw(&header.encode());
    commands.encode_into(&mut e);
    events.encode_into(&mut e);
    e.into_bytes()
}

fn decode_unsigned(
    payload: &[u8],
) -> Result<(BlockHeader, CommandBatch, EventBatch), crate::FormatError> {
    let mut d = Decoder::new(payload);
    d.array_of(4)?;
    d.uint()?;
    let header = BlockHeader::decode_from(&mut d)?;
    let commands = CommandBatch::decode_from(&mut d)?;
    let events = EventBatch::decode_from(&mut d)?;
    d.finish()?;
    Ok((header, commands, events))
}

fn check_roots(
    header: &BlockHeader,
    commands: &CommandBatch,
    events: &EventBatch,
) -> Result<(), crate::FormatError> {
    if header.commands_root != commands.root() {
        return Err(crate::FormatError::CommandsRoot {
            height: header.height,
        });
    }
    if header.events_root != events.root() {
        return Err(crate::FormatError::EventsRoot {
            height: header.height,
        });
    }
    events.check_against(commands.len())
}

impl BlockStore {
    /// Open (creating if needed) the store in `dir`, cutting off a torn tail and checking every
    /// block's linkage and roots.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, DurableError> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        let lock_path = dir.join("LOCK");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;
        lock_exclusive(&lock, &lock_path)?;
        let path = dir.join(FILE);
        let created = !path.exists();
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .append(true)
            .open(&path)?;
        if created {
            sync_dir(dir)?;
        }
        let what = path.display().to_string();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if bytes.len() < MAGIC.len() {
            if !MAGIC.starts_with(&bytes) {
                return Err(DurableError::corrupt(what, "no magic"));
            }
            file.set_len(0)?;
            file.write_all(MAGIC)?;
            file.sync_all()?;
            bytes = MAGIC.to_vec();
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(DurableError::corrupt(what, "no magic"));
        }
        let scan = record::scan(&bytes, MAGIC.len())
            .map_err(|reason| DurableError::corrupt(what.clone(), reason))?;
        if scan.valid_len != bytes.len() {
            file.set_len(scan.valid_len as u64)?;
            file.sync_all()?;
        }
        let mut store = Self {
            path,
            file,
            len: scan.valid_len as u64,
            chain: None,
            blocks: Vec::new(),
            _lock: lock,
        };
        for range in &scan.payloads {
            store
                .load_record(&bytes[range.clone()], range.start as u64)
                .map_err(|reason| {
                    DurableError::corrupt(
                        what.clone(),
                        format!("record at {}: {reason}", range.start),
                    )
                })?;
        }
        if let (Some(chain), Some(last)) = (store.chain, store.blocks.last())
            && let Some(sig) = last.sig
        {
            sig.verify(&chain.params(), &last.header.hash())
                .map_err(|e| DurableError::corrupt(what, format!("last signature: {e}")))?;
        }
        Ok(store)
    }

    fn load_record(&mut self, payload: &[u8], offset: u64) -> Result<(), String> {
        let mut d = Decoder::new(payload);
        let n = d.array().map_err(|e| e.to_string())?;
        let kind = d.uint().map_err(|e| e.to_string())?;
        match (kind, n) {
            (CHAIN, 4) => {
                if self.chain.is_some() || !self.blocks.is_empty() {
                    return Err("chain record not first".into());
                }
                let version = d.uint().map_err(|e| e.to_string())?;
                if version != STORE_VERSION {
                    return Err(format!("store version {version}"));
                }
                let genesis_root = d.bytes_fixed().map_err(|e| e.to_string())?;
                let sequencer = Address(d.bytes_fixed().map_err(|e| e.to_string())?);
                d.finish().map_err(|e| e.to_string())?;
                self.chain = Some(StoreChain {
                    genesis_root,
                    sequencer,
                });
            }
            (UNSIGNED, 4) => {
                let chain = self.chain.ok_or("block before the chain record")?;
                let (header, commands, events) =
                    decode_unsigned(payload).map_err(|e| e.to_string())?;
                if self.blocks.last().is_some_and(|b| b.sig.is_none()) {
                    return Err(format!("block {} follows an unsigned block", header.height));
                }
                self.tip_of(&chain)
                    .check_next(&header)
                    .map_err(|e| e.to_string())?;
                check_roots(&header, &commands, &events).map_err(|e| e.to_string())?;
                self.blocks.push(Entry {
                    header,
                    sig: None,
                    offset,
                    len: payload.len(),
                });
            }
            (SIGNATURE, 3) => {
                let height = d.uint().map_err(|e| e.to_string())?;
                let sig = HeaderSignature::from_bytes(d.bytes_fixed().map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
                d.finish().map_err(|e| e.to_string())?;
                let last = self
                    .blocks
                    .last_mut()
                    .filter(|b| b.header.height == height && b.sig.is_none())
                    .ok_or_else(|| format!("signature for {height} without its unsigned block"))?;
                last.sig = Some(sig);
            }
            (kind, n) => return Err(format!("unknown record type {kind} of {n} fields")),
        }
        Ok(())
    }

    /// The store's file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The chain the store belongs to; `None` for a new store.
    #[must_use]
    pub fn chain(&self) -> Option<StoreChain> {
        self.chain
    }

    /// Record the chain (genesis root and sequencer) of a new store, fsynced. Accepted again
    /// only with the same values.
    pub fn init_chain(&mut self, chain: StoreChain) -> Result<(), DurableError> {
        match self.chain {
            Some(existing) if existing == chain => Ok(()),
            Some(_) => Err(DurableError::ChainMismatch {
                what: self.path.display().to_string(),
            }),
            None => {
                let mut e = Encoder::new();
                e.array(4);
                e.uint(CHAIN);
                e.uint(STORE_VERSION);
                e.bytes(&chain.genesis_root);
                e.bytes(&chain.sequencer.0);
                self.append(&record::frame(&e.into_bytes()))?;
                timed_sync(&self.file)?;
                self.chain = Some(chain);
                Ok(())
            }
        }
    }

    fn require_chain(&self) -> Result<StoreChain, DurableError> {
        self.chain.ok_or_else(|| {
            DurableError::corrupt(self.path.display().to_string(), "no chain record")
        })
    }

    fn tip_of(&self, chain: &StoreChain) -> ChainTip {
        self.blocks
            .iter()
            .rev()
            .find(|b| b.sig.is_some())
            .map_or_else(
                || ChainTip::genesis(&chain.genesis_root),
                |b| ChainTip::of(&b.header),
            )
    }

    /// The highest signed block's tip, or the genesis tip. `None` for a new store.
    #[must_use]
    pub fn tip(&self) -> Option<ChainTip> {
        self.chain.map(|chain| self.tip_of(&chain))
    }

    /// The highest signed height (0 when none).
    #[must_use]
    pub fn sealed_height(&self) -> u64 {
        self.blocks
            .iter()
            .rev()
            .find(|b| b.sig.is_some())
            .map_or(0, |b| b.header.height)
    }

    /// The last block, if it is stored but not yet signed.
    #[must_use]
    pub fn unsigned(&self) -> Option<&BlockHeader> {
        self.blocks
            .last()
            .filter(|b| b.sig.is_none())
            .map(|b| &b.header)
    }

    /// The header at `height`, signed or not.
    #[must_use]
    pub fn header(&self, height: u64) -> Option<&BlockHeader> {
        let i = usize::try_from(height.checked_sub(1)?).ok()?;
        self.blocks.get(i).map(|b| &b.header)
    }

    /// The newest height whose state root is `root`: a signed block, or 0 for the genesis root.
    /// Where a database with that root can resume.
    #[must_use]
    pub fn height_with_root(&self, root: &Hash) -> Option<u64> {
        let chain = self.chain?;
        self.blocks
            .iter()
            .rev()
            .filter(|b| b.sig.is_some())
            .find(|b| &b.header.state_root == root)
            .map(|b| b.header.height)
            .or_else(|| (&chain.genesis_root == root).then_some(0))
    }

    /// Read the block at `height` (signed or not).
    pub fn read(&self, height: u64) -> Result<StoredBlock, DurableError> {
        let entry = height
            .checked_sub(1)
            .and_then(|i| usize::try_from(i).ok())
            .and_then(|i| self.blocks.get(i))
            .ok_or(DurableError::Height {
                expected: self.blocks.len() as u64,
                found: height,
            })?;
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(entry.offset))?;
        let mut payload = vec![0u8; entry.len];
        file.read_exact(&mut payload)?;
        let (header, commands, events) = decode_unsigned(&payload)?;
        if header != entry.header {
            return Err(DurableError::corrupt(
                self.path.display().to_string(),
                format!("block {height} changed on disk"),
            ));
        }
        Ok(StoredBlock {
            header,
            commands,
            events,
            sig: entry.sig,
        })
    }

    /// The signed block at `height`.
    pub fn sealed_block(&self, height: u64) -> Result<SealedBlock, DurableError> {
        self.read(height)?
            .sealed()
            .ok_or_else(|| DurableError::Height {
                expected: self.sealed_height(),
                found: height,
            })
    }

    fn append(&mut self, bytes: &[u8]) -> Result<u64, DurableError> {
        let offset = self.len;
        self.file.write_all(bytes)?;
        self.len += bytes.len() as u64;
        Ok(offset)
    }

    /// Store the unsigned block that follows the tip and fsync it (seal step 1). Returns the
    /// fsync time, or `None` when the identical block is already stored (recovery). A different
    /// block at a stored height is refused.
    pub fn put_unsigned(
        &mut self,
        header: &BlockHeader,
        commands: &CommandBatch,
        events: &EventBatch,
    ) -> Result<Option<Duration>, DurableError> {
        let chain = self.require_chain()?;
        if let Some(stored) = self.header(header.height) {
            if stored != header {
                return Err(DurableError::BlockConflict {
                    height: header.height,
                });
            }
            let block = self.read(header.height)?;
            if &block.commands != commands || &block.events != events {
                return Err(DurableError::BlockConflict {
                    height: header.height,
                });
            }
            return Ok(None);
        }
        if self.unsigned().is_some() {
            return Err(DurableError::Height {
                expected: self.blocks.len() as u64,
                found: header.height,
            });
        }
        self.tip_of(&chain).check_next(header)?;
        check_roots(header, commands, events)?;
        let payload = encode_unsigned(header, commands, events);
        let offset = self.append(&record::frame(&payload))? + 4;
        let took = timed_sync(&self.file)?;
        self.blocks.push(Entry {
            header: *header,
            sig: None,
            offset,
            len: payload.len(),
        });
        Ok(Some(took))
    }

    /// Store the signature of the last (unsigned) block (seal step 3). Checked against the chain's
    /// sequencer first. Not fsynced; see the module documentation. Idempotent.
    pub fn put_signature(
        &mut self,
        height: u64,
        sig: &HeaderSignature,
    ) -> Result<(), DurableError> {
        let chain = self.require_chain()?;
        let entry = self.header(height).copied().ok_or(DurableError::Height {
            expected: self.blocks.len() as u64,
            found: height,
        })?;
        sig.verify(&chain.params(), &entry.hash())
            .map_err(|e| DurableError::Format(e.into()))?;
        let i = usize::try_from(height - 1).unwrap_or(usize::MAX);
        match self.blocks.get(i).and_then(|b| b.sig) {
            Some(existing) if &existing == sig => return Ok(()),
            Some(_) => return Err(DurableError::BlockConflict { height }),
            None if i + 1 != self.blocks.len() => {
                return Err(DurableError::Height {
                    expected: self.blocks.len() as u64,
                    found: height,
                });
            }
            None => {}
        }
        let mut e = Encoder::new();
        e.array(3);
        e.uint(SIGNATURE);
        e.uint(height);
        e.bytes(sig.as_bytes());
        self.append(&record::frame(&e.into_bytes()))?;
        if let Some(entry) = self.blocks.get_mut(i) {
            entry.sig = Some(*sig);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{CommandEntry, SequencerInput, SequencerInputKind};
    use crate::sign::SequencerKey;

    const GENESIS: Hash = [7; 32];

    fn key() -> SequencerKey {
        SequencerKey::from_secret(&[0x11; 32]).unwrap()
    }

    fn chain() -> StoreChain {
        StoreChain {
            genesis_root: GENESIS,
            sequencer: key().address(),
        }
    }

    fn block(prev: &ChainTip, player: i32) -> (BlockHeader, CommandBatch, EventBatch) {
        let commands = CommandBatch::new(vec![CommandEntry::Sequencer(SequencerInput {
            kind: SequencerInputKind::Disconnected,
            player,
        })])
        .unwrap();
        let events = EventBatch::new(vec![]).unwrap();
        let header = prev.next_header(100 + prev.height, commands.root(), events.root(), [9; 32]);
        (header, commands, events)
    }

    fn seal(store: &mut BlockStore, player: i32) -> BlockHeader {
        let prev = store.tip().unwrap();
        let (header, commands, events) = block(&prev, player);
        store.put_unsigned(&header, &commands, &events).unwrap();
        let sig = header.sign(&key(), &GENESIS).unwrap().sequencer_sig;
        store.put_signature(header.height, &sig).unwrap();
        header
    }

    #[test]
    fn sealed_blocks_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (h1, h2) = {
            let mut store = BlockStore::open(dir.path()).unwrap();
            store.init_chain(chain()).unwrap();
            (seal(&mut store, 4), seal(&mut store, 5))
        };
        let store = BlockStore::open(dir.path()).unwrap();
        assert_eq!(store.chain(), Some(chain()));
        assert_eq!(store.sealed_height(), 2);
        assert_eq!(store.tip().unwrap(), ChainTip::of(&h2));
        assert_eq!(store.sealed_block(1).unwrap().header.header, h1);
        assert_eq!(store.height_with_root(&[9; 32]), Some(2));
        assert_eq!(store.height_with_root(&GENESIS), Some(0));
    }

    #[test]
    fn an_unsigned_block_is_kept_and_an_identical_rewrite_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let (header, commands, events) = {
            let mut store = BlockStore::open(dir.path()).unwrap();
            store.init_chain(chain()).unwrap();
            seal(&mut store, 4);
            let b = block(&store.tip().unwrap(), 5);
            store.put_unsigned(&b.0, &b.1, &b.2).unwrap();
            b
        };
        let mut store = BlockStore::open(dir.path()).unwrap();
        assert_eq!(store.unsigned(), Some(&header));
        assert_eq!(store.sealed_height(), 1);
        assert_eq!(
            store.put_unsigned(&header, &commands, &events).unwrap(),
            None
        );
    }

    #[test]
    fn a_different_block_at_a_stored_height_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = BlockStore::open(dir.path()).unwrap();
        store.init_chain(chain()).unwrap();
        let prev = store.tip().unwrap();
        let a = block(&prev, 4);
        store.put_unsigned(&a.0, &a.1, &a.2).unwrap();
        let b = block(&prev, 5);
        assert!(matches!(
            store.put_unsigned(&b.0, &b.1, &b.2),
            Err(DurableError::BlockConflict { height: 1 })
        ));
    }

    #[test]
    fn a_signature_by_another_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = BlockStore::open(dir.path()).unwrap();
        store.init_chain(chain()).unwrap();
        let (header, commands, events) = block(&store.tip().unwrap(), 4);
        store.put_unsigned(&header, &commands, &events).unwrap();
        let other = SequencerKey::from_secret(&[0x22; 32]).unwrap();
        let sig = header.sign(&other, &GENESIS).unwrap().sequencer_sig;
        assert!(store.put_signature(1, &sig).is_err());
    }

    #[test]
    fn a_torn_signature_leaves_the_block_unsigned() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = BlockStore::open(dir.path()).unwrap();
            store.init_chain(chain()).unwrap();
            seal(&mut store, 4);
        }
        let path = dir.path().join(FILE);
        let len = fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len - 5)
            .unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        assert_eq!(
            (store.sealed_height(), store.unsigned().map(|h| h.height)),
            (0, Some(1))
        );
    }
}
