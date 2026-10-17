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

//! The admission step (RuneWorld ADR 0005 decision 3): before a signed envelope's transaction
//! runs, verify its signature, session, scope, nonce and expiry against admission state held in
//! the world database, and consume the nonce in a transaction of its own.
//!
//! # Admission state
//!
//! Admission state is ordinary world state (rows of the property relations), so the state root
//! covers it and objdef exports show it. The step acts as the system principal, the owner of `#0`
//! (which must be a wizard), and every property it defines is owned by that principal with flags
//! `r`: readable by everyone, writable only by this step and by wizards (the system principals).
//!
//! | Property | Value |
//! |---|---|
//! | `<player>.wallet` | `"0x"` + 40 hex digits, or `""` (the core property on `$player`) |
//! | `#0.admission_wallets` | map `"0x.." -> {player, delegation_nonce_floor}` |
//! | `#0.admission_sessions` | list; element `i` is session index `i`: a map with `player`, `key` (64 hex), `scope`, `expires` (block seconds), `box_key` (64 hex), `last_nonce`, `revoked` (0/1) |
//!
//! `#0.admission_*` are defined on first use. `wallet` is written to the player; if the core does
//! not define it, it is defined on the player itself.
//!
//! # Steps per kind
//!
//! - `command`, `connect`, `revoke`: look up the session, verify the Ed25519 signature (ZIP-215),
//!   then require: not revoked, `block.timestamp < expires`, scope allows the kind, `nonce >
//!   last_nonce`, expiry height `>= block.height`. Then store the nonce and commit, before any
//!   MOO code runs, so an aborted command still uses its nonce.
//! - `delegate`: recover the wallet from the EIP-712 signature, check the session key's
//!   proof-of-possession signature and the expiry height, then require `nonce > floor`, a fresh
//!   session key, unexpired `expires`, known scope bits, and `create` iff the wallet has no player.
//! - `revoke_all`: recover the wallet, require `nonce > floor`, revoke every live session.
//!
//! Any failure leaves admission state unchanged; the caller emits a rejection event and runs
//! nothing. The block stays valid (ADR 0001 ratification note 3).

use crate::tasks::{
    TaskHandle, TaskNotification,
    scheduler::{Scheduler, manual::RunSummary},
};
use moor_common::{
    deterministic::{self, BlockContext},
    envelope::{
        self, Address, DecodeError, DelegationPayload, Domain, Envelope, EnvelopeKind,
        RevokeAllPayload, WalletSignatureError, scope,
    },
    model::{CommitResult, ObjFlag, ObjectRef, PropFlag, TaskPermissions, WorldState},
    tasks::{SchedulerError, Session, TaskId},
    util::BitEnum,
};
use moor_var::{
    Associative, List, NOTHING, Obj, SYSTEM_OBJECT, Sequence, Symbol, Var, v_empty_str, v_int,
    v_list, v_map, v_obj, v_str,
};
use std::{fmt, sync::Arc};

/// `#0:create_wallet_player(address :: str, name :: str) => obj`: the system-principal hook that
/// mints a `$player` for a `delegate` with `create = true` (ADR 0005 decision 5). It runs as the
/// verb's owner (a wizard in the core) and must return a valid object with the player flag.
pub const CREATE_PLAYER_HOOK: &str = "create_wallet_player";
/// `#0.admission_sessions`.
pub const SESSIONS_PROP: &str = "admission_sessions";
/// `#0.admission_wallets`.
pub const WALLETS_PROP: &str = "admission_wallets";
/// `$player.wallet`.
pub const WALLET_PROP: &str = "wallet";

/// Why an envelope was not admitted. Every variant leaves admission state unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionRejection {
    /// Not a well-formed envelope or payload.
    Malformed(String),
    /// Deterministic mode is off: there is no block context.
    NotDeterministic,
    /// No session has this index.
    UnknownSession(u32),
    /// The Ed25519 signature does not verify.
    BadSignature,
    /// The EIP-712 wallet signature does not recover.
    BadWalletSignature(String),
    /// The session was revoked.
    SessionRevoked(u32),
    /// The session's `expires` has passed.
    SessionExpired {
        session: u32,
        expires: u64,
        now: u64,
    },
    /// The session's scope does not allow this kind.
    WrongScope { kind: EnvelopeKind, scope: u32 },
    /// The nonce is not above the session's last nonce.
    StaleNonce { last: u64, got: u64 },
    /// The envelope's expiry height is below the current height.
    Expired {
        expiry_height: Option<u64>,
        height: u64,
    },
    /// A `revoke` names a session of another player, or one already revoked.
    BadRevokeTarget(u32),
    /// `delegate` (without `create`) or `revoke_all` from a wallet with no player.
    UnknownWallet(Address),
    /// `delegate` with `create` from a wallet that already has a player.
    WalletHasPlayer { wallet: Address, player: Obj },
    /// The delegation or `revoke_all` nonce is not above the wallet's floor.
    StaleDelegationNonce { floor: u64, got: u64 },
    /// The delegation's `expires` is not in the future.
    DelegationExpired { expires: u64, now: u64 },
    /// Scope is zero or has undefined bits.
    BadScope(u32),
    /// The session key is already registered.
    DuplicateSessionKey(u32),
    /// The creation hook did not return a new player.
    CreationFailed(String),
    /// Admission state could not be read or written.
    Storage(String),
}

impl fmt::Display for AdmissionRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed envelope: {why}"),
            Self::NotDeterministic => write!(f, "deterministic mode is off"),
            Self::UnknownSession(s) => write!(f, "unknown session {s}"),
            Self::BadSignature => write!(f, "bad signature"),
            Self::BadWalletSignature(why) => write!(f, "bad wallet signature: {why}"),
            Self::SessionRevoked(s) => write!(f, "session {s} is revoked"),
            Self::SessionExpired {
                session,
                expires,
                now,
            } => write!(f, "session {session} expired at {expires} (now {now})"),
            Self::WrongScope { kind, scope } => {
                write!(f, "scope {scope:#x} does not allow {kind}")
            }
            Self::StaleNonce { last, got } => write!(f, "stale nonce {got} (last {last})"),
            Self::Expired {
                expiry_height,
                height,
            } => match expiry_height {
                Some(h) => write!(f, "expired at height {h} (now {height})"),
                None => write!(f, "expired (now {height})"),
            },
            Self::BadRevokeTarget(s) => write!(f, "cannot revoke session {s}"),
            Self::UnknownWallet(w) => write!(f, "wallet {w} has no player"),
            Self::WalletHasPlayer { wallet, player } => {
                write!(f, "wallet {wallet} already has player {player}")
            }
            Self::StaleDelegationNonce { floor, got } => {
                write!(f, "stale delegation nonce {got} (floor {floor})")
            }
            Self::DelegationExpired { expires, now } => {
                write!(f, "delegation expires at {expires} (now {now})")
            }
            Self::BadScope(s) => write!(f, "bad scope {s:#x}"),
            Self::DuplicateSessionKey(s) => write!(f, "session key already registered as {s}"),
            Self::CreationFailed(why) => write!(f, "player creation failed: {why}"),
            Self::Storage(why) => write!(f, "admission state: {why}"),
        }
    }
}

impl From<DecodeError> for AdmissionRejection {
    fn from(e: DecodeError) -> Self {
        Self::Malformed(e.to_string())
    }
}

impl From<WalletSignatureError> for AdmissionRejection {
    fn from(e: WalletSignatureError) -> Self {
        Self::BadWalletSignature(e.to_string())
    }
}

fn storage<E: fmt::Display>(e: E) -> AdmissionRejection {
    AdmissionRejection::Storage(e.to_string())
}

/// What an admitted envelope did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admitted {
    /// A command ran as `player`.
    Command { player: Obj, session: u32 },
    /// `player` connected through `session`.
    Connect { player: Obj, session: u32 },
    /// A session was registered; `created` when the delegation minted the player.
    Delegated {
        player: Obj,
        session: u32,
        created: bool,
    },
    /// Sessions of `player` were revoked.
    Revoked { player: Obj, sessions: Vec<u32> },
}

impl Admitted {
    /// The player the envelope acted for.
    #[must_use]
    pub fn player(&self) -> Obj {
        match self {
            Self::Command { player, .. }
            | Self::Connect { player, .. }
            | Self::Delegated { player, .. }
            | Self::Revoked { player, .. } => *player,
        }
    }
}

/// The result of running one envelope.
#[derive(Debug)]
pub struct EnvelopeRun {
    /// The kind, when the bytes decoded.
    pub kind: Option<EnvelopeKind>,
    /// The session index on the wire.
    pub session: u32,
    pub admission: Result<Admitted, AdmissionRejection>,
    /// The task the envelope started (the command, `user_connected`, or `user_created`).
    pub task_id: Option<TaskId>,
    /// That task's result; `None` while it is still suspended.
    pub result: Option<Result<Var, SchedulerError>>,
    /// Jobs run for this envelope (all of its tasks), and whether a budget ran out.
    pub run: RunSummary,
}

/// A session table row.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SessionRecord {
    player: Obj,
    key: [u8; 32],
    scope: u32,
    expires: u64,
    box_key: [u8; 32],
    last_nonce: u64,
    revoked: bool,
}

fn field(row: &Var, name: &str) -> Result<Var, AdmissionRejection> {
    row.as_map()
        .ok_or_else(|| storage("session row is not a map"))?
        .get(&v_str(name))
        .map_err(storage)
}

fn int_field(map: &Var, name: &str) -> Result<u64, AdmissionRejection> {
    field(map, name)?
        .as_integer()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| storage(format!("{name} is not a non-negative integer")))
}

fn key_field(map: &Var, name: &str) -> Result<[u8; 32], AdmissionRejection> {
    field(map, name)?
        .as_string()
        .and_then(envelope::unhex::<32>)
        .ok_or_else(|| storage(format!("{name} is not 64 hex digits")))
}

fn to_int(v: u64) -> Result<Var, AdmissionRejection> {
    i64::try_from(v)
        .map(v_int)
        .map_err(|_| AdmissionRejection::Malformed(format!("{v} does not fit a MOO integer")))
}

impl SessionRecord {
    fn from_var(v: &Var) -> Result<Self, AdmissionRejection> {
        Ok(Self {
            player: field(v, "player")?
                .as_object()
                .ok_or_else(|| storage("player is not an object"))?,
            key: key_field(v, "key")?,
            scope: u32::try_from(int_field(v, "scope")?).map_err(storage)?,
            expires: int_field(v, "expires")?,
            box_key: key_field(v, "box_key")?,
            last_nonce: int_field(v, "last_nonce")?,
            revoked: int_field(v, "revoked")? != 0,
        })
    }

    fn to_var(&self) -> Result<Var, AdmissionRejection> {
        Ok(v_map(&[
            (v_str("box_key"), v_str(&envelope::hex(&self.box_key))),
            (v_str("expires"), to_int(self.expires)?),
            (v_str("key"), v_str(&envelope::hex(&self.key))),
            (v_str("last_nonce"), to_int(self.last_nonce)?),
            (v_str("player"), v_obj(self.player)),
            (v_str("revoked"), v_int(i64::from(self.revoked))),
            (v_str("scope"), v_int(i64::from(self.scope))),
        ]))
    }
}

/// The admission step's view of the world database, with system-principal permissions.
struct Store<'a> {
    ws: &'a mut dyn WorldState,
    perms: TaskPermissions,
}

impl<'a> Store<'a> {
    /// The step acts as the system principal: the owner of `#0`, which must be a wizard.
    fn new(ws: &'a mut dyn WorldState) -> Result<Self, AdmissionRejection> {
        let principal = ws.owner_of(&SYSTEM_OBJECT).map_err(storage)?;
        let flags = ws.flags_of(&principal).map_err(storage)?;
        if !flags.contains(ObjFlag::Wizard) {
            return Err(storage(format!(
                "the owner of #0 ({principal}) is not a wizard"
            )));
        }
        Ok(Self {
            ws,
            perms: TaskPermissions::new(principal, flags),
        })
    }

    fn read(&self, obj: &Obj, name: &str) -> Result<Option<Var>, AdmissionRejection> {
        match self
            .ws
            .retrieve_property(&self.perms, obj, Symbol::mk(name))
        {
            Ok(v) => Ok(Some(v)),
            Err(moor_common::model::WorldStateError::PropertyNotFound(..)) => Ok(None),
            Err(e) => Err(storage(e)),
        }
    }

    fn write(&mut self, obj: &Obj, name: &str, value: Var) -> Result<(), AdmissionRejection> {
        let pname = Symbol::mk(name);
        match self.ws.update_property(&self.perms, obj, pname, &value) {
            Ok(()) => Ok(()),
            Err(moor_common::model::WorldStateError::PropertyNotFound(..)) => self
                .ws
                .define_property(
                    &self.perms,
                    obj,
                    obj,
                    pname,
                    &self.perms.principal(),
                    BitEnum::new_with(PropFlag::Read),
                    Some(value),
                )
                .map_err(storage),
            Err(e) => Err(storage(e)),
        }
    }

    fn sessions(&self) -> Result<List, AdmissionRejection> {
        match self.read(&SYSTEM_OBJECT, SESSIONS_PROP)? {
            None => Ok(List::mk_list(&[])),
            Some(v) => v
                .as_list()
                .cloned()
                .ok_or_else(|| storage("#0.admission_sessions is not a list")),
        }
    }

    fn session(&self, index: u32) -> Result<SessionRecord, AdmissionRejection> {
        let sessions = self.sessions()?;
        let slot = (index as usize)
            .checked_sub(1)
            .filter(|i| *i < sessions.len())
            .ok_or(AdmissionRejection::UnknownSession(index))?;
        SessionRecord::from_var(&sessions.index(slot).map_err(storage)?)
    }

    fn put_session(
        &mut self,
        index: u32,
        record: &SessionRecord,
    ) -> Result<(), AdmissionRejection> {
        let sessions = self.sessions()?;
        let updated = sessions
            .index_set(index as usize - 1, &record.to_var()?)
            .map_err(storage)?;
        self.write(&SYSTEM_OBJECT, SESSIONS_PROP, updated)
    }

    /// Append a session and return its index.
    fn add_session(&mut self, record: &SessionRecord) -> Result<u32, AdmissionRejection> {
        let sessions = self.sessions()?;
        let index = u32::try_from(sessions.len() + 1).map_err(storage)?;
        let updated = sessions.push(&record.to_var()?).map_err(storage)?;
        self.write(&SYSTEM_OBJECT, SESSIONS_PROP, updated)?;
        Ok(index)
    }

    fn session_with_key(&self, key: &[u8; 32]) -> Result<Option<u32>, AdmissionRejection> {
        let wanted = v_str(&envelope::hex(key));
        for (i, row) in self.sessions()?.iter().enumerate() {
            if field(&row, "key")? == wanted {
                return Ok(Some(i as u32 + 1));
            }
        }
        Ok(None)
    }

    fn wallets(&self) -> Result<Var, AdmissionRejection> {
        match self.read(&SYSTEM_OBJECT, WALLETS_PROP)? {
            None => Ok(v_map(&[])),
            Some(v) if v.as_map().is_some() => Ok(v),
            Some(_) => Err(storage("#0.admission_wallets is not a map")),
        }
    }

    /// `(player, delegation nonce floor)` for a wallet.
    fn wallet(&self, wallet: &Address) -> Result<Option<(Obj, u64)>, AdmissionRejection> {
        let wallets = self.wallets()?;
        let map = wallets.as_map().expect("checked by wallets()");
        let Ok(entry) = map.get(&v_str(&wallet.to_hex())) else {
            return Ok(None);
        };
        let list = entry
            .as_list()
            .filter(|l| l.len() == 2)
            .ok_or_else(|| storage("wallet entry is not {player, floor}"))?;
        let player = list
            .index(0)
            .map_err(storage)?
            .as_object()
            .ok_or_else(|| storage("wallet entry player"))?;
        let floor = list
            .index(1)
            .map_err(storage)?
            .as_integer()
            .and_then(|i| u64::try_from(i).ok())
            .ok_or_else(|| storage("wallet entry floor"))?;
        Ok(Some((player, floor)))
    }

    fn put_wallet(
        &mut self,
        wallet: &Address,
        player: Obj,
        floor: u64,
    ) -> Result<(), AdmissionRejection> {
        let updated = self
            .wallets()?
            .as_map()
            .expect("checked by wallets()")
            .set(
                &v_str(&wallet.to_hex()),
                &v_list(&[v_obj(player), to_int(floor)?]),
            )
            .map_err(storage)?;
        self.write(&SYSTEM_OBJECT, WALLETS_PROP, updated)
    }
}

/// What the pure part of admission decided, before any MOO code runs.
enum Decision {
    Run(Admitted, Vec<u8>),
    /// `delegate` with `create`: the creation hook must mint the player first.
    Create {
        wallet: Address,
        payload: DelegationPayload,
    },
    Done(Admitted),
}

fn check_expiry(env: &Envelope, block: &BlockContext) -> Result<(), AdmissionRejection> {
    let expiry_height = envelope::expiry_height(block.height, env.expiry);
    match expiry_height {
        Some(h) if h >= block.height => Ok(()),
        _ => Err(AdmissionRejection::Expired {
            expiry_height,
            height: block.height,
        }),
    }
}

fn admit(
    store: &mut Store<'_>,
    domain: &Domain,
    block: &BlockContext,
    env: &Envelope,
) -> Result<Decision, AdmissionRejection> {
    match env.kind {
        EnvelopeKind::Command | EnvelopeKind::Connect | EnvelopeKind::Revoke => {
            admit_session_signed(store, domain, block, env)
        }
        EnvelopeKind::Delegate => admit_delegate(store, domain, block, env),
        EnvelopeKind::RevokeAll => admit_revoke_all(store, domain, block, env),
    }
}

fn admit_session_signed(
    store: &mut Store<'_>,
    domain: &Domain,
    block: &BlockContext,
    env: &Envelope,
) -> Result<Decision, AdmissionRejection> {
    let mut record = store.session(env.session)?;
    // The signed preimage needs the absolute expiry height; an unrecoverable one is checked
    // (and rejected) only after the signature, so that unsigned bytes never learn anything.
    let expiry_height = envelope::expiry_height(block.height, env.expiry).unwrap_or(0);
    let digest = envelope::envelope_digest(
        domain,
        record.player.as_u64(),
        &record.key,
        env.kind,
        u64::from(env.nonce),
        expiry_height,
        &env.text,
    );
    if !envelope::verify_session_signature(&record.key, &digest, &env.signature) {
        return Err(AdmissionRejection::BadSignature);
    }
    if record.revoked {
        return Err(AdmissionRejection::SessionRevoked(env.session));
    }
    if block.timestamp >= record.expires {
        return Err(AdmissionRejection::SessionExpired {
            session: env.session,
            expires: record.expires,
            now: block.timestamp,
        });
    }
    let required = env.kind.required_scope().unwrap_or(0);
    if record.scope & required == 0 {
        return Err(AdmissionRejection::WrongScope {
            kind: env.kind,
            scope: record.scope,
        });
    }
    let nonce = u64::from(env.nonce);
    if nonce <= record.last_nonce {
        return Err(AdmissionRejection::StaleNonce {
            last: record.last_nonce,
            got: nonce,
        });
    }
    check_expiry(env, block)?;

    let player = record.player;
    let session = env.session;
    let decision = match env.kind {
        EnvelopeKind::Command => {
            std::str::from_utf8(&env.text)
                .map_err(|_| AdmissionRejection::Malformed("command is not UTF-8".into()))?;
            Decision::Run(Admitted::Command { player, session }, env.text.clone())
        }
        EnvelopeKind::Connect => {
            if !env.text.is_empty() {
                return Err(AdmissionRejection::Malformed(
                    "connect carries no text".into(),
                ));
            }
            Decision::Run(Admitted::Connect { player, session }, Vec::new())
        }
        EnvelopeKind::Revoke => {
            let target = if env.text.is_empty() {
                session
            } else {
                std::str::from_utf8(&env.text)
                    .ok()
                    .filter(|t| t.bytes().all(|b| b.is_ascii_digit()) && !t.starts_with('0'))
                    .and_then(|t| t.parse::<u32>().ok())
                    .ok_or_else(|| {
                        AdmissionRejection::Malformed("revoke target is not an index".into())
                    })?
            };
            if target != session {
                let mut other = store
                    .session(target)
                    .map_err(|_| AdmissionRejection::BadRevokeTarget(target))?;
                if other.player != player || other.revoked {
                    return Err(AdmissionRejection::BadRevokeTarget(target));
                }
                other.revoked = true;
                store.put_session(target, &other)?;
            } else {
                record.revoked = true;
            }
            Decision::Done(Admitted::Revoked {
                player,
                sessions: vec![target],
            })
        }
        EnvelopeKind::Delegate | EnvelopeKind::RevokeAll => unreachable!("not session-signed"),
    };
    record.last_nonce = nonce;
    store.put_session(session, &record)?;
    Ok(decision)
}

fn admit_delegate(
    store: &mut Store<'_>,
    domain: &Domain,
    block: &BlockContext,
    env: &Envelope,
) -> Result<Decision, AdmissionRejection> {
    if env.session != 0 || env.nonce != 0 {
        return Err(AdmissionRejection::Malformed(
            "delegate carries no session index or nonce".into(),
        ));
    }
    let payload = DelegationPayload::decode(&env.text)?;
    let d = payload.delegation;
    let wallet = envelope::recover_wallet(&d.digest(domain), &payload.wallet_signature)?;
    let expiry_height = envelope::expiry_height(block.height, env.expiry).unwrap_or(0);
    let digest = envelope::envelope_digest(
        domain,
        NOTHING.as_u64(),
        &d.session_key,
        EnvelopeKind::Delegate,
        0,
        expiry_height,
        &env.text,
    );
    if !envelope::verify_session_signature(&d.session_key, &digest, &env.signature) {
        return Err(AdmissionRejection::BadSignature);
    }
    check_expiry(env, block)?;
    if d.scope == 0 || d.scope & !scope::ALL != 0 {
        return Err(AdmissionRejection::BadScope(d.scope));
    }
    if d.expires <= block.timestamp {
        return Err(AdmissionRejection::DelegationExpired {
            expires: d.expires,
            now: block.timestamp,
        });
    }
    // Values must fit MOO integers in the session table.
    to_int(d.expires)?;
    to_int(d.nonce)?;
    let existing = store.wallet(&wallet)?;
    let floor = existing.map_or(0, |(_, floor)| floor);
    if d.nonce <= floor {
        return Err(AdmissionRejection::StaleDelegationNonce {
            floor,
            got: d.nonce,
        });
    }
    match (existing, d.create) {
        (Some((player, _)), true) => {
            return Err(AdmissionRejection::WalletHasPlayer { wallet, player });
        }
        (None, false) => return Err(AdmissionRejection::UnknownWallet(wallet)),
        _ => {}
    }
    if let Some(index) = store.session_with_key(&d.session_key)? {
        return Err(AdmissionRejection::DuplicateSessionKey(index));
    }
    match existing {
        None => Ok(Decision::Create { wallet, payload }),
        Some((player, _)) => {
            let session = register(store, player, &wallet, &payload)?;
            Ok(Decision::Done(Admitted::Delegated {
                player,
                session,
                created: false,
            }))
        }
    }
}

/// Write a delegation's session row and raise the wallet's nonce floor.
fn register(
    store: &mut Store<'_>,
    player: Obj,
    wallet: &Address,
    payload: &DelegationPayload,
) -> Result<u32, AdmissionRejection> {
    let d = &payload.delegation;
    let session = store.add_session(&SessionRecord {
        player,
        key: d.session_key,
        scope: d.scope,
        expires: d.expires,
        box_key: d.box_key,
        last_nonce: 0,
        revoked: false,
    })?;
    store.put_wallet(wallet, player, d.nonce)?;
    Ok(session)
}

fn admit_revoke_all(
    store: &mut Store<'_>,
    domain: &Domain,
    block: &BlockContext,
    env: &Envelope,
) -> Result<Decision, AdmissionRejection> {
    if env.session != 0 || env.nonce != 0 || env.signature != [0; 64] {
        return Err(AdmissionRejection::Malformed(
            "revoke_all carries no session, nonce or session signature".into(),
        ));
    }
    let payload = RevokeAllPayload::decode(&env.text)?;
    let wallet =
        envelope::recover_wallet(&payload.revoke.digest(domain), &payload.wallet_signature)?;
    check_expiry(env, block)?;
    let (player, floor) = store
        .wallet(&wallet)?
        .ok_or(AdmissionRejection::UnknownWallet(wallet))?;
    let nonce = payload.revoke.nonce;
    if nonce <= floor {
        return Err(AdmissionRejection::StaleDelegationNonce { floor, got: nonce });
    }
    to_int(nonce)?;
    let mut rows: Vec<Var> = store.sessions()?.iter().collect();
    let mut revoked = Vec::new();
    for (i, row) in rows.iter_mut().enumerate() {
        let mut record = SessionRecord::from_var(row)?;
        if record.player == player && !record.revoked {
            record.revoked = true;
            *row = record.to_var()?;
            revoked.push(u32::try_from(i + 1).map_err(storage)?);
        }
    }
    store.write(&SYSTEM_OBJECT, SESSIONS_PROP, v_list(&rows))?;
    store.put_wallet(&wallet, player, nonce)?;
    Ok(Decision::Done(Admitted::Revoked {
        player,
        sessions: revoked,
    }))
}

/// The first terminal result on a handle, skipping `Suspended` notices.
pub(crate) fn take_result(handle: &TaskHandle) -> Option<Result<Var, SchedulerError>> {
    handle
        .receiver()
        .try_iter()
        .find_map(|(_, result)| match result {
            Ok(TaskNotification::Suspended) => None,
            Ok(TaskNotification::Result(value)) => Some(Ok(value)),
            Err(error) => Some(Err(error)),
        })
}

/// A task id and its result (`None` while suspended).
type TaskOutcome = (Option<TaskId>, Option<Result<Var, SchedulerError>>);

/// Called with the player once admission succeeds and before the envelope's task runs. The daemon
/// uses it to bind the connection, so `user_connected` output reaches it.
pub type OnAdmitted = Box<dyn FnOnce(&Admitted) + Send>;

impl Scheduler {
    /// The envelope signing domain for this world.
    #[must_use]
    pub fn envelope_domain(&self) -> Domain {
        Domain::new(self.config.deterministic.domain_salt)
    }

    /// Run admission in its own transaction and commit it. Returns the decision.
    fn admission_transaction(
        &self,
        f: impl FnOnce(&mut Store<'_>) -> Result<Decision, AdmissionRejection>,
    ) -> Result<Decision, AdmissionRejection> {
        let mut ws = self.database.new_world_state().map_err(storage)?;
        let decision = Store::new(ws.as_mut()).and_then(|mut store| f(&mut store));
        match decision {
            Ok(decision) => match ws.commit().map_err(storage)? {
                CommitResult::Success { .. } => Ok(decision),
                CommitResult::ConflictRetry { .. } => {
                    Err(storage("admission transaction conflicted"))
                }
            },
            Err(rejection) => {
                ws.rollback().map_err(storage)?;
                Err(rejection)
            }
        }
    }

    fn system_hook(
        &self,
        player: Obj,
        verb: &str,
        args: &[Var],
        session: Arc<dyn Session>,
    ) -> Result<TaskHandle, SchedulerError> {
        self.submit_verb_task_inner(
            player,
            ObjectRef::Id(SYSTEM_OBJECT),
            Symbol::mk(verb),
            List::mk_list(args),
            v_empty_str(),
            SYSTEM_OBJECT,
            session,
        )
    }

    fn run_task(
        &self,
        submitted: Result<TaskHandle, SchedulerError>,
        budget: usize,
        total: &mut RunSummary,
    ) -> TaskOutcome {
        let summary = self.run_until_quiescent(budget);
        total.jobs_run += summary.jobs_run;
        total.budget_exhausted |= summary.budget_exhausted;
        match submitted {
            Ok(handle) => (Some(handle.task_id()), take_result(&handle)),
            Err(error) => (None, Some(Err(error))),
        }
    }

    /// Admit one envelope and, if admitted, run what it asks for to quiescence. The caller has
    /// already started the sequenced input (command index). Deterministic mode only.
    pub(crate) fn run_envelope(
        &self,
        bytes: &[u8],
        session: Arc<dyn Session>,
        on_admitted: Option<OnAdmitted>,
        budget: usize,
    ) -> EnvelopeRun {
        let env = match Envelope::decode(bytes) {
            Ok(env) => env,
            Err(e) => {
                return EnvelopeRun {
                    kind: bytes.first().copied().and_then(EnvelopeKind::from_byte),
                    session: 0,
                    admission: Err(e.into()),
                    task_id: None,
                    result: None,
                    run: RunSummary::default(),
                };
            }
        };
        let mut run = EnvelopeRun {
            kind: Some(env.kind),
            session: env.session,
            admission: Err(AdmissionRejection::NotDeterministic),
            task_id: None,
            result: None,
            run: RunSummary::default(),
        };
        let Some(block) = deterministic::current().map(|c| c.block) else {
            return run;
        };
        let domain = self.envelope_domain();
        let decision = self.admission_transaction(|store| admit(store, &domain, &block, &env));
        let admitted = match decision {
            Err(rejection) => {
                run.admission = Err(rejection);
                return run;
            }
            Ok(Decision::Done(admitted)) => admitted,
            Ok(Decision::Run(admitted, text)) => {
                if let Some(f) = on_admitted {
                    f(&admitted);
                }
                let submitted = match &admitted {
                    Admitted::Command { player, .. } => self.submit_command_task_inner(
                        SYSTEM_OBJECT,
                        *player,
                        String::from_utf8(text).expect("checked UTF-8"),
                        session,
                    ),
                    Admitted::Connect { player, .. } => {
                        self.system_hook(*player, "user_connected", &[v_obj(*player)], session)
                    }
                    _ => unreachable!("only commands and connects run tasks"),
                };
                (run.task_id, run.result) = self.run_task(submitted, budget, &mut run.run);
                admitted
            }
            Ok(Decision::Create { wallet, payload }) => {
                match self.create_player(&wallet, &payload, &session, budget, &mut run.run) {
                    Ok((admitted, (task_id, result))) => {
                        run.task_id = task_id;
                        run.result = result;
                        admitted
                    }
                    Err(rejection) => {
                        run.admission = Err(rejection);
                        return run;
                    }
                }
            }
        };
        if run.result.is_none() && run.task_id.is_none() {
            run.result = Some(Ok(admitted_value(&admitted)));
        }
        run.admission = Ok(admitted);
        run
    }

    /// `delegate` with `create`: run the creation hook, then register the wallet and first session
    /// against the new player, then run `user_created`.
    fn create_player(
        &self,
        wallet: &Address,
        payload: &DelegationPayload,
        session: &Arc<dyn Session>,
        budget: usize,
        total: &mut RunSummary,
    ) -> Result<(Admitted, TaskOutcome), AdmissionRejection> {
        let hook = self.system_hook(
            SYSTEM_OBJECT,
            CREATE_PLAYER_HOOK,
            &[v_str(&wallet.to_hex()), v_str(&wallet.placeholder_name())],
            session.clone(),
        );
        let (_, result) = self.run_task(hook, budget, total);
        let player = match result {
            Some(Ok(v)) => v.as_object().ok_or_else(|| {
                AdmissionRejection::CreationFailed(format!("hook returned {v:?}"))
            })?,
            Some(Err(e)) => return Err(AdmissionRejection::CreationFailed(e.to_string())),
            None => {
                return Err(AdmissionRejection::CreationFailed(
                    "hook did not finish".into(),
                ));
            }
        };
        let decision = self.admission_transaction(|store| {
            let flags = store.ws.flags_of(&player).map_err(|e| {
                AdmissionRejection::CreationFailed(format!("{player} is not valid: {e}"))
            })?;
            if !flags.contains(ObjFlag::User) {
                return Err(AdmissionRejection::CreationFailed(format!(
                    "{player} is not a player"
                )));
            }
            // Re-check the wallet: the hook ran MOO code in between.
            if let Some((existing, _)) = store.wallet(wallet)? {
                return Err(AdmissionRejection::WalletHasPlayer {
                    wallet: *wallet,
                    player: existing,
                });
            }
            store.write(&player, WALLET_PROP, v_str(&wallet.to_hex()))?;
            let session = register(store, player, wallet, payload)?;
            Ok(Decision::Done(Admitted::Delegated {
                player,
                session,
                created: true,
            }))
        })?;
        let Decision::Done(admitted) = decision else {
            unreachable!("create registers directly")
        };
        let created = self.system_hook(player, "user_created", &[v_obj(player)], session.clone());
        Ok((admitted, self.run_task(created, budget, total)))
    }

    /// The disconnect sequencer input (ADR 0005 decision 6): no signature and no player authority;
    /// submits `player:disfunc()` only. A missing `disfunc` is an ordinary verb-not-found result.
    pub(crate) fn submit_disconnect_input(
        &self,
        player: Obj,
        session: Arc<dyn Session>,
    ) -> Result<TaskHandle, SchedulerError> {
        self.submit_verb_task_inner(
            player,
            ObjectRef::Id(player),
            Symbol::mk("disfunc"),
            List::mk_list(&[]),
            v_empty_str(),
            SYSTEM_OBJECT,
            session,
        )
    }

    /// Bind `wallet` to `player` without a signature: the system-principal operation ADR 0005 calls
    /// `reassign_wallet` (key loss) and that genesis set-up uses to give existing players wallets.
    /// The caller is responsible for logging it as a sequencer input with a public reason.
    pub fn assign_wallet(&self, player: Obj, wallet: Address) -> Result<(), AdmissionRejection> {
        self.admission_transaction(|store| {
            let floor = store.wallet(&wallet)?.map_or(0, |(_, floor)| floor);
            store.write(&player, WALLET_PROP, v_str(&wallet.to_hex()))?;
            store.put_wallet(&wallet, player, floor)?;
            Ok(Decision::Done(Admitted::Revoked {
                player,
                sessions: vec![],
            }))
        })
        .map(|_| ())
    }
}

/// The task-less result value of an admitted envelope: `{player, session}` for a delegation, the
/// revoked session indices for a revocation.
fn admitted_value(admitted: &Admitted) -> Var {
    match admitted {
        Admitted::Command { player, session }
        | Admitted::Connect { player, session }
        | Admitted::Delegated {
            player, session, ..
        } => v_list(&[v_obj(*player), v_int(i64::from(*session))]),
        Admitted::Revoked { sessions, .. } => v_list(
            &sessions
                .iter()
                .map(|s| v_int(i64::from(*s)))
                .collect::<Vec<_>>(),
        ),
    }
}
