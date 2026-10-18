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

//! Development identity in sequencer mode: the daemon acts as the custodial host.
//!
//! ADR 0005's Stage 0 shortcut lets hosts that cannot sign yet (telnet) be used with a
//! `--dev-identity` keyfile. In sequencer mode every logged input must still be a real envelope,
//! so the daemon signs for the host: a password login becomes a signed `connect` and an unsigned
//! command a signed `command`, both by the keyfile's session key for the `--dev-player` it was
//! bound to at genesis. The first use delegates that session key with the keyfile's wallet (a
//! logged `delegate`). Login names and passwords are ignored. The log stays replayable; the
//! daemon is still non-publishing because it holds a player's key.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use moor_block::CommandEntry;
use moor_common::{
    envelope::{self, Delegation, Domain, EnvelopeKind, SessionSigner, WalletSigner, scope},
    model::ObjectRef,
    tasks::{NoopClientSession, Session},
};
use moor_kernel::{
    SchedulerClient,
    tasks::envelope_admission::{Admitted, OnAdmitted, SESSIONS_PROP, WALLETS_PROP},
};
use moor_var::{Associative, Obj, SYSTEM_OBJECT, Sequence, Symbol, Var, v_str};
use tracing::info;

use super::{InputReply, SequencerHandle};
use crate::dev_identity::DevIdentity;

/// Heights an envelope stays valid after the block it was signed for.
const EXPIRY_WINDOW: u64 = 30;
/// How long the development delegation lasts.
const DELEGATION_SECS: u64 = 365 * 24 * 3600;
const DELEGATE_TIMEOUT: Duration = Duration::from_secs(30);

struct Active {
    session: u32,
    next_nonce: u32,
}

/// Signs for the development player.
pub struct DevSigner {
    wallet: WalletSigner,
    session_key: SessionSigner,
    player: Obj,
    domain: Domain,
    active: Mutex<Option<Active>>,
}

fn field(row: &Var, name: &str) -> Option<Var> {
    row.as_map()?.get(&v_str(name)).ok()
}

fn int_field(row: &Var, name: &str) -> Option<u64> {
    field(row, name)?
        .as_integer()
        .and_then(|i| u64::try_from(i).ok())
}

impl DevSigner {
    #[must_use]
    pub fn new(identity: DevIdentity, player: Obj, domain: Domain) -> Self {
        Self {
            wallet: identity.wallet,
            session_key: identity.session,
            player,
            domain,
            active: Mutex::new(None),
        }
    }

    #[must_use]
    pub fn player(&self) -> Obj {
        self.player
    }

    fn read(&self, scheduler: &SchedulerClient, name: &str) -> Result<Option<Var>, String> {
        match scheduler.request_property(
            &self.player,
            &self.player,
            &ObjectRef::Id(SYSTEM_OBJECT),
            Symbol::mk(name),
        ) {
            Ok((_, _, value)) => Ok(Some(value)),
            Err(e) => {
                let text = e.to_string();
                if text.to_lowercase().contains("not found") || text.contains("NotFound") {
                    Ok(None)
                } else {
                    Err(format!("reading #0.{name}: {text}"))
                }
            }
        }
    }

    /// The registered session for the keyfile's key, if any: `(index, last nonce)`.
    fn registered(&self, scheduler: &SchedulerClient) -> Result<Option<(u32, u64)>, String> {
        let Some(sessions) = self.read(scheduler, SESSIONS_PROP)? else {
            return Ok(None);
        };
        let key = v_str(&envelope::hex(&self.session_key.public_key()));
        let Some(list) = sessions.as_list() else {
            return Err("#0.admission_sessions is not a list".into());
        };
        for (i, row) in list.iter().enumerate() {
            if field(&row, "key") != Some(key.clone()) {
                continue;
            }
            if int_field(&row, "revoked") != Some(0) {
                return Err("the development session key was revoked; use a new keyfile".into());
            }
            let index = u32::try_from(i + 1).map_err(|e| e.to_string())?;
            let last = int_field(&row, "last_nonce").ok_or("session row has no last_nonce")?;
            return Ok(Some((index, last)));
        }
        Ok(None)
    }

    /// The wallet's delegation nonce floor, if the wallet is bound to the player.
    fn wallet_floor(&self, scheduler: &SchedulerClient) -> Result<u64, String> {
        let address = self.wallet.address().to_hex();
        let entry = self
            .read(scheduler, WALLETS_PROP)?
            .and_then(|wallets| wallets.as_map()?.get(&v_str(&address)).ok());
        let Some(entry) = entry else {
            return Err(format!(
                "development wallet {address} is not bound to a player; start the sequencer \
                 from a fresh database with --dev-player"
            ));
        };
        let list = entry.as_list().ok_or("wallet entry is not a list")?;
        list.index(1)
            .ok()
            .and_then(|v| v.as_integer())
            .and_then(|i| u64::try_from(i).ok())
            .ok_or_else(|| "wallet entry has no nonce floor".to_string())
    }

    /// Delegate the keyfile's session key to the development player (a logged `delegate`).
    fn delegate(&self, scheduler: &SchedulerClient, seq: &SequencerHandle) -> Result<u32, String> {
        let floor = self.wallet_floor(scheduler)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let delegation = Delegation {
            session_key: self.session_key.public_key(),
            box_key: [0; 32],
            scope: scope::ALL,
            expires: now + DELEGATION_SECS,
            nonce: floor + 1,
            create: false,
        };
        let env = self
            .wallet
            .delegate(
                &self.domain,
                &self.session_key,
                delegation,
                seq.current_height() + EXPIRY_WINDOW,
            )
            .map_err(|e| e.to_string())?;
        let receipt = seq.submit(
            CommandEntry::Envelope(env.encode()),
            Arc::new(NoopClientSession::new()),
            None,
            DELEGATE_TIMEOUT,
        )?;
        match receipt.admission {
            Some(Ok(Admitted::Delegated { session, .. })) => {
                info!(session, player = %self.player, "development session delegated");
                Ok(session)
            }
            Some(Err(reason)) => Err(format!("development delegation rejected: {reason}")),
            other => Err(format!("development delegation: unexpected {other:?}")),
        }
    }

    /// Sign `text` as `kind` with the next nonce and queue it. Signing and queueing happen under
    /// one lock, so nonces reach the queue in increasing order.
    pub fn sign_and_enqueue(
        &self,
        kind: EnvelopeKind,
        text: Vec<u8>,
        session: Arc<dyn Session>,
        on_admitted: Option<OnAdmitted>,
        scheduler: &SchedulerClient,
        seq: &SequencerHandle,
    ) -> Result<flume::Receiver<InputReply>, String> {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if active.is_none() {
            *active = Some(match self.registered(scheduler)? {
                Some((session, last)) => Active {
                    session,
                    next_nonce: u32::try_from(last + 1).map_err(|e| e.to_string())?,
                },
                None => Active {
                    session: self.delegate(scheduler, seq)?,
                    next_nonce: 1,
                },
            });
        }
        let state = active.as_mut().expect("set above");
        let env = self.session_key.envelope(
            &self.domain,
            self.player.as_u64(),
            kind,
            state.session,
            state.next_nonce,
            seq.current_height() + EXPIRY_WINDOW,
            text,
        );
        state.next_nonce += 1;
        seq.enqueue(CommandEntry::Envelope(env.encode()), session, on_admitted)
    }
}
