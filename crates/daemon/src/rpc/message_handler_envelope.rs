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

//! Signed envelopes over the daemon RPC (RuneWorld ADR 0005 decisions 3 and 8).
//!
//! - A signed `connect` arrives on the trusted-login path as
//!   `VerifiedOAuthLogin{connect_args: ["signed_connect", <hex envelope>]}`. The STF admits it,
//!   the connection is bound to the session's player before `user_connected` runs, and only then
//!   does the daemon mint the PASETO, so hosts keep their token handling.
//! - Every other envelope arrives as `ClientData{namespace: "runeworld", kind: "envelope",
//!   payload: <hex string or binary>}`.
//! - An admitted `revoke` or `revoke_all` boots the connections that were opened through the
//!   revoked sessions, since tokens carry no expiry.

use std::sync::Arc;

use moor_common::{
    envelope::{self, Envelope, EnvelopeKind},
    model::ObjFlag,
};
use moor_kernel::{
    SchedulerClient,
    tasks::envelope_admission::{Admitted, EnvelopeRun, OnAdmitted},
};
use moor_runtime_api::{
    RpcMessageError,
    api::{ChainStatus, ClientReply, ConnectType},
};
use moor_var::{Obj, Var};
use tracing::{info, warn};
use uuid::Uuid;

use crate::rpc::message_handler::RpcMessageHandler;

/// Envelope bytes from a hex string (with or without `0x`) or a binary value.
pub(crate) fn envelope_bytes_from_var(payload: &Var) -> Result<Vec<u8>, RpcMessageError> {
    if let Some(binary) = payload.as_binary() {
        return Ok(binary.as_bytes().to_vec());
    }
    let text = payload.as_string().ok_or_else(|| {
        RpcMessageError::InvalidRequest("envelope payload must be hex text or binary".into())
    })?;
    envelope_bytes_from_hex(text)
}

pub(crate) fn envelope_bytes_from_hex(text: &str) -> Result<Vec<u8>, RpcMessageError> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    envelope::unhex_vec(text)
        .ok_or_else(|| RpcMessageError::InvalidRequest("envelope is not hex".into()))
}

pub(crate) fn rejected(run: &EnvelopeRun) -> Option<RpcMessageError> {
    run.admission
        .as_ref()
        .err()
        .map(|reason| RpcMessageError::LoginTaskFailed(format!("envelope rejected: {reason}")))
}

impl RpcMessageHandler {
    /// `signed_connect`: admit a signed `connect`, bind the connection, mint the auth token.
    pub(crate) fn perform_signed_connect(
        &self,
        scheduler_client: SchedulerClient,
        client_id: Uuid,
        connection: Obj,
        hex: &str,
    ) -> Result<ClientReply, RpcMessageError> {
        let bytes = envelope_bytes_from_hex(hex)?;
        let kind = Envelope::decode(&bytes)
            .map_err(|e| RpcMessageError::InvalidRequest(e.to_string()))?
            .kind;
        if kind != EnvelopeKind::Connect {
            return Err(RpcMessageError::InvalidRequest(format!(
                "signed_connect carries a {kind} envelope"
            )));
        }
        let session = Arc::new(self.new_rpc_session(client_id, connection, connection));
        let bind = self.bind_on_admit(connection);
        let run = self.run_envelope_routed(&scheduler_client, bytes, session, Some(bind))?;
        self.finish_signed_connect(&scheduler_client, client_id, run)
    }

    /// Bind `connection` to the admitted player before `user_connected` runs, so its output
    /// reaches the connection.
    pub(crate) fn bind_on_admit(&self, connection: Obj) -> OnAdmitted {
        let connections = self.connections.clone();
        Box::new(move |admitted: &Admitted| {
            if let Err(e) = connections.associate_player_object(connection, admitted.player()) {
                warn!(error = ?e, %connection, "could not bind signed connection");
            }
        })
    }

    /// After a `connect` ran: check the verdict, record the session, mint the auth token.
    pub(crate) fn finish_signed_connect(
        &self,
        scheduler_client: &SchedulerClient,
        client_id: Uuid,
        run: EnvelopeRun,
    ) -> Result<ClientReply, RpcMessageError> {
        if let Some(error) = rejected(&run) {
            return Err(error);
        }
        let Ok(Admitted::Connect { player, session }) = run.admission else {
            return Err(RpcMessageError::InternalError(
                "connect admitted as another kind".into(),
            ));
        };
        let player_flags = scheduler_client
            .get_object_flags(&player)
            .map_err(|e| RpcMessageError::InternalError(e.to_string()))?;
        if player_flags & (1 << ObjFlag::User as u8) == 0 {
            return Err(RpcMessageError::PermissionDenied);
        }
        self.signed_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(client_id, (player, session));
        info!(%player, session, %client_id, "signed connect admitted");
        Ok(ClientReply::LoginResult {
            success: true,
            auth_token: Some(self.make_auth_token(&player)),
            connect_type: ConnectType::Connected,
            player: Some(player),
            player_flags,
        })
    }

    /// Admit and run any other envelope sent as `ClientData`.
    pub(crate) fn submit_signed_envelope(
        &self,
        scheduler_client: SchedulerClient,
        client_id: Uuid,
        connection: Obj,
        payload: &Var,
    ) -> Result<ClientReply, RpcMessageError> {
        let bytes = envelope_bytes_from_var(payload)?;
        if Envelope::decode(&bytes).is_ok_and(|env| env.kind == EnvelopeKind::Connect) {
            return Err(RpcMessageError::InvalidRequest(
                "send connect envelopes as VerifiedOAuthLogin signed_connect".into(),
            ));
        }
        let player = self
            .connections
            .player_object_for_client(client_id)
            .unwrap_or(connection);
        let session = Arc::new(self.new_rpc_session(client_id, connection, player));
        let run = self.run_envelope_routed(&scheduler_client, bytes, session, None)?;
        if let Some(error) = rejected(&run) {
            return Err(error);
        }
        self.publish_envelope_completion(client_id, &run);
        if let Ok(Admitted::Revoked { player, sessions }) = &run.admission {
            self.boot_revoked_sessions(*player, sessions);
        }
        Ok(ClientReply::TaskSubmitted {
            task_id: run.task_id.unwrap_or(0) as u64,
        })
    }

    /// What every host shows (ADR 0006 decision 8): heights, the sealed tip, the signing domain
    /// and the daemon's fork commit (the source offer, ADR 0004 note 1). Public and read-only.
    pub(crate) fn chain_status(&self) -> ChainStatus {
        let (sealed_height, published_height) = self
            .sequencer
            .get()
            .map_or((0, 0), crate::sequencer::SequencerHandle::heights);
        let last = *self.last_seal.lock().unwrap_or_else(|e| e.into_inner());
        let (header_hash, state_root) = last
            .filter(|notice| notice.height == sealed_height && sealed_height > 0)
            .map(|notice| (notice.header_hash.to_vec(), notice.state_root.to_vec()))
            .unwrap_or_default();
        ChainStatus {
            sequencer: self.sequencer.get().is_some(),
            sealed_height,
            published_height,
            header_hash,
            state_root,
            domain_salt: self.config.deterministic.domain_salt,
            fork_commit: moor_common::build::commit().to_string(),
        }
    }

    /// Disconnect every client that connected through one of `sessions` of `player`.
    fn boot_revoked_sessions(&self, player: Obj, sessions: &[u32]) {
        let clients: Vec<Uuid> = {
            let map = self
                .signed_sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            map.iter()
                .filter(|(_, (p, s))| *p == player && sessions.contains(s))
                .map(|(client, _)| *client)
                .collect()
        };
        for client_id in clients {
            info!(%player, %client_id, "booting a connection whose session was revoked");
            if let Err(e) = self.boot_client(client_id) {
                warn!(error = ?e, %client_id, "could not boot revoked connection");
            }
        }
    }
}
