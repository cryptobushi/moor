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

//! Client requests in sequencer mode (RuneWorld ADR 0006 decision 1).
//!
//! Only logged inputs change state: signed envelopes go to the block thread's queue (after the
//! RPC thread checks they decode), disconnects go there as `Disconnected` sequencer inputs, and
//! reads are served from the last committed state by `SchedulerClient` without a command index.
//! Everything that would run MOO code outside the log is refused: the welcome message (a fixed
//! banner instead), password login and unsigned commands (unless the development identity signs
//! them, see `sequencer::dev_signer`), connecting `Attach`es and OAuth logins.

use std::{sync::Arc, time::Duration};

use moor_block::{CommandEntry, SequencerInput, SequencerInputKind};
use moor_common::{
    envelope::{Envelope, EnvelopeKind},
    tasks::Session,
};
use moor_kernel::{
    SchedulerClient,
    tasks::{
        block_driver::RunSummary,
        envelope_admission::{EnvelopeRun, OnAdmitted},
        sequencer::InputReceipt,
    },
};
use moor_runtime_api::{
    RpcMessageError,
    api::{ClientEvent, ClientReply, ClientRequest, ConnectType, InvocationMode},
};
use moor_var::Obj;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    rpc::{
        message_handler::RpcMessageHandler, message_handler_envelope::rejected,
        session::SessionActions,
    },
    sequencer::InputReply,
};

/// How long an RPC thread waits for its input to run.
const INPUT_TIMEOUT: Duration = Duration::from_secs(30);

const WELCOME: &str = "RuneWorld sequencer. Log in with a signed connect (development identity: \
                       `connect <any name> <any password>`).";

fn envelope_run(
    receipt: InputReceipt,
    kind: Option<EnvelopeKind>,
    session: u32,
) -> Result<EnvelopeRun, RpcMessageError> {
    let admission = receipt.admission.ok_or_else(|| {
        RpcMessageError::InternalError("the sequencer did not run an envelope".into())
    })?;
    Ok(EnvelopeRun {
        kind,
        session,
        admission,
        task_id: receipt.task_id,
        result: receipt.result,
        run: RunSummary::default(),
        reservation: None,
    })
}

fn wait(receipt: flume::Receiver<InputReply>) -> Result<InputReceipt, RpcMessageError> {
    receipt
        .recv_timeout(INPUT_TIMEOUT)
        .map_err(|e| RpcMessageError::InternalError(format!("no receipt from the sequencer: {e}")))?
        .map_err(RpcMessageError::InternalError)
}

impl RpcMessageHandler {
    /// Admit and run one envelope: through the sequencer's queue in sequencer mode, otherwise on
    /// the deterministic scheduler's request thread.
    pub(crate) fn run_envelope_routed(
        &self,
        scheduler_client: &SchedulerClient,
        bytes: Vec<u8>,
        session: Arc<dyn Session>,
        on_admitted: Option<OnAdmitted>,
    ) -> Result<EnvelopeRun, RpcMessageError> {
        let Some(sequencer) = self.sequencer.get() else {
            return scheduler_client
                .submit_envelope(bytes, session, on_admitted, INPUT_TIMEOUT)
                .map_err(RpcMessageError::TaskError);
        };
        // Pre-verification (ADR 0005 decision 3): the bytes must at least be an envelope. The
        // admission step in the block re-checks everything against state.
        let decoded = Envelope::decode(&bytes)
            .map_err(|e| RpcMessageError::InvalidRequest(format!("not an envelope: {e}")))?;
        let receipt = sequencer
            .enqueue(CommandEntry::Envelope(bytes), session, on_admitted)
            .map_err(RpcMessageError::InternalError)?;
        envelope_run(wait(receipt)?, Some(decoded.kind), decoded.session)
    }

    /// Tell the client how its input's task ended, as the task monitor does for ordinary tasks.
    pub(crate) fn publish_envelope_completion(&self, client_id: Uuid, run: &EnvelopeRun) {
        let Some(task_id) = run.task_id else {
            return;
        };
        let event = match &run.result {
            Some(Ok(value)) => ClientEvent::TaskSuccess {
                task_id: task_id as u64,
                result: value.clone(),
            },
            Some(Err(error)) => ClientEvent::TaskError {
                task_id: task_id as u64,
                error: error.clone(),
            },
            None => ClientEvent::TaskSuspended {
                task_id: task_id as u64,
            },
        };
        if let Err(e) = self
            .mailbox_sender
            .send(SessionActions::PublishTaskCompletion(client_id, event))
        {
            warn!(error = ?e, %client_id, "could not publish an envelope's completion");
        }
    }

    /// Sequencer mode: the `Disconnected` sequencer input for `player`.
    pub(crate) fn enqueue_disconnect(&self, player: Obj, session: Arc<dyn Session>) -> bool {
        let Some(sequencer) = self.sequencer.get() else {
            return false;
        };
        if !player.is_oid() || player.id().0 < 0 {
            // A connection that never logged in has no player to disconnect.
            return true;
        }
        let entry = CommandEntry::Sequencer(SequencerInput {
            kind: SequencerInputKind::Disconnected,
            player: player.id().0,
        });
        if let Err(e) = sequencer.enqueue(entry, session, None) {
            warn!(error = %e, %player, "could not queue a disconnect");
        }
        true
    }

    /// Sequencer mode: handle `request` if it needs sequencer-specific treatment. `None` means
    /// the ordinary path applies (reads, connection bookkeeping, envelopes, which route through
    /// [`Self::run_envelope_routed`]).
    pub(crate) fn sequencer_route(
        &self,
        scheduler_client: &SchedulerClient,
        client_id: Uuid,
        request: &ClientRequest,
    ) -> Option<Result<ClientReply, RpcMessageError>> {
        self.sequencer.get()?;
        match request {
            ClientRequest::LoginCommand {
                client_token,
                connect_args,
                ..
            } => Some((|| {
                let connection = self.client_auth(client_token.clone(), client_id)?;
                let wants_login = connect_args
                    .first()
                    .is_some_and(|w| w.starts_with("co") || w.starts_with("cr"));
                if wants_login && self.dev_signer.get().is_some() {
                    return self.dev_connect(scheduler_client, client_id, connection);
                }
                // The welcome text is MOO code outside the log; show a fixed banner instead.
                let session = self.new_rpc_session(client_id, connection, connection);
                let _ = session.send_system_msg(connection, WELCOME);
                Ok(ClientReply::LoginResult {
                    success: false,
                    auth_token: None,
                    connect_type: ConnectType::NoConnect,
                    player: None,
                    player_flags: 0,
                })
            })()),
            ClientRequest::Command {
                auth_token,
                command,
                mode: InvocationMode::Connected { client_token },
                ..
            } => Some((|| {
                let (connection, player) =
                    self.verify_tokens(client_token.clone(), auth_token.clone(), client_id)?;
                let Some(dev) = self.dev_signer.get() else {
                    return Err(RpcMessageError::PermissionDenied);
                };
                if player != dev.player() {
                    warn!(%player, "the development identity signs only for its own player");
                    return Err(RpcMessageError::PermissionDenied);
                }
                let _ = self
                    .connections
                    .record_client_activity(client_id, connection);
                let session = Arc::new(self.new_rpc_session(client_id, connection, player));
                let sequencer = self.sequencer.get().expect("checked above");
                let receipt = dev
                    .sign_and_enqueue(
                        EnvelopeKind::Command,
                        command.clone().into_bytes(),
                        session,
                        None,
                        scheduler_client,
                        sequencer,
                    )
                    .map_err(RpcMessageError::InternalError)?;
                let run = envelope_run(wait(receipt)?, Some(EnvelopeKind::Command), 0)?;
                if let Some(error) = rejected(&run) {
                    return Err(error);
                }
                self.publish_envelope_completion(client_id, &run);
                Ok(ClientReply::TaskSubmitted {
                    task_id: run.task_id.unwrap_or(0) as u64,
                })
            })()),
            ClientRequest::Attach { connect_type, .. }
                if *connect_type != ConnectType::NoConnect =>
            {
                warn!(%client_id, "connecting Attach runs user_connected outside the log; refused");
                Some(Err(RpcMessageError::PermissionDenied))
            }
            ClientRequest::VerifiedOAuthLogin { connect_args, .. }
                if connect_args.first().map(String::as_str)
                    != Some(crate::rpc::deterministic_gate::SIGNED_CONNECT) =>
            {
                Some(Err(RpcMessageError::PermissionDenied))
            }
            _ => None,
        }
    }

    /// Development identity: a password login becomes a connect signed for the development player.
    fn dev_connect(
        &self,
        scheduler_client: &SchedulerClient,
        client_id: Uuid,
        connection: Obj,
    ) -> Result<ClientReply, RpcMessageError> {
        let dev = self.dev_signer.get().expect("checked by the caller");
        let sequencer = self.sequencer.get().expect("checked by the caller");
        let session = Arc::new(self.new_rpc_session(client_id, connection, connection));
        let receipt = dev
            .sign_and_enqueue(
                EnvelopeKind::Connect,
                Vec::new(),
                session,
                Some(self.bind_on_admit(connection)),
                scheduler_client,
                sequencer,
            )
            .map_err(RpcMessageError::InternalError)?;
        let run = envelope_run(wait(receipt)?, Some(EnvelopeKind::Connect), 0)?;
        info!(player = %dev.player(), %client_id, "development identity connected");
        self.finish_signed_connect(scheduler_client, client_id, run)
    }
}
