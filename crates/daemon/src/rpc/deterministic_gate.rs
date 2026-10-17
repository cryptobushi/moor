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

//! RPC gating in deterministic mode (RuneWorld ADR 0005 decision 8 and reviewer note 5).
//!
//! In deterministic mode a PASETO authorises reads and event streams only. Every client request
//! that would change world state without a signed envelope is refused unless a development
//! shortcut allows it:
//!
//! | Request | Without shortcuts | Allowed by |
//! |---|---|---|
//! | `Eval`, `InvokeVerb` (both modes), `Program`, `UpdateProperty`, `InvokeSystemHandler`, `OutOfBand`, `RequestedInput`, capture-mode `Command`, `BatchWorldState` with `UpdateProperty`/`ProgramVerb`, `ClientData` (other than an envelope) | refused | `--dev-unsigned-rpc` |
//! | connected `Command` (unsigned text), `LoginCommand` with arguments (password login), `VerifiedOAuthLogin` other than `signed_connect`, `Attach` that runs a connect hook | refused | `--dev-identity` |
//! | `ClientData{namespace: "runeworld", kind: "envelope"}`, `VerifiedOAuthLogin` `signed_connect` | admitted by the STF | - |
//!
//! Everything else is a read, an event-stream operation, connection bookkeeping outside the STF
//! (`ConnectionEstablish`, `ClientPong`, `Detach`, `SetClientAttribute`, `Reattach`), the fixed
//! welcome message, or the per-player event log outside world state, and passes.

use moor_kernel::config::DevShortcuts;
use moor_runtime_api::api::{BatchAction, ClientRequest, ConnectType, InvocationMode};

/// `ClientData` namespace and kind carrying a signed envelope.
pub const ENVELOPE_NAMESPACE: &str = "runeworld";
pub const ENVELOPE_KIND: &str = "envelope";
/// `VerifiedOAuthLogin` operation carrying a signed `connect` envelope.
pub const SIGNED_CONNECT: &str = "signed_connect";

/// Which shortcut a refused request needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Needs {
    UnsignedRpc,
    Identity,
}

/// The name of a request, for refusal messages.
fn name(request: &ClientRequest) -> &'static str {
    match request {
        ClientRequest::Eval { .. } => "Eval",
        ClientRequest::InvokeVerb { .. } => "InvokeVerb",
        ClientRequest::Program { .. } => "Program",
        ClientRequest::UpdateProperty { .. } => "UpdateProperty",
        ClientRequest::InvokeSystemHandler { .. } => "InvokeSystemHandler",
        ClientRequest::OutOfBand { .. } => "OutOfBand",
        ClientRequest::RequestedInput { .. } => "RequestedInput",
        ClientRequest::Command { .. } => "Command",
        ClientRequest::BatchWorldState { .. } => "BatchWorldState",
        ClientRequest::ClientData { .. } => "ClientData",
        ClientRequest::LoginCommand { .. } => "LoginCommand",
        ClientRequest::VerifiedOAuthLogin { .. } => "VerifiedOAuthLogin",
        ClientRequest::Attach { .. } => "Attach",
        _ => "request",
    }
}

/// What a request needs in deterministic mode: `None` when it may run as is.
#[must_use]
pub fn requirement(request: &ClientRequest) -> Option<Needs> {
    match request {
        ClientRequest::Eval { .. }
        | ClientRequest::InvokeVerb { .. }
        | ClientRequest::Program { .. }
        | ClientRequest::UpdateProperty { .. }
        | ClientRequest::InvokeSystemHandler { .. }
        | ClientRequest::OutOfBand { .. }
        | ClientRequest::RequestedInput { .. } => Some(Needs::UnsignedRpc),
        ClientRequest::Command { mode, .. } => match mode {
            InvocationMode::CaptureOutput { .. } => Some(Needs::UnsignedRpc),
            InvocationMode::Connected { .. } => Some(Needs::Identity),
        },
        ClientRequest::BatchWorldState { actions, .. } => actions
            .iter()
            .any(|entry| {
                matches!(
                    entry.action,
                    BatchAction::UpdateProperty { .. } | BatchAction::ProgramVerb { .. }
                )
            })
            .then_some(Needs::UnsignedRpc),
        ClientRequest::ClientData {
            namespace, kind, ..
        } => (namespace.as_str() != ENVELOPE_NAMESPACE || kind.as_str() != ENVELOPE_KIND)
            .then_some(Needs::UnsignedRpc),
        ClientRequest::LoginCommand { connect_args, .. } => {
            (!connect_args.is_empty()).then_some(Needs::Identity)
        }
        ClientRequest::VerifiedOAuthLogin { connect_args, .. } => {
            (connect_args.first().map(String::as_str) != Some(SIGNED_CONNECT))
                .then_some(Needs::Identity)
        }
        ClientRequest::Attach { connect_type, .. } => {
            (*connect_type != ConnectType::NoConnect).then_some(Needs::Identity)
        }
        _ => None,
    }
}

/// Refuse `request` unless it may run in deterministic mode under `dev`. The error is the refusal
/// message.
pub fn check(request: &ClientRequest, dev: &DevShortcuts) -> Result<(), String> {
    match requirement(request) {
        None => Ok(()),
        Some(Needs::UnsignedRpc) if dev.unsigned_rpc => Ok(()),
        Some(Needs::Identity) if dev.identity.is_some() || dev.unsigned_rpc => Ok(()),
        Some(Needs::UnsignedRpc) => Err(format!(
            "{} changes world state without a signed envelope; refused in deterministic mode \
             (development: --dev-unsigned-rpc)",
            name(request)
        )),
        Some(Needs::Identity) => Err(format!(
            "{} needs a signed connect or command in deterministic mode \
             (development: --dev-identity)",
            name(request)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moor_common::model::ObjectRef;
    use moor_runtime_api::{AuthToken, ClientToken, api::BatchActionEntry};
    use moor_var::{Obj, SYSTEM_OBJECT, Symbol, v_int, v_str};

    fn token() -> AuthToken {
        AuthToken("t".into())
    }

    fn connected() -> InvocationMode {
        InvocationMode::Connected {
            client_token: ClientToken("c".into()),
        }
    }

    fn capture() -> InvocationMode {
        InvocationMode::CaptureOutput { timeout: None }
    }

    fn eval() -> ClientRequest {
        ClientRequest::Eval {
            auth_token: token(),
            expression: "return 1;".into(),
            mode: connected(),
        }
    }

    fn update_property() -> ClientRequest {
        ClientRequest::UpdateProperty {
            auth_token: token(),
            object: ObjectRef::Id(SYSTEM_OBJECT),
            property: Symbol::mk("x"),
            value: v_int(1),
        }
    }

    fn off() -> DevShortcuts {
        DevShortcuts::default()
    }

    #[test]
    fn eval_is_refused_without_the_dev_flag() {
        assert!(check(&eval(), &off()).is_err());
    }

    #[test]
    fn eval_is_allowed_with_dev_unsigned_rpc() {
        let dev = DevShortcuts {
            unsigned_rpc: true,
            identity: None,
        };
        assert_eq!(check(&eval(), &dev), Ok(()));
    }

    #[test]
    fn dev_identity_does_not_open_eval() {
        let dev = DevShortcuts {
            unsigned_rpc: false,
            identity: Some("k.json".into()),
        };
        assert!(check(&eval(), &dev).is_err());
    }

    #[test]
    fn every_paseto_only_write_is_refused() {
        let requests = [
            eval(),
            ClientRequest::Eval {
                auth_token: token(),
                expression: "x".into(),
                mode: capture(),
            },
            ClientRequest::InvokeVerb {
                auth_token: token(),
                object: ObjectRef::Id(SYSTEM_OBJECT),
                verb: Symbol::mk("v"),
                args: vec![],
                mode: connected(),
            },
            ClientRequest::InvokeVerb {
                auth_token: token(),
                object: ObjectRef::Id(SYSTEM_OBJECT),
                verb: Symbol::mk("v"),
                args: vec![],
                mode: capture(),
            },
            ClientRequest::Program {
                auth_token: token(),
                object: ObjectRef::Id(SYSTEM_OBJECT),
                verb: Symbol::mk("v"),
                code: vec![],
            },
            update_property(),
            ClientRequest::Command {
                auth_token: token(),
                handler_object: SYSTEM_OBJECT,
                command: "look".into(),
                mode: capture(),
            },
            ClientRequest::BatchWorldState {
                auth_token: token(),
                actions: vec![BatchActionEntry {
                    id: "1".into(),
                    action: BatchAction::ProgramVerb {
                        obj: ObjectRef::Id(SYSTEM_OBJECT),
                        verb_name: Symbol::mk("v"),
                        code: vec![],
                    },
                }],
                rollback: false,
            },
            ClientRequest::ClientData {
                client_token: ClientToken("c".into()),
                auth_token: Some(token()),
                handler_object: SYSTEM_OBJECT,
                namespace: Symbol::mk("ui"),
                kind: "click".into(),
                payload: v_int(0),
            },
        ];
        let refused: Vec<bool> = requests.iter().map(|r| check(r, &off()).is_err()).collect();
        assert_eq!(refused, vec![true; requests.len()]);
    }

    #[test]
    fn unsigned_connected_command_needs_dev_identity() {
        let command = ClientRequest::Command {
            auth_token: token(),
            handler_object: SYSTEM_OBJECT,
            command: "look".into(),
            mode: connected(),
        };
        assert_eq!(requirement(&command), Some(Needs::Identity));
    }

    #[test]
    fn password_login_needs_dev_identity() {
        let login = ClientRequest::LoginCommand {
            client_token: ClientToken("c".into()),
            handler_object: SYSTEM_OBJECT,
            connect_args: vec!["connect".into(), "wizard".into(), "pw".into()],
            do_attach: true,
            registration_data: None,
        };
        assert_eq!(requirement(&login), Some(Needs::Identity));
    }

    #[test]
    fn welcome_login_passes() {
        let welcome = ClientRequest::LoginCommand {
            client_token: ClientToken("c".into()),
            handler_object: SYSTEM_OBJECT,
            connect_args: vec![],
            do_attach: false,
            registration_data: None,
        };
        assert_eq!(check(&welcome, &off()), Ok(()));
    }

    #[test]
    fn signed_connect_and_envelopes_pass() {
        let connect = ClientRequest::VerifiedOAuthLogin {
            client_token: ClientToken("c".into()),
            connect_args: vec![SIGNED_CONNECT.into(), "00".into()],
            do_attach: true,
        };
        let envelope = ClientRequest::ClientData {
            client_token: ClientToken("c".into()),
            auth_token: None,
            handler_object: SYSTEM_OBJECT,
            namespace: Symbol::mk(ENVELOPE_NAMESPACE),
            kind: ENVELOPE_KIND.into(),
            payload: v_str("00"),
        };
        assert_eq!(
            (check(&connect, &off()), check(&envelope, &off())),
            (Ok(()), Ok(()))
        );
    }

    #[test]
    fn reads_pass() {
        let reads = [
            ClientRequest::Retrieve {
                auth_token: token(),
                object: ObjectRef::Id(SYSTEM_OBJECT),
                entity_type: moor_runtime_api::api::EntityType::Property,
                name: Symbol::mk("name"),
            },
            ClientRequest::BatchWorldState {
                auth_token: token(),
                actions: vec![BatchActionEntry {
                    id: "1".into(),
                    action: BatchAction::GetObjectFlags { obj: Obj::mk_id(1) },
                }],
                rollback: false,
            },
            ClientRequest::ListObjects {
                auth_token: token(),
            },
        ];
        assert!(reads.iter().all(|r| check(r, &off()).is_ok()));
    }

    #[test]
    fn noconnect_attach_passes_but_connecting_attach_needs_identity() {
        let attach = |connect_type| ClientRequest::Attach {
            auth_token: token(),
            connect_type,
            handler_object: SYSTEM_OBJECT,
            peer_addr: "h".into(),
            local_port: 0,
            remote_port: 0,
            acceptable_content_types: None,
        };
        assert_eq!(
            (
                requirement(&attach(ConnectType::NoConnect)),
                requirement(&attach(ConnectType::Connected))
            ),
            (None, Some(Needs::Identity))
        );
    }
}
