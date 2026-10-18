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

//! The daemon in deterministic mode (RuneWorld ADR 0005 decision 8): gated RPCs, a signed
//! `connect` minting the auth token, signed envelopes over `ClientData`, revocation booting.
//!
//! Deterministic mode is process-global, so this test would change the behaviour of every other
//! daemon test running beside it. It is ignored by default; run it alone:
//! `cargo test -p moor-daemon --lib deterministic_rpc -- --ignored --test-threads=1`.

use super::{
    MockTransport,
    test_env::{self, TestEnvironment},
};
use moor_common::{
    deterministic::{self, DeterministicMode},
    envelope::{self, Delegation, Domain, EnvelopeKind, SessionSigner, WalletSigner, scope},
    model::ObjectRef,
    tasks::NoopClientSession,
};
use moor_kernel::{
    config::{DevShortcuts, FeaturesConfig},
    tasks::{TaskHandle, TaskNotification},
};
use moor_runtime_api::{
    AuthToken, ClientToken, RpcMessageError,
    api::{ClientReply, ClientRequest, EntityType, InvocationMode},
};
use moor_var::{Obj, SYSTEM_OBJECT, Symbol, Var, v_str};
use std::{path::PathBuf, sync::Arc, time::Duration};
use uuid::Uuid;

use crate::rpc::deterministic_gate::{ENVELOPE_KIND, ENVELOPE_NAMESPACE, SIGNED_CONNECT};

const DOMAIN: Domain = Domain { salt: [0; 32] };

struct Fixture {
    env: TestEnvironment<MockTransport>,
    features: Arc<FeaturesConfig>,
}

impl Fixture {
    fn new(dev: DevShortcuts) -> Self {
        let _ = moor_kernel::initialize_server_symmetric_key([42; 32]);
        deterministic::disable();
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../cores/lambda-moor/src");
        let features = Arc::new(FeaturesConfig::default());
        let env = test_env::setup_test_environment_with_core(
            Arc::new(MockTransport::new()),
            |config| {
                config.features = features.clone();
                config.deterministic = DeterministicMode::on();
                config.dev = dev;
            },
            Some(&path),
        );
        let fixture = Self { env, features };
        fixture.eval(
            r#"add_verb(#0, {#2, "rxd", "create_wallet_player"}, {"this", "none", "this"});
               set_verb_code(#0, "create_wallet_player", {"p = create($player);", "set_player_flag(p, 1);", "p.owner = p;", "p.name = args[2];", "return p;"});
               return 1;"#,
        );
        fixture
    }

    fn eval(&self, source: &str) -> Var {
        let task = self
            .env
            .scheduler_client
            .submit_eval_task(
                &Obj::mk_id(2),
                &Obj::mk_id(2),
                source.into(),
                None,
                Arc::new(NoopClientSession::new()),
                self.features.clone(),
            )
            .unwrap();
        wait(task)
    }

    fn call(&self, id: Uuid, request: ClientRequest) -> Result<ClientReply, RpcMessageError> {
        self.env.rpc_server.runtime_api().handle_client_request(
            self.env.scheduler_client.clone(),
            id,
            request,
        )
    }

    fn connection(&self) -> (Uuid, ClientToken) {
        let id = Uuid::new_v4();
        let reply = self
            .call(
                id,
                ClientRequest::ConnectionEstablish {
                    peer_addr: "127.0.0.1".into(),
                    local_port: 7777,
                    remote_port: 12345,
                    acceptable_content_types: None,
                    connection_attributes: None,
                },
            )
            .unwrap();
        let ClientReply::NewConnection { client_token, .. } = reply else {
            panic!("{reply:?}")
        };
        (id, client_token)
    }

    fn envelope(
        &self,
        id: Uuid,
        token: &ClientToken,
        bytes: &[u8],
    ) -> Result<ClientReply, RpcMessageError> {
        self.call(
            id,
            ClientRequest::ClientData {
                client_token: token.clone(),
                auth_token: None,
                handler_object: SYSTEM_OBJECT,
                namespace: Symbol::mk(ENVELOPE_NAMESPACE),
                kind: ENVELOPE_KIND.into(),
                payload: v_str(&envelope::hex(bytes)),
            },
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        deterministic::disable();
    }
}

fn wait(task: TaskHandle) -> Var {
    loop {
        match task
            .receiver()
            .recv_timeout(Duration::from_secs(20))
            .expect("task timeout")
        {
            (_, Ok(TaskNotification::Result(value))) => return value,
            (_, Ok(TaskNotification::Suspended)) => continue,
            (_, Err(error)) => panic!("{error:?}"),
        }
    }
}

fn eval_request(token: AuthToken, client_token: ClientToken) -> ClientRequest {
    ClientRequest::Eval {
        auth_token: token,
        expression: "return 1;".into(),
        mode: InvocationMode::Connected { client_token },
    }
}

#[test]
#[ignore = "turns on process-global deterministic mode; run alone with --ignored --test-threads=1"]
fn deterministic_daemon_signed_flow() {
    let fixture = Fixture::new(DevShortcuts::default());
    let (id, client_token) = fixture.connection();
    let wallet = WalletSigner::from_secret([1; 32]).unwrap();
    let key = SessionSigner::from_seed([2; 32]);

    // Gated before any token is looked at.
    assert!(matches!(
        fixture.call(
            id,
            eval_request(AuthToken("x".into()), client_token.clone())
        ),
        Err(RpcMessageError::PermissionDenied)
    ));

    // Delegate with create over ClientData.
    let delegate = wallet
        .delegate(
            &DOMAIN,
            &key,
            Delegation {
                session_key: key.public_key(),
                box_key: [0; 32],
                scope: scope::PLAY,
                expires: 1_000_000,
                nonce: 1,
                create: true,
            },
            100,
        )
        .unwrap();
    assert!(matches!(
        fixture.envelope(id, &client_token, &delegate.encode()),
        Ok(ClientReply::TaskSubmitted { .. })
    ));
    let player = fixture
        .eval(&format!(
            "return #0.admission_wallets[\"{}\"][1];",
            wallet.address().to_hex()
        ))
        .as_object()
        .unwrap();

    // A signed connect mints the auth token.
    let connect = key.envelope(
        &DOMAIN,
        player.as_u64(),
        EnvelopeKind::Connect,
        1,
        1,
        100,
        vec![],
    );
    let reply = fixture
        .call(
            id,
            ClientRequest::VerifiedOAuthLogin {
                client_token: client_token.clone(),
                connect_args: vec![SIGNED_CONNECT.into(), envelope::hex(&connect.encode())],
                do_attach: true,
            },
        )
        .unwrap();
    let ClientReply::LoginResult {
        success: true,
        auth_token: Some(auth_token),
        player: Some(logged_in),
        ..
    } = reply
    else {
        panic!("{reply:?}");
    };
    assert_eq!(logged_in, player);

    // The token authorises reads, not writes.
    assert!(matches!(
        fixture.call(id, eval_request(auth_token.clone(), client_token.clone())),
        Err(RpcMessageError::PermissionDenied)
    ));
    assert!(matches!(
        fixture.call(
            id,
            ClientRequest::Retrieve {
                auth_token: auth_token.clone(),
                object: ObjectRef::Id(player),
                entity_type: EntityType::Property,
                name: Symbol::mk("wallet"),
            }
        ),
        Ok(ClientReply::PropertyValue { .. })
    ));
    assert!(matches!(
        fixture.call(
            id,
            ClientRequest::Command {
                auth_token: auth_token.clone(),
                handler_object: SYSTEM_OBJECT,
                command: "look".into(),
                mode: InvocationMode::Connected {
                    client_token: client_token.clone()
                },
            }
        ),
        Err(RpcMessageError::PermissionDenied)
    ));

    // A signed command runs; replaying it is rejected.
    let look = key.envelope(
        &DOMAIN,
        player.as_u64(),
        EnvelopeKind::Command,
        1,
        2,
        100,
        b"look".to_vec(),
    );
    assert!(matches!(
        fixture.envelope(id, &client_token, &look.encode()),
        Ok(ClientReply::TaskSubmitted { .. })
    ));
    assert!(matches!(
        fixture.envelope(id, &client_token, &look.encode()),
        Err(RpcMessageError::LoginTaskFailed(_))
    ));

    // Revoking the session boots the connection opened through it.
    let revoke = key.envelope(
        &DOMAIN,
        player.as_u64(),
        EnvelopeKind::Revoke,
        1,
        3,
        100,
        vec![],
    );
    assert!(matches!(
        fixture.envelope(id, &client_token, &revoke.encode()),
        Ok(ClientReply::TaskSubmitted { .. })
    ));
    assert_eq!(fixture.env.connections.player_object_for_client(id), None);
}

/// A daemon-signed auth token for `player`, as the PASETO login path would mint.
pub(super) fn auth_token_for(player: Obj) -> AuthToken {
    use rusty_paseto::core::{Footer, Paseto, PasetoAsymmetricPrivateKey, Payload, Public, V4};
    let (_, key) = test_env::create_test_keys();
    AuthToken(
        Paseto::<V4, Public>::default()
            .set_footer(Footer::from(moor_runtime_api::MOOR_AUTH_TOKEN_FOOTER))
            .set_payload(Payload::from(
                serde_json::json!({"player": player.to_string()})
                    .to_string()
                    .as_str(),
            ))
            .try_sign(&PasetoAsymmetricPrivateKey::from(&key))
            .unwrap(),
    )
}

#[test]
#[ignore = "turns on process-global deterministic mode; run alone with --ignored --test-threads=1"]
fn wizard_eval_is_refused_without_the_dev_flag_and_runs_with_it() {
    let refused = {
        let fixture = Fixture::new(DevShortcuts::default());
        let (id, client_token) = fixture.connection();
        fixture.call(
            id,
            eval_request(auth_token_for(Obj::mk_id(2)), client_token),
        )
    };
    let allowed = {
        let fixture = Fixture::new(DevShortcuts {
            unsigned_rpc: true,
            identity: None,
        });
        let (id, _) = fixture.connection();
        fixture.call(
            id,
            ClientRequest::Eval {
                auth_token: auth_token_for(Obj::mk_id(2)),
                expression: "return 1;".into(),
                mode: InvocationMode::CaptureOutput { timeout: None },
            },
        )
    };
    assert!(
        matches!(refused, Err(RpcMessageError::PermissionDenied))
            && matches!(allowed, Ok(ClientReply::InvocationResponse { .. })),
        "{refused:?} {allowed:?}"
    );
}
