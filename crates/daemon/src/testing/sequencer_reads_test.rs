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

//! Read RPCs in sequencer mode (RuneWorld ADR 0006 decision 1, S0-8's open reads, issue #53).
//!
//! The daemon runs `--sequencer` without scheduler service threads: the block driver owns the
//! scheduler and only logged inputs may run work. Every read must be answered from the last
//! committed snapshot on the RPC thread, consume no command index and leave the state root alone.
//! `BatchWorldState` used to be submitted as a task that nothing served, so `/v1/objects/query`
//! (the bridge's roster query) returned HTTP 500.
//!
//! Deterministic mode is process-global, so these tests are ignored by default; run them alone:
//! `cargo test -p moor-daemon --lib sequencer_reads -- --ignored --test-threads=1`.

use super::{
    MockTransport,
    deterministic_rpc_test::auth_token_for,
    test_env::{self, TestEnvironment},
};
use moor_common::{
    deterministic::{self, DeterministicMode},
    model::ObjectRef,
};
use moor_kernel::config::{DevShortcuts, FeaturesConfig};
use moor_runtime_api::{
    AuthToken, RpcMessageError,
    api::{
        BatchAction, BatchActionEntry, ClientReply, ClientRequest, EntityType, HistoryRecall,
        InvocationMode, WorldStateResult,
    },
};
use moor_var::{Obj, SYSTEM_OBJECT, Symbol, v_int};
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;

const WIZARD: Obj = Obj::mk_id(2);
const ROOT_CLASS: Obj = Obj::mk_id(1);
const PLAYER: Obj = Obj::mk_id(6);

struct Sequencer {
    env: TestEnvironment<MockTransport>,
    token: AuthToken,
    client: Uuid,
}

impl Sequencer {
    fn new() -> Self {
        let _ = moor_kernel::initialize_server_symmetric_key([42; 32]);
        deterministic::disable();
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../cores/lambda-moor/src");
        let env = test_env::setup_sequencer_environment(
            Arc::new(MockTransport::new()),
            |config| {
                config.features = Arc::new(FeaturesConfig::default());
                config.deterministic = DeterministicMode::on();
                config.dev = DevShortcuts::default();
            },
            Some(&path),
        );
        assert!(env.scheduler_client.is_sequencer_owned());
        Self {
            env,
            token: auth_token_for(WIZARD),
            client: Uuid::new_v4(),
        }
    }

    fn call(&self, request: ClientRequest) -> Result<ClientReply, RpcMessageError> {
        self.env.rpc_server.runtime_api().handle_client_request(
            self.env.scheduler_client.clone(),
            self.client,
            request,
        )
    }

    /// The command index and state root, before and after `read`, which must not move either.
    fn read<T>(&mut self, read: impl FnOnce(&Self) -> T) -> T {
        let index = deterministic::current().map(|c| c.command);
        let root = self.env.driver.as_ref().unwrap().state_root().unwrap().root;
        let out = read(self);
        assert_eq!(deterministic::current().map(|c| c.command), index);
        assert_eq!(
            self.env.driver.as_ref().unwrap().state_root().unwrap().root,
            root
        );
        out
    }

    fn batch(&self, action: BatchAction) -> Result<ClientReply, RpcMessageError> {
        self.call(ClientRequest::BatchWorldState {
            auth_token: self.token.clone(),
            actions: vec![BatchActionEntry {
                id: "1".into(),
                action,
            }],
            rollback: false,
        })
    }

    fn batch_result(&self, action: BatchAction) -> WorldStateResult {
        match self.batch(action) {
            Ok(ClientReply::BatchWorldStateReply { mut results }) => {
                assert_eq!(results.len(), 1);
                let entry = results.remove(0);
                assert_eq!(entry.id, "1");
                entry.result
            }
            other => panic!("{other:?}"),
        }
    }
}

impl Drop for Sequencer {
    fn drop(&mut self) {
        deterministic::disable();
    }
}

#[test]
#[ignore = "turns on process-global deterministic mode; run alone with --ignored --test-threads=1"]
fn batch_roster_query_is_answered_in_sequencer_mode() {
    let mut s = Sequencer::new();
    let result = s.read(|s| {
        s.batch_result(BatchAction::QueryObjects {
            parent: None,
            location: None,
            owner: Some(WIZARD),
            flags_all: 0,
            flags_any: 0,
        })
    });
    assert!(matches!(result, WorldStateResult::QueriedObjects(objects) if !objects.is_empty()));
}

#[test]
#[ignore = "turns on process-global deterministic mode; run alone with --ignored --test-threads=1"]
fn batch_reads_are_answered_in_sequencer_mode() {
    let mut s = Sequencer::new();
    let kinds = s.read(|s| {
        [
            BatchAction::GetObjectFlags { obj: WIZARD },
            BatchAction::ListObjects,
            BatchAction::RequestAllObjects,
            BatchAction::RequestProperties {
                obj: ObjectRef::Id(WIZARD),
                inherited: true,
            },
            BatchAction::RequestVerbs {
                obj: ObjectRef::Id(SYSTEM_OBJECT),
                inherited: false,
            },
            BatchAction::ResolveObject {
                objref: ObjectRef::Id(WIZARD),
            },
            BatchAction::RequestProperty {
                obj: ObjectRef::Id(ROOT_CLASS),
                property: Symbol::mk("aliases"),
            },
        ]
        .map(|action| std::mem::discriminant(&s.batch_result(action)))
    });
    assert_eq!(
        kinds.iter().collect::<std::collections::HashSet<_>>().len(),
        kinds.len()
    );
}

#[test]
#[ignore = "turns on process-global deterministic mode; run alone with --ignored --test-threads=1"]
fn batch_writes_are_still_refused_in_sequencer_mode() {
    let mut s = Sequencer::new();
    let refused = s.read(|s| {
        s.batch(BatchAction::UpdateProperty {
            obj: ObjectRef::Id(WIZARD),
            property: Symbol::mk("name"),
            value: v_int(1),
        })
    });
    assert!(matches!(refused, Err(RpcMessageError::PermissionDenied)));
}

#[test]
#[ignore = "turns on process-global deterministic mode; run alone with --ignored --test-threads=1"]
fn capture_mode_command_is_still_refused_in_sequencer_mode() {
    let mut s = Sequencer::new();
    let refused = s.read(|s| {
        s.call(ClientRequest::Command {
            auth_token: s.token.clone(),
            handler_object: SYSTEM_OBJECT,
            command: "look".into(),
            mode: InvocationMode::CaptureOutput { timeout: None },
        })
    });
    assert!(matches!(refused, Err(RpcMessageError::PermissionDenied)));
}

#[test]
#[ignore = "turns on process-global deterministic mode; run alone with --ignored --test-threads=1"]
fn retrieve_property_and_verb_are_answered_in_sequencer_mode() {
    let mut s = Sequencer::new();
    let (property, verb) = s.read(|s| {
        let retrieve = |entity_type, object: Obj, name: &str| {
            s.call(ClientRequest::Retrieve {
                auth_token: s.token.clone(),
                object: ObjectRef::Id(object),
                entity_type,
                name: Symbol::mk(name),
            })
        };
        (
            retrieve(EntityType::Property, ROOT_CLASS, "aliases"),
            retrieve(EntityType::Verb, PLAYER, "@more"),
        )
    });
    assert!(
        matches!(property, Ok(ClientReply::PropertyValue { .. }))
            && matches!(verb, Ok(ClientReply::VerbValue { .. })),
        "{property:?} {verb:?}"
    );
}

#[test]
#[ignore = "turns on process-global deterministic mode; run alone with --ignored --test-threads=1"]
fn properties_and_verbs_listings_are_answered_in_sequencer_mode() {
    let mut s = Sequencer::new();
    let (properties, verbs) = s.read(|s| {
        (
            s.call(ClientRequest::Properties {
                auth_token: s.token.clone(),
                object: ObjectRef::Id(WIZARD),
                inherited: true,
            }),
            s.call(ClientRequest::Verbs {
                auth_token: s.token.clone(),
                object: ObjectRef::Id(SYSTEM_OBJECT),
                inherited: false,
            }),
        )
    });
    assert!(
        matches!(properties, Ok(ClientReply::PropertiesReply { .. }))
            && matches!(verbs, Ok(ClientReply::VerbsReply { .. })),
        "{properties:?} {verbs:?}"
    );
}

#[test]
#[ignore = "turns on process-global deterministic mode; run alone with --ignored --test-threads=1"]
fn object_listing_and_resolve_are_answered_in_sequencer_mode() {
    let mut s = Sequencer::new();
    let (list, resolved) = s.read(|s| {
        (
            s.call(ClientRequest::ListObjects {
                auth_token: s.token.clone(),
            }),
            s.call(ClientRequest::Resolve {
                auth_token: s.token.clone(),
                objref: ObjectRef::Id(WIZARD),
            }),
        )
    });
    assert!(
        matches!(list, Ok(ClientReply::ListObjectsReply { .. }))
            && matches!(resolved, Ok(ClientReply::ResolveResult { .. })),
        "{list:?} {resolved:?}"
    );
}

#[test]
#[ignore = "turns on process-global deterministic mode; run alone with --ignored --test-threads=1"]
fn history_and_presentations_are_answered_in_sequencer_mode() {
    let mut s = Sequencer::new();
    let (history, presentations) = s.read(|s| {
        (
            s.call(ClientRequest::RequestHistory {
                auth_token: s.token.clone(),
                recall: HistoryRecall::None,
            }),
            s.call(ClientRequest::RequestCurrentPresentations {
                auth_token: s.token.clone(),
            }),
        )
    });
    assert!(
        matches!(history, Ok(ClientReply::HistoryResponseReply { .. }))
            && matches!(presentations, Ok(ClientReply::CurrentPresentations { .. })),
        "{history:?} {presentations:?}"
    );
}
