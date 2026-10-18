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

//! RuneWorld routes (ADR 0005 decisions 6 and 8, ADR 0006 decision 8, ADR 0004 note 1).
//!
//! - `POST /v1/rw/signed_connect`: a signed `connect` envelope (raw bytes or hex). The daemon
//!   admits it on its trusted-login path, binds the new connection to the session's player and
//!   only then mints the PASETO. The reply carries the same credentials as `/auth/connect`
//!   (headers and a JSON body); a WebSocket then *reattaches* to that connection
//!   (`/ws/attach/connect` without `initial_attach`), because a connecting `Attach` is refused in
//!   deterministic mode.
//! - `POST /v1/rw/envelope`: any other envelope. With `X-Moor-Client-Id`/`X-Moor-Client-Token`
//!   it is submitted on that connection, so its output reaches that connection's stream;
//!   without them on a transient connection (a `delegate` before the first `connect`).
//! - WebSocket frames `0x05 || envelope` on an attached session do the same as
//!   `/v1/rw/envelope` (see `session`).
//! - `GET /v1/heights`: sealed and published heights, the sealed header hash and state root,
//!   the envelope signing domain's salt, and the daemon's fork commit with its source link.
//! - `GET /v1/rw/session/{key}` and `GET /v1/rw/wallet/{address}`: the public admission state a
//!   custodial host needs to sign (session index, player, last nonce; delegation nonce floor).
//!
//! web-host never holds a signing key and never sees a password on these routes.

use std::net::SocketAddr;

use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use moor_common::{
    envelope::{self, Address, Envelope, EnvelopeKind},
    model::ObjectRef,
};
use moor_runtime_api::{
    AuthToken, ClientToken, RpcError, RpcMessageError,
    api::{ChainStatus, ClientReply, ClientRequest, RuntimeClient},
};
use moor_var::{Associative, Obj, SYSTEM_OBJECT, Sequence, Symbol, Var, v_str};
use serde_json::{Value, json};
use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::host::{
    WebHost,
    auth::{extract_auth_token_header, extract_client_credentials},
};

/// WebSocket binary frame prefix for a signed envelope (`0x05 || envelope bytes`).
pub(crate) const ENVELOPE_FRAME_PREFIX: u8 = 0x05;
/// `ClientData` namespace and kind the daemon admits as an envelope (S0-8).
const ENVELOPE_NAMESPACE: &str = "runeworld";
const ENVELOPE_KIND: &str = "envelope";
/// `VerifiedOAuthLogin` operation carrying a signed `connect`.
const SIGNED_CONNECT: &str = "signed_connect";
/// Where the fork's source lives; `MOOR_SOURCE_REPOSITORY` overrides it.
const DEFAULT_SOURCE_REPOSITORY: &str = "https://github.com/cryptobushi/moor";
const SESSIONS_PROP: &str = "admission_sessions";
const WALLETS_PROP: &str = "admission_wallets";
/// Largest envelope the sequencer logs (block format per-entry limit).
const MAX_ENVELOPE_BYTES: usize = 2048;

/// True for a WebSocket frame carrying an envelope.
pub(crate) fn is_envelope_frame(bytes: &[u8]) -> bool {
    bytes.len() > 1 && bytes[0] == ENVELOPE_FRAME_PREFIX
}

/// Why a request body is not an envelope.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BodyError {
    #[error("empty body")]
    Empty,
    #[error("envelope is {0} bytes, more than {MAX_ENVELOPE_BYTES}")]
    TooLarge(usize),
    #[error("body is neither envelope bytes nor hex")]
    NotHex,
    #[error("not an envelope: {0}")]
    Decode(String),
}

/// An envelope from a request body: raw wire bytes, or hex text (an optional `0x`, surrounding
/// whitespace ignored). Raw bytes start with the kind byte (0-4), which is never a hex digit, so
/// the two forms cannot be confused.
pub(crate) fn envelope_from_body(body: &[u8]) -> Result<(Vec<u8>, Envelope), BodyError> {
    let first = *body.first().ok_or(BodyError::Empty)?;
    let bytes = if first <= EnvelopeKind::RevokeAll as u8 {
        body.to_vec()
    } else {
        let text = std::str::from_utf8(body)
            .map_err(|_| BodyError::NotHex)?
            .trim();
        let text = text.strip_prefix("0x").unwrap_or(text);
        envelope::unhex_vec(text).ok_or(BodyError::NotHex)?
    };
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(BodyError::TooLarge(bytes.len()));
    }
    let decoded = Envelope::decode(&bytes).map_err(|e| BodyError::Decode(e.to_string()))?;
    Ok((bytes, decoded))
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

/// Map a daemon refusal of an envelope to an HTTP status. A rejected envelope (bad signature,
/// stale nonce, expired) is the client's fault and says why; nothing else leaks.
pub(crate) fn rpc_error_response(error: &RpcError) -> Response {
    match error {
        RpcError::Daemon(RpcMessageError::LoginTaskFailed(reason)) => {
            error_response(StatusCode::UNAUTHORIZED, reason.clone())
        }
        RpcError::Daemon(RpcMessageError::InvalidRequest(reason)) => {
            error_response(StatusCode::BAD_REQUEST, reason.clone())
        }
        RpcError::Daemon(RpcMessageError::PermissionDenied) => {
            error_response(StatusCode::FORBIDDEN, "permission denied")
        }
        RpcError::Daemon(RpcMessageError::NoConnection) => {
            error_response(StatusCode::UNAUTHORIZED, "no such connection")
        }
        other => {
            warn!(error = %other, "envelope submission failed");
            error_response(StatusCode::BAD_GATEWAY, "the world is unavailable")
        }
    }
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", envelope::hex(bytes))
}

/// The source link for a fork commit (ADR 0004 note 1).
pub(crate) fn source_url(repository: &str, commit: &str) -> String {
    let repository = repository.trim_end_matches('/');
    if commit.bytes().all(|b| b.is_ascii_hexdigit()) && !commit.is_empty() {
        format!("{repository}/commit/{commit}")
    } else {
        repository.to_string()
    }
}

fn source_repository() -> String {
    std::env::var("MOOR_SOURCE_REPOSITORY")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SOURCE_REPOSITORY.to_string())
}

/// The JSON a host shows: heights, sealed tip, signing domain, source offer.
pub(crate) fn chain_status_json(status: &ChainStatus, repository: &str) -> Value {
    let hash = |bytes: &[u8]| (!bytes.is_empty()).then(|| hex0x(bytes));
    json!({
        "sequencer": status.sequencer,
        "sealed": status.sealed_height,
        "published": status.published_height,
        "header_hash": hash(&status.header_hash),
        "state_root": hash(&status.state_root),
        "domain_salt": hex0x(&status.domain_salt),
        // EIP-712 domain separator for the salt: signers without keccak256 (Node, WebCrypto) need
        // it for the envelope preimage.
        "domain_separator": hex0x(&envelope::Domain::new(status.domain_salt).separator()),
        "fork_commit": status.fork_commit,
        "source_url": source_url(repository, &status.fork_commit),
        "web_host_commit": moor_common::build::commit(),
    })
}

async fn chain_status(rpc_client: &Arc<dyn RuntimeClient>) -> Result<ChainStatus, Box<Response>> {
    match rpc_client
        .client_call(Uuid::new_v4(), ClientRequest::RequestChainStatus)
        .await
    {
        Ok(ClientReply::ChainStatus(status)) => Ok(status),
        Ok(_) => Err(Box::new(error_response(
            StatusCode::BAD_GATEWAY,
            "unexpected chain status reply",
        ))),
        Err(e) => Err(Box::new(rpc_error_response(&e))),
    }
}

/// `GET /v1/heights`.
pub async fn heights_handler(State(host): State<WebHost>) -> Response {
    match chain_status(&host.create_daemon_client()).await {
        Ok(status) => Json(chain_status_json(&status, &source_repository())).into_response(),
        Err(response) => *response,
    }
}

/// Detach a connection web-host opened for one request.
fn detach_later(host: &WebHost, client_id: Uuid, client_token: ClientToken) {
    let rpc_client = host.create_daemon_client();
    tokio::spawn(async move {
        let _ = rpc_client
            .client_call(
                client_id,
                ClientRequest::Detach {
                    client_token,
                    disconnected: true,
                },
            )
            .await;
    });
}

/// `POST /v1/rw/signed_connect`.
pub async fn signed_connect_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(host): State<WebHost>,
    body: Bytes,
) -> Response {
    let (bytes, decoded) = match envelope_from_body(&body) {
        Ok(parsed) => parsed,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    if decoded.kind != EnvelopeKind::Connect {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "signed_connect takes a connect envelope, not {}",
                decoded.kind
            ),
        );
    }
    let (client_id, rpc_client, client_token) = match host.establish_client_connection(addr).await {
        Ok(established) => established,
        Err(e) => {
            warn!(error = %e, "could not open a connection for a signed connect");
            return error_response(StatusCode::BAD_GATEWAY, "the world is unavailable");
        }
    };
    let request = ClientRequest::VerifiedOAuthLogin {
        client_token: client_token.clone(),
        connect_args: vec![SIGNED_CONNECT.to_string(), envelope::hex(&bytes)],
        do_attach: true,
    };
    let reply = match rpc_client.client_call(client_id, request).await {
        Ok(reply) => reply,
        Err(e) => {
            detach_later(&host, client_id, client_token);
            return rpc_error_response(&e);
        }
    };
    let ClientReply::LoginResult {
        success: true,
        auth_token: Some(auth_token),
        player: Some(player),
        player_flags,
        ..
    } = reply
    else {
        detach_later(&host, client_id, client_token);
        return error_response(StatusCode::UNAUTHORIZED, "connect was not admitted");
    };
    debug!(%player, %client_id, "signed connect admitted");
    signed_connect_response(&auth_token, &client_token, client_id, player, player_flags)
}

fn signed_connect_response(
    auth_token: &AuthToken,
    client_token: &ClientToken,
    client_id: Uuid,
    player: Obj,
    player_flags: u16,
) -> Response {
    let body = json!({
        "player": player.to_literal(),
        "player_u64": player.as_u64().to_string(),
        "player_flags": player_flags,
        "auth_token": auth_token.0,
        "client_token": client_token.0,
        "client_id": client_id.to_string(),
    });
    let mut response = Json(body).into_response();
    let headers = response.headers_mut();
    for (name, value) in [
        ("x-moor-auth-token", auth_token.0.as_str()),
        ("x-moor-client-token", client_token.0.as_str()),
        ("x-moor-client-id", &client_id.to_string()),
    ] {
        if let Ok(value) = value.parse() {
            headers.insert(name, value);
        }
    }
    response
}

/// The `ClientData` request carrying an envelope.
pub(crate) fn envelope_request(
    handler_object: Obj,
    client_token: ClientToken,
    auth_token: Option<AuthToken>,
    bytes: Vec<u8>,
) -> ClientRequest {
    ClientRequest::ClientData {
        client_token,
        auth_token,
        handler_object,
        namespace: Symbol::mk(ENVELOPE_NAMESPACE),
        kind: ENVELOPE_KIND.to_string(),
        payload: Var::mk_binary(bytes),
    }
}

/// `POST /v1/rw/envelope`.
pub async fn envelope_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(host): State<WebHost>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (bytes, decoded) = match envelope_from_body(&body) {
        Ok(parsed) => parsed,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    if decoded.kind == EnvelopeKind::Connect {
        return error_response(
            StatusCode::BAD_REQUEST,
            "send connect envelopes to /v1/rw/signed_connect",
        );
    }
    let (client_id, client_token, transient) = match extract_client_credentials(&headers) {
        Some((client_id, client_token)) => (client_id, client_token, false),
        None => match host.establish_client_connection(addr).await {
            Ok((client_id, _, client_token)) => (client_id, client_token, true),
            Err(e) => {
                warn!(error = %e, "could not open a connection for an envelope");
                return error_response(StatusCode::BAD_GATEWAY, "the world is unavailable");
            }
        },
    };
    let auth_token = extract_auth_token_header(&headers).ok();
    let request = envelope_request(host.handler_object, client_token.clone(), auth_token, bytes);
    let reply = host
        .create_daemon_client()
        .client_call(client_id, request)
        .await;
    if transient {
        detach_later(&host, client_id, client_token);
    }
    match reply {
        Ok(ClientReply::TaskSubmitted { task_id }) => (
            StatusCode::ACCEPTED,
            Json(json!({ "kind": decoded.kind.as_str(), "task_id": task_id })),
        )
            .into_response(),
        Ok(_) => error_response(StatusCode::BAD_GATEWAY, "unexpected envelope reply"),
        Err(e) => rpc_error_response(&e),
    }
}

async fn read_system_property(host: &WebHost, name: &str) -> Result<Option<Var>, Box<Response>> {
    let request = ClientRequest::RequestSysProp {
        auth_token: None,
        object: ObjectRef::Id(SYSTEM_OBJECT),
        property: Symbol::mk(name),
    };
    match host
        .create_daemon_client()
        .client_call(Uuid::new_v4(), request)
        .await
    {
        Ok(ClientReply::SysPropValue { value }) => Ok(value),
        Ok(_) => Err(Box::new(error_response(
            StatusCode::BAD_GATEWAY,
            "unexpected property reply",
        ))),
        // An undefined `#0.admission_*` (no delegation yet) reads as "not found".
        Err(RpcError::Daemon(RpcMessageError::ErrorCouldNotRetrieveSysProp(_))) => Ok(None),
        Err(e) => Err(Box::new(rpc_error_response(&e))),
    }
}

fn field(row: &Var, name: &str) -> Option<Var> {
    row.as_map()?.get(&v_str(name)).ok()
}

fn int_field(row: &Var, name: &str) -> Option<i64> {
    field(row, name)?.as_integer()
}

/// The session row for `key` in `#0.admission_sessions` (element `i` is session index `i`).
pub(crate) fn session_json(sessions: &Var, key: &[u8; 32]) -> Option<Value> {
    let wanted = v_str(&envelope::hex(key));
    let list = sessions.as_list()?;
    list.iter().enumerate().find_map(|(i, row)| {
        if field(&row, "key")? != wanted {
            return None;
        }
        let player = field(&row, "player")?.as_object()?;
        Some(json!({
            "index": i + 1,
            "player": player.to_literal(),
            "player_u64": player.as_u64().to_string(),
            "last_nonce": int_field(&row, "last_nonce")?,
            "revoked": int_field(&row, "revoked")? != 0,
            "expires": int_field(&row, "expires")?,
            "scope": int_field(&row, "scope")?,
        }))
    })
}

/// The entry for `address` in `#0.admission_wallets` (`{player, delegation_nonce_floor}`).
pub(crate) fn wallet_json(wallets: &Var, address: &Address) -> Option<Value> {
    let entry = wallets.as_map()?.get(&v_str(&address.to_hex())).ok()?;
    let list = entry.as_list()?;
    let player = list.index(0).ok()?.as_object()?;
    let floor = list.index(1).ok()?.as_integer()?;
    Some(json!({
        "address": address.to_hex(),
        "player": player.to_literal(),
        "player_u64": player.as_u64().to_string(),
        "nonce_floor": floor,
    }))
}

/// `GET /v1/rw/session/{key}`: 64 hex digits (optional `0x`).
pub async fn session_handler(State(host): State<WebHost>, Path(key): Path<String>) -> Response {
    let digits = key.strip_prefix("0x").unwrap_or(&key).to_ascii_lowercase();
    let Some(key) = envelope::unhex::<32>(&digits) else {
        return error_response(StatusCode::BAD_REQUEST, "key is not 64 hex digits");
    };
    let sessions = match read_system_property(&host, SESSIONS_PROP).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    match sessions.as_ref().and_then(|s| session_json(s, &key)) {
        Some(body) => Json(body).into_response(),
        None => error_response(StatusCode::NOT_FOUND, "no session with that key"),
    }
}

/// `GET /v1/rw/wallet/{address}`.
pub async fn wallet_handler(State(host): State<WebHost>, Path(address): Path<String>) -> Response {
    let Some(address) = Address::from_hex(&address) else {
        return error_response(StatusCode::BAD_REQUEST, "address is not 0x + 40 hex digits");
    };
    let wallets = match read_system_property(&host, WALLETS_PROP).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    match wallets.as_ref().and_then(|w| wallet_json(w, &address)) {
        Some(body) => Json(body).into_response(),
        None => error_response(StatusCode::NOT_FOUND, "wallet has no player"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moor_common::envelope::{Domain, SessionSigner};
    use moor_var::{v_int, v_list, v_map, v_obj};

    fn command_envelope() -> Vec<u8> {
        SessionSigner::from_seed([7; 32])
            .envelope(
                &Domain::default(),
                Obj::mk_id(5).as_u64(),
                EnvelopeKind::Command,
                1,
                3,
                40,
                b"look".to_vec(),
            )
            .encode()
    }

    #[test]
    fn body_accepts_raw_envelope_bytes() {
        let bytes = command_envelope();
        assert_eq!(envelope_from_body(&bytes).unwrap().0, bytes);
    }

    #[test]
    fn body_accepts_hex_with_prefix_and_whitespace() {
        let bytes = command_envelope();
        let text = format!(" 0x{}\n", envelope::hex(&bytes));
        assert_eq!(envelope_from_body(text.as_bytes()).unwrap().0, bytes);
    }

    #[test]
    fn body_rejects_trailing_bytes() {
        let mut bytes = command_envelope();
        bytes.push(0);
        assert!(matches!(
            envelope_from_body(&bytes),
            Err(BodyError::Decode(_))
        ));
    }

    #[test]
    fn body_rejects_non_hex_text() {
        assert_eq!(
            envelope_from_body(b"connect bob secret"),
            Err(BodyError::NotHex)
        );
    }

    #[test]
    fn body_rejects_empty() {
        assert_eq!(envelope_from_body(b""), Err(BodyError::Empty));
    }

    #[test]
    fn body_rejects_oversized() {
        let text = "00".repeat(MAX_ENVELOPE_BYTES + 1);
        assert_eq!(
            envelope_from_body(text.as_bytes()),
            Err(BodyError::TooLarge(MAX_ENVELOPE_BYTES + 1))
        );
    }

    #[test]
    fn envelope_frames_need_a_payload() {
        assert!(is_envelope_frame(&[ENVELOPE_FRAME_PREFIX, 0]));
        assert!(!is_envelope_frame(&[ENVELOPE_FRAME_PREFIX]));
        assert!(!is_envelope_frame(b"\x04{}"));
    }

    #[test]
    fn source_url_links_the_commit() {
        assert_eq!(
            source_url("https://github.com/cryptobushi/moor/", "0ad1f89c3abc"),
            "https://github.com/cryptobushi/moor/commit/0ad1f89c3abc"
        );
    }

    #[test]
    fn source_url_falls_back_to_the_repository() {
        assert_eq!(
            source_url("https://github.com/cryptobushi/moor", "unknown"),
            "https://github.com/cryptobushi/moor"
        );
    }

    #[test]
    fn chain_status_json_has_the_host_fields() {
        let status = ChainStatus {
            sequencer: true,
            sealed_height: 12,
            published_height: 10,
            header_hash: vec![0xab; 32],
            state_root: vec![0xcd; 32],
            domain_salt: [0; 32],
            fork_commit: "0ad1f89c3".into(),
        };
        let body = chain_status_json(&status, DEFAULT_SOURCE_REPOSITORY);
        assert_eq!(
            (
                body["sealed"].as_u64(),
                body["published"].as_u64(),
                body["header_hash"].as_str().map(str::len),
                body["source_url"].as_str()
            ),
            (
                Some(12),
                Some(10),
                Some(66),
                Some("https://github.com/cryptobushi/moor/commit/0ad1f89c3")
            )
        );
    }

    #[test]
    fn chain_status_json_has_the_domain_separator() {
        let status = ChainStatus {
            sequencer: true,
            sealed_height: 1,
            published_height: 0,
            header_hash: vec![],
            state_root: vec![],
            domain_salt: [0; 32],
            fork_commit: "unknown".into(),
        };
        assert_eq!(
            chain_status_json(&status, DEFAULT_SOURCE_REPOSITORY)["domain_separator"].as_str(),
            Some(hex0x(&envelope::Domain::default().separator()).as_str())
        );
    }

    #[test]
    fn chain_status_json_has_null_hashes_off_sequencer() {
        let status = ChainStatus {
            sequencer: false,
            sealed_height: 0,
            published_height: 0,
            header_hash: vec![],
            state_root: vec![],
            domain_salt: [0; 32],
            fork_commit: "unknown".into(),
        };
        assert!(chain_status_json(&status, DEFAULT_SOURCE_REPOSITORY)["header_hash"].is_null());
    }

    fn session_row(key: [u8; 32], player: i32, last_nonce: i64) -> Var {
        v_map(&[
            (v_str("box_key"), v_str(&envelope::hex(&[0; 32]))),
            (v_str("expires"), v_int(1_800_000_000)),
            (v_str("key"), v_str(&envelope::hex(&key))),
            (v_str("last_nonce"), v_int(last_nonce)),
            (v_str("player"), v_obj(Obj::mk_id(player))),
            (v_str("revoked"), v_int(0)),
            (v_str("scope"), v_int(1)),
        ])
    }

    #[test]
    fn session_lookup_finds_the_index_and_nonce() {
        let sessions = v_list(&[session_row([1; 32], 4, 9), session_row([2; 32], 15, 3)]);
        let row = session_json(&sessions, &[2; 32]).unwrap();
        assert_eq!(
            (
                row["index"].as_u64(),
                row["player"].as_str(),
                row["last_nonce"].as_i64()
            ),
            (Some(2), Some("#15"), Some(3))
        );
    }

    #[test]
    fn session_lookup_misses_an_unknown_key() {
        let sessions = v_list(&[session_row([1; 32], 4, 9)]);
        assert!(session_json(&sessions, &[3; 32]).is_none());
    }

    #[test]
    fn wallet_lookup_reads_player_and_floor() {
        let address = Address([0x11; 20]);
        let wallets = v_map(&[(
            v_str(&address.to_hex()),
            v_list(&[v_obj(Obj::mk_id(15)), v_int(2)]),
        )]);
        let entry = wallet_json(&wallets, &address).unwrap();
        assert_eq!(
            (entry["player"].as_str(), entry["nonce_floor"].as_i64()),
            (Some("#15"), Some(2))
        );
    }

    #[test]
    fn envelope_request_is_runeworld_client_data() {
        let request = envelope_request(
            SYSTEM_OBJECT,
            ClientToken("c".into()),
            None,
            command_envelope(),
        );
        assert!(matches!(
            request,
            ClientRequest::ClientData { ref namespace, ref kind, ref payload, .. }
                if namespace.as_string() == "runeworld" && kind == "envelope" && payload.as_binary().is_some()
        ));
    }
}
