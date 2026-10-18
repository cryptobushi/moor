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

//! RuneWorld signing for the telnet host (ADR 0005 decision 6, Stage 0/1 developer path).
//!
//! With `--session-keyfile FILE` the host holds one Ed25519 session key (generated into the file
//! on first start, mode 0600). A player links it once: `link <wallet>` prints the EIP-712
//! `Delegation` as a link URL and as typed-data JSON for `cast wallet sign --data`; the player
//! pastes the wallet's signature with `sign <0x…>`; the host submits the `delegate` envelope
//! (proof of possession by the session key) and then a signed `connect`. Later visits type
//! `connect`. Every line after login is a signed `command` envelope. The host is custodial for
//! the session (scope `play`, 24 h), never for the wallet.
//!
//! Every connection is shown the source offer (the daemon's fork commit, ADR 0004 note 1) and the
//! sealed and published heights (ADR 0006 decision 8) when the daemon is a sequencer.

use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use eyre::{Context, bail, eyre};
use moor_common::envelope::{
    self, Address, Delegation, DelegationPayload, Domain, Envelope, EnvelopeKind, SessionSigner,
    envelope_digest, scope,
};
use moor_common::{model::ObjectRef, util::parse_into_words};
use moor_runtime_api::{
    AuthToken, RpcError, RpcMessageError,
    api::{ChainStatus, ClientReply, ClientRequest},
};
use moor_var::{Associative, NOTHING, Obj, SYSTEM_OBJECT, Sequence, Symbol, Var, v_str};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, info, warn};

use super::{PendingTask, TelnetConnection};

/// Blocks an envelope stays valid after the next block (ADR 0005: about 30 s of blocks).
pub const EXPIRY_WINDOW: u64 = 30;
/// Session lifetime the link asks for (ADR 0005 decision 6: telnet defaults to 24 h).
pub const SESSION_SECS: u64 = 24 * 3600;
/// Where the fork's source lives; `MOOR_SOURCE_REPOSITORY` overrides it.
const DEFAULT_SOURCE_REPOSITORY: &str = "https://github.com/cryptobushi/moor";
/// The default link page (the bridge host's, which can sign for an external session key).
const DEFAULT_LINK_URL: &str = "http://127.0.0.1:43595/link";

/// The keyfile's JSON. Only the seed is secret; the session index and nonce live in the world.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Keyfile {
    /// 64 hex digits: the Ed25519 seed.
    session_seed: String,
    /// The wallet this key was last linked to, for display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wallet: Option<String>,
}

/// The session's state in the world, read from `#0.admission_sessions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRow {
    pub index: u32,
    pub player: Obj,
    pub last_nonce: u64,
    pub revoked: bool,
    pub expires: u64,
}

/// Signing state while connections use the session.
#[derive(Debug, Clone, Copy)]
pub struct Active {
    pub session: u32,
    pub player: Obj,
    pub next_nonce: u32,
}

/// The host's one custodial session key.
pub struct HostSigner {
    path: PathBuf,
    key: SessionSigner,
    keyfile: Mutex<Keyfile>,
    /// Held across sign-and-submit so nonces reach the sequencer in order.
    pub(crate) active: tokio::sync::Mutex<Option<Active>>,
}

impl HostSigner {
    /// Load the keyfile, or create it with a fresh seed.
    pub fn load_or_create(path: &Path) -> eyre::Result<Self> {
        let keyfile = if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading session keyfile {}", path.display()))?;
            serde_json::from_str::<Keyfile>(&text)
                .with_context(|| format!("parsing session keyfile {}", path.display()))?
        } else {
            let seed: [u8; 32] = rand::rng().random();
            let keyfile = Keyfile {
                session_seed: envelope::hex(&seed),
                wallet: None,
            };
            write_keyfile(path, &keyfile)?;
            keyfile
        };
        let seed = envelope::unhex::<32>(&keyfile.session_seed)
            .ok_or_else(|| eyre!("session_seed in {} is not 64 hex digits", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            key: SessionSigner::from_seed(seed),
            keyfile: Mutex::new(keyfile),
            active: tokio::sync::Mutex::new(None),
        })
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.public_key()
    }

    #[must_use]
    pub fn key(&self) -> &SessionSigner {
        &self.key
    }

    /// The wallet the keyfile was last linked to.
    #[must_use]
    pub fn wallet(&self) -> Option<String> {
        self.keyfile
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .wallet
            .clone()
    }

    /// Record the linked wallet in the keyfile.
    pub fn remember_wallet(&self, wallet: &Address) -> eyre::Result<()> {
        let mut keyfile = self.keyfile.lock().unwrap_or_else(|e| e.into_inner());
        keyfile.wallet = Some(wallet.to_hex());
        write_keyfile(&self.path, &keyfile)
    }
}

fn write_keyfile(path: &Path, keyfile: &Keyfile) -> eyre::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let text = serde_json::to_string_pretty(keyfile)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing session keyfile {}", path.display()))?;
    file.write_all(text.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

/// Host-wide RuneWorld state shared by every connection.
pub struct RuneWorldHost {
    signer: Option<HostSigner>,
    link_url: String,
    sealed: AtomicU64,
    published: AtomicU64,
    domain_salt: Mutex<Option<[u8; 32]>>,
}

impl std::fmt::Debug for RuneWorldHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuneWorldHost")
            .field("signing", &self.signer.is_some())
            .field("link_url", &self.link_url)
            .field("sealed", &self.sealed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Default for RuneWorldHost {
    fn default() -> Self {
        Self {
            signer: None,
            link_url: DEFAULT_LINK_URL.to_string(),
            sealed: AtomicU64::new(0),
            published: AtomicU64::new(0),
            domain_salt: Mutex::new(None),
        }
    }
}

impl RuneWorldHost {
    pub fn new(keyfile: Option<&Path>, link_url: Option<String>) -> eyre::Result<Self> {
        let signer = keyfile.map(HostSigner::load_or_create).transpose()?;
        Ok(Self {
            signer,
            link_url: link_url.unwrap_or_else(|| DEFAULT_LINK_URL.to_string()),
            ..Self::default()
        })
    }

    #[must_use]
    pub fn signer(&self) -> Option<&HostSigner> {
        self.signer.as_ref()
    }

    /// A seal notice arrived.
    pub fn note_seal(&self, height: u64) {
        self.sealed.fetch_max(height, Ordering::AcqRel);
    }

    /// A chain status arrived.
    pub fn note_status(&self, status: &ChainStatus) {
        self.sealed
            .fetch_max(status.sealed_height, Ordering::AcqRel);
        self.published
            .fetch_max(status.published_height, Ordering::AcqRel);
        *self.domain_salt.lock().unwrap_or_else(|e| e.into_inner()) = Some(status.domain_salt);
    }

    /// The signing domain, once a chain status has been read.
    #[must_use]
    pub fn domain(&self) -> Option<Domain> {
        self.domain_salt
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(Domain::new)
    }

    /// The expiry height for an envelope signed now.
    #[must_use]
    pub fn expiry_height(&self) -> u64 {
        expiry_after(self.sealed.load(Ordering::Acquire))
    }

    #[must_use]
    pub fn link_url(&self) -> &str {
        &self.link_url
    }
}

/// The last height an envelope signed after block `sealed` may land in.
#[must_use]
pub fn expiry_after(sealed: u64) -> u64 {
    sealed + 1 + EXPIRY_WINDOW
}

fn source_repository() -> String {
    std::env::var("MOOR_SOURCE_REPOSITORY")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SOURCE_REPOSITORY.to_string())
}

/// The source link for a fork commit (ADR 0004 note 1).
#[must_use]
pub fn source_url(repository: &str, commit: &str) -> String {
    let repository = repository.trim_end_matches('/');
    if !commit.is_empty() && commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        format!("{repository}/commit/{commit}")
    } else {
        repository.to_string()
    }
}

fn short(bytes: &[u8]) -> String {
    let hex = envelope::hex(bytes);
    format!("0x{}", hex.get(..12).unwrap_or(&hex))
}

/// The banner every telnet connection is shown: source offer and heights.
#[must_use]
pub fn banner_lines(status: &ChainStatus, signer: Option<&HostSigner>) -> Vec<String> {
    let mut lines = vec![format!(
        "RuneWorld source (AGPL-3.0 section 13): {}",
        source_url(&source_repository(), &status.fork_commit)
    )];
    if status.sequencer {
        let header = if status.header_hash.is_empty() {
            String::new()
        } else {
            format!(", header {}", short(&status.header_hash))
        };
        lines.push(format!(
            "Chain: sealed #{}, published #{}{header}",
            status.sealed_height, status.published_height
        ));
    }
    if let Some(signer) = signer {
        lines.push(format!(
            "Signed login: this host holds session key {} (custodial: play scope, 24 h).",
            short(&signer.public_key())
        ));
        match signer.wallet() {
            Some(wallet) => lines.push(format!(
                "  Linked to {wallet}: type `connect`. To link another wallet: `link <0xwallet>`."
            )),
            None => lines.push(
                "  Type `link <0xwallet>` to delegate it, then `sign <0xsignature>`.".to_string(),
            ),
        }
        lines.push("  `heights` shows the chain heights.".to_string());
    }
    lines
}

/// The delegation a link asks the wallet to sign.
#[must_use]
pub fn delegation_for(session_key: [u8; 32], now: u64, wallet: Option<(Obj, u64)>) -> Delegation {
    Delegation {
        session_key,
        // Private messages (decision 7) are not implemented by this host yet.
        box_key: [0; 32],
        scope: scope::PLAY,
        expires: now + SESSION_SECS,
        nonce: wallet.map_or(1, |(_, floor)| floor + 1),
        create: wallet.is_none(),
    }
}

/// EIP-712 typed data for `eth_signTypedData_v4` and `cast wallet sign --data`.
#[must_use]
pub fn typed_data_json(delegation: &Delegation, domain: &Domain) -> serde_json::Value {
    let hex0x = |bytes: &[u8]| format!("0x{}", envelope::hex(bytes));
    serde_json::json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "salt", "type": "bytes32"}
            ],
            "Delegation": [
                {"name": "session_key", "type": "bytes32"},
                {"name": "box_key", "type": "bytes32"},
                {"name": "scope", "type": "uint32"},
                {"name": "expires", "type": "uint64"},
                {"name": "nonce", "type": "uint64"},
                {"name": "create", "type": "bool"}
            ]
        },
        "primaryType": "Delegation",
        "domain": {
            "name": envelope::DOMAIN_NAME,
            "version": envelope::DOMAIN_VERSION,
            "salt": hex0x(&domain.salt)
        },
        "message": {
            "session_key": hex0x(&delegation.session_key),
            "box_key": hex0x(&delegation.box_key),
            "scope": delegation.scope,
            "expires": delegation.expires,
            "nonce": delegation.nonce,
            "create": delegation.create
        }
    })
}

/// The link page URL carrying the session key and the delegation to sign.
#[must_use]
pub fn link_url(base: &str, delegation: &Delegation, domain: &Domain, wallet: &Address) -> String {
    format!(
        "{base}?session_key=0x{}&box_key=0x{}&scope={}&expires={}&nonce={}&create={}&salt=0x{}&wallet={}",
        envelope::hex(&delegation.session_key),
        envelope::hex(&delegation.box_key),
        delegation.scope,
        delegation.expires,
        delegation.nonce,
        u8::from(delegation.create),
        envelope::hex(&domain.salt),
        wallet.to_hex()
    )
}

/// A `delegate` envelope from a wallet signature the host did not make. The session key signs it
/// (proof of possession).
#[must_use]
pub fn delegate_envelope(
    session: &SessionSigner,
    domain: &Domain,
    delegation: Delegation,
    wallet_signature: [u8; 65],
    expiry_height: u64,
) -> Envelope {
    let text = DelegationPayload {
        delegation,
        wallet_signature,
    }
    .encode();
    let digest = envelope_digest(
        domain,
        NOTHING.as_u64(),
        &delegation.session_key,
        EnvelopeKind::Delegate,
        0,
        expiry_height,
        &text,
    );
    Envelope {
        kind: EnvelopeKind::Delegate,
        session: 0,
        nonce: 0,
        expiry: Envelope::expiry_field(expiry_height),
        text,
        signature: session.sign_digest(&digest),
    }
}

/// `r || s || v` from `0x` + 130 hex digits.
#[must_use]
pub fn parse_wallet_signature(text: &str) -> Option<[u8; 65]> {
    let text = text.trim();
    envelope::unhex::<65>(text.strip_prefix("0x").unwrap_or(text))
}

fn field(row: &Var, name: &str) -> Option<Var> {
    row.as_map()?.get(&v_str(name)).ok()
}

fn uint_field(row: &Var, name: &str) -> Option<u64> {
    field(row, name)?
        .as_integer()
        .and_then(|i| u64::try_from(i).ok())
}

/// The row for `key` in `#0.admission_sessions`.
#[must_use]
pub fn find_session(sessions: &Var, key: &[u8; 32]) -> Option<SessionRow> {
    let wanted = v_str(&envelope::hex(key));
    sessions.as_list()?.iter().enumerate().find_map(|(i, row)| {
        if field(&row, "key")? != wanted {
            return None;
        }
        Some(SessionRow {
            index: u32::try_from(i + 1).ok()?,
            player: field(&row, "player")?.as_object()?,
            last_nonce: uint_field(&row, "last_nonce")?,
            revoked: uint_field(&row, "revoked")? != 0,
            expires: uint_field(&row, "expires")?,
        })
    })
}

/// `(player, delegation nonce floor)` for `wallet` in `#0.admission_wallets`.
#[must_use]
pub fn find_wallet(wallets: &Var, wallet: &Address) -> Option<(Obj, u64)> {
    let entry = wallets.as_map()?.get(&v_str(&wallet.to_hex())).ok()?;
    let list = entry.as_list()?;
    let player = list.index(0).ok()?.as_object()?;
    let floor = list
        .index(1)
        .ok()?
        .as_integer()
        .and_then(|i| u64::try_from(i).ok())?;
    Some((player, floor))
}

/// Unix seconds.
pub fn now_secs() -> eyre::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// The next nonce for a session whose world state says `last` and whose host state says `local`.
pub fn next_nonce(last: u64, local: Option<u32>) -> eyre::Result<u32> {
    let from_world = u32::try_from(last + 1)?;
    let next = local.map_or(from_world, |n| n.max(from_world));
    if next > envelope::MAX_NONCE {
        bail!("session nonce space is exhausted; link a new session key");
    }
    Ok(next)
}

/// What a pre-login line did.
pub(crate) enum LoginStep {
    /// Not a RuneWorld login line; send it to the daemon as before.
    NotMine,
    /// Answered here; keep waiting for a login.
    Handled,
    /// Logged in through a signed `connect`.
    LoggedIn(AuthToken, Obj),
}

const ENVELOPE_NAMESPACE: &str = "runeworld";
const ENVELOPE_KIND: &str = "envelope";
const SIGNED_CONNECT: &str = "signed_connect";
const SESSIONS_PROP: &str = "admission_sessions";
const WALLETS_PROP: &str = "admission_wallets";

impl TelnetConnection {
    async fn rw_call(&mut self, request: ClientRequest) -> Result<ClientReply, RpcError> {
        self.daemon_client
            .client_call(self.client_id, request)
            .await
    }

    /// The daemon's chain status, remembered host-wide. `None` when the daemon does not answer
    /// (an older daemon).
    pub(crate) async fn rw_chain_status(&mut self) -> Option<ChainStatus> {
        match self.rw_call(ClientRequest::RequestChainStatus).await {
            Ok(ClientReply::ChainStatus(status)) => {
                self.runeworld.note_status(&status);
                Some(status)
            }
            Ok(other) => {
                debug!(?other, "unexpected chain status reply");
                None
            }
            Err(e) => {
                debug!(error = %e, "no chain status");
                None
            }
        }
    }

    /// The source offer and heights, shown after the welcome message (ADR 0004 note 1, ADR 0006
    /// decision 8). Shown when the daemon is a sequencer or this host signs.
    pub(crate) async fn rw_banner(&mut self) -> eyre::Result<()> {
        let Some(status) = self.rw_chain_status().await else {
            return Ok(());
        };
        if !status.sequencer && self.runeworld.signer().is_none() {
            return Ok(());
        }
        for line in banner_lines(&status, self.runeworld.signer()) {
            self.send_line(&line).await?;
        }
        self.flush().await
    }

    async fn rw_system_property(&mut self, name: &str) -> eyre::Result<Option<Var>> {
        let request = ClientRequest::RequestSysProp {
            auth_token: None,
            object: ObjectRef::Id(SYSTEM_OBJECT),
            property: Symbol::mk(name),
        };
        match self.rw_call(request).await {
            Ok(ClientReply::SysPropValue { value }) => Ok(value),
            Ok(other) => bail!("unexpected property reply {other:?}"),
            Err(RpcError::Daemon(RpcMessageError::ErrorCouldNotRetrieveSysProp(_))) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn rw_session_row(&mut self, key: &[u8; 32]) -> eyre::Result<Option<SessionRow>> {
        Ok(self
            .rw_system_property(SESSIONS_PROP)
            .await?
            .and_then(|sessions| find_session(&sessions, key)))
    }

    async fn rw_domain(&mut self) -> eyre::Result<Domain> {
        if let Some(domain) = self.runeworld.domain() {
            return Ok(domain);
        }
        self.rw_chain_status()
            .await
            .map(|status| Domain::new(status.domain_salt))
            .ok_or_else(|| eyre!("the daemon reports no chain status"))
    }

    fn rw_envelope_request(&self, bytes: Vec<u8>) -> ClientRequest {
        ClientRequest::ClientData {
            client_token: self.client_token.clone(),
            auth_token: self.auth_token.clone(),
            handler_object: self.handler_object,
            namespace: Symbol::mk(ENVELOPE_NAMESPACE),
            kind: ENVELOPE_KIND.to_string(),
            payload: Var::mk_binary(bytes),
        }
    }

    /// Handle a line typed before login. Only `link`, `sign`, a bare `connect` and `heights` are
    /// RuneWorld's; anything else goes to the daemon unchanged.
    pub(crate) async fn rw_login_line(&mut self, line: &str) -> eyre::Result<LoginStep> {
        let words = parse_into_words(line);
        let first = words.first().map(|w| w.to_ascii_lowercase());
        match (first.as_deref(), words.len()) {
            (Some("heights"), 1) => {
                self.rw_heights().await?;
                Ok(LoginStep::Handled)
            }
            _ if self.runeworld.signer().is_none() => Ok(LoginStep::NotMine),
            (Some("link"), 2) => {
                self.rw_link(&words[1]).await?;
                Ok(LoginStep::Handled)
            }
            (Some("sign"), 2) => self.rw_sign(&words[1]).await,
            (Some("connect"), 1) => self.rw_signed_connect().await,
            _ => Ok(LoginStep::NotMine),
        }
    }

    async fn rw_heights(&mut self) -> eyre::Result<()> {
        match self.rw_chain_status().await {
            Some(status) => {
                let line = format!(
                    "Chain: sealed #{}, published #{}{}",
                    status.sealed_height,
                    status.published_height,
                    if status.header_hash.is_empty() {
                        String::new()
                    } else {
                        format!(", header 0x{}", envelope::hex(&status.header_hash))
                    }
                );
                self.send_line(&line).await
            }
            None => self.send_line("The world reports no chain status.").await,
        }
    }

    async fn rw_link(&mut self, wallet: &str) -> eyre::Result<()> {
        let Some(wallet) = Address::from_hex(&wallet.to_ascii_lowercase()) else {
            return self
                .send_line("link takes a wallet address: 0x and 40 hex digits.")
                .await;
        };
        let Some(signer) = self.runeworld.signer() else {
            return Ok(());
        };
        let session_key = signer.public_key();
        let domain = self.rw_domain().await?;
        let existing = self
            .rw_system_property(WALLETS_PROP)
            .await?
            .and_then(|wallets| find_wallet(&wallets, &wallet));
        let delegation = delegation_for(session_key, now_secs()?, existing);
        let url = link_url(self.runeworld.link_url(), &delegation, &domain, &wallet);
        let typed = typed_data_json(&delegation, &domain).to_string();
        let what = match existing {
            Some((player, _)) => format!("log in as {player}"),
            None => "create a player for this wallet".to_string(),
        };
        let lines = [
            format!(
                "Delegating session key 0x{} to {wallet} ({what}; play scope, 24 h, nonce {}).",
                envelope::hex(&session_key),
                delegation.nonce
            ),
            format!("Sign in a browser wallet: {url}"),
            "Or sign offline with Foundry (any of --private-key, --account, --ledger):".to_string(),
            format!("  cast wallet sign --data '{typed}'"),
            "Then type: sign <0xsignature>".to_string(),
        ];
        for line in lines {
            self.send_line(&line).await?;
        }
        self.pending_link = Some((delegation, wallet));
        Ok(())
    }

    async fn rw_sign(&mut self, signature: &str) -> eyre::Result<LoginStep> {
        let Some((delegation, wallet)) = self.pending_link else {
            self.send_line("Nothing to sign yet: type `link <0xwallet>` first.")
                .await?;
            return Ok(LoginStep::Handled);
        };
        let Some(signature) = parse_wallet_signature(signature) else {
            self.send_line("sign takes 0x and 130 hex digits (r, s, v).")
                .await?;
            return Ok(LoginStep::Handled);
        };
        let domain = self.rw_domain().await?;
        match envelope::recover_wallet(&delegation.digest(&domain), &signature) {
            Ok(signer) if signer == wallet => {}
            Ok(other) => {
                self.send_line(&format!(
                    "That signature is from {other}, not {wallet}; the delegation was not sent."
                ))
                .await?;
                return Ok(LoginStep::Handled);
            }
            Err(e) => {
                self.send_line(&format!("Bad signature: {e}.")).await?;
                return Ok(LoginStep::Handled);
            }
        }
        let runeworld = self.runeworld.clone();
        let Some(signer) = runeworld.signer() else {
            return Ok(LoginStep::Handled);
        };
        let env = delegate_envelope(
            signer.key(),
            &domain,
            delegation,
            signature,
            self.runeworld.expiry_height(),
        );
        let request = self.rw_envelope_request(env.encode());
        match self.rw_call(request).await {
            Ok(_) => {}
            Err(RpcError::Daemon(RpcMessageError::LoginTaskFailed(reason))) => {
                self.send_line(&format!("Delegation refused: {reason}."))
                    .await?;
                return Ok(LoginStep::Handled);
            }
            Err(e) => return Err(e.into()),
        }
        self.pending_link = None;
        if let Err(e) = signer.remember_wallet(&wallet) {
            warn!(error = %e, "could not record the linked wallet in the keyfile");
        }
        *signer.active.lock().await = None;
        self.send_line(&format!("Session key delegated by {wallet}."))
            .await?;
        self.rw_signed_connect().await
    }

    /// Sign and submit a `connect`; on admission the daemon binds this connection and mints the
    /// auth token (ADR 0005 decision 8).
    async fn rw_signed_connect(&mut self) -> eyre::Result<LoginStep> {
        let runeworld = self.runeworld.clone();
        let Some(signer) = runeworld.signer() else {
            return Ok(LoginStep::NotMine);
        };
        let key = signer.public_key();
        let Some(row) = self.rw_session_row(&key).await? else {
            self.send_line("This host's session key is not linked: type `link <0xwallet>`.")
                .await?;
            return Ok(LoginStep::Handled);
        };
        if row.revoked || row.expires <= now_secs()? {
            self.send_line(
                "This host's session was revoked or has expired: type `link <0xwallet>` again.",
            )
            .await?;
            return Ok(LoginStep::Handled);
        }
        let domain = self.rw_domain().await?;
        let mut active = signer.active.lock().await;
        let local = active
            .filter(|a| a.session == row.index)
            .map(|a| a.next_nonce);
        let nonce = next_nonce(row.last_nonce, local)?;
        let env = signer.key().envelope(
            &domain,
            row.player.as_u64(),
            EnvelopeKind::Connect,
            row.index,
            nonce,
            self.runeworld.expiry_height(),
            Vec::new(),
        );
        let request = ClientRequest::VerifiedOAuthLogin {
            client_token: self.client_token.clone(),
            connect_args: vec![SIGNED_CONNECT.to_string(), envelope::hex(&env.encode())],
            do_attach: true,
        };
        let reply = self.rw_call(request).await;
        *active = Some(Active {
            session: row.index,
            player: row.player,
            next_nonce: nonce + 1,
        });
        drop(active);
        match reply {
            Ok(ClientReply::LoginResult {
                success: true,
                auth_token: Some(auth_token),
                player: Some(player),
                ..
            }) => {
                self.signed_session = true;
                info!(%player, session = row.index, client_id = %self.client_id, "signed connect");
                Ok(LoginStep::LoggedIn(auth_token, player))
            }
            Ok(_) => {
                self.send_line("The world did not admit the connect.")
                    .await?;
                Ok(LoginStep::Handled)
            }
            Err(RpcError::Daemon(RpcMessageError::LoginTaskFailed(reason))) => {
                self.send_line(&format!("Connect refused: {reason}."))
                    .await?;
                Ok(LoginStep::Handled)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Sign one command line and submit it (logged in through the signer).
    pub(crate) async fn rw_signed_command(&mut self, line: String) -> eyre::Result<()> {
        let runeworld = self.runeworld.clone();
        let Some(signer) = runeworld.signer() else {
            bail!("signed command without a signer");
        };
        if line.len() > envelope::MAX_TEXT_BYTES {
            return self
                .send_line(&format!(
                    "Commands are limited to {} bytes.",
                    envelope::MAX_TEXT_BYTES
                ))
                .await;
        }
        let domain = self.rw_domain().await?;
        let mut active = signer.active.lock().await;
        let Some(state) = active.as_mut() else {
            drop(active);
            return self
                .send_line("This host's session is not active; reconnect and type `connect`.")
                .await;
        };
        let env = signer.key().envelope(
            &domain,
            state.player.as_u64(),
            EnvelopeKind::Command,
            state.session,
            state.next_nonce,
            self.runeworld.expiry_height(),
            line.into_bytes(),
        );
        state.next_nonce += 1;
        let request = self.rw_envelope_request(env.encode());
        // Held across the call: the next line's nonce must not overtake this one.
        let reply = self.rw_call(request).await;
        drop(active);
        match reply {
            // An admitted envelope that ran no MOO task has no completion to wait for.
            Ok(ClientReply::TaskSubmitted { task_id: 0 }) => Ok(()),
            Ok(ClientReply::TaskSubmitted { task_id }) => {
                self.pending_task = Some(PendingTask {
                    task_id: task_id as usize,
                    start_time: Instant::now(),
                });
                Ok(())
            }
            Ok(other) => bail!("unexpected reply to a signed command: {other:?}"),
            Err(RpcError::Daemon(RpcMessageError::LoginTaskFailed(reason))) => {
                if reason.contains("nonce") {
                    // Another signer used the session; resynchronise from the world.
                    *signer.active.lock().await = None;
                }
                self.send_line(&format!("Command refused: {reason}.")).await
            }
            Err(error) => {
                self.handle_client_rpc_error(error, "An error occurred processing your request.")
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moor_common::envelope::{WalletSigner, recover_wallet};
    use moor_var::{v_int, v_list, v_map, v_obj};

    fn signer() -> SessionSigner {
        SessionSigner::from_seed([0x22; 32])
    }

    #[test]
    fn delegation_for_a_new_wallet_creates() {
        let d = delegation_for([1; 32], 1_000, None);
        assert_eq!(
            (d.create, d.nonce, d.expires, d.scope),
            (true, 1, 1_000 + SESSION_SECS, scope::PLAY)
        );
    }

    #[test]
    fn delegation_for_a_known_wallet_bumps_the_floor() {
        let d = delegation_for([1; 32], 1_000, Some((Obj::mk_id(4), 3)));
        assert_eq!((d.create, d.nonce), (false, 4));
    }

    #[test]
    fn delegate_envelope_is_admissible_shape() {
        let wallet = WalletSigner::from_secret([0x11; 32]).unwrap();
        let domain = Domain::default();
        let delegation = delegation_for(signer().public_key(), 1_000, None);
        let sig = wallet.sign_digest(&delegation.digest(&domain)).unwrap();
        let ours = delegate_envelope(&signer(), &domain, delegation, sig, 40);
        let reference = wallet.delegate(&domain, &signer(), delegation, 40).unwrap();
        assert_eq!(ours.encode(), reference.encode());
    }

    #[test]
    fn wallet_signature_parses_with_or_without_prefix() {
        let hex = "ab".repeat(65);
        assert_eq!(
            (
                parse_wallet_signature(&format!("0x{hex}")),
                parse_wallet_signature(&hex)
            ),
            (Some([0xab; 65]), Some([0xab; 65]))
        );
    }

    #[test]
    fn typed_data_carries_the_delegation() {
        let delegation = delegation_for([0x33; 32], 10, None);
        let json = typed_data_json(&delegation, &Domain::default());
        assert_eq!(
            (
                json["primaryType"].as_str(),
                json["message"]["session_key"].as_str().map(str::len),
                json["message"]["create"].as_bool(),
                json["domain"]["name"].as_str()
            ),
            (Some("Delegation"), Some(66), Some(true), Some("RuneWorld"))
        );
    }

    #[test]
    fn signed_typed_data_recovers_the_wallet() {
        // What a wallet signs for this JSON is `Delegation::digest`; the cast cross-check of that
        // digest is S0-8's golden vector.
        let wallet = WalletSigner::from_secret([0x11; 32]).unwrap();
        let delegation = delegation_for(signer().public_key(), 10, None);
        let sig = wallet
            .sign_digest(&delegation.digest(&Domain::default()))
            .unwrap();
        assert_eq!(
            recover_wallet(&delegation.digest(&Domain::default()), &sig).unwrap(),
            wallet.address()
        );
    }

    #[test]
    fn link_url_names_the_key_and_wallet() {
        let delegation = delegation_for([0x33; 32], 10, None);
        let url = link_url(
            "http://h/link",
            &delegation,
            &Domain::default(),
            &Address([0x11; 20]),
        );
        assert!(url.starts_with("http://h/link?session_key=0x3333") && url.contains("&create=1"));
    }

    fn row(key: [u8; 32], player: i32, last: i64, revoked: i64) -> Var {
        v_map(&[
            (v_str("box_key"), v_str(&envelope::hex(&[0; 32]))),
            (v_str("expires"), v_int(99)),
            (v_str("key"), v_str(&envelope::hex(&key))),
            (v_str("last_nonce"), v_int(last)),
            (v_str("player"), v_obj(Obj::mk_id(player))),
            (v_str("revoked"), v_int(revoked)),
            (v_str("scope"), v_int(1)),
        ])
    }

    #[test]
    fn find_session_reads_index_and_nonce() {
        let sessions = v_list(&[row([1; 32], 4, 7, 0), row([2; 32], 15, 2, 1)]);
        assert_eq!(
            find_session(&sessions, &[2; 32]),
            Some(SessionRow {
                index: 2,
                player: Obj::mk_id(15),
                last_nonce: 2,
                revoked: true,
                expires: 99
            })
        );
    }

    #[test]
    fn find_wallet_reads_player_and_floor() {
        let address = Address([0x11; 20]);
        let wallets = v_map(&[(
            v_str(&address.to_hex()),
            v_list(&[v_obj(Obj::mk_id(15)), v_int(2)]),
        )]);
        assert_eq!(find_wallet(&wallets, &address), Some((Obj::mk_id(15), 2)));
    }

    #[test]
    fn next_nonce_takes_the_larger() {
        assert_eq!(
            (
                next_nonce(4, None).unwrap(),
                next_nonce(4, Some(9)).unwrap(),
                next_nonce(9, Some(4)).unwrap()
            ),
            (5, 9, 10)
        );
    }

    #[test]
    fn expiry_is_thirty_blocks_after_the_next() {
        assert_eq!(expiry_after(100), 131);
    }

    #[test]
    fn source_url_links_the_commit() {
        assert_eq!(
            source_url("https://github.com/cryptobushi/moor", "0ad1f89c3"),
            "https://github.com/cryptobushi/moor/commit/0ad1f89c3"
        );
    }

    #[test]
    fn keyfile_is_created_private_and_reloads_the_same_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let first = HostSigner::load_or_create(&path).unwrap().public_key();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let again = HostSigner::load_or_create(&path).unwrap().public_key();
        assert_eq!((first, mode), (again, 0o600));
    }

    #[test]
    fn banner_shows_source_and_heights() {
        let status = ChainStatus {
            sequencer: true,
            sealed_height: 7,
            published_height: 5,
            header_hash: vec![0xab; 32],
            state_root: vec![0; 32],
            domain_salt: [0; 32],
            fork_commit: "0ad1f89c3".into(),
        };
        let lines = banner_lines(&status, None);
        assert!(
            lines[0].ends_with("/commit/0ad1f89c3")
                && lines[1] == "Chain: sealed #7, published #5, header 0xabababababab"
        );
    }
}
