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

//! The `--dev-identity` keyfile (RuneWorld ADR 0005 decision 8, Stage 0 shortcut).
//!
//! A JSON file holding a development wallet secret and session seed:
//!
//! ```json
//! {"wallet_secret": "<64 hex digits>", "session_seed": "<64 hex digits>"}
//! ```
//!
//! Hosts on the developer's machine read the same file and auto-sign envelopes with the session
//! key; the wallet signs its delegation. The daemon only validates the file and reports the
//! wallet address and session key. A daemon started with it accepts password login and is
//! non-publishing. Never use a keyfile holding a real wallet's secret.

use std::path::Path;

use eyre::{WrapErr, eyre};
use moor_common::envelope::{self, Address, SessionSigner, WalletSigner};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    wallet_secret: String,
    session_seed: String,
}

/// A loaded development identity.
pub struct DevIdentity {
    pub wallet: WalletSigner,
    pub session: SessionSigner,
}

impl DevIdentity {
    #[must_use]
    pub fn address(&self) -> Address {
        self.wallet.address()
    }

    #[must_use]
    pub fn session_key_hex(&self) -> String {
        envelope::hex(&self.session.public_key())
    }
}

fn secret(field: &str, text: &str) -> eyre::Result<[u8; 32]> {
    envelope::unhex::<32>(text.strip_prefix("0x").unwrap_or(text))
        .ok_or_else(|| eyre!("{field} must be 64 hex digits"))
}

/// Parse a keyfile's contents.
pub fn parse(text: &str) -> eyre::Result<DevIdentity> {
    let file: KeyFile = serde_json::from_str(text).wrap_err("dev identity keyfile")?;
    let wallet = WalletSigner::from_secret(secret("wallet_secret", &file.wallet_secret)?)
        .ok_or_else(|| eyre!("wallet_secret is not a valid secp256k1 secret"))?;
    let session = SessionSigner::from_seed(secret("session_seed", &file.session_seed)?);
    Ok(DevIdentity { wallet, session })
}

/// Read and parse a keyfile.
pub fn load(path: &Path) -> eyre::Result<DevIdentity> {
    let text = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("reading dev identity keyfile {}", path.display()))?;
    parse(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyfile_yields_the_wallet_address() {
        let id = parse(&format!(
            r#"{{"wallet_secret": "{}", "session_seed": "{}"}}"#,
            "11".repeat(32),
            "22".repeat(32)
        ))
        .unwrap();
        assert_eq!(
            id.address().to_hex(),
            "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
        );
    }

    #[test]
    fn short_secret_is_rejected() {
        assert!(parse(r#"{"wallet_secret": "11", "session_seed": "22"}"#).is_err());
    }
}
