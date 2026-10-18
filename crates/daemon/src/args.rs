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

use crate::feature_args::FeatureArgs;
use clap::builder::ValueHint;
use clap_derive::{Parser, ValueEnum};
use moor_common::threading::TaskPoolPinningMode;
use moor_common::util::config_path;
use moor_db::DatabaseConfig;
use moor_kernel::config::{
    Config, DeterministicMode, ImportExportConfig, ImportFormat, RuntimeConfig,
};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};

use std::sync::LazyLock;

static VERSION_STRING: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{} (commit: {})",
        env!("CARGO_PKG_VERSION"),
        moor_common::build::short_commit()
    )
});

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ValueEnum)]
pub enum RuntimeTaskPoolPinningMode {
    Auto,
    Performance,
    None,
}

impl From<RuntimeTaskPoolPinningMode> for TaskPoolPinningMode {
    fn from(value: RuntimeTaskPoolPinningMode) -> Self {
        match value {
            RuntimeTaskPoolPinningMode::Auto => TaskPoolPinningMode::Auto,
            RuntimeTaskPoolPinningMode::Performance => TaskPoolPinningMode::Performance,
            RuntimeTaskPoolPinningMode::None => TaskPoolPinningMode::None,
        }
    }
}

#[allow(dead_code)]
#[derive(Parser, Debug, Serialize, Deserialize)]
#[command(version = VERSION_STRING.as_str())]
pub struct Args {
    #[arg(
        value_name = "data-dir",
        help = "Directory to store all database files under",
        value_hint = ValueHint::DirPath,
        default_value = "./moor-data"
    )]
    pub data_dir: PathBuf,

    #[command(flatten)]
    pub db_args: DatabaseArgs,

    #[command(flatten)]
    import_export_args: Option<ImportExportArgs>,

    #[command(flatten)]
    runtime_args: Option<RuntimeArgs>,

    #[command(flatten)]
    feature_args: Option<FeatureArgs>,

    #[arg(
        long,
        value_name = "config",
        help = "Path to configuration (YAML) file to use, if any. If not specified, defaults are used.\
                Configuration file values can be overridden by command line arguments.",
        value_hint = ValueHint::FilePath
    )]
    pub config_file: Option<PathBuf>,

    #[arg(
        short,
        long,
        value_name = "connections-db",
        help = "Path to connections database to use or create (relative to data-dir if not absolute)",
        value_hint = ValueHint::FilePath
    )]
    pub connections_file: Option<PathBuf>,

    #[arg(
        short = 'x',
        long,
        value_name = "tasks-db",
        help = "Path to persistent tasks database to use or create (relative to data-dir if not absolute)",
        value_hint = ValueHint::FilePath
    )]
    pub tasks_db: Option<PathBuf>,

    #[arg(
        short = 'e',
        long,
        value_name = "events-db",
        help = "Path to persistent events database to use or create (relative to data-dir if not absolute)",
        value_hint = ValueHint::FilePath
    )]
    pub events_db: Option<PathBuf>,

    #[arg(
        long,
        value_name = "rpc-listen",
        help = "RPC server address(es). Comma-separated list of endpoints (e.g. ipc:///path/rpc.sock,tcp://0.0.0.0:7899). IPC endpoints have no encryption; TCP endpoints use CURVE encryption.",
        default_value = "ipc:///tmp/moor_rpc.sock"
    )]
    pub rpc_listen: String,

    #[arg(
        long,
        value_name = "events-listen",
        help = "Events publisher address(es). Comma-separated list of endpoints (e.g. ipc:///path/events.sock,tcp://0.0.0.0:7898). IPC endpoints have no encryption; TCP endpoints use CURVE encryption.",
        default_value = "ipc:///tmp/moor_events.sock"
    )]
    pub events_listen: String,

    #[arg(
        long,
        value_name = "workers-response-listen",
        help = "Workers server RPC address for receiving attachment, responses, and pings etc",
        default_value = "ipc:///tmp/moor_workers_response.sock"
    )]
    pub workers_response_listen: String,

    #[arg(
        long,
        value_name = "workers-request-listen",
        help = "Workers server pub-sub address for broadcasting dispatch requests",
        default_value = "ipc:///tmp/moor_workers_request.sock"
    )]
    pub workers_request_listen: String,

    #[arg(
        long,
        value_name = "enrollment-listen",
        help = "Enrollment server address for host registration",
        default_value = "tcp://0.0.0.0:7900"
    )]
    pub enrollment_listen: String,

    #[arg(
        long,
        value_name = "enrollment-token-file",
        help = "Path to enrollment token file. If omitted, defaults to ${XDG_CONFIG_HOME:-$HOME/.config}/moor/enrollment-token. Relative paths are resolved under the XDG config directory.",
        value_hint = ValueHint::FilePath
    )]
    pub enrollment_token_file: Option<PathBuf>,

    #[arg(
        long,
        value_name = "public-key",
        help = "file containing the PEM encoded public key (shared with the daemon), used for authenticating client & host connections. If omitted, defaults to ${XDG_CONFIG_HOME:-$HOME/.config}/moor/moor-verifying-key.pem. Relative paths are resolved under the XDG config directory.",
        value_hint = ValueHint::FilePath
    )]
    pub public_key: Option<PathBuf>,

    #[arg(
        long,
        value_name = "private-key",
        help = "file containing an openssh generated ed25519 format private key (shared with the daemon), used for authenticating client & host connections. If omitted, defaults to ${XDG_CONFIG_HOME:-$HOME/.config}/moor/moor-signing-key.pem. Relative paths are resolved under the XDG config directory.",
        value_hint = ValueHint::FilePath
    )]
    pub private_key: Option<PathBuf>,

    #[arg(
        long,
        value_name = "num-io-threads",
        help = "Number of ZeroMQ IO threads to use",
        default_value = "8"
    )]
    pub num_io_threads: i32,

    #[arg(long, help = "Enable debug logging", default_value = "false")]
    pub debug: bool,

    #[arg(
        long,
        help = "Run the world as a deterministic state transition function: block time, seeded \
                randomness and derived ids replace the clock and OS entropy. The block context is \
                set by a driver; with none attached the daemon stays in the genesis block. \
                Independent of any development shortcut."
    )]
    pub deterministic: bool,

    #[arg(
        long,
        help = "Deterministic mode, development only: accept the PASETO-only state-changing RPCs \
                (Eval, InvokeVerb, Program, UpdateProperty, capture-mode invocations and the rest \
                of the gated list) without a signed envelope. Makes the daemon non-publishing."
    )]
    pub dev_unsigned_rpc: bool,

    #[arg(
        long,
        value_name = "KEYFILE",
        help = "Deterministic mode, development only (Stage 0 identity shortcut): a JSON keyfile \
                {wallet_secret, session_seed} that local hosts auto-sign envelopes with. Also \
                accepts password login, unsigned connected commands and connecting attaches. \
                Makes the daemon non-publishing. Separate from --dev-unsigned-rpc."
    )]
    pub dev_identity: Option<PathBuf>,

    #[arg(
        long,
        help = "RuneWorld sequencer mode (needs --deterministic): one input queue, 1 s blocks \
                sealed with the --sequencer-key and published to the --sequencer-sink FileSink. \
                Reads are served from the last committed state; only logged inputs change it."
    )]
    pub sequencer: bool,

    #[arg(
        long,
        value_name = "FILE",
        help = "Sequencer mode: file holding the sequencer's secp256k1 secret (64 hex digits)"
    )]
    pub sequencer_key: Option<PathBuf>,

    #[arg(
        long,
        value_name = "FILE",
        help = "Sequencer mode: signing guard file, exclusively locked while the key is in use                 (default: <sequencer-key>.guard)"
    )]
    pub sequencer_guard: Option<PathBuf>,

    #[arg(
        long,
        value_name = "DIR",
        help = "Sequencer mode: directory of the input journal and local block store                 (default: <data-dir>/sequencer)"
    )]
    pub sequencer_state: Option<PathBuf>,

    #[arg(
        long,
        value_name = "DIR",
        help = "Sequencer mode: FileSink directory sealed segments are published to \
                (default: <data-dir>/fsink)"
    )]
    pub sequencer_sink: Option<PathBuf>,

    #[arg(
        long,
        value_name = "N",
        help = "Sequencer mode: blocks per published segment (default 10)"
    )]
    pub sequencer_segment_blocks: Option<usize>,

    #[arg(
        long,
        value_name = "N",
        hide = true,
        help = "Sequencer mode, tests only: the DA lag halt threshold (default 300 blocks)"
    )]
    pub sequencer_max_da_lag: Option<u64>,

    #[arg(
        long,
        value_name = "N",
        help = "Sequencer mode: write a checkpoint after every N-th sealed block (default 3600; \
                0 = none). Recovery restores the newest one instead of rebuilding at genesis"
    )]
    pub sequencer_checkpoint_every: Option<u64>,

    #[arg(
        long,
        value_name = "K",
        help = "Sequencer mode: checkpoints kept in <sequencer-state>/checkpoints (default 24)"
    )]
    pub sequencer_checkpoint_keep: Option<usize>,

    #[arg(
        long,
        value_name = "N",
        help = "Sequencer mode: publish the checkpoint to the sink every N blocks (default 86400, \
                daily; 0 = never)"
    )]
    pub sequencer_checkpoint_publish_every: Option<u64>,

    #[arg(
        long,
        value_name = "OBJ",
        help = "Sequencer mode with --dev-identity: the player object number the development \
                wallet is bound to at genesis; the daemon then signs that player's password-login \
                connects and unsigned commands with the keyfile's session key"
    )]
    pub dev_player: Option<i32>,

    #[arg(
        long,
        help = "Generate ED25519 keypair if it doesn't exist, then continue"
    )]
    pub generate_keypair: bool,

    #[arg(long, help = "Rotate enrollment token and exit")]
    pub rotate_enrollment_token: bool,

    #[cfg(feature = "trace_events")]
    #[arg(
        long,
        value_name = "trace-output",
        help = "Path to output Chrome trace events JSON file. If not specified, tracing is disabled.",
        value_hint = ValueHint::FilePath
    )]
    pub trace_output: Option<PathBuf>,
}

/// Formats for import
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Default, Serialize, Deserialize,
)]
pub enum Format {
    /// Traditional LambdaMOO textdump format
    #[default]
    Textdump,
    /// New-style objdef/dirdump format
    Objdef,
}

#[allow(dead_code)]
#[derive(Parser, Debug, Serialize, Deserialize)]
pub struct ImportExportArgs {
    #[arg(short, long, value_name = "import", help = "Path to a textdump or objdef directory to import", value_hint = ValueHint::FilePath)]
    pub import: Option<PathBuf>,

    #[arg(
        long,
        value_name = "export",
        help = "Path to export checkpoints into (always uses objdef format)",
        value_hint = ValueHint::FilePath
    )]
    pub export: Option<PathBuf>,

    #[arg(
        long,
        value_name = "import-format",
        help = "Format to import from.",
        value_enum
    )]
    pub import_format: Option<Format>,

    /// Prepare initial program baselines from HEAD's common ancestor with this remote-tracking ref.
    /// Uses local Git history only; fetch the remote first when needed.
    #[arg(long, conflicts_with = "baseline_objdef_dir")]
    pub git_upstream: Option<String>,

    /// Use this objdef directory as the upstream baseline for the initial import.
    #[arg(long)]
    pub baseline_objdef_dir: Option<PathBuf>,

    #[arg(
        long,
        value_name = "export-format",
        help = "DEPRECATED: Export format is always objdef. This option is ignored.",
        value_enum,
        hide = true
    )]
    pub export_format: Option<Format>,

    #[arg(
        long,
        value_name = "checkpoint-interval-seconds",
        help = "Interval in seconds between database checkpoints"
    )]
    pub checkpoint_interval_seconds: Option<u16>,
}

impl ImportExportArgs {
    pub fn merge_config(&self, config: &mut ImportExportConfig) -> Result<(), eyre::Report> {
        if let Some(args) = self.import.as_ref() {
            config.input_path = Some(args.clone());
        }
        if let Some(args) = self.export.as_ref() {
            config.output_path = Some(args.clone());
        }
        if let Some(args) = self.checkpoint_interval_seconds {
            config.checkpoint_interval = Some(std::time::Duration::from_secs(u64::from(args)));
        }
        if let Some(import_format) = self.import_format {
            config.import_format = match import_format {
                Format::Textdump => ImportFormat::Textdump,
                Format::Objdef => ImportFormat::Objdef,
            };
        }
        if let Some(upstream) = &self.git_upstream {
            config.git_upstream = Some(upstream.clone());
            config.baseline_objdef_dir = None;
        }
        if let Some(directory) = &self.baseline_objdef_dir {
            config.baseline_objdef_dir = Some(directory.clone());
            config.git_upstream = None;
        }
        if self.export_format.is_some() {
            tracing::warn!(
                "--export-format is deprecated and ignored. Checkpoints always use objdef format."
            );
        }
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Parser, Debug, Serialize, Deserialize)]
pub struct RuntimeArgs {
    #[arg(
        long,
        value_name = "gc-interval-seconds",
        help = "Interval in seconds for automatic garbage collection (default: 30)"
    )]
    pub gc_interval_seconds: Option<u16>,

    #[arg(
        long,
        value_name = "scheduler-tick-ms",
        help = "Scheduler tick interval in milliseconds - controls how often the scheduler wakes to check for events. Lower values provide better latency but higher CPU usage (default: 10)"
    )]
    pub scheduler_tick_ms: Option<u16>,

    #[arg(
        long,
        value_enum,
        help = "Task worker pinning mode: auto, performance, or none"
    )]
    pub task_pool_pinning: Option<RuntimeTaskPoolPinningMode>,

    #[arg(
        long,
        value_name = "service-perf-cores",
        help = "Reserve detected performance cores for service/control-plane threads"
    )]
    pub service_perf_cores: Option<usize>,

    #[arg(
        long,
        value_name = "max-capture-deadline-seconds",
        help = "Longest deadline, in seconds, a client may request when waiting for a verb call's captured output (default: 60)"
    )]
    pub max_capture_deadline_seconds: Option<u16>,

    #[arg(long, help = "Enable or disable perf timing (default: enabled)")]
    pub perf_timing_enabled: Option<bool>,

    #[arg(
        long,
        value_name = "perf-hot-shift",
        help = "Sampling shift for hot-path timings (0 => exact, 6 => 1/64, default: 6)"
    )]
    pub perf_timing_hot_path_shift: Option<u32>,
}

impl RuntimeArgs {
    pub fn merge_config(&self, config: &mut RuntimeConfig) -> Result<(), eyre::Report> {
        if let Some(args) = self.gc_interval_seconds {
            config.gc_interval = Some(std::time::Duration::from_secs(u64::from(args)));
        }
        if let Some(args) = self.scheduler_tick_ms {
            config.scheduler_tick_duration =
                Some(std::time::Duration::from_millis(u64::from(args)));
        }
        if let Some(args) = self.task_pool_pinning {
            config.task_pool_pinning = Some(args.into());
        }
        if let Some(args) = self.service_perf_cores {
            config.service_perf_cores = Some(args);
        }
        if let Some(args) = self.max_capture_deadline_seconds {
            config.max_capture_deadline = Some(std::time::Duration::from_secs(u64::from(args)));
        }
        if let Some(args) = self.perf_timing_enabled {
            config.perf_timing_enabled = Some(args);
        }
        if let Some(args) = self.perf_timing_hot_path_shift {
            config.perf_timing_hot_path_shift = Some(args);
        }
        Ok(())
    }
}
#[allow(dead_code)]
#[derive(Parser, Debug, Serialize, Deserialize)]
pub struct DatabaseArgs {
    #[arg(
        long,
        value_name = "db",
        help = "Main database filename (relative to data-dir if not absolute)",
        value_hint = ValueHint::FilePath,
        default_value = "world.db"
    )]
    pub db: PathBuf,
}

impl DatabaseArgs {
    pub(crate) fn merge_config(&self, _db_config: &mut DatabaseConfig) -> Result<(), eyre::Report> {
        // Noop for now
        Ok(())
    }
}

impl Args {
    #[allow(dead_code)]
    fn merge_config(&self, mut config: Config) -> Result<Config, eyre::Report> {
        if let Some(args) = self.import_export_args.as_ref() {
            args.merge_config(&mut config.import_export)?;
        }
        if let Some(args) = self.runtime_args.as_ref() {
            args.merge_config(&mut config.runtime)?;
        }
        // The flag turns the mode on; a `deterministic:` section in the config file may already
        // have set a genesis block, which is kept.
        if self.deterministic && !config.deterministic.is_on() {
            config.deterministic = DeterministicMode::on();
        }
        if self.dev_unsigned_rpc {
            config.dev.unsigned_rpc = true;
        }
        if let Some(path) = &self.dev_identity {
            config.dev.identity = Some(path.clone());
        }
        if self.sequencer {
            config.sequencer.enabled = true;
        }
        if let Some(path) = &self.sequencer_key {
            config.sequencer.key_file = Some(path.clone());
        }
        if let Some(path) = &self.sequencer_sink {
            config.sequencer.sink_dir = Some(path.clone());
        }
        if let Some(path) = &self.sequencer_guard {
            config.sequencer.guard_file = Some(path.clone());
        }
        if let Some(path) = &self.sequencer_state {
            config.sequencer.state_dir = Some(path.clone());
        }
        if let Some(n) = self.sequencer_segment_blocks {
            config.sequencer.segment_blocks = n;
        }
        if let Some(n) = self.sequencer_max_da_lag {
            config.sequencer.max_da_lag = n;
        }
        if let Some(n) = self.sequencer_checkpoint_every {
            config.sequencer.checkpoint_every = n;
        }
        if let Some(n) = self.sequencer_checkpoint_keep {
            config.sequencer.checkpoint_keep = n;
        }
        if let Some(n) = self.sequencer_checkpoint_publish_every {
            config.sequencer.checkpoint_publish_every = n;
        }
        if let Some(player) = self.dev_player {
            config.sequencer.dev_player = Some(player);
        }
        if let Some(args) = self.feature_args.as_ref() {
            let mut copy = config.features.as_ref().clone();
            args.merge_config(&mut copy)?;
            config.features = Arc::new(copy);
        }
        let mut features = config.features.as_ref().clone();
        features.normalize_deprecated_flags();
        config.features = Arc::new(features);

        if let Some(database_config) = config.database.as_mut() {
            self.db_args.merge_config(database_config)?;
        }

        Ok(config)
    }

    /// Load the configuration file if we have it, and then we'll merge the arguments into it.
    pub fn load_config(&self) -> Result<Arc<Config>, eyre::Report> {
        let config_path = self.config_file.clone();
        let config =
            moor_common::config::apply_yaml_config_file(Config::default(), config_path.as_deref())?;
        let config = self.merge_config(config)?;
        // Every source has now been applied, so a value can finally be judged. Checking here rather
        // than in each merge means a setting is validated the same way whether it came from the
        // file or the command line.
        config.validate().map_err(|e| eyre::eyre!(e))?;
        let config = Arc::new(config);
        Ok(config)
    }
}

// Helper functions for resolving configuration and data paths (XDG-compliant)
impl Args {
    /// Resolve the data directory for moor (databases live under this)
    pub fn resolved_data_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }

    /// Resolve the allowed-hosts directory (XDG data)
    pub fn resolved_allowed_hosts_dir(&self) -> PathBuf {
        if let Ok(data) = std::env::var("XDG_DATA_HOME") {
            std::path::PathBuf::from(data).join("moor/allowed-hosts")
        } else if let Ok(home) = std::env::var("HOME") {
            std::path::PathBuf::from(home).join(".local/share/moor/allowed-hosts")
        } else {
            self.resolved_data_dir().join("allowed-hosts")
        }
    }

    /// Resolve the enrollment token path
    ///
    /// Priority:
    /// - explicit path if provided (absolute used as-is, relative resolved under XDG config)
    /// - XDG default: $XDG_CONFIG_HOME/moor/enrollment-token or ~/.config/moor/enrollment-token
    pub fn resolved_enrollment_token_path(&self) -> PathBuf {
        match &self.enrollment_token_file {
            Some(p) if p.is_absolute() => p.clone(),
            Some(p) => config_path(p),
            None => config_path("enrollment-token"),
        }
    }

    /// Resolve the PASETO verifying key path (public key)
    ///
    /// If not provided, defaults to XDG config: moor-verifying-key.pem
    pub fn resolved_public_key_path(&self) -> PathBuf {
        match &self.public_key {
            Some(p) if p.is_absolute() => p.clone(),
            Some(p) => config_path(p),
            None => config_path("moor-verifying-key.pem"),
        }
    }

    /// Resolve the PASETO signing key path (private key)
    ///
    /// If not provided, defaults to XDG config: moor-signing-key.pem
    pub fn resolved_private_key_path(&self) -> PathBuf {
        match &self.private_key {
            Some(p) if p.is_absolute() => p.clone(),
            Some(p) => config_path(p),
            None => config_path("moor-signing-key.pem"),
        }
    }

    /// Resolve the main database path relative to resolved data dir
    pub(crate) fn resolved_db_path(&self) -> PathBuf {
        if self.db_args.db.is_absolute() {
            self.db_args.db.clone()
        } else {
            self.resolved_data_dir().join(&self.db_args.db)
        }
    }

    /// Resolve the tasks database path relative to resolved data dir
    pub(crate) fn resolved_tasks_db_path(&self) -> PathBuf {
        match &self.tasks_db {
            Some(path) => {
                if path.is_absolute() {
                    path.clone()
                } else {
                    self.resolved_data_dir().join(path)
                }
            }
            None => self.resolved_data_dir().join("tasks.db"),
        }
    }

    /// Resolve the connections database path relative to resolved data dir
    pub(crate) fn resolved_connections_db_path(&self) -> Option<PathBuf> {
        match &self.connections_file {
            Some(path) => {
                if path.is_absolute() {
                    Some(path.clone())
                } else {
                    Some(self.resolved_data_dir().join(path))
                }
            }
            None => Some(self.resolved_data_dir().join("connections.db")),
        }
    }

    /// Resolve the events database path relative to resolved data dir
    pub(crate) fn resolved_events_db_path(&self) -> PathBuf {
        match &self.events_db {
            Some(path) => {
                if path.is_absolute() {
                    path.clone()
                } else {
                    self.resolved_data_dir().join(path)
                }
            }
            None => self.resolved_data_dir().join("events.db"),
        }
    }

    #[cfg(feature = "trace_events")]
    /// Resolve the trace output path relative to resolved data dir
    pub(crate) fn resolved_trace_output_path(&self) -> Option<PathBuf> {
        self.trace_output.as_ref().map(|path| {
            if path.is_absolute() {
                path.clone()
            } else {
                self.resolved_data_dir().join(path)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Args;
    use clap::Parser as _;
    use moor_kernel::config::{DeterministicMode, ImportFormat};

    fn write_config(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("daemon.yaml");
        std::fs::write(&path, contents).expect("write config");
        (dir, path)
    }

    #[test]
    fn load_config_reads_features_section() {
        let (_dir, config_path) = write_config(
            r#"
features:
  custom_errors: true
import_export:
  import_format: Objdef
"#,
        );
        let args = Args::try_parse_from([
            "moor-daemon",
            "--config-file",
            config_path.to_str().expect("utf-8 path"),
        ])
        .expect("parse args");

        let config = args.load_config().expect("load config");

        assert!(config.features.custom_errors);
        assert!(config.features.rich_notify);
        assert_eq!(config.import_export.import_format, ImportFormat::Objdef);
    }

    #[test]
    fn load_config_rejects_unknown_sections() {
        let (_dir, config_path) = write_config(
            r#"
features_config:
  custom_errors: true
"#,
        );
        let args = Args::try_parse_from([
            "moor-daemon",
            "--config-file",
            config_path.to_str().expect("utf-8 path"),
        ])
        .expect("parse args");

        assert!(args.load_config().is_err());
    }

    #[test]
    fn load_config_rejects_unknown_nested_keys() {
        let (_dir, config_path) = write_config(
            r#"
features:
  custom_errors: true
  typo: true
"#,
        );
        let args = Args::try_parse_from([
            "moor-daemon",
            "--config-file",
            config_path.to_str().expect("utf-8 path"),
        ])
        .expect("parse args");

        assert!(args.load_config().is_err());
    }

    #[test]
    fn load_config_cli_args_override_file_values() {
        let (_dir, config_path) = write_config(
            r#"
features:
  custom_errors: false
import_export:
  import_format: Objdef
"#,
        );
        let args = Args::try_parse_from([
            "moor-daemon",
            "--config-file",
            config_path.to_str().expect("utf-8 path"),
            "--custom-errors",
            "true",
            "--import-format",
            "textdump",
        ])
        .expect("parse args");

        let config = args.load_config().expect("load config");

        assert!(config.features.custom_errors);
        assert_eq!(config.import_export.import_format, ImportFormat::Textdump);
    }

    #[test]
    fn dev_shortcuts_are_off_by_default() {
        let args = Args::try_parse_from(["moor-daemon", "--deterministic"]).expect("parse args");

        let config = args.load_config().expect("load config");

        assert!(!config.dev.any());
    }

    #[test]
    fn dev_flags_are_separate_switches() {
        let args = Args::try_parse_from([
            "moor-daemon",
            "--deterministic",
            "--dev-identity",
            "dev-key.json",
        ])
        .expect("parse args");

        let config = args.load_config().expect("load config");

        assert_eq!(
            (config.dev.unsigned_rpc, config.dev.identity.clone()),
            (false, Some(std::path::PathBuf::from("dev-key.json")))
        );
    }

    #[test]
    fn deterministic_mode_is_off_by_default() {
        let args = Args::try_parse_from(["moor-daemon"]).expect("parse args");

        let config = args.load_config().expect("load config");

        assert_eq!(config.deterministic, DeterministicMode::default());
    }

    #[test]
    fn deterministic_flag_turns_the_mode_on() {
        let args = Args::try_parse_from(["moor-daemon", "--deterministic"]).expect("parse args");

        let config = args.load_config().expect("load config");

        assert!(config.deterministic.is_on());
    }

    #[test]
    fn deterministic_section_in_the_config_file_sets_the_genesis_block() {
        let (_dir, config_path) = write_config(
            r#"
deterministic:
  enabled: true
  genesis:
    height: 7
    timestamp: 1700000000
    seed: "0000000000000000000000000000000000000000000000000000000000000009"
"#,
        );
        let args = Args::try_parse_from([
            "moor-daemon",
            "--config-file",
            config_path.to_str().expect("utf-8 path"),
            "--deterministic",
        ])
        .expect("parse args");

        let config = args.load_config().expect("load config");

        let genesis = config.deterministic.genesis;
        assert_eq!(
            (genesis.height, genesis.timestamp, genesis.seed[31]),
            (7, 1_700_000_000, 9)
        );
    }

    #[test]
    fn max_capture_deadline_defaults_to_sixty_seconds() {
        let args = Args::try_parse_from(["moor-daemon"]).expect("parse args");

        let config = args.load_config().expect("load config");

        assert_eq!(
            config.runtime.max_capture_deadline(),
            std::time::Duration::from_secs(60)
        );
    }

    #[test]
    fn max_capture_deadline_reads_from_config_file_and_cli() {
        let (_dir, config_path) = write_config(
            r#"
runtime:
  max_capture_deadline: 5s
"#,
        );
        let args = Args::try_parse_from([
            "moor-daemon",
            "--config-file",
            config_path.to_str().expect("utf-8 path"),
        ])
        .expect("parse args");

        let config = args.load_config().expect("load config");
        assert_eq!(
            config.runtime.max_capture_deadline(),
            std::time::Duration::from_secs(5)
        );

        let args = Args::try_parse_from([
            "moor-daemon",
            "--config-file",
            config_path.to_str().expect("utf-8 path"),
            "--max-capture-deadline-seconds",
            "12",
        ])
        .expect("parse args");

        let config = args.load_config().expect("load config");
        assert_eq!(
            config.runtime.max_capture_deadline(),
            std::time::Duration::from_secs(12)
        );
    }

    #[test]
    fn max_capture_deadline_rejects_zero_from_the_command_line() {
        let args = Args::try_parse_from(["moor-daemon", "--max-capture-deadline-seconds", "0"])
            .expect("parse args");

        assert!(args.load_config().is_err());
    }

    #[test]
    fn max_capture_deadline_rejects_zero_from_the_config_file() {
        let (_dir, config_path) = write_config(
            r#"
runtime:
  max_capture_deadline: 0s
"#,
        );
        let args = Args::try_parse_from([
            "moor-daemon",
            "--config-file",
            config_path.to_str().expect("utf-8 path"),
        ])
        .expect("parse args");

        assert!(args.load_config().is_err());
    }

    #[test]
    fn max_capture_deadline_rejects_more_than_the_protocol_maximum() {
        let (_dir, config_path) = write_config(
            r#"
runtime:
  max_capture_deadline: 10m
"#,
        );
        let args = Args::try_parse_from([
            "moor-daemon",
            "--config-file",
            config_path.to_str().expect("utf-8 path"),
        ])
        .expect("parse args");

        assert!(args.load_config().is_err());
    }

    #[test]
    fn baseline_preparation_combines_cli_and_yaml() {
        let (_dir, config_path) = write_config(
            "import_export:\n  input_path: core\n  import_format: Objdef\n  baseline_objdef_dir: base\n",
        );
        let args = Args::try_parse_from([
            "moor-daemon",
            "--config-file",
            config_path.to_str().unwrap(),
            "--git-upstream",
            "origin/main",
        ])
        .unwrap();
        let config = args.load_config().unwrap();
        assert_eq!(
            config.import_export.git_upstream.as_deref(),
            Some("origin/main")
        );
        assert!(config.import_export.baseline_objdef_dir.is_none());

        // Validate after combining settings: the import may come from YAML.
        for extra in [
            vec![],
            vec!["--import", "core", "--import-format", "textdump"],
        ] {
            let mut argv = vec!["moor-daemon", "--git-upstream", "origin/main"];
            argv.extend(extra);
            assert!(Args::try_parse_from(argv).unwrap().load_config().is_err());
        }
        let (_dir, config_path) = write_config(
            "import_export:\n  input_path: core\n  import_format: Objdef\n  git_upstream: origin/main\n  baseline_objdef_dir: base\n",
        );
        assert!(
            Args::try_parse_from([
                "moor-daemon",
                "--config-file",
                config_path.to_str().unwrap(),
            ])
            .unwrap()
            .load_config()
            .is_err()
        );
    }

    #[test]
    fn packaged_daemon_config_loads() {
        let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("debian")
            .join("moor-daemon-config.yaml");
        let args = Args::try_parse_from([
            "moor-daemon",
            "--config-file",
            config_path.to_str().expect("utf-8 path"),
        ])
        .expect("parse args");

        let config = args.load_config().expect("load packaged config");

        assert!(config.features.custom_errors);
        assert_eq!(config.import_export.import_format, ImportFormat::Objdef);
    }
}
