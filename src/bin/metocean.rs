//! Phase-8 met-ocean advisory service binary.
//!
//! Commands:
//!   `metocean status`                  render the status document (honest
//!                                      UNAVAILABLE when no feed configured)
//!   `metocean poll --once`             one poll → evaluate → issue cycle
//!   `metocean override <document>`     apply a signed operator override
//!   `metocean metrics`                 render local Prometheus metrics
//!
//! Configuration is environment-only, mirroring `gateway.rs`:
//!   MET_OCEAN_FEED_CONFIG          path to the feed-set JSON (absent => no
//!                                  feeds; service reports UNAVAILABLE)
//!   MET_OCEAN_REGISTRY_PATH        signed hazard-zone registry document
//!   MET_OCEAN_POLICY_PATH          signed advisory policy document
//!   MET_OCEAN_REGISTRY_KEY_DIRECTORY  governance public-key directory
//!   MET_OCEAN_OPERATOR_KEY_DIRECTORY  operator public-key directory
//!   MET_OCEAN_DATABASE_DSN         PostgreSQL DSN (metocean-pg-store build)
//!   MET_OCEAN_KAFKA_BROKERS        broker list (kafka-transport build)
//!   PROVENANCE_SIGNING_KEY         base64url Ed25519 signing key (secret)
//!   MET_OCEAN_PRINCIPAL_ID         issuance principal (Keycloak sub)
//!   MET_OCEAN_ENVELOPE_KEY_ID      envelope signing key id (default
//!                                  blueeconomy-waterway-safety-0)
//! Every failure is an exit code with a structured error line; there is no
//! synthetic feed and no fallback data path.

#[cfg(feature = "metocean-pg-store")]
use blueeconomy_waterway_safety::metocean::envelope::EnvelopeSigningContext;
#[cfg(feature = "metocean-pg-store")]
use blueeconomy_waterway_safety::metocean::fetch;
#[cfg(feature = "metocean-pg-store")]
use blueeconomy_waterway_safety::metocean::publish;
#[cfg(feature = "metocean-pg-store")]
use blueeconomy_waterway_safety::metocean::registry::{
    load_advisory_policy, load_hazard_zone_registry, KeyDirectory,
};
#[cfg(feature = "metocean-pg-store")]
use blueeconomy_waterway_safety::metocean::service::{
    MetoceanService, OperatorRegistry, ENV_OPERATOR_KEY_DIRECTORY,
};
#[cfg(feature = "metocean-pg-store")]
use blueeconomy_waterway_safety::metocean::store;
#[cfg(feature = "metocean-pg-store")]
use blueeconomy_waterway_safety::metocean::FeedSetConfig;
use blueeconomy_waterway_safety::ValidationError;
#[cfg(feature = "metocean-pg-store")]
use chrono::Utc;
#[cfg(feature = "metocean-pg-store")]
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(feature = "metocean-pg-store")]
const ENV_FEED_CONFIG: &str = "MET_OCEAN_FEED_CONFIG";
#[cfg(feature = "metocean-pg-store")]
const ENV_REGISTRY_PATH: &str = "MET_OCEAN_REGISTRY_PATH";
#[cfg(feature = "metocean-pg-store")]
const ENV_POLICY_PATH: &str = "MET_OCEAN_POLICY_PATH";
#[cfg(feature = "metocean-pg-store")]
const ENV_KEY_DIRECTORY: &str = "MET_OCEAN_REGISTRY_KEY_DIRECTORY";
#[cfg(feature = "metocean-pg-store")]
const ENV_DATABASE_DSN: &str = "MET_OCEAN_DATABASE_DSN";
#[cfg(feature = "metocean-pg-store")]
const ENV_KAFKA_BROKERS: &str = "MET_OCEAN_KAFKA_BROKERS";

fn error(code: &'static str, message: impl Into<String>) -> ValidationError {
    ValidationError {
        code,
        message: message.into(),
    }
}

#[cfg(feature = "metocean-pg-store")]
fn load_regular_file(path: &std::path::Path) -> Result<Vec<u8>, ValidationError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|fs_error| error("config_read_failed", fs_error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(error(
            "invalid_config_path",
            "configuration path must be a regular file and not a symbolic link",
        ));
    }
    std::fs::read(path).map_err(|fs_error| error("config_read_failed", fs_error.to_string()))
}

#[cfg(feature = "metocean-pg-store")]
fn required_env_path(name: &str) -> Result<PathBuf, ValidationError> {
    let value =
        std::env::var(name).map_err(|_| error("missing_env", format!("{name} is required")))?;
    let trimmed = value.trim().to_owned();
    if trimmed.is_empty() {
        return Err(error("missing_env", format!("{name} must not be empty")));
    }
    Ok(PathBuf::from(trimmed))
}

#[cfg(feature = "metocean-pg-store")]
fn load_feed_config() -> Result<FeedSetConfig, ValidationError> {
    let Some(path) = std::env::var(ENV_FEED_CONFIG)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        // No feed configured: honest UNAVAILABLE, zero advisories.
        return Ok(FeedSetConfig {
            feeds: vec![],
            advisory_staleness_seconds: None,
        });
    };
    let raw = load_regular_file(&PathBuf::from(path))?;
    let config: FeedSetConfig = serde_json::from_slice(&raw)
        .map_err(|serde_error| error("invalid_feed_config", serde_error.to_string()))?;
    config.validate()?;
    Ok(config)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(run_error) => {
            eprintln!("error {}: {}", run_error.code, run_error.message);
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "metocean-pg-store"))]
fn run() -> Result<(), ValidationError> {
    Err(error(
        "store_unavailable",
        "this binary requires the metocean-pg-store build feature",
    ))
}

#[cfg(feature = "metocean-pg-store")]
fn run() -> Result<(), ValidationError> {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "status".to_owned());
    let key_directory = KeyDirectory::load(&required_env_path(ENV_KEY_DIRECTORY)?)?;
    let registry = load_hazard_zone_registry(
        &load_regular_file(&required_env_path(ENV_REGISTRY_PATH)?)?,
        &key_directory,
    )?;
    let policy = load_advisory_policy(
        &load_regular_file(&required_env_path(ENV_POLICY_PATH)?)?,
        &key_directory,
    )?;
    let config = load_feed_config()?;
    let dsn = std::env::var(ENV_DATABASE_DSN)
        .map_err(|_| error("missing_env", format!("{ENV_DATABASE_DSN} is required")))?;
    #[cfg(feature = "metocean-pg-store")]
    let pg = {
        let mut pg = store::connect_postgres(dsn.trim())?;
        pg.migrate()?;
        pg
    };
    {
        let mut service = MetoceanService::new(config, registry, policy, pg)?;
        let now = Utc::now();
        match command.as_str() {
            "status" => {
                let status = service.status(now)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&status)
                        .map_err(|e| error("encode_failed", e.to_string()))?
                );
            }
            "metrics" => print!("{}", service.metrics().render_prometheus()),
            "poll" => {
                let once = std::env::args().any(|arg| arg == "--once");
                if !once {
                    return Err(error(
                        "invalid_arguments",
                        "only `poll --once` is supported by this binary",
                    ));
                }
                let brokers = std::env::var(ENV_KAFKA_BROKERS).map_err(|_| {
                    error("missing_env", format!("{ENV_KAFKA_BROKERS} is required"))
                })?;
                let mut fetcher = fetch::connect_https()?;
                let mut publisher = publish::connect_kafka(brokers.trim())?;
                let signing = EnvelopeSigningContext::from_env()?;
                let report =
                    service.poll_once(fetcher.as_mut(), publisher.as_mut(), &signing, now)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .map_err(|e| error("encode_failed", e.to_string()))?
                );
            }
            "override" => {
                let document = std::env::args().nth(2).ok_or_else(|| {
                    error("invalid_arguments", "override requires a document path")
                })?;
                let raw = load_regular_file(&PathBuf::from(document))?;
                let operators =
                    OperatorRegistry::load(&required_env_path(ENV_OPERATOR_KEY_DIRECTORY)?)?;
                let brokers = std::env::var(ENV_KAFKA_BROKERS).map_err(|_| {
                    error("missing_env", format!("{ENV_KAFKA_BROKERS} is required"))
                })?;
                let mut publisher = publish::connect_kafka(brokers.trim())?;
                let signing = EnvelopeSigningContext::from_env()?;
                let advisory = service.operator_override(
                    &raw,
                    &operators,
                    publisher.as_mut(),
                    &signing,
                    now,
                )?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&advisory)
                        .map_err(|e| error("encode_failed", e.to_string()))?
                );
            }
            _ => {
                return Err(error(
                    "invalid_arguments",
                    "usage: metocean [status|poll --once|override <document>|metrics]",
                ))
            }
        }
        Ok(())
    }
}
