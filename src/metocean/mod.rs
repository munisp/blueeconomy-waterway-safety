//! Phase-8 met-ocean advisories subsystem (PRA-093).
//!
//! Feed-driven WMO CAP 1.2-profile advisories for waterway hazard zones,
//! issued onto `waterways.met_ocean.advisories.v1` as envelope-v1.0 FHIR
//! message Bundles signed with fleet JWS-EdDSA over RFC 8785 JCS.
//!
//! Doctrine (adopted verbatim from `sensor.rs` / `ingest.rs`):
//!
//! - **No feed configured => honest `UNAVAILABLE`.** The service boots so
//!   dashboards can show the honest state, but it issues zero advisories and
//!   serves zero synthetic readings. There is no synthetic feed.
//! - **Never fabricate a measurement.** A reading exists only when parsed
//!   from a digest-bound source payload fetched from a documented open API.
//!   Malformed, out-of-range, stale or over-capacity feed output is
//!   dead-lettered explicitly ([`MetoceanDeadLetter`]), never silently
//!   dropped and never turned into a reading.
//! - **Stale feeds cancel, they never silently persist advisories.** A
//!   reading older than the advisory staleness window can never trigger a
//!   new advisory; an active advisory whose feed goes dark is terminated by
//!   an explicit CAP `CANCEL` so consumers (the ferry boarding-pause bridge)
//!   resume deterministically.
//! - **Licence compliance is code-visible.** Every reading and advisory
//!   carries the feed's attribution text; per-feed request budgets enforce
//!   the free-tier limits client-side.
//! - **Configuration is governed.** Hazard zones and threshold policies load
//!   only as signed, schema-versioned documents; threshold changes never
//!   arrive through runtime flags.

pub mod envelope;
pub mod evaluate;
pub mod fetch;
pub mod metrics;
pub mod parse;
pub mod publish;
pub mod registry;
pub mod service;
pub mod store;

use crate::geo::GeoPosition;
use crate::ValidationError;
use serde::{Deserialize, Serialize};

/// The advisory topic and event type (blueeconomy-contracts
/// `proto/blueeconomy/contracts/v1/metocean.proto`).
pub const ADVISORY_TOPIC: &str = "waterways.met_ocean.advisories.v1";
pub const ADVISORY_EVENT_TYPE: &str = "waterways.met_ocean.advisory.v1";
/// Envelope producer name (envelope v1.0 `producer` field).
pub const ADVISORY_PRODUCER: &str = "blueeconomy-waterway-safety";
/// Envelope principal role asserted on produced advisories.
pub const ADVISORY_PRINCIPAL_ROLE: &str = "metocean-producer";

/// JSON-schema version tags of the governed configuration artifacts.
pub const HAZARD_ZONE_REGISTRY_SCHEMA_VERSION: &str =
    "blueeconomy.waterway-safety.hazard-zone-registry.v1";
pub const ADVISORY_POLICY_SCHEMA_VERSION: &str = "blueeconomy.waterway-safety.advisory-policy.v1";
pub const READING_SCHEMA_VERSION: &str = "blueeconomy.waterway-safety.met-ocean-reading.v1";
pub const ADVISORY_SCHEMA_VERSION: &str = "blueeconomy.waterway-safety.met-ocean-advisory.v1";
pub const DEAD_LETTER_SCHEMA_VERSION: &str = "blueeconomy.waterway-safety.met-ocean-dead-letter.v1";
pub const STATUS_SCHEMA_VERSION: &str = "blueeconomy.waterway-safety.met-ocean-status.v1";

/// Feed-request budget (free-tier guard, enforced client-side per feed):
/// at most 600 requests per minute, 5_000 per hour and 10_000 per day.
pub const BUDGET_MAX_PER_MINUTE: u32 = 600;
pub const BUDGET_MAX_PER_HOUR: u32 = 5_000;
pub const BUDGET_MAX_PER_DAY: u32 = 10_000;

pub const MAX_FEED_BASE_URL_BYTES: usize = 512;
pub const MAX_ATTRIBUTION_BYTES: usize = 512;
pub const MAX_FEED_PAYLOAD_BYTES: usize = 8_388_608;
pub const MAX_READINGS_PER_PAYLOAD: usize = 100_000;
pub const MIN_POLL_INTERVAL_SECONDS: i64 = 60;
pub const MAX_POLL_INTERVAL_SECONDS: i64 = 86_400;
pub const MAX_STALENESS_SECONDS: i64 = 604_800;

/// Physical sanity bounds; parsed values outside them are dead-lettered,
/// never clamped (no silent correction of upstream data).
pub const MAX_WAVE_HEIGHT_M: f64 = 100.0;
pub const MAX_WAVE_PERIOD_S: f64 = 60.0;
pub const MAX_WIND_SPEED_MS: f64 = 200.0;
pub const MIN_SST_C: f64 = -5.0;
pub const MAX_SST_C: f64 = 45.0;

pub(crate) fn error(code: &'static str, message: impl Into<String>) -> ValidationError {
    ValidationError {
        code,
        message: message.into(),
    }
}

/// Fail-closed taxonomy of met-ocean feed adapters (mirrors
/// `MetoceanFeedKind` in the contract proto).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeedKind {
    OpenMeteoMarine,
    CopernicusWave,
    NoaaGfs,
    /// National met authority CAP feed. Requires an external agreement before
    /// any integration exists; the variant exists so the taxonomy is
    /// forward-compatible, and selecting it without a configured agreement
    /// fails closed at startup.
    NimetCap,
}

impl FeedKind {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        match value {
            "open_meteo_marine" => Ok(Self::OpenMeteoMarine),
            "copernicus_wave" => Ok(Self::CopernicusWave),
            "noaa_gfs" => Ok(Self::NoaaGfs),
            "nimet_cap" => Ok(Self::NimetCap),
            _ => Err(error(
                "invalid_feed_kind",
                "feed kind must be open_meteo_marine, copernicus_wave, noaa_gfs or nimet_cap",
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OpenMeteoMarine => "open_meteo_marine",
            Self::CopernicusWave => "copernicus_wave",
            Self::NoaaGfs => "noaa_gfs",
            Self::NimetCap => "nimet_cap",
        }
    }

    /// Canonical enum wire rendering on the advisory event (proto JSON form
    /// without the `METOCEAN_FEED_KIND_` prefix).
    pub fn contract_name(&self) -> &'static str {
        match self {
            Self::OpenMeteoMarine => "OPEN_METEO_MARINE",
            Self::CopernicusWave => "COPERNICUS_WAVE",
            Self::NoaaGfs => "NOAA_GFS",
            Self::NimetCap => "NIMET_CAP",
        }
    }

    /// Documented default endpoint of the open API this adapter targets.
    pub fn default_base_url(&self) -> &'static str {
        match self {
            // https://open-meteo.com/en/docs/marine-weather-api
            Self::OpenMeteoMarine => "https://marine-api.open-meteo.com/v1/marine",
            // Copernicus Marine toolbox subset service.
            Self::CopernicusWave => "https://marine.copernicus.eu",
            // https://nomads.ncep.noaa.gov/ GRIB filter (GFS 0.25 degree).
            Self::NoaaGfs => "https://nomads.ncep.noaa.gov/cgi-bin/filter_gfs_0p25.pl",
            Self::NimetCap => "https://nimet.gov.ng",
        }
    }
}

/// One configured met-ocean feed source. Secrets never appear here: API
/// credentials (for example the Copernicus Marine account) are resolved
/// environment-only by the fetch layer.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FeedSourceConfig {
    pub feed_id: String,
    #[serde(deserialize_with = "deserialize_feed_kind")]
    pub kind: FeedKind,
    pub base_url: String,
    pub poll_interval_seconds: i64,
    /// Licence attribution rendered on every reading and advisory derived
    /// from this feed (for example "Weather data by Open-Meteo.com").
    pub attribution_text: String,
    pub enabled: bool,
}

fn deserialize_feed_kind<'de, D>(deserializer: D) -> Result<FeedKind, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    FeedKind::parse(&raw).map_err(serde::de::Error::custom)
}

/// The deployment's feed set plus advisory staleness policy.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FeedSetConfig {
    pub feeds: Vec<FeedSourceConfig>,
    /// Readings older than this (by `fetched_at`) can never trigger a new
    /// advisory. Absent => default of twice the feed's poll interval.
    #[serde(default)]
    pub advisory_staleness_seconds: Option<i64>,
}

impl FeedSetConfig {
    pub const MAX_FEEDS: usize = 32;

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.feeds.len() > Self::MAX_FEEDS {
            return Err(error(
                "invalid_feed_config",
                format!("feed set must contain at most {} feeds", Self::MAX_FEEDS),
            ));
        }
        for (index, feed) in self.feeds.iter().enumerate() {
            validate_feed(feed)?;
            if self.feeds[..index]
                .iter()
                .any(|previous| previous.feed_id == feed.feed_id)
            {
                return Err(error(
                    "invalid_feed_config",
                    "feed identifiers must be unique",
                ));
            }
        }
        if let Some(staleness) = self.advisory_staleness_seconds {
            validate_staleness(staleness)?;
        }
        Ok(())
    }

    pub fn enabled_feeds(&self) -> impl Iterator<Item = &FeedSourceConfig> {
        self.feeds.iter().filter(|feed| feed.enabled)
    }

    /// The staleness window applying to one feed: the configured override or
    /// the default of twice the poll interval.
    pub fn staleness_for(&self, feed: &FeedSourceConfig) -> i64 {
        self.advisory_staleness_seconds
            .unwrap_or(feed.poll_interval_seconds.saturating_mul(2))
    }
}

pub fn validate_staleness(staleness_seconds: i64) -> Result<(), ValidationError> {
    if staleness_seconds <= 0 || staleness_seconds > MAX_STALENESS_SECONDS {
        return Err(error(
            "invalid_staleness_window",
            format!("advisory staleness must be between 1 and {MAX_STALENESS_SECONDS} seconds"),
        ));
    }
    Ok(())
}

pub fn validate_feed(feed: &FeedSourceConfig) -> Result<(), ValidationError> {
    crate::validate_identifier("feed.feed_id", &feed.feed_id, 128)?;
    // The NiMet CAP feed needs an external agreement before any integration
    // exists (standing external-action boundary); configuring it is refused.
    if feed.kind == FeedKind::NimetCap {
        return Err(error(
            "feed_requires_external_agreement",
            "nimet_cap feeds require a concluded external agreement; no adapter ships",
        ));
    }
    if feed.base_url.is_empty() || feed.base_url.len() > MAX_FEED_BASE_URL_BYTES {
        return Err(error(
            "invalid_feed_config",
            format!("feed base_url must contain between 1 and {MAX_FEED_BASE_URL_BYTES} bytes"),
        ));
    }
    // Plain-HTTP feeds are refused: licence terms and payload integrity both
    // require TLS on the open API endpoints.
    if !feed.base_url.starts_with("https://") {
        return Err(error(
            "invalid_feed_config",
            "feed base_url must be an https:// endpoint",
        ));
    }
    if feed.poll_interval_seconds < MIN_POLL_INTERVAL_SECONDS
        || feed.poll_interval_seconds > MAX_POLL_INTERVAL_SECONDS
    {
        return Err(error(
            "invalid_feed_config",
            format!(
                "poll interval must be between {MIN_POLL_INTERVAL_SECONDS} and {MAX_POLL_INTERVAL_SECONDS} seconds"
            ),
        ));
    }
    if feed.enabled
        && (feed.attribution_text.is_empty()
            || feed.attribution_text.len() > MAX_ATTRIBUTION_BYTES
            || feed.attribution_text.trim() != feed.attribution_text)
    {
        return Err(error(
            "invalid_feed_config",
            "enabled feeds must carry non-empty canonical licence attribution text",
        ));
    }
    Ok(())
}

/// One normalised met-ocean observation/forecast at a monitored point. Raw
/// truth, immutable, digest-bound to its source payload. `Option` fields are
/// absent measurements — never fabricated defaults.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NormalizedReading {
    pub schema_version: String,
    pub reading_id: String,
    pub feed_id: String,
    pub feed_kind: FeedKind,
    pub zone_id: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    #[serde(default)]
    pub observed_at: Option<String>,
    #[serde(default)]
    pub forecast_for: Option<String>,
    #[serde(default)]
    pub model_run_at: Option<String>,
    pub fetched_at: String,
    #[serde(default)]
    pub wave_height_m: Option<f64>,
    #[serde(default)]
    pub wave_period_s: Option<f64>,
    #[serde(default)]
    pub wave_direction_deg: Option<f64>,
    #[serde(default)]
    pub swell_height_m: Option<f64>,
    #[serde(default)]
    pub swell_period_s: Option<f64>,
    #[serde(default)]
    pub wind_speed_ms: Option<f64>,
    #[serde(default)]
    pub wind_gust_ms: Option<f64>,
    #[serde(default)]
    pub sst_c: Option<f64>,
    pub source_payload_sha256: String,
    pub attribution_text: String,
}

/// Why feed output was rejected to the explicit dead-letter outcome.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MetoceanDeadLetterReason {
    MalformedPayload,
    StaleReading,
    CapacityExceeded,
    TransportFailure,
    BudgetExceeded,
}

/// Durable, explicit record of rejected feed output (mirrors
/// `ingest::DeadLetterEvent` discipline).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MetoceanDeadLetter {
    pub schema_version: String,
    pub feed_id: String,
    pub feed_kind: String,
    pub reason: MetoceanDeadLetterReason,
    pub error_code: String,
    pub payload_sha256: String,
    pub detail: String,
    pub recorded_at: String,
}

pub fn dead_letter(
    feed: &FeedSourceConfig,
    reason: MetoceanDeadLetterReason,
    error_code: &str,
    payload: &[u8],
    detail: &str,
    recorded_at: &str,
) -> MetoceanDeadLetter {
    use sha2::{Digest, Sha256};
    MetoceanDeadLetter {
        schema_version: DEAD_LETTER_SCHEMA_VERSION.to_owned(),
        feed_id: truncate_field(&feed.feed_id),
        feed_kind: feed.kind.as_str().to_owned(),
        reason,
        error_code: truncate_field(error_code),
        payload_sha256: crate::hex_lowercase(Sha256::digest(payload)),
        detail: truncate_field(detail),
        recorded_at: recorded_at.to_owned(),
    }
}

fn truncate_field(value: &str) -> String {
    const LIMIT: usize = 256;
    if value.len() <= LIMIT {
        return value.to_owned();
    }
    let mut end = LIMIT;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

/// Per-feed availability as reported by the status surface. `Unavailable`
/// is the honest state when no feed is configured or a feed has never
/// succeeded — never masked, never synthesised.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FeedAvailability {
    Ok,
    Degraded,
    Unavailable,
}

/// Health of one configured feed.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FeedHealth {
    pub feed_id: String,
    pub feed_kind: String,
    pub enabled: bool,
    pub availability: FeedAvailability,
    #[serde(default)]
    pub last_success_at: Option<String>,
    #[serde(default)]
    pub last_failure_at: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    /// Age of the last successful poll at evaluation time, when known.
    #[serde(default)]
    pub staleness_seconds: Option<i64>,
}

/// The canonical status document (`GET /v1/met-ocean/status` equivalent).
/// With zero configured feeds the overall availability is `UNAVAILABLE`
/// with the explicit reason `no_feed_configured`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MetoceanStatus {
    pub schema_version: String,
    pub evaluated_at: String,
    pub availability: FeedAvailability,
    pub reason: String,
    pub feeds: Vec<FeedHealth>,
}

/// A monitored point of a hazard zone: where the feed is sampled.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
pub struct MonitoredPoint {
    pub latitude: f64,
    pub longitude: f64,
}

impl MonitoredPoint {
    pub fn position(&self) -> Result<GeoPosition, ValidationError> {
        GeoPosition::new(self.latitude, self.longitude)
    }
}

/// Deterministic reading identifier: `mor-` plus the first 24 hex characters
/// of the SHA-256 over the feed identity, source payload digest and the
/// reading's distinguishing fields. Identical upstream payloads re-ingested
/// produce identical identifiers (idempotent re-delivery).
pub fn reading_id(
    feed_id: &str,
    source_payload_sha256: &str,
    zone_id: Option<&str>,
    forecast_for: Option<&str>,
    observed_at: Option<&str>,
) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    for field in [
        feed_id,
        source_payload_sha256,
        zone_id.unwrap_or(""),
        forecast_for.unwrap_or(""),
        observed_at.unwrap_or(""),
    ] {
        digest.update(field.as_bytes());
        digest.update([0]);
    }
    format!("mor-{}", &crate::hex_lowercase(digest.finalize())[..24])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(kind: FeedKind) -> FeedSourceConfig {
        FeedSourceConfig {
            feed_id: "feed-1".to_owned(),
            kind,
            base_url: kind.default_base_url().to_owned(),
            poll_interval_seconds: 900,
            attribution_text: "Weather data by Open-Meteo.com".to_owned(),
            enabled: true,
        }
    }

    #[test]
    fn rejects_nimet_feed_pending_external_agreement() {
        assert_eq!(
            validate_feed(&feed(FeedKind::NimetCap)).unwrap_err().code,
            "feed_requires_external_agreement"
        );
    }

    #[test]
    fn rejects_plain_http_and_missing_attribution() {
        let mut insecure = feed(FeedKind::OpenMeteoMarine);
        insecure.base_url = "http://marine-api.open-meteo.com".to_owned();
        assert_eq!(
            validate_feed(&insecure).unwrap_err().code,
            "invalid_feed_config"
        );
        let mut no_attribution = feed(FeedKind::OpenMeteoMarine);
        no_attribution.attribution_text = "  ".to_owned();
        assert_eq!(
            validate_feed(&no_attribution).unwrap_err().code,
            "invalid_feed_config"
        );
    }

    #[test]
    fn staleness_defaults_to_twice_poll_interval() {
        let set = FeedSetConfig {
            feeds: vec![feed(FeedKind::OpenMeteoMarine)],
            advisory_staleness_seconds: None,
        };
        set.validate().expect("valid feed set");
        assert_eq!(set.staleness_for(&set.feeds[0]), 1800);
        let overridden = FeedSetConfig {
            feeds: vec![feed(FeedKind::OpenMeteoMarine)],
            advisory_staleness_seconds: Some(600),
        };
        assert_eq!(overridden.staleness_for(&overridden.feeds[0]), 600);
    }

    #[test]
    fn rejects_duplicate_feed_ids_and_oversized_sets() {
        let set = FeedSetConfig {
            feeds: vec![
                feed(FeedKind::OpenMeteoMarine),
                feed(FeedKind::OpenMeteoMarine),
            ],
            advisory_staleness_seconds: None,
        };
        assert_eq!(set.validate().unwrap_err().code, "invalid_feed_config");
    }

    #[test]
    fn reading_ids_are_deterministic_and_distinct() {
        let digest = "a".repeat(64);
        let first = reading_id(
            "feed-1",
            &digest,
            Some("zone-a"),
            Some("2026-08-30T00:00:00Z"),
            None,
        );
        assert_eq!(
            first,
            reading_id(
                "feed-1",
                &digest,
                Some("zone-a"),
                Some("2026-08-30T00:00:00Z"),
                None
            )
        );
        assert_ne!(
            first,
            reading_id(
                "feed-1",
                &digest,
                Some("zone-a"),
                Some("2026-08-30T01:00:00Z"),
                None
            )
        );
        assert!(first.starts_with("mor-"));
        assert_eq!(first.len(), 4 + 24);
    }
}
