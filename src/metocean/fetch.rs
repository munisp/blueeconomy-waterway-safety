//! Feed fetch transports for the ingest adapters.
//!
//! The production fetch is a real HTTPS client behind the `http-feeds`
//! cargo feature (pinned `ureq`, rustls TLS). Without the feature the
//! transport reports `transport_unavailable` — fail-closed, and the service
//! degrades the feed honestly rather than fabricating readings.
//!
//! Secrets are environment-only: the Copernicus Marine account arrives via
//! `COPERNICUSMARINE_SERVICE_USERNAME` / `COPERNICUSMARINE_SERVICE_PASSWORD`
//! (the documented toolbox variable names) and is sent as HTTP basic auth;
//! Open-Meteo and NOAA NOMADS are keyless.

use super::parse::{gfs_request_url, open_meteo_request_url};
use super::{error, FeedKind, FeedSourceConfig, MonitoredPoint};
use crate::ValidationError;
use chrono::{DateTime, Datelike, Duration, Timelike, Utc};

/// Copernicus Marine account credentials (documented toolbox variable
/// names), resolved environment-only.
pub const ENV_COPERNICUS_USERNAME: &str = "COPERNICUSMARINE_SERVICE_USERNAME";
pub const ENV_COPERNICUS_PASSWORD: &str = "COPERNICUSMARINE_SERVICE_PASSWORD";

#[cfg(feature = "http-feeds")]
const FETCH_TIMEOUT_SECONDS: u64 = 30;
/// GFS cycles run 00/06/12/18 UTC; data appears roughly four hours after
/// the cycle, so the fetch targets the latest cycle older than this lag.
const GFS_MODEL_LAG_HOURS: i64 = 4;
const GFS_FORECAST_HOUR: u32 = 3;

/// The production fetch surface: return the raw response body or an error.
pub trait FeedFetch {
    fn fetch(&mut self, feed: &FeedSourceConfig, url: &str) -> Result<Vec<u8>, ValidationError>;
}

/// Build the documented request URL for one monitored point at `now`.
pub fn request_url(
    feed: &FeedSourceConfig,
    point: MonitoredPoint,
    now: DateTime<Utc>,
) -> Result<String, ValidationError> {
    match feed.kind {
        FeedKind::OpenMeteoMarine => Ok(open_meteo_request_url(&feed.base_url, point, 3)),
        FeedKind::NoaaGfs => {
            let run = latest_gfs_model_run(now);
            gfs_request_url(&feed.base_url, point, &run, GFS_FORECAST_HOUR)
        }
        FeedKind::CopernicusWave => {
            // The toolbox `subset` endpoint requires the registered account;
            // the URL is assembled but the fetch refuses without env creds.
            Ok(format!(
                "{}/api/subset?latitude={:.4}&longitude={:.4}",
                feed.base_url.trim_end_matches('/'),
                point.latitude,
                point.longitude
            ))
        }
        FeedKind::NimetCap => Err(error(
            "feed_requires_external_agreement",
            "nimet_cap feeds require a concluded external agreement; no adapter ships",
        )),
    }
}

/// The GFS model run stamp ("YYYYMMDD/HH") whose data is plausibly
/// published at `now` (latest 6-hourly cycle older than the publish lag).
pub fn latest_gfs_model_run(now: DateTime<Utc>) -> String {
    let eligible = now - Duration::hours(GFS_MODEL_LAG_HOURS);
    let cycle_hour = (eligible.hour() / 6) * 6;
    format!(
        "{:04}{:02}{:02}/{:02}",
        eligible.year(),
        eligible.month(),
        eligible.day(),
        cycle_hour
    )
}

/// HTTPS fetch via `ureq` (`http-feeds` feature).
#[cfg(feature = "http-feeds")]
pub struct UreqFetch {
    agent: ureq::Agent,
}

#[cfg(feature = "http-feeds")]
impl UreqFetch {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECONDS))
            .build();
        Self { agent }
    }

    fn copernicus_auth(&self) -> Result<(String, String), ValidationError> {
        let username = std::env::var(ENV_COPERNICUS_USERNAME)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let password = std::env::var(ENV_COPERNICUS_PASSWORD)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        match (username, password) {
            (Some(username), Some(password)) => Ok((username, password)),
            _ => Err(error(
                "missing_feed_credentials",
                "copernicus_wave feeds require COPERNICUSMARINE_SERVICE_USERNAME and COPERNICUSMARINE_SERVICE_PASSWORD (env-only)",
            )),
        }
    }
}

#[cfg(feature = "http-feeds")]
impl Default for UreqFetch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "http-feeds")]
impl FeedFetch for UreqFetch {
    fn fetch(&mut self, feed: &FeedSourceConfig, url: &str) -> Result<Vec<u8>, ValidationError> {
        use std::io::Read;
        let mut request = self.agent.get(url).set(
            "User-Agent",
            "blueeconomy-waterway-safety/metocean (contact: NIMASA ops)",
        );
        if feed.kind == FeedKind::CopernicusWave {
            let (username, password) = self.copernicus_auth()?;
            request = request.set(
                "Authorization",
                &format!(
                    "Basic {}",
                    base64::engine::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        format!("{username}:{password}").as_bytes(),
                    )
                ),
            );
        }
        let response = request.call().map_err(|fetch_error| {
            error(
                "feed_fetch_failed",
                format!("{}: {fetch_error}", feed.feed_id),
            )
        })?;
        let mut body = Vec::new();
        response
            .into_reader()
            .take((super::MAX_FEED_PAYLOAD_BYTES + 1) as u64)
            .read_to_end(&mut body)
            .map_err(|io_error| error("feed_fetch_failed", io_error.to_string()))?;
        if body.len() > super::MAX_FEED_PAYLOAD_BYTES {
            return Err(error(
                "feed_payload_capacity_exceeded",
                "feed payload exceeds the accepted byte limit",
            ));
        }
        Ok(body)
    }
}

/// Construct the HTTPS fetch when the feature is compiled in; otherwise
/// fail closed like the gateway's transport selection.
pub fn connect_https() -> Result<Box<dyn FeedFetch>, ValidationError> {
    #[cfg(feature = "http-feeds")]
    {
        Ok(Box::new(UreqFetch::new()))
    }
    #[cfg(not(feature = "http-feeds"))]
    {
        Err(error(
            "transport_unavailable",
            "the http-feeds feature is not compiled in; feed fetching is unavailable",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gfs_model_run_rolls_to_latest_published_cycle() {
        let now = DateTime::parse_from_rfc3339("2026-08-30T15:30:00Z")
            .expect("time")
            .with_timezone(&Utc);
        assert_eq!(latest_gfs_model_run(now), "20260830/06");
        let early = DateTime::parse_from_rfc3339("2026-08-30T02:00:00Z")
            .expect("time")
            .with_timezone(&Utc);
        assert_eq!(latest_gfs_model_run(early), "20260829/18");
    }

    #[test]
    fn request_urls_are_kind_specific_and_fail_closed_for_nimet() {
        let feed = FeedSourceConfig {
            feed_id: "feed".to_owned(),
            kind: FeedKind::OpenMeteoMarine,
            base_url: FeedKind::OpenMeteoMarine.default_base_url().to_owned(),
            poll_interval_seconds: 900,
            attribution_text: "Weather data by Open-Meteo.com".to_owned(),
            enabled: true,
        };
        let point = MonitoredPoint {
            latitude: 6.0,
            longitude: 3.0,
        };
        let now = DateTime::parse_from_rfc3339("2026-08-30T12:00:00Z")
            .expect("time")
            .with_timezone(&Utc);
        assert!(request_url(&feed, point, now)
            .expect("url")
            .starts_with("https://marine-api.open-meteo.com/v1/marine?"));
        let gfs = FeedSourceConfig {
            kind: FeedKind::NoaaGfs,
            base_url: FeedKind::NoaaGfs.default_base_url().to_owned(),
            attribution_text: "NOAA GFS (NCEP/NOMADS), public domain".to_owned(),
            ..feed.clone()
        };
        assert!(request_url(&gfs, point, now)
            .expect("url")
            .contains("filter_gfs_0p25.pl"));
        let nimet = FeedSourceConfig {
            kind: FeedKind::NimetCap,
            ..feed
        };
        assert_eq!(
            request_url(&nimet, point, now).unwrap_err().code,
            "feed_requires_external_agreement"
        );
    }
}
