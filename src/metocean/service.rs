//! Service orchestration: poll → parse → persist → evaluate → issue/cancel
//! → publish, plus the authenticated operator-override channel. All failure
//! modes are explicit: feed failures dead-letter and degrade the feed,
//! publish failures abort issuance (the advisory is not recorded), and with
//! zero configured feeds the service reports honest `UNAVAILABLE` and issues
//! nothing.

use super::envelope::{build_signed_envelope, EnvelopeSigningContext};
use super::evaluate::{
    advisory_id, build_cancel_advisory, reading_is_fresh, Advisory, AdvisorySource, AdvisoryStatus,
    CancelReason, CapCertainty, CapMessageType, CapSeverity, CapUrgency, EngineAction,
};
use super::fetch::{request_url, FeedFetch};
use super::metrics::MetoceanMetrics;
use super::parse::parse_feed_payload;
use super::publish::AdvisoryPublisher;
use super::registry::{
    combined_policy_digest, verify_signed_document, AdvisoryPolicy, HazardZoneRegistry,
    KeyDirectory, ThresholdParam,
};
use super::store::{AdvisoryDelivery, MetoceanStore};
use super::{
    dead_letter, error, FeedAvailability, FeedHealth, FeedSetConfig, FeedSourceConfig,
    MetoceanDeadLetterReason, MetoceanStatus, NormalizedReading, BUDGET_MAX_PER_DAY,
    BUDGET_MAX_PER_HOUR, BUDGET_MAX_PER_MINUTE, STATUS_SCHEMA_VERSION,
};
use crate::ValidationError;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Environment variable carrying the operator key directory path.
pub const ENV_OPERATOR_KEY_DIRECTORY: &str = "MET_OCEAN_OPERATOR_KEY_DIRECTORY";
/// Signed override document schema version.
pub const OPERATOR_OVERRIDE_SCHEMA_VERSION: &str =
    "blueeconomy.waterway-safety.met-ocean-operator-override.v1";
/// The only role permitted to issue operator overrides.
pub const OPERATOR_ROLE: &str = "nimasa-ops";
/// Override freshness window: the signed request must be issued within five
/// minutes of service time (replay window bound; nonces make it exact).
pub const OPERATOR_OVERRIDE_MAX_AGE_SECONDS: i64 = 300;
/// Fixed attribution rendered on operator-override advisories (the audited
/// manual channel carries no feed licence text).
pub const OPERATOR_ATTRIBUTION: &str = "NIMASA operations override (audited manual channel)";

fn rfc3339_z(now: DateTime<Utc>) -> String {
    now.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Per-feed request budget windows (free-tier guard).
#[derive(Clone, Copy, Debug, Default)]
struct BudgetWindow {
    minute_start: i64,
    minute_count: u32,
    hour_start: i64,
    hour_count: u32,
    day_start: i64,
    day_count: u32,
}

impl BudgetWindow {
    fn check_and_record(&mut self, epoch: i64) -> bool {
        if epoch / 60 != self.minute_start {
            self.minute_start = epoch / 60;
            self.minute_count = 0;
        }
        if epoch / 3_600 != self.hour_start {
            self.hour_start = epoch / 3_600;
            self.hour_count = 0;
        }
        if epoch / 86_400 != self.day_start {
            self.day_start = epoch / 86_400;
            self.day_count = 0;
        }
        if self.minute_count >= BUDGET_MAX_PER_MINUTE
            || self.hour_count >= BUDGET_MAX_PER_HOUR
            || self.day_count >= BUDGET_MAX_PER_DAY
        {
            return false;
        }
        self.minute_count += 1;
        self.hour_count += 1;
        self.day_count += 1;
        true
    }
}

/// Operator key directory: signing keys plus their asserted roles. JSON
/// shape `{kid: {"public_key_base64url": "...", "role": "nimasa-ops"}}`;
/// loaded fail-closed (regular file, no symlinks).
pub struct OperatorRegistry {
    directory: KeyDirectory,
    roles: BTreeMap<String, String>,
}

impl OperatorRegistry {
    pub fn from_json(raw: &[u8]) -> Result<Self, ValidationError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Entry {
            public_key_base64url: String,
            role: String,
        }
        let entries: BTreeMap<String, Entry> = serde_json::from_slice(raw)
            .map_err(|serde_error| error("invalid_key_directory", serde_error.to_string()))?;
        if entries.is_empty() {
            return Err(error(
                "invalid_key_directory",
                "operator directory must contain at least one key",
            ));
        }
        let mut roles = BTreeMap::new();
        let mut directory_entries = BTreeMap::new();
        for (kid, entry) in entries {
            crate::validate_identifier("operator.kid", &kid, 256)?;
            crate::validate_identifier("operator.role", &entry.role, 64)?;
            use base64::Engine as _;
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(entry.public_key_base64url.as_bytes())
                .map_err(|_| error("invalid_key_directory", "key is not base64url"))?;
            let encoded: [u8; 32] = bytes
                .try_into()
                .map_err(|_| error("invalid_key_directory", "Ed25519 key must be 32 bytes"))?;
            directory_entries.insert(
                kid.clone(),
                ed25519_dalek::VerifyingKey::from_bytes(&encoded)
                    .map_err(|key_error| error("invalid_key_directory", key_error.to_string()))?,
            );
            roles.insert(kid, entry.role);
        }
        Ok(Self {
            directory: KeyDirectory::from_entries(directory_entries),
            roles,
        })
    }

    pub fn load(path: &std::path::Path) -> Result<Self, ValidationError> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|fs_error| error("key_directory_read_failed", fs_error.to_string()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(error(
                "invalid_key_directory_path",
                "operator key directory path must be a regular file and not a symbolic link",
            ));
        }
        let raw = std::fs::read(path)
            .map_err(|fs_error| error("key_directory_read_failed", fs_error.to_string()))?;
        Self::from_json(&raw)
    }
}

/// The authenticated, validated operator override request.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorOverridePayload {
    pub schema_version: String,
    /// `met_ocean.operator_override` (issue) or `met_ocean.operator_cancel`.
    pub action: String,
    pub zone_id: String,
    pub phenomenon_code: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub effective_from: Option<String>,
    #[serde(default)]
    pub effective_until: Option<String>,
    #[serde(default)]
    pub references_advisory_id: Option<String>,
    pub rationale: String,
    pub nonce: String,
    pub issued_at: String,
}

/// What one poll cycle did — explicit counts, never silent.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PollReport {
    pub readings_ingested: usize,
    pub dead_letters: usize,
    pub advisories_issued: usize,
    pub advisories_cancelled: usize,
    pub feeds_ok: usize,
    pub feeds_degraded: usize,
}

/// The met-ocean advisory service.
pub struct MetoceanService<S: MetoceanStore> {
    config: FeedSetConfig,
    registry: HazardZoneRegistry,
    policy: AdvisoryPolicy,
    policy_digest: String,
    store: S,
    metrics: MetoceanMetrics,
    budgets: BTreeMap<String, BudgetWindow>,
}

impl<S: MetoceanStore> MetoceanService<S> {
    /// Fail-closed construction: config, registry and policy validate before
    /// the service can do anything.
    pub fn new(
        config: FeedSetConfig,
        registry: HazardZoneRegistry,
        policy: AdvisoryPolicy,
        store: S,
    ) -> Result<Self, ValidationError> {
        config.validate()?;
        let policy_digest = combined_policy_digest(&policy, &registry);
        Ok(Self {
            config,
            registry,
            policy,
            policy_digest,
            store,
            metrics: MetoceanMetrics::default(),
            budgets: BTreeMap::new(),
        })
    }

    pub fn metrics(&self) -> &MetoceanMetrics {
        &self.metrics
    }

    pub fn store(&mut self) -> &mut S {
        &mut self.store
    }

    pub fn registry(&self) -> &HazardZoneRegistry {
        &self.registry
    }

    pub fn policy(&self) -> &AdvisoryPolicy {
        &self.policy
    }

    pub fn config(&self) -> &FeedSetConfig {
        &self.config
    }

    /// The canonical status document. Zero configured feeds => UNAVAILABLE
    /// with reason `no_feed_configured` (honest, never masked).
    pub fn status(&mut self, now: DateTime<Utc>) -> Result<MetoceanStatus, ValidationError> {
        let mut feeds = Vec::new();
        for feed in &self.config.feeds {
            let health = self.store.feed_health(&feed.feed_id)?;
            let staleness_window = self.config.staleness_for(feed);
            let staleness_seconds = health
                .as_ref()
                .and_then(|health| health.last_success_at.clone())
                .and_then(|success| DateTime::parse_from_rfc3339(&success).ok())
                .map(|success| {
                    now.signed_duration_since(success.with_timezone(&Utc))
                        .num_seconds()
                });
            let availability = match &health {
                None => FeedAvailability::Unavailable,
                Some(_) if !feed.enabled => FeedAvailability::Unavailable,
                Some(health) => match staleness_seconds {
                    Some(age) if age >= 0 && age <= staleness_window => health.availability,
                    Some(_) => FeedAvailability::Degraded,
                    None => FeedAvailability::Unavailable,
                },
            };
            feeds.push(FeedHealth {
                feed_id: feed.feed_id.clone(),
                feed_kind: feed.kind.as_str().to_owned(),
                enabled: feed.enabled,
                availability,
                last_success_at: health.as_ref().and_then(|h| h.last_success_at.clone()),
                last_failure_at: health.as_ref().and_then(|h| h.last_failure_at.clone()),
                last_error: health.as_ref().and_then(|h| h.last_error.clone()),
                staleness_seconds,
            });
        }
        let enabled: Vec<&FeedHealth> = feeds.iter().filter(|feed| feed.enabled).collect();
        let (availability, reason) = if feeds.is_empty() {
            (
                FeedAvailability::Unavailable,
                "no_feed_configured".to_owned(),
            )
        } else if enabled.is_empty() {
            (
                FeedAvailability::Unavailable,
                "all_feeds_disabled".to_owned(),
            )
        } else if enabled
            .iter()
            .all(|feed| feed.availability == FeedAvailability::Unavailable)
        {
            (
                FeedAvailability::Unavailable,
                "feeds_unavailable".to_owned(),
            )
        } else if enabled
            .iter()
            .all(|feed| feed.availability == FeedAvailability::Ok)
        {
            (FeedAvailability::Ok, "ok".to_owned())
        } else {
            (FeedAvailability::Degraded, "feed_degraded".to_owned())
        };
        Ok(MetoceanStatus {
            schema_version: STATUS_SCHEMA_VERSION.to_owned(),
            evaluated_at: rfc3339_z(now),
            availability,
            reason,
            feeds,
        })
    }

    fn record_feed_health(
        &mut self,
        feed: &FeedSourceConfig,
        availability: FeedAvailability,
        success_at: Option<String>,
        failure_at: Option<String>,
        last_error: Option<String>,
    ) -> Result<(), ValidationError> {
        self.store.upsert_feed_health(&FeedHealth {
            feed_id: feed.feed_id.clone(),
            feed_kind: feed.kind.as_str().to_owned(),
            enabled: feed.enabled,
            availability,
            last_success_at: success_at,
            last_failure_at: failure_at,
            last_error,
            staleness_seconds: None,
        })
    }

    fn letter(
        &mut self,
        feed: &FeedSourceConfig,
        reason: MetoceanDeadLetterReason,
        code: &str,
        payload: &[u8],
        detail: &str,
        now: DateTime<Utc>,
    ) -> Result<(), ValidationError> {
        let letter = dead_letter(feed, reason, code, payload, detail, &rfc3339_z(now));
        self.store.record_dead_letter(&letter)?;
        self.metrics.dead_letter(code);
        Ok(())
    }

    /// One poll cycle across every enabled feed and zone, then evaluation.
    /// Spans: `metocean.feed.poll`, `metocean.feed.parse`,
    /// `metocean.advisory.evaluate`, `metocean.advisory.issue`,
    /// `metocean.advisory.cancel`.
    pub fn poll_once(
        &mut self,
        fetcher: &mut dyn FeedFetch,
        publisher: &mut dyn AdvisoryPublisher,
        signing: &EnvelopeSigningContext,
        now: DateTime<Utc>,
    ) -> Result<PollReport, ValidationError> {
        let mut report = PollReport::default();
        let feeds: Vec<FeedSourceConfig> = self.config.enabled_feeds().cloned().collect();
        for feed in feeds {
            let poll_span = tracing::info_span!(
                "metocean.feed.poll",
                feed.id = %feed.feed_id,
                feed.kind = feed.kind.as_str(),
            );
            let _poll_guard = poll_span.enter();
            let budget_ok = self
                .budgets
                .entry(feed.feed_id.clone())
                .or_default()
                .check_and_record(now.timestamp());
            if !budget_ok {
                self.metrics
                    .feed_poll(feed.kind.as_str(), "budget_exceeded");
                self.letter(
                    &feed,
                    MetoceanDeadLetterReason::BudgetExceeded,
                    "feed_budget_exceeded",
                    b"",
                    "client-side request budget exhausted",
                    now,
                )?;
                report.dead_letters += 1;
                self.record_feed_health(
                    &feed,
                    FeedAvailability::Degraded,
                    None,
                    Some(rfc3339_z(now)),
                    Some("feed_budget_exceeded".to_owned()),
                )?;
                report.feeds_degraded += 1;
                continue;
            }
            let mut feed_failed = false;
            for zone in self.registry.zones.clone() {
                for point in zone.monitored_points.clone() {
                    let url = match request_url(&feed, point, now) {
                        Ok(url) => url,
                        Err(request_error) => {
                            feed_failed = true;
                            self.letter(
                                &feed,
                                MetoceanDeadLetterReason::TransportFailure,
                                request_error.code,
                                b"",
                                &request_error.message,
                                now,
                            )?;
                            continue;
                        }
                    };
                    let payload = match fetcher.fetch(&feed, &url) {
                        Ok(payload) => payload,
                        Err(fetch_error) => {
                            feed_failed = true;
                            self.metrics.feed_poll(feed.kind.as_str(), "error");
                            self.letter(
                                &feed,
                                MetoceanDeadLetterReason::TransportFailure,
                                fetch_error.code,
                                b"",
                                &fetch_error.message,
                                now,
                            )?;
                            continue;
                        }
                    };
                    let parse_span = tracing::info_span!(
                        "metocean.feed.parse",
                        feed.id = %feed.feed_id,
                        feed.kind = feed.kind.as_str(),
                    );
                    let readings = {
                        let _parse_guard = parse_span.enter();
                        parse_feed_payload(&feed, &zone.zone_id, point, &payload, &rfc3339_z(now))
                    };
                    match readings {
                        Ok(readings) => {
                            for reading in &readings {
                                if self.store.record_reading(reading)? {
                                    self.metrics.readings_ingested(1);
                                    report.readings_ingested += 1;
                                }
                            }
                            self.metrics.feed_poll(feed.kind.as_str(), "ok");
                            self.metrics
                                .feed_last_success(feed.kind.as_str(), now.timestamp());
                        }
                        Err(parse_error) => {
                            feed_failed = true;
                            report.dead_letters += 1;
                            self.metrics.feed_poll(feed.kind.as_str(), "error");
                            let reason = match parse_error.code {
                                "feed_payload_capacity_exceeded" => {
                                    MetoceanDeadLetterReason::CapacityExceeded
                                }
                                _ => MetoceanDeadLetterReason::MalformedPayload,
                            };
                            self.letter(
                                &feed,
                                reason,
                                parse_error.code,
                                &payload,
                                &parse_error.message,
                                now,
                            )?;
                        }
                    }
                }
            }
            if feed_failed {
                report.feeds_degraded += 1;
                self.record_feed_health(
                    &feed,
                    FeedAvailability::Degraded,
                    None,
                    Some(rfc3339_z(now)),
                    Some("feed_poll_failed".to_owned()),
                )?;
            } else {
                report.feeds_ok += 1;
                self.record_feed_health(
                    &feed,
                    FeedAvailability::Ok,
                    Some(rfc3339_z(now)),
                    None,
                    None,
                )?;
            }
            drop(_poll_guard);

            // Evaluation per zone against this feed's readings.
            let evaluate_span = tracing::info_span!(
                "metocean.advisory.evaluate",
                feed.id = %feed.feed_id,
                feed.kind = feed.kind.as_str(),
            );
            let _evaluate_guard = evaluate_span.enter();
            let staleness = self.config.staleness_for(&feed);
            let not_before = now - Duration::seconds(staleness);
            for zone in self.registry.zones.clone() {
                let fresh: Vec<NormalizedReading> = self
                    .store
                    .fresh_readings(&zone.zone_id, &feed.feed_id, not_before)?
                    .into_iter()
                    .filter(|reading| reading_is_fresh(reading, now, staleness))
                    .collect();
                let active = self.store.active_advisories(&zone.zone_id)?;
                let actions = super::evaluate::evaluate_zone(
                    &self.policy,
                    &self.policy_digest,
                    &feed,
                    &super::evaluate::ZoneEvaluation {
                        zone_id: &zone.zone_id,
                        active: &active,
                        fresh_readings: &fresh,
                        feed_healthy: !feed_failed,
                        staleness_seconds: staleness,
                        now,
                    },
                )?;
                for action in actions {
                    match action {
                        EngineAction::Issue(advisory) => {
                            self.issue(publisher, signing, advisory, now)?;
                            report.advisories_issued += 1;
                        }
                        EngineAction::Cancel {
                            target_advisory_id,
                            target_status,
                            advisory,
                        } => {
                            self.issue(publisher, signing, advisory, now)?;
                            self.store
                                .set_advisory_status(&target_advisory_id, target_status)?;
                            report.advisories_cancelled += 1;
                        }
                    }
                }
                self.refresh_active_gauge(&zone.zone_id)?;
            }
        }
        Ok(report)
    }

    fn refresh_active_gauge(&mut self, zone_id: &str) -> Result<(), ValidationError> {
        let active = self.store.active_advisories(zone_id)?;
        let mut by_severity: BTreeMap<String, u64> = BTreeMap::new();
        for advisory in active {
            *by_severity
                .entry(advisory.severity.wire().to_owned())
                .or_insert(0) += 1;
        }
        for (severity, count) in by_severity {
            self.metrics.advisories_active(zone_id, &severity, count);
        }
        Ok(())
    }

    /// Sign, publish, then persist an advisory. Publish failure aborts the
    /// issuance (nothing is recorded) — fail closed, no partial state.
    fn issue(
        &mut self,
        publisher: &mut dyn AdvisoryPublisher,
        signing: &EnvelopeSigningContext,
        advisory: Advisory,
        now: DateTime<Utc>,
    ) -> Result<(), ValidationError> {
        let span = if advisory.msg_type == CapMessageType::Cancel {
            tracing::info_span!(
                "metocean.advisory.cancel",
                zone_id = %advisory.zone_id,
                phenomenon_code = %advisory.phenomenon_code,
                severity = advisory.severity.wire(),
                msg_type = advisory.msg_type.wire(),
            )
        } else {
            tracing::info_span!(
                "metocean.advisory.issue",
                zone_id = %advisory.zone_id,
                phenomenon_code = %advisory.phenomenon_code,
                severity = advisory.severity.wire(),
                msg_type = advisory.msg_type.wire(),
            )
        };
        let _guard = span.enter();
        let envelope = build_signed_envelope(signing, &advisory)?;
        match publisher.publish(&advisory.advisory_id, &envelope) {
            Ok(receipt) => {
                self.metrics.advisory_delivery("kafka", "ok");
                self.store.record_advisory(&advisory)?;
                self.store.record_delivery(&AdvisoryDelivery {
                    advisory_id: advisory.advisory_id.clone(),
                    channel: receipt.topic,
                    delivered_at: rfc3339_z(now),
                    outcome: "ok".to_owned(),
                })?;
                self.metrics
                    .advisory_issued(advisory.msg_type.wire(), advisory.severity.wire());
                Ok(())
            }
            Err(publish_error) => {
                self.metrics.advisory_delivery("kafka", "error");
                Err(error(
                    "publish_failed",
                    format!(
                        "advisory {} not issued: {}",
                        advisory.advisory_id, publish_error.message
                    ),
                ))
            }
        }
    }

    /// The audited operator-override channel. The signed request must verify
    /// against the operator key directory, carry the `nimasa-ops` role, be
    /// fresh, and present an unused nonce; only then is the advisory signed
    /// as `OPERATOR_OVERRIDE` and published. Any failure refuses the
    /// override closed.
    pub fn operator_override(
        &mut self,
        raw: &[u8],
        operators: &OperatorRegistry,
        publisher: &mut dyn AdvisoryPublisher,
        signing: &EnvelopeSigningContext,
        now: DateTime<Utc>,
    ) -> Result<Advisory, ValidationError> {
        let (mut payload, bulletin) =
            verify_signed_document(raw, OPERATOR_OVERRIDE_SCHEMA_VERSION, &operators.directory)?;
        payload.remove("signature_key_id");
        let request: OperatorOverridePayload =
            serde_json::from_value(serde_json::Value::Object(payload)).map_err(|serde_error| {
                error("invalid_operator_override", serde_error.to_string())
            })?;
        crate::validate_identifier("operator.zone_id", &request.zone_id, 128)?;
        crate::validate_identifier("operator.phenomenon_code", &request.phenomenon_code, 64)?;
        crate::validate_identifier("operator.nonce", &request.nonce, 128)?;
        if request.rationale.trim().is_empty() || request.rationale.len() > 1024 {
            return Err(error(
                "invalid_operator_override",
                "rationale must contain between 1 and 1024 bytes",
            ));
        }
        let issued = DateTime::parse_from_rfc3339(&request.issued_at)
            .map_err(|_| error("invalid_operator_override", "issued_at is not RFC 3339"))?
            .with_timezone(&Utc);
        let skew = now.signed_duration_since(issued).num_seconds().abs();
        if skew > OPERATOR_OVERRIDE_MAX_AGE_SECONDS {
            return Err(error(
                "operator_override_stale",
                "operator override is outside the freshness window",
            ));
        }
        let known_params: Vec<String> = [
            ThresholdParam::WaveHeightM,
            ThresholdParam::SwellHeightM,
            ThresholdParam::SwellPeriodS,
            ThresholdParam::WindSpeedMs,
            ThresholdParam::WindGustMs,
        ]
        .into_iter()
        .map(|param| param.phenomenon_code().to_owned())
        .collect();
        if !known_params.contains(&request.phenomenon_code) {
            return Err(error(
                "invalid_operator_override",
                "phenomenon_code is not in the governed taxonomy",
            ));
        }
        // The verifying kid is recovered from the signed document: the
        // payload keeps it inside the JWS payload, so it is authenticated.
        let document: serde_json::Value = serde_json::from_slice(raw)
            .map_err(|serde_error| error("invalid_operator_override", serde_error.to_string()))?;
        let kid = document
            .get("signature_key_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| error("invalid_signature", "signature_key_id is required"))?;
        if operators.roles.get(kid).map(String::as_str) != Some(OPERATOR_ROLE) {
            return Err(error(
                "operator_forbidden",
                "operator key does not carry the nimasa-ops role",
            ));
        }
        if !self
            .store
            .claim_operator_nonce(kid, &request.nonce, &rfc3339_z(now))?
        {
            return Err(error(
                "operator_nonce_replay",
                "operator override nonce was already used",
            ));
        }

        let advisory = match request.action.as_str() {
            "met_ocean.operator_override" => {
                let severity = match request.severity.as_deref() {
                    Some("Minor") => CapSeverity::Minor,
                    Some("Moderate") => CapSeverity::Moderate,
                    Some("Severe") => CapSeverity::Severe,
                    Some("Extreme") => CapSeverity::Extreme,
                    _ => {
                        return Err(error(
                            "invalid_operator_override",
                            "severity must be Minor, Moderate, Severe or Extreme",
                        ))
                    }
                };
                let effective_from = request
                    .effective_from
                    .as_deref()
                    .ok_or_else(|| error("invalid_operator_override", "effective_from is required"))
                    .and_then(|value| {
                        super::envelope::render_timestamp(value)
                            .map_err(|_| error("invalid_operator_override", "bad effective_from"))
                    })?;
                let effective_until = request
                    .effective_until
                    .as_deref()
                    .ok_or_else(|| {
                        error("invalid_operator_override", "effective_until is required")
                    })
                    .and_then(|value| {
                        super::envelope::render_timestamp(value)
                            .map_err(|_| error("invalid_operator_override", "bad effective_until"))
                    })?;
                let issued_at = rfc3339_z(now);
                let advisory = Advisory {
                    schema_version: super::ADVISORY_SCHEMA_VERSION.to_owned(),
                    advisory_id: advisory_id(
                        &request.zone_id,
                        &request.phenomenon_code,
                        CapMessageType::Alert,
                        &bulletin,
                        &issued_at,
                    ),
                    msg_type: CapMessageType::Alert,
                    phenomenon_code: request.phenomenon_code.clone(),
                    urgency: CapUrgency::Immediate,
                    severity,
                    certainty: CapCertainty::Observed,
                    zone_id: request.zone_id.clone(),
                    effective_from,
                    onset: None,
                    effective_until,
                    bulletin_reference: bulletin,
                    references_advisory_id: String::new(),
                    source: AdvisorySource::OperatorOverride,
                    feed_kind: None,
                    attribution_text: OPERATOR_ATTRIBUTION.to_owned(),
                    status: AdvisoryStatus::Active,
                    policy_digest_sha256: self.policy_digest.clone(),
                    issued_at,
                    cancel_reason: None,
                };
                advisory.validate()?;
                advisory
            }
            "met_ocean.operator_cancel" => {
                let target_id = request.references_advisory_id.as_deref().ok_or_else(|| {
                    error(
                        "invalid_operator_override",
                        "references_advisory_id is required for operator_cancel",
                    )
                })?;
                let active = self.store.active_advisories(&request.zone_id)?;
                let target = active
                    .iter()
                    .find(|advisory| advisory.advisory_id == target_id)
                    .ok_or_else(|| {
                        error(
                            "advisory_not_found",
                            "no active advisory with that identifier in the zone",
                        )
                    })?;
                let cancel = build_cancel_advisory(
                    target,
                    CancelReason::OperatorCountermand,
                    &self.policy_digest,
                    now,
                )?;
                self.issue(publisher, signing, cancel.clone(), now)?;
                self.store
                    .set_advisory_status(&target.advisory_id, AdvisoryStatus::Cancelled)?;
                self.refresh_active_gauge(&request.zone_id)?;
                return Ok(cancel);
            }
            _ => {
                return Err(error(
                    "invalid_operator_override",
                    "action must be met_ocean.operator_override or met_ocean.operator_cancel",
                ))
            }
        };
        self.issue(publisher, signing, advisory.clone(), now)?;
        self.refresh_active_gauge(&request.zone_id)?;
        Ok(advisory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metocean::publish::PublishReceipt;
    use crate::metocean::registry::sign_document;
    use crate::metocean::registry::tests::signed_registry_and_policy;
    use crate::metocean::{FeedKind, MonitoredPoint, READING_SCHEMA_VERSION};
    use crate::provenance::ProvenanceSigner;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap as Map;

    /// In-test store (mirrors the gateway's in-test uploader precedent);
    /// production builds ship no in-memory store.
    #[derive(Default)]
    struct TestStore {
        readings: Vec<NormalizedReading>,
        advisories: Vec<Advisory>,
        statuses: Map<String, AdvisoryStatus>,
        nonces: Vec<(String, String)>,
        health: Map<String, FeedHealth>,
        deliveries: Vec<AdvisoryDelivery>,
        dead_letters: usize,
    }

    impl MetoceanStore for TestStore {
        fn record_reading(&mut self, reading: &NormalizedReading) -> Result<bool, ValidationError> {
            if self
                .readings
                .iter()
                .any(|existing| existing.reading_id == reading.reading_id)
            {
                return Ok(false);
            }
            self.readings.push(reading.clone());
            Ok(true)
        }
        fn record_dead_letter(
            &mut self,
            _letter: &crate::metocean::MetoceanDeadLetter,
        ) -> Result<(), ValidationError> {
            self.dead_letters += 1;
            Ok(())
        }
        fn fresh_readings(
            &mut self,
            zone_id: &str,
            feed_id: &str,
            not_before: DateTime<Utc>,
        ) -> Result<Vec<NormalizedReading>, ValidationError> {
            Ok(self
                .readings
                .iter()
                .filter(|reading| {
                    reading.zone_id.as_deref() == Some(zone_id)
                        && reading.feed_id == feed_id
                        && DateTime::parse_from_rfc3339(&reading.fetched_at)
                            .map(|fetched| fetched.with_timezone(&Utc) >= not_before)
                            .unwrap_or(false)
                })
                .cloned()
                .collect())
        }
        fn active_advisories(&mut self, zone_id: &str) -> Result<Vec<Advisory>, ValidationError> {
            Ok(self
                .advisories
                .iter()
                .filter(|advisory| {
                    advisory.zone_id == zone_id
                        && advisory.msg_type != CapMessageType::Cancel
                        && self
                            .statuses
                            .get(&advisory.advisory_id)
                            .copied()
                            .unwrap_or(AdvisoryStatus::Active)
                            == AdvisoryStatus::Active
                })
                .cloned()
                .collect())
        }
        fn record_advisory(&mut self, advisory: &Advisory) -> Result<(), ValidationError> {
            advisory.validate()?;
            if !self
                .advisories
                .iter()
                .any(|existing| existing.advisory_id == advisory.advisory_id)
            {
                self.advisories.push(advisory.clone());
            }
            Ok(())
        }
        fn set_advisory_status(
            &mut self,
            advisory_id: &str,
            status: AdvisoryStatus,
        ) -> Result<(), ValidationError> {
            self.statuses.insert(advisory_id.to_owned(), status);
            Ok(())
        }
        fn upsert_feed_health(&mut self, health: &FeedHealth) -> Result<(), ValidationError> {
            self.health.insert(health.feed_id.clone(), health.clone());
            Ok(())
        }
        fn feed_health(&mut self, feed_id: &str) -> Result<Option<FeedHealth>, ValidationError> {
            Ok(self.health.get(feed_id).cloned())
        }
        fn record_delivery(&mut self, delivery: &AdvisoryDelivery) -> Result<(), ValidationError> {
            self.deliveries.push(delivery.clone());
            Ok(())
        }
        fn claim_operator_nonce(
            &mut self,
            key_id: &str,
            nonce: &str,
            _at: &str,
        ) -> Result<bool, ValidationError> {
            let pair = (key_id.to_owned(), nonce.to_owned());
            if self.nonces.contains(&pair) {
                return Ok(false);
            }
            self.nonces.push(pair);
            Ok(true)
        }
        fn advisories(
            &mut self,
            zone_id: Option<&str>,
            _active_only: bool,
        ) -> Result<Vec<Advisory>, ValidationError> {
            Ok(self
                .advisories
                .iter()
                .filter(|advisory| zone_id.map(|zone| advisory.zone_id == zone).unwrap_or(true))
                .cloned()
                .collect())
        }
        fn readings(
            &mut self,
            zone_id: &str,
            from: DateTime<Utc>,
            to: DateTime<Utc>,
        ) -> Result<Vec<NormalizedReading>, ValidationError> {
            Ok(self
                .readings
                .iter()
                .filter(|reading| {
                    reading.zone_id.as_deref() == Some(zone_id)
                        && DateTime::parse_from_rfc3339(&reading.fetched_at)
                            .map(|fetched| {
                                let fetched = fetched.with_timezone(&Utc);
                                fetched >= from && fetched <= to
                            })
                            .unwrap_or(false)
                })
                .cloned()
                .collect())
        }
    }

    /// In-test fetch/publish: the integration tests bind these to the real
    /// Postgres/Kafka backends; unit tests use recorded fixture payloads.
    struct FixtureFetch {
        payload: Vec<u8>,
    }

    impl FeedFetch for FixtureFetch {
        fn fetch(
            &mut self,
            _feed: &FeedSourceConfig,
            _url: &str,
        ) -> Result<Vec<u8>, ValidationError> {
            Ok(self.payload.clone())
        }
    }

    struct CollectPublisher {
        published: Vec<(String, Vec<u8>)>,
    }

    impl AdvisoryPublisher for CollectPublisher {
        fn publish(
            &mut self,
            key: &str,
            payload: &[u8],
        ) -> Result<PublishReceipt, ValidationError> {
            self.published.push((key.to_owned(), payload.to_vec()));
            Ok(PublishReceipt {
                topic: crate::metocean::ADVISORY_TOPIC.to_owned(),
                key: key.to_owned(),
                payload_bytes: payload.len(),
            })
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-30T12:00:00Z")
            .expect("time")
            .with_timezone(&Utc)
    }

    fn config(kind: FeedKind) -> FeedSetConfig {
        FeedSetConfig {
            feeds: vec![FeedSourceConfig {
                feed_id: "feed-1".to_owned(),
                kind,
                base_url: kind.default_base_url().to_owned(),
                poll_interval_seconds: 900,
                attribution_text: "Weather data by Open-Meteo.com".to_owned(),
                enabled: true,
            }],
            advisory_staleness_seconds: None,
        }
    }

    fn signing() -> EnvelopeSigningContext {
        EnvelopeSigningContext::new(
            ProvenanceSigner::new("blueeconomy-waterway-safety-0", &[41u8; 32]).expect("signer"),
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        )
        .expect("context")
    }

    #[test]
    fn no_feeds_reports_honest_unavailable() {
        let (registry, policy, _) = signed_registry_and_policy();
        let config = FeedSetConfig {
            feeds: vec![],
            advisory_staleness_seconds: None,
        };
        let mut service =
            MetoceanService::new(config, registry, policy, TestStore::default()).expect("service");
        let status = service.status(now()).expect("status");
        assert_eq!(status.availability, FeedAvailability::Unavailable);
        assert_eq!(status.reason, "no_feed_configured");
        assert!(status.feeds.is_empty());
        // And a poll cycle issues nothing.
        let mut fetch = FixtureFetch { payload: vec![] };
        let mut publisher = CollectPublisher { published: vec![] };
        let report = service
            .poll_once(&mut fetch, &mut publisher, &signing(), now())
            .expect("poll");
        assert_eq!(report.advisories_issued, 0);
        assert!(publisher.published.is_empty());
    }

    #[test]
    fn poll_parses_persists_and_reports_readings() {
        let (registry, policy, _) = signed_registry_and_policy();
        let fixture: Vec<u8> =
            include_bytes!("../../tests/fixtures/metocean/open_meteo_marine_sample.json").to_vec();
        // fetched_at is the poll time; fixture forecast hours are same-day.
        let mut service = MetoceanService::new(
            config(FeedKind::OpenMeteoMarine),
            registry,
            policy,
            TestStore::default(),
        )
        .expect("service");
        let mut fetch = FixtureFetch { payload: fixture };
        let mut publisher = CollectPublisher { published: vec![] };
        let report = service
            .poll_once(&mut fetch, &mut publisher, &signing(), now())
            .expect("poll");
        assert!(report.readings_ingested > 0);
        assert_eq!(report.feeds_ok, 1);
        assert_eq!(report.feeds_degraded, 0);
        let readings = service
            .store()
            .readings(
                "hz-lagos-approach",
                now() - Duration::hours(1),
                now() + Duration::hours(1),
            )
            .expect("readings");
        assert!(!readings.is_empty());
        assert!(readings
            .iter()
            .all(|reading| reading.attribution_text == "Weather data by Open-Meteo.com"));
        let status = service.status(now()).expect("status");
        assert_eq!(status.availability, FeedAvailability::Ok);
        let exposition = service.metrics().render_prometheus();
        assert!(exposition
            .contains("metocean_feed_poll_total{kind=\"open_meteo_marine\",outcome=\"ok\"}"));
    }

    #[test]
    fn malformed_feed_output_dead_letters_and_degrades() {
        let (registry, policy, _) = signed_registry_and_policy();
        let mut service = MetoceanService::new(
            config(FeedKind::OpenMeteoMarine),
            registry,
            policy,
            TestStore::default(),
        )
        .expect("service");
        let mut fetch = FixtureFetch {
            payload: b"{not json".to_vec(),
        };
        let mut publisher = CollectPublisher { published: vec![] };
        let report = service
            .poll_once(&mut fetch, &mut publisher, &signing(), now())
            .expect("poll");
        assert_eq!(report.readings_ingested, 0);
        assert_eq!(report.dead_letters, 1);
        assert_eq!(report.feeds_degraded, 1);
        assert!(publisher.published.is_empty());
        let health = service
            .store()
            .feed_health("feed-1")
            .expect("health")
            .expect("present");
        assert_eq!(health.availability, FeedAvailability::Degraded);
    }

    #[test]
    fn operator_override_issues_and_cancels_with_auth_and_replay_guard() {
        let (registry, policy, _) = signed_registry_and_policy();
        let operator_signer =
            ProvenanceSigner::new("nimasa-ops-lagos-1", &[99u8; 32]).expect("signer");
        let operator_key = URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[99u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let operators = OperatorRegistry::from_json(
            serde_json::to_vec(&serde_json::json!({
                "nimasa-ops-lagos-1": {"public_key_base64url": operator_key, "role": "nimasa-ops"}
            }))
            .expect("encode")
            .as_slice(),
        )
        .expect("operators");
        let mut service = MetoceanService::new(
            FeedSetConfig {
                feeds: vec![],
                advisory_staleness_seconds: None,
            },
            registry,
            policy,
            TestStore::default(),
        )
        .expect("service");
        let mut publisher = CollectPublisher { published: vec![] };
        let override_payload = serde_json::json!({
            "schema_version": OPERATOR_OVERRIDE_SCHEMA_VERSION,
            "action": "met_ocean.operator_override",
            "zone_id": "hz-lagos-approach",
            "phenomenon_code": "HIGH_SIGNIFICANT_WAVE_HEIGHT",
            "severity": "Severe",
            "effective_from": "2026-08-30T12:00:00Z",
            "effective_until": "2026-08-30T16:00:00Z",
            "rationale": "Pilot report: hazardous swell at the bar",
            "nonce": "op-20260830-001",
            "issued_at": "2026-08-30T12:00:00Z"
        });
        let document = sign_document(
            override_payload.as_object().expect("object").clone(),
            &operator_signer,
        )
        .expect("signed");
        let raw = serde_json::to_vec(&document).expect("encode");
        let advisory = service
            .operator_override(&raw, &operators, &mut publisher, &signing(), now())
            .expect("override issued");
        assert_eq!(advisory.source, AdvisorySource::OperatorOverride);
        assert_eq!(advisory.severity, CapSeverity::Severe);
        assert_eq!(advisory.feed_kind, None);
        assert_eq!(advisory.attribution_text, OPERATOR_ATTRIBUTION);
        assert_eq!(publisher.published.len(), 1);
        let verified = crate::metocean::envelope::verify_envelope(&publisher.published[0].1, &{
            let mut entries = Map::new();
            entries.insert(
                "blueeconomy-waterway-safety-0".to_owned(),
                SigningKey::from_bytes(&[41u8; 32]).verifying_key(),
            );
            KeyDirectory::from_entries(entries)
        })
        .expect("envelope verifies");
        assert_eq!(verified.source, "OPERATOR_OVERRIDE");
        assert_eq!(verified.severity, "Severe");

        // Replay: same nonce must be refused.
        assert_eq!(
            service
                .operator_override(&raw, &operators, &mut publisher, &signing(), now())
                .unwrap_err()
                .code,
            "operator_nonce_replay"
        );

        // Operator cancel of the active override advisory.
        let cancel_payload = serde_json::json!({
            "schema_version": OPERATOR_OVERRIDE_SCHEMA_VERSION,
            "action": "met_ocean.operator_cancel",
            "zone_id": "hz-lagos-approach",
            "phenomenon_code": "HIGH_SIGNIFICANT_WAVE_HEIGHT",
            "references_advisory_id": advisory.advisory_id,
            "rationale": "Pilot window closed",
            "nonce": "op-20260830-002",
            "issued_at": "2026-08-30T12:00:00Z"
        });
        let document = sign_document(
            cancel_payload.as_object().expect("object").clone(),
            &operator_signer,
        )
        .expect("signed");
        let cancel = service
            .operator_override(
                serde_json::to_vec(&document).expect("encode").as_slice(),
                &operators,
                &mut publisher,
                &signing(),
                now(),
            )
            .expect("cancel issued");
        assert_eq!(cancel.msg_type, CapMessageType::Cancel);
        assert_eq!(
            cancel.cancel_reason,
            Some(CancelReason::OperatorCountermand)
        );
        assert_eq!(cancel.references_advisory_id, advisory.advisory_id);
    }

    #[test]
    fn operator_override_rejects_wrong_role_stale_and_tampered() {
        let (registry, policy, _) = signed_registry_and_policy();
        let operator_signer = ProvenanceSigner::new("contractor-1", &[98u8; 32]).expect("signer");
        let operator_key = URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[98u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let operators = OperatorRegistry::from_json(
            serde_json::to_vec(&serde_json::json!({
                "contractor-1": {"public_key_base64url": operator_key, "role": "contractor"}
            }))
            .expect("encode")
            .as_slice(),
        )
        .expect("operators");
        let mut service = MetoceanService::new(
            FeedSetConfig {
                feeds: vec![],
                advisory_staleness_seconds: None,
            },
            registry,
            policy,
            TestStore::default(),
        )
        .expect("service");
        let mut publisher = CollectPublisher { published: vec![] };
        let payload = serde_json::json!({
            "schema_version": OPERATOR_OVERRIDE_SCHEMA_VERSION,
            "action": "met_ocean.operator_override",
            "zone_id": "hz-lagos-approach",
            "phenomenon_code": "HIGH_WIND",
            "severity": "Severe",
            "effective_from": "2026-08-30T12:00:00Z",
            "effective_until": "2026-08-30T16:00:00Z",
            "rationale": "test",
            "nonce": "n-1",
            "issued_at": "2026-08-30T12:00:00Z"
        });
        let document = sign_document(
            payload.as_object().expect("object").clone(),
            &operator_signer,
        )
        .expect("signed");
        let raw = serde_json::to_vec(&document).expect("encode");
        assert_eq!(
            service
                .operator_override(&raw, &operators, &mut publisher, &signing(), now())
                .unwrap_err()
                .code,
            "operator_forbidden"
        );
        // Tampered rationale breaks the signature byte-match.
        let mut tampered = document.clone();
        tampered["rationale"] = serde_json::json!("tampered");
        assert_eq!(
            service
                .operator_override(
                    serde_json::to_vec(&tampered).expect("encode").as_slice(),
                    &operators,
                    &mut publisher,
                    &signing(),
                    now()
                )
                .unwrap_err()
                .code,
            "payload_mismatch"
        );
    }

    #[test]
    fn publish_failure_aborts_issuance_without_state() {
        struct FailingPublisher;
        impl AdvisoryPublisher for FailingPublisher {
            fn publish(
                &mut self,
                _key: &str,
                _payload: &[u8],
            ) -> Result<PublishReceipt, ValidationError> {
                Err(error("publish_failed", "broker unreachable"))
            }
        }
        let (registry, policy, _) = signed_registry_and_policy();
        let mut service = MetoceanService::new(
            FeedSetConfig {
                feeds: vec![],
                advisory_staleness_seconds: None,
            },
            registry,
            policy,
            TestStore::default(),
        )
        .expect("service");
        let operator_signer =
            ProvenanceSigner::new("nimasa-ops-lagos-1", &[99u8; 32]).expect("signer");
        let operator_key = URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[99u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let operators = OperatorRegistry::from_json(
            serde_json::to_vec(&serde_json::json!({
                "nimasa-ops-lagos-1": {"public_key_base64url": operator_key, "role": "nimasa-ops"}
            }))
            .expect("encode")
            .as_slice(),
        )
        .expect("operators");
        let payload = serde_json::json!({
            "schema_version": OPERATOR_OVERRIDE_SCHEMA_VERSION,
            "action": "met_ocean.operator_override",
            "zone_id": "hz-lagos-approach",
            "phenomenon_code": "HIGH_WIND",
            "severity": "Severe",
            "effective_from": "2026-08-30T12:00:00Z",
            "effective_until": "2026-08-30T16:00:00Z",
            "rationale": "test",
            "nonce": "n-9",
            "issued_at": "2026-08-30T12:00:00Z"
        });
        let document = sign_document(
            payload.as_object().expect("object").clone(),
            &operator_signer,
        )
        .expect("signed");
        let mut publisher = FailingPublisher;
        assert_eq!(
            service
                .operator_override(
                    serde_json::to_vec(&document).expect("encode").as_slice(),
                    &operators,
                    &mut publisher,
                    &signing(),
                    now()
                )
                .unwrap_err()
                .code,
            "publish_failed"
        );
        assert!(service
            .store()
            .advisories(Some("hz-lagos-approach"), false)
            .expect("advisories")
            .is_empty());
    }

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    #[test]
    fn monitored_point_types_round_trip() {
        let point = MonitoredPoint {
            latitude: 6.0,
            longitude: 3.0,
        };
        assert!(point.position().is_ok());
        assert!(MonitoredPoint {
            latitude: 91.0,
            longitude: 3.0
        }
        .position()
        .is_err());
        let _ = READING_SCHEMA_VERSION;
    }
}
