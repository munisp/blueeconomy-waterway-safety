//! Deterministic advisory evaluation: normalised readings against the signed
//! threshold policy, with the CAP 1.2 lifecycle (ALERT / UPDATE / explicit
//! CANCEL). Stale readings can never open a new advisory; an active advisory
//! whose feed goes dark or whose `effective_until` passes is terminated by an
//! explicit CANCEL — boarding never silently un-pauses and never silently
//! stays paused.

use super::registry::{AdvisoryPolicy, ThresholdParam, ThresholdRule};
use super::{error, NormalizedReading};
use crate::ValidationError;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// CAP 1.2 msgType; renders without prefix on the wire (`Alert`/`Update`/`Cancel`).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum CapMessageType {
    Alert,
    Update,
    Cancel,
}

impl CapMessageType {
    pub fn wire(&self) -> &'static str {
        match self {
            Self::Alert => "Alert",
            Self::Update => "Update",
            Self::Cancel => "Cancel",
        }
    }
}

/// CAP 1.2 severity scale (fail-closed wire rendering).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapSeverity {
    Minor,
    Moderate,
    Severe,
    Extreme,
    Unknown,
}

impl CapSeverity {
    pub fn wire(&self) -> &'static str {
        match self {
            Self::Minor => "Minor",
            Self::Moderate => "Moderate",
            Self::Severe => "Severe",
            Self::Extreme => "Extreme",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum CapUrgency {
    Immediate,
    Expected,
    Future,
    Past,
    Unknown,
}

impl CapUrgency {
    pub fn wire(&self) -> &'static str {
        match self {
            Self::Immediate => "Immediate",
            Self::Expected => "Expected",
            Self::Future => "Future",
            Self::Past => "Past",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum CapCertainty {
    Observed,
    Likely,
    Possible,
    Unlikely,
    Unknown,
}

impl CapCertainty {
    pub fn wire(&self) -> &'static str {
        match self {
            Self::Observed => "Observed",
            Self::Likely => "Likely",
            Self::Possible => "Possible",
            Self::Unlikely => "Unlikely",
            Self::Unknown => "Unknown",
        }
    }
}

/// Origin of an advisory (`AdvisorySource` in the contract proto).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdvisorySource {
    Feed,
    OperatorOverride,
}

impl AdvisorySource {
    pub fn wire(&self) -> &'static str {
        match self {
            Self::Feed => "FEED",
            Self::OperatorOverride => "OPERATOR_OVERRIDE",
        }
    }
}

/// Advisory instance status (`MetoceanAdvisoryStatus` in the proto).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum AdvisoryStatus {
    Active,
    Expired,
    Cancelled,
}

impl AdvisoryStatus {
    pub fn wire(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Expired => "EXPIRED",
            Self::Cancelled => "CANCELLED",
        }
    }
}

/// Why a CANCEL advisory was issued.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CancelReason {
    /// Conditions subsided below the warn threshold.
    ConditionsSubsided,
    /// The producing feed went stale while an advisory was active.
    FeedUnavailable,
    /// The advisory's effective_until passed.
    EffectiveWindowElapsed,
    /// Operator countermand through the audited override channel.
    OperatorCountermand,
}

/// One CAP-profile advisory inside the producing boundary (persisted form).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Advisory {
    pub schema_version: String,
    pub advisory_id: String,
    pub msg_type: CapMessageType,
    pub phenomenon_code: String,
    pub urgency: CapUrgency,
    pub severity: CapSeverity,
    pub certainty: CapCertainty,
    pub zone_id: String,
    pub effective_from: String,
    pub onset: Option<String>,
    pub effective_until: String,
    pub bulletin_reference: String,
    pub references_advisory_id: String,
    pub source: AdvisorySource,
    pub feed_kind: Option<super::FeedKind>,
    pub attribution_text: String,
    pub status: AdvisoryStatus,
    pub policy_digest_sha256: String,
    pub issued_at: String,
    /// Recorded on CANCEL advisories: the machine-readable cancellation
    /// rationale kind.
    #[serde(default)]
    pub cancel_reason: Option<CancelReason>,
}

impl Advisory {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != super::ADVISORY_SCHEMA_VERSION {
            return Err(error(
                "invalid_advisory",
                "advisory schema_version is not supported",
            ));
        }
        crate::validate_identifier("advisory_id", &self.advisory_id, 128)?;
        crate::validate_identifier("phenomenon_code", &self.phenomenon_code, 64)?;
        crate::validate_identifier("zone_id", &self.zone_id, 128)?;
        crate::validate_timestamp("effective_from", &self.effective_from)?;
        crate::validate_timestamp("effective_until", &self.effective_until)?;
        crate::validate_timestamp("issued_at", &self.issued_at)?;
        if let Some(onset) = &self.onset {
            crate::validate_timestamp("onset", onset)?;
        }
        validate_bulletin_reference(&self.bulletin_reference)?;
        match self.msg_type {
            CapMessageType::Alert => {
                if !self.references_advisory_id.is_empty() {
                    return Err(error(
                        "invalid_advisory",
                        "ALERT advisories must not reference another advisory",
                    ));
                }
            }
            CapMessageType::Update | CapMessageType::Cancel => {
                crate::validate_identifier(
                    "references_advisory_id",
                    &self.references_advisory_id,
                    128,
                )?;
            }
        }
        if matches!(self.msg_type, CapMessageType::Cancel) != self.cancel_reason.is_some() {
            return Err(error(
                "invalid_advisory",
                "CANCEL advisories must carry a cancel_reason; other types must not",
            ));
        }
        match self.source {
            AdvisorySource::Feed => {
                if self.feed_kind.is_none() || self.attribution_text.trim().is_empty() {
                    return Err(error(
                        "invalid_advisory",
                        "feed-derived advisories must carry feed_kind and non-empty attribution",
                    ));
                }
            }
            AdvisorySource::OperatorOverride => {
                if self.feed_kind.is_some() {
                    return Err(error(
                        "invalid_advisory",
                        "operator overrides must not carry a feed_kind",
                    ));
                }
            }
        }
        if self.policy_digest_sha256.len() != 7 + 64
            || !self.policy_digest_sha256.starts_with("sha256:")
        {
            return Err(error(
                "invalid_advisory",
                "policy_digest_sha256 must be a sha256:<hex> digest",
            ));
        }
        Ok(())
    }
}

pub fn validate_bulletin_reference(value: &str) -> Result<(), ValidationError> {
    if value.len() != 7 + 64
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(error(
            "invalid_bulletin_reference",
            "bulletin_reference must be sha256:<64 lowercase hex>",
        ));
    }
    Ok(())
}

/// The deterministic threshold band for one measured value. Boundary values
/// (== threshold) trigger the band (fail towards alerting).
pub fn threshold_band(value: f64, rule: &ThresholdRule) -> Option<CapSeverity> {
    if !value.is_finite() {
        return None;
    }
    if let Some(extreme) = rule.extreme {
        if value >= extreme {
            return Some(CapSeverity::Extreme);
        }
    }
    if value >= rule.severe {
        return Some(CapSeverity::Severe);
    }
    if value >= rule.warn {
        return Some(CapSeverity::Moderate);
    }
    None
}

/// Evaluate one reading against the whole policy: every exceeded threshold
/// as (phenomenon_code, severity, rule). Missing measurements evaluate to
/// nothing — absence of data never fabricates a hazard.
pub fn evaluate_reading<'a>(
    policy: &'a AdvisoryPolicy,
    reading: &NormalizedReading,
) -> Vec<(ThresholdParam, CapSeverity, &'a ThresholdRule)> {
    let mut exceeded = Vec::new();
    for rule in &policy.thresholds {
        if let Some(value) = rule.param.value_of(reading) {
            if let Some(severity) = threshold_band(value, rule) {
                exceeded.push((rule.param, severity, rule));
            }
        }
    }
    exceeded
}

/// Is this reading fresh enough to drive a NEW advisory at `now`?
/// Stale readings can never trigger issuance (hard rule 2).
pub fn reading_is_fresh(
    reading: &NormalizedReading,
    now: DateTime<Utc>,
    staleness_seconds: i64,
) -> bool {
    let Ok(fetched_at) = DateTime::parse_from_rfc3339(&reading.fetched_at) else {
        return false;
    };
    let age = now.signed_duration_since(fetched_at.with_timezone(&Utc));
    // Future-dated (clock skew) or over-age readings are stale (fail closed).
    age >= Duration::zero() && age <= Duration::seconds(staleness_seconds)
}

/// Bulletin reference binding an advisory to its source artifacts: SHA-256
/// over the contributing readings' source payload digests (feed-derived) —
/// `"sha256:<hex>"`.
pub fn bulletin_reference_for(readings: &[NormalizedReading]) -> String {
    let mut digests: Vec<&str> = readings
        .iter()
        .map(|reading| reading.source_payload_sha256.as_str())
        .collect();
    digests.sort_unstable();
    digests.dedup();
    let mut digest = Sha256::new();
    digest.update(b"metocean-bulletin-v1");
    digest.update([0]);
    for item in digests {
        digest.update(item.as_bytes());
        digest.update([0]);
    }
    format!("sha256:{}", crate::hex_lowercase(digest.finalize()))
}

/// Bulletin reference binding a CANCEL advisory to its rationale record.
pub fn bulletin_reference_for_cancel(
    references_advisory_id: &str,
    reason: CancelReason,
    cancelled_at: &str,
) -> String {
    let record = serde_json::json!({
        "cancelled_at": cancelled_at,
        "reason": reason,
        "references_advisory_id": references_advisory_id,
        "record": "blueeconomy.waterway-safety.advisory-cancellation.v1",
    });
    let canonical = crate::provenance::canonicalize(&record)
        .expect("static cancellation record always canonicalizes");
    format!("sha256:{}", crate::hex_lowercase(Sha256::digest(canonical)))
}

/// One engine decision for the store/publisher to apply.
#[derive(Clone, Debug, PartialEq)]
pub enum EngineAction {
    /// Issue a new ALERT or UPDATE advisory.
    Issue(Advisory),
    /// Terminate an active advisory: mark it Expired or Cancelled and emit
    /// the paired CANCEL advisory.
    Cancel {
        target_advisory_id: String,
        target_status: AdvisoryStatus,
        advisory: Advisory,
    },
}

/// Deterministic advisory id: `moa-` + 24 hex of SHA-256 over the advisory's
/// identity fields. Re-issuing the same content at the same time is
/// idempotent; distinct lifecycle events get distinct identifiers.
pub fn advisory_id(
    zone_id: &str,
    phenomenon_code: &str,
    msg_type: CapMessageType,
    bulletin_reference: &str,
    issued_at: &str,
) -> String {
    let mut digest = Sha256::new();
    for field in [
        zone_id,
        phenomenon_code,
        msg_type.wire(),
        bulletin_reference,
        issued_at,
    ] {
        digest.update(field.as_bytes());
        digest.update([0]);
    }
    format!("moa-{}", &crate::hex_lowercase(digest.finalize())[..24])
}

/// What one feed-derived ALERT/UPDATE advisory asserts.
pub struct FeedAdvisorySpec<'a> {
    pub msg_type: CapMessageType,
    pub zone_id: &'a str,
    pub param: ThresholdParam,
    pub severity: CapSeverity,
    pub duration_min: i64,
    pub references_advisory_id: &'a str,
}

/// Build one feed-derived ALERT/UPDATE advisory.
pub fn build_feed_advisory(
    spec: &FeedAdvisorySpec<'_>,
    contributing: &[NormalizedReading],
    feed: &super::FeedSourceConfig,
    policy_digest_sha256: &str,
    issued_at: DateTime<Utc>,
) -> Result<Advisory, ValidationError> {
    let FeedAdvisorySpec {
        msg_type,
        zone_id,
        param,
        severity,
        duration_min,
        references_advisory_id,
    } = *spec;
    if contributing.is_empty() {
        return Err(error(
            "invalid_advisory",
            "advisories are never issued without digest-bound source readings",
        ));
    }
    let effective_from = contributing
        .iter()
        .filter_map(|reading| reading.forecast_for.clone().or(reading.observed_at.clone()))
        .min()
        .unwrap_or_else(|| issued_at.to_rfc3339());
    let bulletin = bulletin_reference_for(contributing);
    let issued = issued_at.to_rfc3339();
    let until = (issued_at + Duration::minutes(duration_min)).to_rfc3339();
    let attribution = contributing
        .iter()
        .map(|reading| reading.attribution_text.as_str())
        .find(|text| !text.is_empty())
        .unwrap_or(feed.attribution_text.as_str())
        .to_owned();
    let advisory = Advisory {
        schema_version: super::ADVISORY_SCHEMA_VERSION.to_owned(),
        advisory_id: advisory_id(
            zone_id,
            param.phenomenon_code(),
            msg_type,
            &bulletin,
            &issued,
        ),
        msg_type,
        phenomenon_code: param.phenomenon_code().to_owned(),
        urgency: CapUrgency::Expected,
        severity,
        certainty: CapCertainty::Likely,
        zone_id: zone_id.to_owned(),
        effective_from,
        onset: None,
        effective_until: until,
        bulletin_reference: bulletin,
        references_advisory_id: references_advisory_id.to_owned(),
        source: AdvisorySource::Feed,
        feed_kind: Some(feed.kind),
        attribution_text: attribution,
        status: AdvisoryStatus::Active,
        policy_digest_sha256: policy_digest_sha256.to_owned(),
        issued_at: issued.clone(),
        cancel_reason: None,
    };
    advisory.validate()?;
    Ok(advisory)
}

/// Build the explicit CANCEL advisory terminating `target`.
pub fn build_cancel_advisory(
    target: &Advisory,
    reason: CancelReason,
    policy_digest_sha256: &str,
    issued_at: DateTime<Utc>,
) -> Result<Advisory, ValidationError> {
    let issued = issued_at.to_rfc3339();
    let bulletin = bulletin_reference_for_cancel(&target.advisory_id, reason, &issued);
    let advisory = Advisory {
        schema_version: super::ADVISORY_SCHEMA_VERSION.to_owned(),
        advisory_id: advisory_id(
            &target.zone_id,
            &target.phenomenon_code,
            CapMessageType::Cancel,
            &bulletin,
            &issued,
        ),
        msg_type: CapMessageType::Cancel,
        phenomenon_code: target.phenomenon_code.clone(),
        urgency: CapUrgency::Past,
        severity: CapSeverity::Unknown,
        certainty: CapCertainty::Observed,
        zone_id: target.zone_id.clone(),
        effective_from: issued.clone(),
        onset: None,
        effective_until: issued.clone(),
        bulletin_reference: bulletin,
        references_advisory_id: target.advisory_id.clone(),
        source: target.source,
        feed_kind: target.feed_kind,
        attribution_text: target.attribution_text.clone(),
        status: AdvisoryStatus::Active,
        policy_digest_sha256: policy_digest_sha256.to_owned(),
        issued_at: issued,
        cancel_reason: Some(reason),
    };
    advisory.validate()?;
    Ok(advisory)
}

/// One zone evaluation window: the zone's currently active advisories, its
/// fresh contributing readings (already staleness screened by the caller),
/// whether the responsible feed is healthy, the staleness window and `now`.
pub struct ZoneEvaluation<'a> {
    pub zone_id: &'a str,
    pub active: &'a [Advisory],
    pub fresh_readings: &'a [NormalizedReading],
    pub feed_healthy: bool,
    pub staleness_seconds: i64,
    pub now: DateTime<Utc>,
}

/// The deterministic rule engine. Pure: no IO, no clocks beyond the
/// injected `now`.
pub fn evaluate_zone(
    policy: &AdvisoryPolicy,
    policy_digest: &str,
    feed: &super::FeedSourceConfig,
    evaluation: &ZoneEvaluation<'_>,
) -> Result<Vec<EngineAction>, ValidationError> {
    let ZoneEvaluation {
        zone_id,
        active,
        fresh_readings,
        feed_healthy,
        staleness_seconds,
        now,
    } = *evaluation;
    crate::validate_identifier("zone_id", zone_id, 128)?;
    super::validate_staleness(staleness_seconds)?;
    let mut actions = Vec::new();
    for rule in &policy.thresholds {
        let phenomenon = rule.param.phenomenon_code();
        let active_for_phenomenon: Vec<&Advisory> = active
            .iter()
            .filter(|advisory| {
                advisory.zone_id == zone_id
                    && advisory.phenomenon_code == phenomenon
                    && advisory.msg_type != CapMessageType::Cancel
            })
            .collect();
        // Highest severity across fresh readings of this zone.
        let mut best: Option<(CapSeverity, Vec<&NormalizedReading>)> = None;
        for reading in fresh_readings {
            if let Some(value) = rule.param.value_of(reading) {
                if let Some(severity) = threshold_band(value, rule) {
                    let replace = match &best {
                        None => true,
                        Some((current, _)) => severity > *current,
                    };
                    if replace {
                        best = Some((severity, Vec::new()));
                    }
                    if let Some((current, readings)) = &mut best {
                        if severity == *current {
                            readings.push(reading);
                        }
                    }
                }
            }
        }
        match best {
            Some((severity, contributing_refs)) => {
                let contributing: Vec<NormalizedReading> =
                    contributing_refs.into_iter().cloned().collect();
                match active_for_phenomenon.first() {
                    None => {
                        actions.push(EngineAction::Issue(build_feed_advisory(
                            &FeedAdvisorySpec {
                                msg_type: CapMessageType::Alert,
                                zone_id,
                                param: rule.param,
                                severity,
                                duration_min: rule.duration_min,
                                references_advisory_id: "",
                            },
                            &contributing,
                            feed,
                            policy_digest,
                            now,
                        )?));
                    }
                    Some(current) if current.severity != severity => {
                        actions.push(EngineAction::Issue(build_feed_advisory(
                            &FeedAdvisorySpec {
                                msg_type: CapMessageType::Update,
                                zone_id,
                                param: rule.param,
                                severity,
                                duration_min: rule.duration_min,
                                references_advisory_id: &current.advisory_id,
                            },
                            &contributing,
                            feed,
                            policy_digest,
                            now,
                        )?));
                    }
                    // Same severity sustained: the active advisory stands; no
                    // duplicate issuance.
                    Some(_) => {}
                }
            }
            None => {
                for current in active_for_phenomenon {
                    let until = DateTime::parse_from_rfc3339(&current.effective_until)
                        .map(|value| value.with_timezone(&Utc))
                        .map_err(|_| {
                            error("invalid_advisory", "stored advisory timestamp invalid")
                        })?;
                    let (reason, target_status) = if !feed_healthy {
                        (CancelReason::FeedUnavailable, AdvisoryStatus::Expired)
                    } else if now >= until {
                        (
                            CancelReason::EffectiveWindowElapsed,
                            AdvisoryStatus::Expired,
                        )
                    } else {
                        (CancelReason::ConditionsSubsided, AdvisoryStatus::Cancelled)
                    };
                    actions.push(EngineAction::Cancel {
                        target_advisory_id: current.advisory_id.clone(),
                        target_status,
                        advisory: build_cancel_advisory(current, reason, policy_digest, now)?,
                    });
                }
            }
        }
    }
    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metocean::registry::tests::signed_registry_and_policy;
    use crate::metocean::{FeedKind, FeedSourceConfig};

    fn feed() -> FeedSourceConfig {
        FeedSourceConfig {
            feed_id: "feed-open-meteo".to_owned(),
            kind: FeedKind::OpenMeteoMarine,
            base_url: FeedKind::OpenMeteoMarine.default_base_url().to_owned(),
            poll_interval_seconds: 900,
            attribution_text: "Weather data by Open-Meteo.com".to_owned(),
            enabled: true,
        }
    }

    fn reading(wave_height: Option<f64>, wind: Option<f64>, fetched_at: &str) -> NormalizedReading {
        NormalizedReading {
            schema_version: crate::metocean::READING_SCHEMA_VERSION.to_owned(),
            reading_id: format!("mor-{:064x}", wave_height.unwrap_or(0.0).to_bits()),
            feed_id: "feed-open-meteo".to_owned(),
            feed_kind: FeedKind::OpenMeteoMarine,
            zone_id: Some("hz-lagos-approach".to_owned()),
            latitude: 6.0,
            longitude: 3.0,
            observed_at: None,
            forecast_for: Some("2026-08-30T18:00:00Z".to_owned()),
            model_run_at: None,
            fetched_at: fetched_at.to_owned(),
            wave_height_m: wave_height,
            wave_period_s: Some(9.5),
            wave_direction_deg: Some(180.0),
            swell_height_m: None,
            swell_period_s: None,
            wind_speed_ms: wind,
            wind_gust_ms: None,
            sst_c: None,
            source_payload_sha256: "b".repeat(64),
            attribution_text: "Weather data by Open-Meteo.com".to_owned(),
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-30T12:00:00Z")
            .expect("fixture time")
            .with_timezone(&Utc)
    }

    #[test]
    fn threshold_bands_include_boundaries_and_reject_nan() {
        let rule = ThresholdRule {
            param: ThresholdParam::WaveHeightM,
            warn: 2.5,
            severe: 4.0,
            extreme: Some(6.0),
            duration_min: 180,
        };
        assert_eq!(threshold_band(2.49, &rule), None);
        assert_eq!(threshold_band(2.5, &rule), Some(CapSeverity::Moderate));
        assert_eq!(threshold_band(4.0, &rule), Some(CapSeverity::Severe));
        assert_eq!(threshold_band(6.0, &rule), Some(CapSeverity::Extreme));
        assert_eq!(threshold_band(f64::NAN, &rule), None);
        assert_eq!(threshold_band(f64::INFINITY, &rule), None);
        let rule_no_extreme = ThresholdRule {
            extreme: None,
            ..rule
        };
        assert_eq!(
            threshold_band(9.9, &rule_no_extreme),
            Some(CapSeverity::Severe)
        );
    }

    #[test]
    fn missing_measurements_never_trigger() {
        let (_, policy, _) = signed_registry_and_policy();
        let mut bare = reading(None, None, "2026-08-30T12:00:00Z");
        bare.wave_period_s = None;
        bare.wave_direction_deg = None;
        assert!(evaluate_reading(&policy, &bare).is_empty());
    }

    #[test]
    fn staleness_gate_rejects_old_and_future_readings() {
        let fresh = reading(Some(3.0), None, "2026-08-30T11:00:00Z");
        assert!(reading_is_fresh(&fresh, now(), 3600));
        assert!(!reading_is_fresh(&fresh, now(), 3599));
        let future = reading(Some(3.0), None, "2026-08-30T12:05:00Z");
        assert!(!reading_is_fresh(&future, now(), 7200));
        let broken = reading(Some(3.0), None, "not-a-time");
        assert!(!reading_is_fresh(&broken, now(), 7200));
    }

    #[test]
    fn alert_then_sustained_then_cancel_on_subsidence() {
        let (registry, policy, _) = signed_registry_and_policy();
        let digest = crate::metocean::registry::combined_policy_digest(&policy, &registry);
        let feed = feed();
        let zone = "hz-lagos-approach";
        // Wave height 3.0 >= warn 2.5 => Moderate ALERT.
        let actions = evaluate_zone(
            &policy,
            &digest,
            &feed,
            &ZoneEvaluation {
                zone_id: zone,
                active: &[],
                fresh_readings: &[reading(Some(3.0), None, "2026-08-30T12:00:00Z")],
                feed_healthy: true,
                staleness_seconds: 1800,
                now: now(),
            },
        )
        .expect("evaluation");
        assert_eq!(actions.len(), 1);
        let alert = match &actions[0] {
            EngineAction::Issue(advisory) => advisory.clone(),
            other => panic!("expected issue, got {other:?}"),
        };
        assert_eq!(alert.msg_type, CapMessageType::Alert);
        assert_eq!(alert.severity, CapSeverity::Moderate);
        assert_eq!(alert.phenomenon_code, "HIGH_SIGNIFICANT_WAVE_HEIGHT");
        assert_eq!(alert.source, AdvisorySource::Feed);
        assert_eq!(alert.feed_kind, Some(FeedKind::OpenMeteoMarine));
        assert_eq!(alert.attribution_text, "Weather data by Open-Meteo.com");
        assert!(alert.references_advisory_id.is_empty());
        assert!(alert.bulletin_reference.starts_with("sha256:"));

        // Same severity sustained: no duplicate issuance.
        let actions = evaluate_zone(
            &policy,
            &digest,
            &feed,
            &ZoneEvaluation {
                zone_id: zone,
                active: std::slice::from_ref(&alert),
                fresh_readings: &[reading(Some(3.1), None, "2026-08-30T12:15:00Z")],
                feed_healthy: true,
                staleness_seconds: 1800,
                now: now() + Duration::minutes(15),
            },
        )
        .expect("evaluation");
        assert!(actions.is_empty());

        // Escalation to severe => UPDATE referencing the ALERT.
        let actions = evaluate_zone(
            &policy,
            &digest,
            &feed,
            &ZoneEvaluation {
                zone_id: zone,
                active: std::slice::from_ref(&alert),
                fresh_readings: &[reading(Some(4.2), None, "2026-08-30T12:15:00Z")],
                feed_healthy: true,
                staleness_seconds: 1800,
                now: now() + Duration::minutes(15),
            },
        )
        .expect("evaluation");
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            EngineAction::Issue(advisory) => {
                assert_eq!(advisory.msg_type, CapMessageType::Update);
                assert_eq!(advisory.severity, CapSeverity::Severe);
                assert_eq!(advisory.references_advisory_id, alert.advisory_id);
            }
            other => panic!("expected update, got {other:?}"),
        }

        // Conditions subside => explicit CANCEL, target marked CANCELLED.
        let actions = evaluate_zone(
            &policy,
            &digest,
            &feed,
            &ZoneEvaluation {
                zone_id: zone,
                active: std::slice::from_ref(&alert),
                fresh_readings: &[reading(Some(1.0), None, "2026-08-30T12:30:00Z")],
                feed_healthy: true,
                staleness_seconds: 1800,
                now: now() + Duration::minutes(30),
            },
        )
        .expect("evaluation");
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            EngineAction::Cancel {
                target_advisory_id,
                target_status,
                advisory,
            } => {
                assert_eq!(target_advisory_id, &alert.advisory_id);
                assert_eq!(*target_status, AdvisoryStatus::Cancelled);
                assert_eq!(advisory.msg_type, CapMessageType::Cancel);
                assert_eq!(
                    advisory.cancel_reason,
                    Some(CancelReason::ConditionsSubsided)
                );
                assert_eq!(advisory.references_advisory_id, alert.advisory_id);
            }
            other => panic!("expected cancel, got {other:?}"),
        }
    }

    #[test]
    fn stale_feed_cancels_active_advisory_with_expired_status() {
        let (registry, policy, _) = signed_registry_and_policy();
        let digest = crate::metocean::registry::combined_policy_digest(&policy, &registry);
        let feed = feed();
        let zone = "hz-lagos-approach";
        let actions = evaluate_zone(
            &policy,
            &digest,
            &feed,
            &ZoneEvaluation {
                zone_id: zone,
                active: &[],
                fresh_readings: &[reading(Some(5.0), None, "2026-08-30T12:00:00Z")],
                feed_healthy: true,
                staleness_seconds: 1800,
                now: now(),
            },
        )
        .expect("evaluation");
        let alert = match &actions[0] {
            EngineAction::Issue(advisory) => advisory.clone(),
            other => panic!("expected issue, got {other:?}"),
        };
        // Feed went dark: no fresh readings and feed unhealthy => CANCEL with
        // feed_unavailable, target EXPIRED.
        let actions = evaluate_zone(
            &policy,
            &digest,
            &feed,
            &ZoneEvaluation {
                zone_id: zone,
                active: std::slice::from_ref(&alert),
                fresh_readings: &[],
                feed_healthy: false,
                staleness_seconds: 1800,
                now: now() + Duration::hours(1),
            },
        )
        .expect("evaluation");
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            EngineAction::Cancel {
                target_status,
                advisory,
                ..
            } => {
                assert_eq!(*target_status, AdvisoryStatus::Expired);
                assert_eq!(advisory.cancel_reason, Some(CancelReason::FeedUnavailable));
            }
            other => panic!("expected cancel, got {other:?}"),
        }
    }

    #[test]
    fn stale_readings_never_open_new_advisories() {
        let (registry, policy, _) = signed_registry_and_policy();
        let digest = crate::metocean::registry::combined_policy_digest(&policy, &registry);
        let feed = feed();
        // Reading fetched 10 minutes ago with a staleness window just under
        // that age: stale, never opens a new advisory.
        let stale = reading(Some(9.9), None, "2026-08-30T11:50:00Z");
        assert!(!reading_is_fresh(&stale, now(), 599));
        // The engine only ever receives staleness-screened readings; verify
        // the gate leaves it nothing to act on.
        let fresh: Vec<NormalizedReading> = [stale]
            .into_iter()
            .filter(|reading| reading_is_fresh(reading, now(), 599))
            .collect();
        let actions = evaluate_zone(
            &policy,
            &digest,
            &feed,
            &ZoneEvaluation {
                zone_id: "hz-lagos-approach",
                active: &[],
                fresh_readings: &fresh,
                feed_healthy: false,
                staleness_seconds: 599,
                now: now(),
            },
        )
        .expect("evaluation");
        assert!(actions.is_empty());
    }

    #[test]
    fn elapsed_effective_window_expires_with_cancel() {
        let (registry, policy, _) = signed_registry_and_policy();
        let digest = crate::metocean::registry::combined_policy_digest(&policy, &registry);
        let feed = feed();
        let actions = evaluate_zone(
            &policy,
            &digest,
            &feed,
            &ZoneEvaluation {
                zone_id: "hz-lagos-approach",
                active: &[],
                fresh_readings: &[reading(Some(3.0), None, "2026-08-30T12:00:00Z")],
                feed_healthy: true,
                staleness_seconds: 1800,
                now: now(),
            },
        )
        .expect("evaluation");
        let alert = match &actions[0] {
            EngineAction::Issue(advisory) => advisory.clone(),
            other => panic!("expected issue, got {other:?}"),
        };
        // Feed healthy, no exceedance now, and effective_until has passed.
        let later = now() + Duration::minutes(181);
        let actions = evaluate_zone(
            &policy,
            &digest,
            &feed,
            &ZoneEvaluation {
                zone_id: "hz-lagos-approach",
                active: std::slice::from_ref(&alert),
                fresh_readings: &[reading(Some(1.0), None, "2026-08-30T15:00:00Z")],
                feed_healthy: true,
                staleness_seconds: 5400,
                now: later,
            },
        )
        .expect("evaluation");
        match &actions[0] {
            EngineAction::Cancel {
                target_status,
                advisory,
                ..
            } => {
                assert_eq!(*target_status, AdvisoryStatus::Expired);
                assert_eq!(
                    advisory.cancel_reason,
                    Some(CancelReason::EffectiveWindowElapsed)
                );
            }
            other => panic!("expected cancel, got {other:?}"),
        }
    }

    #[test]
    fn advisory_validation_is_fail_closed() {
        let (registry, policy, _) = signed_registry_and_policy();
        let digest = crate::metocean::registry::combined_policy_digest(&policy, &registry);
        let feed = feed();
        let contributing = vec![reading(Some(3.0), None, "2026-08-30T12:00:00Z")];
        // Never issue without a digest-bound source.
        assert_eq!(
            build_feed_advisory(
                &FeedAdvisorySpec {
                    msg_type: CapMessageType::Alert,
                    zone_id: "hz-lagos-approach",
                    param: ThresholdParam::WaveHeightM,
                    severity: CapSeverity::Moderate,
                    duration_min: 180,
                    references_advisory_id: "",
                },
                &[],
                &feed,
                &digest,
                now(),
            )
            .unwrap_err()
            .code,
            "invalid_advisory"
        );
        let advisory = build_feed_advisory(
            &FeedAdvisorySpec {
                msg_type: CapMessageType::Alert,
                zone_id: "hz-lagos-approach",
                param: ThresholdParam::WaveHeightM,
                severity: CapSeverity::Moderate,
                duration_min: 180,
                references_advisory_id: "",
            },
            &contributing,
            &feed,
            &digest,
            now(),
        )
        .expect("advisory builds");
        advisory.validate().expect("valid advisory");
        let mut bad_reference = advisory.clone();
        bad_reference.bulletin_reference = "sha256:ZZZ".to_owned();
        assert_eq!(
            bad_reference.validate().unwrap_err().code,
            "invalid_bulletin_reference"
        );
        let mut bad_attribution = advisory.clone();
        bad_attribution.attribution_text = String::new();
        assert_eq!(
            bad_attribution.validate().unwrap_err().code,
            "invalid_advisory"
        );
    }
}
