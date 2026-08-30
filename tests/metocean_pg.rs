//! Integration test: the PostgreSQL met-ocean store round-trips readings,
//! advisories, dead letters, feed health and operator nonces against a real
//! database. Gated on WWS_TEST_PG_DSN — without a database the test is
//! skipped explicitly, never silently (mirrors tests/gateway_pg.rs).

use blueeconomy_waterway_safety::metocean::evaluate::{
    Advisory, AdvisorySource, AdvisoryStatus, CapCertainty, CapMessageType, CapSeverity, CapUrgency,
};
use blueeconomy_waterway_safety::metocean::store::{AdvisoryDelivery, MetoceanStore, PgMetoceanStore};
use blueeconomy_waterway_safety::metocean::{
    FeedAvailability, FeedHealth, FeedKind, MetoceanDeadLetter, MetoceanDeadLetterReason,
    NormalizedReading, ADVISORY_SCHEMA_VERSION, DEAD_LETTER_SCHEMA_VERSION, READING_SCHEMA_VERSION,
};
use chrono::{DateTime, Utc};

fn dsn() -> Option<String> {
    std::env::var("WWS_TEST_PG_DSN")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn reading(id: &str) -> NormalizedReading {
    NormalizedReading {
        schema_version: READING_SCHEMA_VERSION.to_owned(),
        reading_id: id.to_owned(),
        feed_id: "feed-pg-it".to_owned(),
        feed_kind: FeedKind::OpenMeteoMarine,
        zone_id: Some("hz-lagos-approach".to_owned()),
        latitude: 6.0,
        longitude: 3.0,
        observed_at: None,
        forecast_for: Some("2026-08-30T18:00:00Z".to_owned()),
        model_run_at: None,
        fetched_at: "2026-08-30T12:00:00Z".to_owned(),
        wave_height_m: Some(3.2),
        wave_period_s: Some(9.5),
        wave_direction_deg: Some(182.0),
        swell_height_m: Some(1.1),
        swell_period_s: Some(8.8),
        wind_speed_ms: None,
        wind_gust_ms: None,
        sst_c: Some(28.4),
        source_payload_sha256: "a".repeat(64),
        attribution_text: "Weather data by Open-Meteo.com".to_owned(),
    }
}

fn advisory(id: &str) -> Advisory {
    Advisory {
        schema_version: ADVISORY_SCHEMA_VERSION.to_owned(),
        advisory_id: id.to_owned(),
        msg_type: CapMessageType::Alert,
        phenomenon_code: "HIGH_SIGNIFICANT_WAVE_HEIGHT".to_owned(),
        urgency: CapUrgency::Expected,
        severity: CapSeverity::Moderate,
        certainty: CapCertainty::Likely,
        zone_id: "hz-lagos-approach".to_owned(),
        effective_from: "2026-08-30T12:00:00Z".to_owned(),
        onset: None,
        effective_until: "2026-08-30T15:00:00Z".to_owned(),
        bulletin_reference: format!("sha256:{}", "b".repeat(64)),
        references_advisory_id: String::new(),
        source: AdvisorySource::Feed,
        feed_kind: Some(FeedKind::OpenMeteoMarine),
        attribution_text: "Weather data by Open-Meteo.com".to_owned(),
        status: AdvisoryStatus::Active,
        policy_digest_sha256: format!("sha256:{}", "c".repeat(64)),
        issued_at: "2026-08-30T12:00:00Z".to_owned(),
        cancel_reason: None,
    }
}

#[test]
fn pg_store_round_trips_and_enforces_nonce_replay() {
    let Some(dsn) = dsn() else {
        eprintln!(
            "skipping pg_store_round_trips_and_enforces_nonce_replay: \
             WWS_TEST_PG_DSN is not set (database-gated by design)"
        );
        return;
    };
    let mut store = PgMetoceanStore::connect(&dsn).expect("database connects");
    store.migrate().expect("schema applies");
    let suffix = format!("it-{}-{}", std::process::id(), 1);
    let reading = reading(&format!("mor-{suffix}"));
    let advisory = advisory(&format!("moa-{suffix}"));

    // Readings: idempotent re-ingest.
    assert!(store.record_reading(&reading).expect("first insert"));
    assert!(!store.record_reading(&reading).expect("re-ingest is a no-op"));
    let not_before = DateTime::parse_from_rfc3339("2026-08-30T11:00:00Z")
        .expect("time")
        .with_timezone(&Utc);
    let fresh = store
        .fresh_readings("hz-lagos-approach", "feed-pg-it", not_before)
        .expect("fresh readings");
    assert!(fresh.iter().any(|r| r.reading_id == reading.reading_id));

    // Advisory lifecycle.
    store.record_advisory(&advisory).expect("record advisory");
    let active = store
        .active_advisories("hz-lagos-approach")
        .expect("active advisories");
    assert!(active
        .iter()
        .any(|a| a.advisory_id == advisory.advisory_id));
    store
        .set_advisory_status(&advisory.advisory_id, AdvisoryStatus::Cancelled)
        .expect("cancel");
    let active = store
        .active_advisories("hz-lagos-approach")
        .expect("active advisories");
    assert!(!active
        .iter()
        .any(|a| a.advisory_id == advisory.advisory_id));

    // Dead letters, health, deliveries.
    store
        .record_dead_letter(&MetoceanDeadLetter {
            schema_version: DEAD_LETTER_SCHEMA_VERSION.to_owned(),
            feed_id: "feed-pg-it".to_owned(),
            feed_kind: "open_meteo_marine".to_owned(),
            reason: MetoceanDeadLetterReason::MalformedPayload,
            error_code: "invalid_json".to_owned(),
            payload_sha256: "0".repeat(64),
            detail: "it".to_owned(),
            recorded_at: "2026-08-30T12:00:00Z".to_owned(),
        })
        .expect("dead letter");
    store
        .upsert_feed_health(&FeedHealth {
            feed_id: "feed-pg-it".to_owned(),
            feed_kind: "open_meteo_marine".to_owned(),
            enabled: true,
            availability: FeedAvailability::Ok,
            last_success_at: Some("2026-08-30T12:00:00Z".to_owned()),
            last_failure_at: None,
            last_error: None,
            staleness_seconds: None,
        })
        .expect("health upsert");
    let health = store
        .feed_health("feed-pg-it")
        .expect("health")
        .expect("present");
    assert_eq!(health.availability, FeedAvailability::Ok);
    store
        .record_delivery(&AdvisoryDelivery {
            advisory_id: advisory.advisory_id.clone(),
            channel: "waterways.met_ocean.advisories.v1".to_owned(),
            delivered_at: "2026-08-30T12:00:00Z".to_owned(),
            outcome: "ok".to_owned(),
        })
        .expect("delivery");

    // Nonce replay: first claim succeeds, second is refused.
    assert!(store
        .claim_operator_nonce("ops-key-it", &format!("nonce-{suffix}"), "2026-08-30T12:00:00Z")
        .expect("first claim"));
    assert!(!store
        .claim_operator_nonce("ops-key-it", &format!("nonce-{suffix}"), "2026-08-30T12:00:01Z")
        .expect("replay refused"));

    // Cleanup is unnecessary: rows are keyed by the unique suffix.
}
