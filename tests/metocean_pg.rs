//! PostgreSQL-gated integration tests for the met-ocean store.
//!
//! Runs only when `MET_OCEAN_TEST_DATABASE_URL` points at a dedicated,
//! fresh test database (local stack: `metocean_test`) and the
//! `metocean-pg-store` feature is enabled. The suite exercises the real
//! persistence path: migration, idempotent reading ingest, advisory
//! lifecycle persistence, feed health, delivery records and nonce replay
//! protection.

#![cfg(feature = "metocean-pg-store")]

use blueeconomy_waterway_safety::metocean::dead_letter;
use blueeconomy_waterway_safety::metocean::evaluate::{
    build_cancel_advisory, build_feed_advisory, AdvisoryStatus, CancelReason, CapMessageType,
    CapSeverity,
};
use blueeconomy_waterway_safety::metocean::registry::ThresholdParam;
use blueeconomy_waterway_safety::metocean::store::{
    AdvisoryDelivery, MetoceanStore, PgMetoceanStore,
};
use blueeconomy_waterway_safety::metocean::{
    FeedAvailability, FeedHealth, FeedKind, FeedSourceConfig, MetoceanDeadLetterReason,
    NormalizedReading, READING_SCHEMA_VERSION,
};
use chrono::{DateTime, Duration, Utc};

fn test_store() -> Option<PgMetoceanStore> {
    let dsn = std::env::var("MET_OCEAN_TEST_DATABASE_URL").ok()?;
    let mut store = PgMetoceanStore::connect(dsn.trim()).expect("connect to test database");
    store.migrate().expect("migrate");
    // Dedicated fresh DB per run: the harness owns this database.
    for table in [
        "metocean_delivery",
        "metocean_advisory",
        "metocean_reading",
        "metocean_dead_letter",
        "metocean_feed_health",
        "metocean_operator_nonce",
    ] {
        store
            .raw_execute(&format!("DELETE FROM {table}"))
            .expect("clean test table");
    }
    Some(store)
}

fn feed() -> FeedSourceConfig {
    FeedSourceConfig {
        feed_id: "feed-it".to_owned(),
        kind: FeedKind::OpenMeteoMarine,
        base_url: FeedKind::OpenMeteoMarine.default_base_url().to_owned(),
        poll_interval_seconds: 900,
        attribution_text: "Weather data by Open-Meteo.com".to_owned(),
        enabled: true,
    }
}

fn reading(id_suffix: &str, fetched_at: &str, wave_height: f64) -> NormalizedReading {
    NormalizedReading {
        schema_version: READING_SCHEMA_VERSION.to_owned(),
        reading_id: format!("mor-it-{id_suffix}"),
        feed_id: "feed-it".to_owned(),
        feed_kind: FeedKind::OpenMeteoMarine,
        zone_id: Some("hz-lagos-approach".to_owned()),
        latitude: 6.0,
        longitude: 3.0,
        observed_at: None,
        forecast_for: Some("2026-08-30T18:00:00Z".to_owned()),
        model_run_at: None,
        fetched_at: fetched_at.to_owned(),
        wave_height_m: Some(wave_height),
        wave_period_s: Some(9.5),
        wave_direction_deg: Some(182.0),
        swell_height_m: Some(1.1),
        swell_period_s: None,
        wind_speed_ms: None,
        wind_gust_ms: None,
        sst_c: Some(28.4),
        source_payload_sha256: "d".repeat(64),
        attribution_text: "Weather data by Open-Meteo.com".to_owned(),
    }
}

fn advisory_at(now: DateTime<Utc>) -> blueeconomy_waterway_safety::metocean::evaluate::Advisory {
    build_feed_advisory(
        &blueeconomy_waterway_safety::metocean::evaluate::FeedAdvisorySpec {
            msg_type: CapMessageType::Alert,
            zone_id: "hz-lagos-approach",
            param: ThresholdParam::WaveHeightM,
            severity: CapSeverity::Severe,
            duration_min: 180,
            references_advisory_id: "",
        },
        &[reading("src", "2026-08-30T12:00:00Z", 4.2)],
        &feed(),
        &format!("sha256:{}", "e".repeat(64)),
        now,
    )
    .expect("advisory builds")
}

#[test]
fn pg_store_round_trips_readings_advisories_and_health() {
    let Some(mut store) = test_store() else {
        eprintln!("MET_OCEAN_TEST_DATABASE_URL unset; skipping pg-gated test");
        return;
    };
    let now = DateTime::parse_from_rfc3339("2026-08-30T12:00:00Z")
        .expect("time")
        .with_timezone(&Utc);

    // Readings: insert + idempotent re-insert.
    assert!(store
        .record_reading(&reading("a", "2026-08-30T11:50:00Z", 3.2))
        .expect("insert"));
    assert!(!store
        .record_reading(&reading("a", "2026-08-30T11:50:00Z", 3.2))
        .expect("idempotent"));
    store
        .record_reading(&reading("b", "2026-08-30T11:55:00Z", 1.1))
        .expect("insert");

    let fresh = store
        .fresh_readings(
            "hz-lagos-approach",
            "feed-it",
            now - Duration::seconds(1800),
        )
        .expect("fresh");
    assert_eq!(fresh.len(), 2);
    assert_eq!(fresh[0].wave_height_m, Some(3.2));
    assert_eq!(fresh[0].attribution_text, "Weather data by Open-Meteo.com");
    let stale_only = store
        .fresh_readings("hz-lagos-approach", "feed-it", now)
        .expect("fresh");
    assert!(stale_only.is_empty());

    // Read API window.
    let window = store
        .readings(
            "hz-lagos-approach",
            now - Duration::hours(1),
            now + Duration::hours(1),
        )
        .expect("readings");
    assert_eq!(window.len(), 2);

    // Advisory lifecycle: issue, then CANCEL pairs the terminal status.
    let alert = advisory_at(now);
    store.record_advisory(&alert).expect("record advisory");
    let active = store
        .active_advisories("hz-lagos-approach")
        .expect("active");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].advisory_id, alert.advisory_id);

    let cancel = build_cancel_advisory(
        &alert,
        CancelReason::FeedUnavailable,
        &format!("sha256:{}", "e".repeat(64)),
        now + Duration::hours(1),
    )
    .expect("cancel builds");
    store.record_advisory(&cancel).expect("record cancel");
    store
        .set_advisory_status(&alert.advisory_id, AdvisoryStatus::Expired)
        .expect("status");
    assert!(store
        .active_advisories("hz-lagos-approach")
        .expect("active")
        .is_empty());
    let all = store
        .advisories(Some("hz-lagos-approach"), false)
        .expect("all advisories");
    assert_eq!(all.len(), 2);
    assert_eq!(all[1].msg_type, CapMessageType::Cancel);

    // Delivery record bound to the advisory.
    store
        .record_delivery(&AdvisoryDelivery {
            advisory_id: alert.advisory_id.clone(),
            channel: "waterways.met_ocean.advisories.v1".to_owned(),
            delivered_at: "2026-08-30T12:00:01Z".to_owned(),
            outcome: "ok".to_owned(),
        })
        .expect("delivery");

    // Dead letter persists.
    let letter = dead_letter(
        &feed(),
        MetoceanDeadLetterReason::MalformedPayload,
        "invalid_json",
        b"{bad",
        "fixture",
        "2026-08-30T12:00:00Z",
    );
    store.record_dead_letter(&letter).expect("dead letter");

    // Feed health upsert.
    store
        .upsert_feed_health(&FeedHealth {
            feed_id: "feed-it".to_owned(),
            feed_kind: "open_meteo_marine".to_owned(),
            enabled: true,
            availability: FeedAvailability::Ok,
            last_success_at: Some("2026-08-30T12:00:00Z".to_owned()),
            last_failure_at: None,
            last_error: None,
            staleness_seconds: None,
        })
        .expect("upsert");
    let health = store
        .feed_health("feed-it")
        .expect("health")
        .expect("present");
    assert_eq!(health.availability, FeedAvailability::Ok);
    assert_eq!(
        health.last_success_at.as_deref(),
        Some("2026-08-30T12:00:00Z")
    );

    // Nonce replay protection: first claim succeeds, replay is refused.
    assert!(store
        .claim_operator_nonce("nimasa-ops-lagos-1", "nonce-1", "2026-08-30T12:00:00Z")
        .expect("claim"));
    assert!(!store
        .claim_operator_nonce("nimasa-ops-lagos-1", "nonce-1", "2026-08-30T12:00:01Z")
        .expect("replay"));
    assert!(store
        .claim_operator_nonce("nimasa-ops-lagos-1", "nonce-2", "2026-08-30T12:00:02Z")
        .expect("distinct nonce"));
}
