//! Integration test: met-ocean advisory envelopes round-trip through a real
//! Kafka broker (`waterways.met_ocean.advisories.v1`). Gated on
//! WWS_TEST_KAFKA_BROKERS — without a broker the test is skipped explicitly,
//! never silently (mirrors tests/gateway_kafka.rs conventions).

use blueeconomy_waterway_safety::metocean::envelope::{
    build_signed_envelope, verify_envelope, EnvelopeSigningContext,
};
use blueeconomy_waterway_safety::metocean::evaluate::{
    build_feed_advisory, AdvisorySource, CapMessageType, CapSeverity, FeedAdvisorySpec,
};
use blueeconomy_waterway_safety::metocean::publish::{AdvisoryPublisher, KafkaAdvisoryPublisher};
use blueeconomy_waterway_safety::metocean::registry::{
    combined_policy_digest, KeyDirectory, ThresholdParam,
};
use blueeconomy_waterway_safety::metocean::{
    Advisory, FeedKind, FeedSourceConfig, NormalizedReading, ADVISORY_TOPIC, READING_SCHEMA_VERSION,
};
use blueeconomy_waterway_safety::provenance::ProvenanceSigner;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;

fn brokers() -> Option<String> {
    std::env::var("WWS_TEST_KAFKA_BROKERS")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn signing_context() -> EnvelopeSigningContext {
    let signer =
        ProvenanceSigner::new("blueeconomy-waterway-safety-0", &[41u8; 32]).expect("signer");
    EnvelopeSigningContext::new(signer, "f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("context")
}

fn directory() -> KeyDirectory {
    let mut entries = BTreeMap::new();
    entries.insert(
        "blueeconomy-waterway-safety-0".to_owned(),
        SigningKey::from_bytes(&[41u8; 32]).verifying_key(),
    );
    KeyDirectory::from_entries(entries)
}

fn fixture_advisory() -> Advisory {
    let feed = FeedSourceConfig {
        feed_id: "feed-open-meteo".to_owned(),
        kind: FeedKind::OpenMeteoMarine,
        base_url: FeedKind::OpenMeteoMarine.default_base_url().to_owned(),
        poll_interval_seconds: 900,
        attribution_text: "Weather data by Open-Meteo.com".to_owned(),
        enabled: true,
    };
    let reading = NormalizedReading {
        schema_version: READING_SCHEMA_VERSION.to_owned(),
        reading_id: "mor-kafka-it".to_owned(),
        feed_id: "feed-open-meteo".to_owned(),
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
        source_payload_sha256: "d".repeat(64),
        attribution_text: "Weather data by Open-Meteo.com".to_owned(),
    };
    let policy_digest = combined_policy_digest(
        &blueeconomy_waterway_safety::metocean::registry::AdvisoryPolicy {
            policy_version: "it".to_owned(),
            thresholds: vec![],
            policy_digest_sha256: format!("sha256:{}", "e".repeat(64)),
        },
        &blueeconomy_waterway_safety::metocean::registry::HazardZoneRegistry {
            registry_version: "it".to_owned(),
            zones: vec![],
            registry_digest_sha256: format!("sha256:{}", "f".repeat(64)),
        },
    );
    let now = DateTime::parse_from_rfc3339("2026-08-30T12:00:00Z")
        .expect("time")
        .with_timezone(&Utc);
    build_feed_advisory(
        &FeedAdvisorySpec {
            msg_type: CapMessageType::Alert,
            zone_id: "hz-lagos-approach",
            param: ThresholdParam::WaveHeightM,
            severity: CapSeverity::Moderate,
            duration_min: 180,
            references_advisory_id: "",
        },
        &[reading],
        &feed,
        &policy_digest,
        now,
    )
    .expect("advisory")
}

#[test]
fn advisory_envelope_round_trips_through_real_kafka() {
    let Some(brokers) = brokers() else {
        eprintln!(
            "skipping advisory_envelope_round_trips_through_real_kafka: \
             WWS_TEST_KAFKA_BROKERS is not set (broker-gated by design)"
        );
        return;
    };
    let context = signing_context();
    let advisory = fixture_advisory();
    let envelope = build_signed_envelope(&context, &advisory).expect("envelope");

    let mut publisher = KafkaAdvisoryPublisher::connect(&brokers).expect("broker connects");
    let receipt = publisher
        .publish(&advisory.advisory_id, &envelope)
        .expect("publish ack");
    assert_eq!(receipt.topic, ADVISORY_TOPIC);
    assert_eq!(receipt.key, advisory.advisory_id);
    assert_eq!(receipt.payload_bytes, envelope.len());

    // Consume the record back with a fresh group and re-verify the signature
    // and contract checks exactly as a consumer would.
    let mut consumer = kafka::consumer::Consumer::from_hosts(vec![brokers])
        .with_topic(ADVISORY_TOPIC.to_owned())
        .with_group(format!("wws-metocean-it-{}", std::process::id()))
        .with_fallback_offset(kafka::consumer::FetchOffset::Earliest)
        .create()
        .expect("consumer connects");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut verified = None;
    while std::time::Instant::now() < deadline {
        for message_set in consumer.poll().expect("poll").iter() {
            for message in message_set.messages() {
                if message.key == advisory.advisory_id.as_bytes() {
                    verified = Some(
                        verify_envelope(message.value, &directory()).expect("envelope verifies"),
                    );
                }
            }
        }
        if verified.is_some() {
            break;
        }
    }
    let verified = verified.expect("advisory record consumed from the broker");
    assert_eq!(verified.advisory_id, advisory.advisory_id);
    assert_eq!(verified.msg_type, CapMessageType::Alert);
    assert_eq!(verified.source, AdvisorySource::Feed.wire());
    assert_eq!(verified.zone_id, "hz-lagos-approach");
}
