//! Broker-gated Kafka emission test: a signed advisory envelope is produced
//! onto `waterways.met_ocean.advisories.v1` through the real Kafka transport
//! and consumed back, then verified byte-for-byte through the consumer-side
//! envelope verification (JWS-EdDSA over RFC 8785 JCS round-trip).
//!
//! Runs only when `MET_OCEAN_TEST_KAFKA_BROKERS` is set (local stack) and
//! the `kafka-transport` feature is enabled.

#![cfg(feature = "kafka-transport")]

use blueeconomy_waterway_safety::metocean::envelope::{
    build_signed_envelope, verify_envelope, EnvelopeSigningContext,
};
use blueeconomy_waterway_safety::metocean::evaluate::{
    build_feed_advisory, CapMessageType, CapSeverity,
};
use blueeconomy_waterway_safety::metocean::publish::{AdvisoryPublisher, KafkaAdvisoryPublisher};
use blueeconomy_waterway_safety::metocean::registry::KeyDirectory;
use blueeconomy_waterway_safety::metocean::registry::ThresholdParam;
use blueeconomy_waterway_safety::metocean::{
    FeedKind, FeedSourceConfig, NormalizedReading, ADVISORY_TOPIC, READING_SCHEMA_VERSION,
};
use blueeconomy_waterway_safety::provenance::ProvenanceSigner;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;

const SIGNING_KEY: [u8; 32] = [41u8; 32];

fn signed_advisory_envelope() -> (Vec<u8>, String) {
    let feed = FeedSourceConfig {
        feed_id: "feed-kafka-it".to_owned(),
        kind: FeedKind::OpenMeteoMarine,
        base_url: FeedKind::OpenMeteoMarine.default_base_url().to_owned(),
        poll_interval_seconds: 900,
        attribution_text: "Weather data by Open-Meteo.com".to_owned(),
        enabled: true,
    };
    let reading = NormalizedReading {
        schema_version: READING_SCHEMA_VERSION.to_owned(),
        reading_id: "mor-kafka-it".to_owned(),
        feed_id: "feed-kafka-it".to_owned(),
        feed_kind: FeedKind::OpenMeteoMarine,
        zone_id: Some("hz-lagos-approach".to_owned()),
        latitude: 6.0,
        longitude: 3.0,
        observed_at: None,
        forecast_for: Some("2026-08-30T18:00:00Z".to_owned()),
        model_run_at: None,
        fetched_at: "2026-08-30T12:00:00Z".to_owned(),
        wave_height_m: Some(4.4),
        wave_period_s: Some(10.2),
        wave_direction_deg: Some(185.0),
        swell_height_m: Some(1.3),
        swell_period_s: Some(9.1),
        wind_speed_ms: None,
        wind_gust_ms: None,
        sst_c: Some(28.4),
        source_payload_sha256: "f".repeat(64),
        attribution_text: "Weather data by Open-Meteo.com".to_owned(),
    };
    let now = DateTime::parse_from_rfc3339("2026-08-30T12:00:00Z")
        .expect("time")
        .with_timezone(&Utc);
    let advisory = build_feed_advisory(
        &blueeconomy_waterway_safety::metocean::evaluate::FeedAdvisorySpec {
            msg_type: CapMessageType::Alert,
            zone_id: "hz-lagos-approach",
            param: ThresholdParam::WaveHeightM,
            severity: CapSeverity::Severe,
            duration_min: 180,
            references_advisory_id: "",
        },
        &[reading],
        &feed,
        &format!("sha256:{}", "9".repeat(64)),
        now,
    )
    .expect("advisory builds");
    let signer =
        ProvenanceSigner::new("blueeconomy-waterway-safety-0", &SIGNING_KEY).expect("signer");
    let context = EnvelopeSigningContext::new(signer, "kafka-it-principal").expect("context");
    let envelope = build_signed_envelope(&context, &advisory).expect("envelope");
    (envelope, advisory.advisory_id)
}

#[test]
fn signed_envelope_round_trips_through_the_real_broker() {
    let Ok(brokers) = std::env::var("MET_OCEAN_TEST_KAFKA_BROKERS") else {
        eprintln!("MET_OCEAN_TEST_KAFKA_BROKERS unset; skipping broker-gated test");
        return;
    };
    let (envelope, advisory_id) = signed_advisory_envelope();
    let mut publisher = KafkaAdvisoryPublisher::connect(brokers.trim()).expect("connect");
    let receipt = publisher
        .publish(&advisory_id, &envelope)
        .expect("publish to real broker");
    assert_eq!(receipt.topic, ADVISORY_TOPIC);
    assert_eq!(receipt.key, advisory_id);
    assert_eq!(receipt.payload_bytes, envelope.len());

    // Consume back from the real topic (earliest offset).
    let hosts: Vec<String> = brokers
        .trim()
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect();
    // Group-less consumer: the pinned kafka 0.9 client's group-coordinator
    // calls are not needed to verify the round-trip; a direct earliest-offset
    // fetch is sufficient and keeps the test on the documented produce/fetch
    // path only.
    let mut consumer = kafka::consumer::Consumer::from_hosts(hosts)
        .with_topic(ADVISORY_TOPIC.to_owned())
        .with_fallback_offset(kafka::consumer::FetchOffset::Earliest)
        .create()
        .expect("consumer");
    let mut consumed: Option<Vec<u8>> = None;
    for _ in 0..30 {
        let sets = consumer.poll().expect("poll");
        for set in sets.iter() {
            for message in set.messages() {
                if message.key == advisory_id.as_bytes() {
                    consumed = Some(message.value.to_vec());
                }
            }
        }
        if consumed.is_some() {
            break;
        }
    }
    let consumed = consumed.expect("published envelope is consumed back");

    // Byte-exact round trip, then full consumer-side signature verification.
    assert_eq!(consumed, envelope);
    let mut keys = BTreeMap::new();
    keys.insert(
        "blueeconomy-waterway-safety-0".to_owned(),
        SigningKey::from_bytes(&SIGNING_KEY).verifying_key(),
    );
    let directory = KeyDirectory::from_entries(keys);
    let verified = verify_envelope(&consumed, &directory).expect("signature round-trip verifies");
    assert_eq!(verified.advisory_id, advisory_id);
    assert_eq!(verified.msg_type, CapMessageType::Alert);
    assert_eq!(verified.severity, "Severe");
    assert_eq!(verified.source, "FEED");
    assert_eq!(verified.zone_id, "hz-lagos-approach");
    assert!(verified.bulletin_reference.starts_with("sha256:"));
    assert_eq!(verified.attribution_text, "Weather data by Open-Meteo.com");

    // Tampering with the consumed record must fail verification closed.
    let mut tampered = consumed.clone();
    let length = tampered.len();
    tampered[length / 2] ^= 0x01;
    assert!(verify_envelope(&tampered, &directory).is_err());
}

/// End-to-end: the `metocean` binary boots with zero feeds (honest
/// UNAVAILABLE status), then a signed operator override flows through the
/// real Postgres store and the real Kafka broker, and the consumed envelope
/// verifies byte-exact. Gated on both `MET_OCEAN_TEST_DATABASE_URL` and
/// `MET_OCEAN_TEST_KAFKA_BROKERS`.
#[test]
fn operator_override_end_to_end_through_binary() {
    use blueeconomy_waterway_safety::metocean::registry::{
        load_advisory_policy, load_hazard_zone_registry, sign_document,
    };
    use blueeconomy_waterway_safety::metocean::{
        ADVISORY_POLICY_SCHEMA_VERSION, HAZARD_ZONE_REGISTRY_SCHEMA_VERSION,
    };

    let (Ok(dsn), Ok(brokers)) = (
        std::env::var("MET_OCEAN_TEST_DATABASE_URL"),
        std::env::var("MET_OCEAN_TEST_KAFKA_BROKERS"),
    ) else {
        eprintln!("gated env unset; skipping end-to-end test");
        return;
    };
    let run_id = format!(
        "e2e-{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let dir = std::env::temp_dir().join(run_id);
    std::fs::create_dir_all(&dir).expect("temp dir");

    // Governance and operator keys.
    let governance_signer =
        ProvenanceSigner::new("metocean-governance-e2e", &[7u8; 32]).expect("governance signer");
    let operator_signer =
        ProvenanceSigner::new("nimasa-ops-e2e-1", &[8u8; 32]).expect("operator signer");
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let governance_dir = serde_json::json!({
        "metocean-governance-e2e": b64.encode(SigningKey::from_bytes(&[7u8; 32]).verifying_key().as_bytes())
    });
    let operator_dir = serde_json::json!({
        "nimasa-ops-e2e-1": {
            "public_key_base64url": b64.encode(SigningKey::from_bytes(&[8u8; 32]).verifying_key().as_bytes()),
            "role": "nimasa-ops"
        }
    });
    let envelope_dir = serde_json::json!({
        "blueeconomy-waterway-safety-0": b64.encode(SigningKey::from_bytes(&SIGNING_KEY).verifying_key().as_bytes())
    });

    let registry_doc = sign_document(
        serde_json::json!({
            "schema_version": HAZARD_ZONE_REGISTRY_SCHEMA_VERSION,
            "registry_version": "e2e-r1",
            "zones": [{
                "zone_id": "hz-e2e",
                "name": "E2E zone",
                "polygon": [
                    {"latitude": 5.5, "longitude": 2.5},
                    {"latitude": 5.5, "longitude": 3.5},
                    {"latitude": 6.5, "longitude": 3.5},
                    {"latitude": 6.5, "longitude": 2.5}
                ],
                "monitored_points": [{"latitude": 6.0, "longitude": 3.0}],
                "route_refs": ["route-e2e"]
            }]
        })
        .as_object()
        .expect("object")
        .clone(),
        &governance_signer,
    )
    .expect("registry signed");
    let policy_doc = sign_document(
        serde_json::json!({
            "schema_version": ADVISORY_POLICY_SCHEMA_VERSION,
            "policy_version": "e2e-p1",
            "thresholds": [
                {"param": "wave_height_m", "warn": 2.5, "severe": 4.0, "duration_min": 180}
            ]
        })
        .as_object()
        .expect("object")
        .clone(),
        &governance_signer,
    )
    .expect("policy signed");

    let write = |name: &str, value: &serde_json::Value| {
        let path = dir.join(name);
        std::fs::write(&path, serde_json::to_vec(value).expect("encode")).expect("write");
        path
    };
    let registry_path = write("registry.json", &registry_doc);
    let policy_path = write("policy.json", &policy_doc);
    let governance_path = write("governance_keys.json", &governance_dir);
    let operator_path = write("operator_keys.json", &operator_dir);
    let envelope_path = write("envelope_keys.json", &envelope_dir);

    // Sanity: the docs verify through the library loaders.
    let keys = KeyDirectory::load(&governance_path).expect("key dir loads");
    load_hazard_zone_registry(&std::fs::read(&registry_path).expect("read"), &keys)
        .expect("registry loads");
    load_advisory_policy(&std::fs::read(&policy_path).expect("read"), &keys).expect("policy loads");

    let bin = env!("CARGO_BIN_EXE_metocean");
    let base_command = || {
        let mut command = std::process::Command::new(bin);
        command
            .env("MET_OCEAN_REGISTRY_KEY_DIRECTORY", &governance_path)
            .env("MET_OCEAN_REGISTRY_PATH", &registry_path)
            .env("MET_OCEAN_POLICY_PATH", &policy_path)
            .env("MET_OCEAN_OPERATOR_KEY_DIRECTORY", &operator_path)
            .env("MET_OCEAN_DATABASE_DSN", dsn.trim())
            .env("MET_OCEAN_KAFKA_BROKERS", brokers.trim())
            .env("PROVENANCE_SIGNING_KEY", b64.encode(SIGNING_KEY))
            .env("MET_OCEAN_PRINCIPAL_ID", "e2e-principal");
        // Deliberately no MET_OCEAN_FEED_CONFIG: zero feeds.
        command
    };

    // 1. status: honest UNAVAILABLE, zero fabricated readings.
    let status = base_command().arg("status").output().expect("status runs");
    assert!(status.status.success(), "status exits ok: {status:?}");
    let status_json: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(status_json["availability"], "UNAVAILABLE");
    assert_eq!(status_json["reason"], "no_feed_configured");
    assert_eq!(
        status_json["schema_version"],
        "blueeconomy.waterway-safety.met-ocean-status.v1"
    );

    // 2. Signed operator override through the binary.
    let issued_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let until = (chrono::Utc::now() + chrono::Duration::hours(2))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let pid = std::process::id();
    let override_doc = sign_document(
        serde_json::json!({
            "schema_version": "blueeconomy.waterway-safety.met-ocean-operator-override.v1",
            "action": "met_ocean.operator_override",
            "zone_id": "hz-e2e",
            "phenomenon_code": "HIGH_SIGNIFICANT_WAVE_HEIGHT",
            "severity": "Severe",
            "effective_from": issued_at,
            "effective_until": until,
            "rationale": "e2e: pilot report of dangerous swell",
            "nonce": format!("e2e-nonce-{pid}"),
            "issued_at": issued_at
        })
        .as_object()
        .expect("object")
        .clone(),
        &operator_signer,
    )
    .expect("override signed");
    let override_path = write("override.json", &override_doc);
    let output = base_command()
        .arg("override")
        .arg(&override_path)
        .output()
        .expect("override runs");
    assert!(
        output.status.success(),
        "override exits ok: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let advisory: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("advisory json");
    assert_eq!(advisory["source"], "OPERATOR_OVERRIDE");
    let advisory_id = advisory["advisory_id"].as_str().expect("id").to_owned();

    // 3. The envelope landed on the real topic and verifies byte-exact.
    let hosts: Vec<String> = brokers
        .trim()
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect();
    let mut consumer = kafka::consumer::Consumer::from_hosts(hosts)
        .with_topic(ADVISORY_TOPIC.to_owned())
        .with_fallback_offset(kafka::consumer::FetchOffset::Earliest)
        .create()
        .expect("consumer");
    let mut found = None;
    for _ in 0..30 {
        for set in consumer.poll().expect("poll").iter() {
            for message in set.messages() {
                if message.key == advisory_id.as_bytes() {
                    found = Some(message.value.to_vec());
                }
            }
        }
        if found.is_some() {
            break;
        }
    }
    let envelope = found.expect("override envelope on topic");
    let directory = KeyDirectory::load(&envelope_path).expect("envelope key dir");
    let verified = verify_envelope(&envelope, &directory).expect("e2e signature verifies");
    assert_eq!(verified.advisory_id, advisory_id);
    assert_eq!(verified.source, "OPERATOR_OVERRIDE");
    assert_eq!(verified.severity, "Severe");
    assert_eq!(verified.zone_id, "hz-e2e");

    // 4. Replay of the same signed override is refused closed.
    let replay = base_command()
        .arg("override")
        .arg(&override_path)
        .output()
        .expect("replay runs");
    assert!(!replay.status.success(), "replay must fail closed");
    assert!(String::from_utf8_lossy(&replay.stderr).contains("operator_nonce_replay"));

    std::fs::remove_dir_all(&dir).ok();
}
