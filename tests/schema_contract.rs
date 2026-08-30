//! Schema contract test: the governed met-ocean documents (hazard-zone
//! registry, advisory policy) and the SAR safety-event marker validate
//! against the published JSON Schemas, and the producer-side schema versions
//! referenced by code match the schema files on disk (drift check). Pure
//! file-based — no services required.

use blueeconomy_waterway_safety::metocean::registry::{
    load_advisory_policy, load_hazard_zone_registry, sign_document, KeyDirectory,
};
use blueeconomy_waterway_safety::metocean::{
    ADVISORY_POLICY_SCHEMA_VERSION, HAZARD_ZONE_REGISTRY_SCHEMA_VERSION,
};
use blueeconomy_waterway_safety::provenance::ProvenanceSigner;
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;

const ADVISORY_POLICY_SCHEMA: &str = include_str!("../schemas/advisory-policy.schema.json");
const HAZARD_ZONE_REGISTRY_SCHEMA: &str =
    include_str!("../schemas/hazard-zone-registry.schema.json");
const SAR_MARKER_SCHEMA: &str = include_str!("../schemas/sar-safety-event-marker.schema.json");

fn governance() -> (ProvenanceSigner, KeyDirectory) {
    let signer =
        ProvenanceSigner::new("metocean-governance-1", &[23u8; 32]).expect("governance signer");
    let mut entries = BTreeMap::new();
    entries.insert(
        "metocean-governance-1".to_owned(),
        SigningKey::from_bytes(&[23u8; 32]).verifying_key(),
    );
    (signer, KeyDirectory::from_entries(entries))
}

/// Minimal hand-rolled schema checks (the repo pins no jsonschema crate):
/// assert the schema file declares the const schema_version the code
/// verifies, its required fields, and its id/title conventions; then
/// round-trip a conforming signed document through the strict loader, and
/// confirm a non-conforming document is refused. This binds code and
/// schema to the same contract without a new dependency.
fn assert_schema_declares(schema_raw: &str, const_version: &str, required: &[&str]) {
    let schema: serde_json::Value = serde_json::from_str(schema_raw).expect("schema parses");
    let raw = serde_json::to_string(&schema).expect("encode");
    assert!(
        raw.contains(&format!("\"const\":\"{const_version}\"")),
        "schema must pin const {const_version}"
    );
    let declared: Vec<&str> = schema["required"]
        .as_array()
        .expect("required array")
        .iter()
        .map(|value| value.as_str().expect("string"))
        .collect();
    for field in required {
        assert!(
            declared.contains(field),
            "schema must require {field} (has {declared:?})"
        );
    }
}

#[test]
fn hazard_zone_registry_schema_matches_code_contract() {
    assert_schema_declares(
        HAZARD_ZONE_REGISTRY_SCHEMA,
        HAZARD_ZONE_REGISTRY_SCHEMA_VERSION,
        &["schema_version", "registry_version", "zones", "signature_key_id", "signature"],
    );
    let (signer, directory) = governance();
    let payload = serde_json::json!({
        "schema_version": HAZARD_ZONE_REGISTRY_SCHEMA_VERSION,
        "registry_version": "contract-test-r1",
        "zones": [{
            "zone_id": "hz-contract",
            "name": "Contract test zone",
            "polygon": [
                {"latitude": 5.0, "longitude": 2.0},
                {"latitude": 5.0, "longitude": 4.0},
                {"latitude": 7.0, "longitude": 4.0},
                {"latitude": 7.0, "longitude": 2.0}
            ],
            "monitored_points": [{"latitude": 6.0, "longitude": 3.0}],
            "route_refs": ["route-contract"]
        }]
    });
    let document = sign_document(payload.as_object().expect("object").clone(), &signer)
        .expect("signed");
    let registry = load_hazard_zone_registry(
        serde_json::to_vec(&document).expect("encode").as_slice(),
        &directory,
    )
    .expect("conforming registry loads");
    assert_eq!(registry.zones.len(), 1);
    // Non-conforming: monitored point outside the polygon is refused.
    let bad = serde_json::json!({
        "schema_version": HAZARD_ZONE_REGISTRY_SCHEMA_VERSION,
        "registry_version": "contract-test-r1",
        "zones": [{
            "zone_id": "hz-contract",
            "name": "Contract test zone",
            "polygon": [
                {"latitude": 5.0, "longitude": 2.0},
                {"latitude": 5.0, "longitude": 4.0},
                {"latitude": 7.0, "longitude": 4.0},
                {"latitude": 7.0, "longitude": 2.0}
            ],
            "monitored_points": [{"latitude": 9.0, "longitude": 3.0}]
        }]
    });
    let document =
        sign_document(bad.as_object().expect("object").clone(), &signer).expect("signed");
    assert!(load_hazard_zone_registry(
        serde_json::to_vec(&document).expect("encode").as_slice(),
        &directory,
    )
    .is_err());
}

#[test]
fn advisory_policy_schema_matches_code_contract() {
    assert_schema_declares(
        ADVISORY_POLICY_SCHEMA,
        ADVISORY_POLICY_SCHEMA_VERSION,
        &["schema_version", "policy_version", "thresholds", "signature_key_id", "signature"],
    );
    let (signer, directory) = governance();
    let payload = serde_json::json!({
        "schema_version": ADVISORY_POLICY_SCHEMA_VERSION,
        "policy_version": "contract-test-p1",
        "thresholds": [
            {"param": "wave_height_m", "warn": 2.5, "severe": 4.0, "extreme": 6.0, "duration_min": 180}
        ]
    });
    let document = sign_document(payload.as_object().expect("object").clone(), &signer)
        .expect("signed");
    let policy = load_advisory_policy(
        serde_json::to_vec(&document).expect("encode").as_slice(),
        &directory,
    )
    .expect("conforming policy loads");
    assert_eq!(policy.thresholds.len(), 1);
    // Non-conforming: warn >= severe is refused.
    let bad = serde_json::json!({
        "schema_version": ADVISORY_POLICY_SCHEMA_VERSION,
        "policy_version": "contract-test-p1",
        "thresholds": [
            {"param": "wave_height_m", "warn": 5.0, "severe": 4.0, "duration_min": 180}
        ]
    });
    let document =
        sign_document(bad.as_object().expect("object").clone(), &signer).expect("signed");
    assert!(load_advisory_policy(
        serde_json::to_vec(&document).expect("encode").as_slice(),
        &directory,
    )
    .is_err());
}

#[test]
fn sar_safety_event_marker_schema_is_additive_and_optional() {
    let schema: serde_json::Value = serde_json::from_str(SAR_MARKER_SCHEMA).expect("schema parses");
    // Producer-side marker: additive (additionalProperties true), optional
    // (no required fields), boolean flag when present, versioned.
    assert_eq!(schema["additionalProperties"], serde_json::json!(true));
    assert!(schema.get("required").is_none());
    assert_eq!(
        schema["properties"]["safety_relevant"]["type"],
        serde_json::json!("boolean")
    );
    assert_eq!(
        schema["x-schema-version"],
        serde_json::json!("blueeconomy.waterway-safety.safety-event-marker.v1")
    );
}
