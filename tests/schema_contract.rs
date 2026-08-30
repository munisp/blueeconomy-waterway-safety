#![forbid(unsafe_code)]
//! CI drift guard: the committed gateway telemetry profile JSON schema must
//! mirror the `TelemetryFrame` contract enforced by the Rust code. The test
//! fails if the schema's field set drifts from the serializer output, if the
//! schema adopts keywords this guard cannot verify, or if any fixture document
//! is accepted by one side and rejected by the other.
//!
//! The validator below intentionally supports only the keyword subset used by
//! the committed schema (type/required/properties/additionalProperties/
//! minLength/maxLength/minimum/enum/format/pattern) so that the guard stays
//! dependency-free and deterministic.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use blueeconomy_waterway_safety::{validate_json, TelemetryFrame, MAX_PAYLOAD_BYTES};
use chrono::DateTime;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const SCHEMA_JSON: &str = include_str!("../schemas/gateway-telemetry-profile.schema.json");

const SUPPORTED_KEYWORDS: &[&str] = &[
    "$schema",
    "$id",
    "title",
    "description",
    "type",
    "required",
    "properties",
    "additionalProperties",
    "minLength",
    "maxLength",
    "minimum",
    "enum",
    "format",
    "pattern",
];

const SUPPORTED_PATTERNS: &[&str] = &["^[0-9a-f]{64}$"];
const SUPPORTED_FORMATS: &[&str] = &["date-time"];

fn schema() -> Value {
    serde_json::from_str(SCHEMA_JSON).expect("committed schema must be valid JSON")
}

fn valid_frame() -> TelemetryFrame {
    let payload = b"bytes";
    TelemetryFrame {
        device_id: "device-001".to_owned(),
        gateway_id: "gateway-001".to_owned(),
        source_sequence: 1,
        observed_at: "2026-08-12T00:00:00Z".to_owned(),
        received_at: "2026-08-12T00:00:01Z".to_owned(),
        data_classification: "internal".to_owned(),
        payload_base64: STANDARD.encode(payload),
        payload_sha256: format!("{:x}", Sha256::digest(payload)),
    }
}

fn valid_document() -> Value {
    serde_json::to_value(valid_frame()).expect("serialize frame fixture")
}

fn key_set(value: &Value) -> BTreeSet<String> {
    value.as_object().expect("object").keys().cloned().collect()
}

#[test]
fn schema_field_set_matches_serializer_output_exactly() {
    let schema = schema();
    let required: BTreeSet<String> = schema["required"]
        .as_array()
        .expect("required array")
        .iter()
        .map(|value| value.as_str().expect("required entry").to_owned())
        .collect();
    let properties = key_set(&schema["properties"]);
    let serialized = key_set(&valid_document());
    assert_eq!(
        required, properties,
        "schema required fields must equal declared properties"
    );
    assert_eq!(
        properties, serialized,
        "schema properties must equal TelemetryFrame serializer output keys"
    );
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    assert_eq!(schema["type"], Value::String("object".to_owned()));
}

#[test]
fn schema_uses_only_verifiable_keywords() {
    let schema = schema();
    let check_object = |object: &Map<String, Value>| {
        for keyword in object.keys() {
            assert!(
                SUPPORTED_KEYWORDS.contains(&keyword.as_str()),
                "schema keyword {keyword} is not verifiable by this guard"
            );
        }
    };
    check_object(schema.as_object().expect("schema object"));
    for (name, subschema) in schema["properties"].as_object().expect("properties object") {
        check_object(subschema.as_object().expect("subschema object"));
        if let Some(pattern) = subschema.get("pattern") {
            assert!(
                SUPPORTED_PATTERNS.contains(&pattern.as_str().expect("pattern string")),
                "pattern for {name} is not verifiable by this guard"
            );
        }
        if let Some(format) = subschema.get("format") {
            assert!(
                SUPPORTED_FORMATS.contains(&format.as_str().expect("format string")),
                "format for {name} is not verifiable by this guard"
            );
        }
    }
}

/// Minimal JSON Schema evaluation for the supported keyword subset. Returns
/// the list of violations; an empty list means the instance validates.
fn schema_violations(instance: &Value) -> Vec<String> {
    let schema = schema();
    let mut violations = Vec::new();
    let Some(object) = instance.as_object() else {
        violations.push("instance is not an object".to_owned());
        return violations;
    };
    let properties = schema["properties"].as_object().expect("properties object");
    for required in schema["required"].as_array().expect("required array") {
        let name = required.as_str().expect("required entry");
        if !object.contains_key(name) {
            violations.push(format!("missing required property {name}"));
        }
    }
    for key in object.keys() {
        if !properties.contains_key(key) {
            violations.push(format!("additional property {key}"));
        }
    }
    for (name, subschema) in properties {
        if let Some(value) = object.get(name) {
            check_value(name, value, subschema, &mut violations);
        }
    }
    violations
}

fn check_value(name: &str, value: &Value, subschema: &Value, violations: &mut Vec<String>) {
    match subschema["type"].as_str().expect("type keyword") {
        "string" => {
            let Some(text) = value.as_str() else {
                violations.push(format!("{name} is not a string"));
                return;
            };
            let length = text.chars().count();
            if let Some(minimum) = subschema.get("minLength") {
                if length < minimum.as_u64().expect("minLength") as usize {
                    violations.push(format!("{name} shorter than minLength"));
                }
            }
            if let Some(maximum) = subschema.get("maxLength") {
                if length > maximum.as_u64().expect("maxLength") as usize {
                    violations.push(format!("{name} longer than maxLength"));
                }
            }
            if let Some(choices) = subschema.get("enum") {
                let allowed = choices
                    .as_array()
                    .expect("enum array")
                    .iter()
                    .any(|choice| choice.as_str() == Some(text));
                if !allowed {
                    violations.push(format!("{name} not in enum"));
                }
            }
            if let Some(format) = subschema.get("format") {
                match format.as_str().expect("format string") {
                    "date-time" => {
                        if DateTime::parse_from_rfc3339(text).is_err() {
                            violations.push(format!("{name} is not RFC 3339"));
                        }
                    }
                    other => panic!("unsupported format {other}"),
                }
            }
            if let Some(pattern) = subschema.get("pattern") {
                match pattern.as_str().expect("pattern string") {
                    "^[0-9a-f]{64}$" => {
                        let matches = text.len() == 64
                            && text
                                .bytes()
                                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
                        if !matches {
                            violations.push(format!("{name} does not match pattern"));
                        }
                    }
                    other => panic!("unsupported pattern {other}"),
                }
            }
        }
        "integer" => {
            let Some(number) = value.as_u64() else {
                violations.push(format!("{name} is not an unsigned integer"));
                return;
            };
            if let Some(minimum) = subschema.get("minimum") {
                if number < minimum.as_u64().expect("minimum") {
                    violations.push(format!("{name} below minimum"));
                }
            }
        }
        other => panic!("unsupported type {other}"),
    }
}

#[test]
fn round_trips_serializer_output_through_schema_and_code() {
    for classification in [
        "public",
        "internal",
        "confidential",
        "restricted",
        "highly_restricted",
    ] {
        let mut frame = valid_frame();
        frame.data_classification = classification.to_owned();
        let serialized = serde_json::to_vec(&frame).expect("serialize frame");
        let document: Value = serde_json::from_slice(&serialized).expect("serializer output JSON");
        assert_eq!(
            schema_violations(&document),
            Vec::<String>::new(),
            "schema must accept valid serializer output"
        );
        validate_json(&serialized).expect("code must accept valid serializer output");
    }
}

#[test]
fn schema_and_code_jointly_reject_invalid_documents() {
    let mut invalid_documents: Vec<(&str, Value)> = Vec::new();

    for field in [
        "device_id",
        "gateway_id",
        "source_sequence",
        "observed_at",
        "received_at",
        "data_classification",
        "payload_base64",
        "payload_sha256",
    ] {
        let mut document = valid_document();
        document.as_object_mut().expect("object").remove(field);
        invalid_documents.push(("missing required field", document));
    }

    // Field names from the previously drifted schema revision must stay rejected.
    let mut renamed = valid_document();
    let object = renamed.as_object_mut().expect("object");
    object.remove("data_classification");
    object.insert(
        "classification".to_owned(),
        Value::String("PUBLIC".to_owned()),
    );
    invalid_documents.push(("drifted classification field name", renamed));

    for extra in ["signature", "rules_policy_version"] {
        let mut document = valid_document();
        document
            .as_object_mut()
            .expect("object")
            .insert(extra.to_owned(), Value::String("unexpected".to_owned()));
        invalid_documents.push(("unexpected additional property", document));
    }

    let mut document = valid_document();
    document["source_sequence"] = Value::from(0);
    invalid_documents.push(("zero source sequence", document));

    let mut document = valid_document();
    document["data_classification"] = Value::String("PUBLIC".to_owned());
    invalid_documents.push(("uppercase drifted classification", document));

    let mut document = valid_document();
    document["data_classification"] = Value::String("undeclared".to_owned());
    invalid_documents.push(("unapproved classification", document));

    let mut document = valid_document();
    document["payload_sha256"] = Value::String("A".repeat(64));
    invalid_documents.push(("uppercase digest", document));

    let mut document = valid_document();
    document["payload_sha256"] = Value::String("g".repeat(64));
    invalid_documents.push(("non-hex digest", document));

    let mut document = valid_document();
    document["payload_sha256"] = Value::String("a".repeat(63));
    invalid_documents.push(("short digest", document));

    let mut document = valid_document();
    document["observed_at"] = Value::String("not-a-time".to_owned());
    invalid_documents.push(("non RFC 3339 observed_at", document));

    let mut document = valid_document();
    document["device_id"] = Value::String(String::new());
    invalid_documents.push(("empty device_id", document));

    let mut document = valid_document();
    document["device_id"] = Value::String("d".repeat(257));
    invalid_documents.push(("overlong device_id", document));

    let mut document = valid_document();
    document["payload_base64"] = Value::String(String::new());
    invalid_documents.push(("empty payload", document));

    let mut document = valid_document();
    document["payload_base64"] = Value::String("A".repeat(MAX_PAYLOAD_BYTES * 2));
    invalid_documents.push(("oversized encoded payload", document));

    for (label, document) in invalid_documents {
        assert!(
            !schema_violations(&document).is_empty(),
            "schema must reject: {label}"
        );
        let encoded = serde_json::to_vec(&document).expect("encode invalid fixture");
        assert!(
            validate_json(&encoded).is_err(),
            "code must reject: {label}"
        );
    }
}

#[test]
fn code_remains_stricter_than_schema_for_canonical_identifiers() {
    // The schema documents the declarative subset of the contract; the code
    // additionally rejects whitespace- and control-altered identifiers. This
    // direction is intentional and pinned here so neither side loosens.
    let mut document = valid_document();
    document["device_id"] = Value::String(" device-001".to_owned());
    let encoded = serde_json::to_vec(&document).expect("encode fixture");
    assert!(validate_json(&encoded).is_err());
}

/// Phase-8 PRA-098 / ruling C6: the producer-side SAR safety-event marker
/// schema must stay a documented, additive, optional frame-level marker —
/// waterway-safety stays producer-only; maritime-intelligence owns the SAR
/// engine.
#[test]
fn sar_safety_event_marker_schema_is_valid_and_additive() {
    let raw = include_str!("../schemas/sar-safety-event-marker.schema.json");
    let schema: Value = serde_json::from_str(raw).expect("marker schema parses");
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("marker schema has properties");
    let marker = properties
        .get("safety_relevant")
        .expect("marker field documented");
    assert_eq!(marker.get("type").and_then(Value::as_str), Some("boolean"));
    // Additive and optional: not in `required`.
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        !required.iter().any(|field| field == "safety_relevant"),
        "the marker must stay optional for wire compatibility"
    );
    assert_eq!(
        schema.get("x-schema-version").and_then(Value::as_str),
        Some("blueeconomy.waterway-safety.safety-event-marker.v1")
    );
}
