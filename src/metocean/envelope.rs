//! Envelope v1.0 issuance for `waterways.met_ocean.advisories.v1`: each
//! advisory is the primary resource of an EventEnvelope FHIR R4 message
//! Bundle, signed per `docs/envelope-signature.md` (JWS compact EdDSA over
//! the RFC 8785 JCS canonicalization of the envelope minus
//! `provenance.signature`). The consumer-side [`verify_envelope`] implements
//! the fail-closed verification algorithm byte-for-byte and doubles as the
//! broker round-trip checker in tests.

use super::evaluate::{Advisory, CapMessageType};
use super::{error, ADVISORY_EVENT_TYPE, ADVISORY_PRINCIPAL_ROLE, ADVISORY_PRODUCER};
use crate::provenance::ProvenanceSigner;
use crate::ValidationError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::SecondsFormat;
use ed25519_dalek::{Signature, Verifier};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Environment variables for the issuance identity. The signing key is
/// env-only (`PROVENANCE_SIGNING_KEY`, shared with the fleet scheme); the
/// envelope key id follows the `<producer>-<epoch>` convention.
pub const ENV_ENVELOPE_KEY_ID: &str = "MET_OCEAN_ENVELOPE_KEY_ID";
pub const ENV_PRINCIPAL_ID: &str = "MET_OCEAN_PRINCIPAL_ID";
pub const DEFAULT_ENVELOPE_KEY_ID: &str = "blueeconomy-waterway-safety-0";

/// The resource type URL of the advisory inside the Bundle.
pub const ADVISORY_RESOURCE_TYPE: &str =
    "type.googleapis.com/blueeconomy.contracts.v1.MetoceanAdvisoryIssued";

/// Signing identity for advisory envelopes.
#[derive(Clone, Debug)]
pub struct EnvelopeSigningContext {
    pub signer: ProvenanceSigner,
    pub principal_id: String,
}

impl EnvelopeSigningContext {
    pub fn new(signer: ProvenanceSigner, principal_id: &str) -> Result<Self, ValidationError> {
        crate::validate_identifier("principal_id", principal_id, 256)?;
        Ok(Self {
            signer,
            principal_id: principal_id.to_owned(),
        })
    }

    pub fn from_env() -> Result<Self, ValidationError> {
        Self::from_env_with(|name| std::env::var(name).ok())
    }

    /// Test seam for environment resolution.
    pub fn from_env_with(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ValidationError> {
        let kid = lookup(ENV_ENVELOPE_KEY_ID)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_ENVELOPE_KEY_ID.to_owned());
        let raw_key = lookup(crate::provenance::ENV_SIGNING_KEY)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                error(
                    "missing_signing_key",
                    "PROVENANCE_SIGNING_KEY is required to issue advisories",
                )
            })?;
        let key_bytes = URL_SAFE_NO_PAD
            .decode(raw_key.as_bytes())
            .map_err(|_| error("invalid_signing_key", "signing key is not base64url"))?;
        let signer = ProvenanceSigner::new(&kid, &key_bytes)
            .map_err(|signer_error| error("invalid_signing_key", signer_error.message))?;
        let principal_id = lookup(ENV_PRINCIPAL_ID)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                error(
                    "missing_principal_id",
                    "MET_OCEAN_PRINCIPAL_ID is required to issue advisories",
                )
            })?;
        Self::new(signer, &principal_id)
    }
}

/// RFC 3339 with Zulu rendering (matches the canonical wire form).
pub fn render_timestamp(rfc3339: &str) -> Result<String, ValidationError> {
    let parsed = crate::validate_timestamp("timestamp", rfc3339)?;
    Ok(parsed
        .with_timezone(&chrono::Utc)
        .to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn digest_uuid(name: &str) -> String {
    // Name-based UUID (SHA-256 truncated to 16 bytes, version 5 / variant
    // RFC 4122 bit shaping): deterministic, so re-issuance is idempotent.
    let hash = Sha256::digest(name.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = crate::hex_lowercase(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The CAP-profile advisory as the Bundle entry resource (proto JSON wire
/// form, camelCase keys, enums without prefixes).
pub fn advisory_resource_value(advisory: &Advisory) -> Result<Value, ValidationError> {
    advisory.validate()?;
    let mut resource = Map::new();
    resource.insert(
        "@type".to_owned(),
        Value::String(ADVISORY_RESOURCE_TYPE.to_owned()),
    );
    resource.insert(
        "advisoryId".to_owned(),
        Value::String(advisory.advisory_id.clone()),
    );
    resource.insert(
        "sender".to_owned(),
        Value::String(ADVISORY_PRODUCER.to_owned()),
    );
    resource.insert(
        "msgType".to_owned(),
        Value::String(advisory.msg_type.wire().to_owned()),
    );
    // CAP category is fixed to "Met"; consumers fail closed on anything else.
    resource.insert("category".to_owned(), Value::String("Met".to_owned()));
    resource.insert(
        "phenomenonCode".to_owned(),
        Value::String(advisory.phenomenon_code.clone()),
    );
    resource.insert(
        "urgency".to_owned(),
        Value::String(advisory.urgency.wire().to_owned()),
    );
    resource.insert(
        "severity".to_owned(),
        Value::String(advisory.severity.wire().to_owned()),
    );
    resource.insert(
        "certainty".to_owned(),
        Value::String(advisory.certainty.wire().to_owned()),
    );
    resource.insert("zoneId".to_owned(), Value::String(advisory.zone_id.clone()));
    resource.insert(
        "effectiveFrom".to_owned(),
        Value::String(render_timestamp(&advisory.effective_from)?),
    );
    if let Some(onset) = &advisory.onset {
        resource.insert("onset".to_owned(), Value::String(render_timestamp(onset)?));
    }
    resource.insert(
        "effectiveUntil".to_owned(),
        Value::String(render_timestamp(&advisory.effective_until)?),
    );
    resource.insert(
        "bulletinReference".to_owned(),
        Value::String(advisory.bulletin_reference.clone()),
    );
    resource.insert(
        "referencesAdvisoryId".to_owned(),
        Value::String(advisory.references_advisory_id.clone()),
    );
    resource.insert(
        "source".to_owned(),
        Value::String(advisory.source.wire().to_owned()),
    );
    resource.insert(
        "feedKind".to_owned(),
        Value::String(
            advisory
                .feed_kind
                .map(|kind| kind.contract_name())
                .unwrap_or("UNSPECIFIED")
                .to_owned(),
        ),
    );
    resource.insert(
        "attributionText".to_owned(),
        Value::String(advisory.attribution_text.clone()),
    );
    resource.insert(
        "status".to_owned(),
        Value::String(advisory.status.wire().to_owned()),
    );
    resource.insert(
        "policyDigestSha256".to_owned(),
        Value::String(advisory.policy_digest_sha256.clone()),
    );
    resource.insert(
        "issuedAt".to_owned(),
        Value::String(render_timestamp(&advisory.issued_at)?),
    );
    Ok(Value::Object(resource))
}

/// Build and sign the envelope for one advisory. Returns the canonical JSON
/// document bytes (the exact bytes published to the topic).
pub fn build_signed_envelope(
    context: &EnvelopeSigningContext,
    advisory: &Advisory,
) -> Result<Vec<u8>, ValidationError> {
    let occurred_at = render_timestamp(&advisory.issued_at)?;
    let event_name = format!(
        "waterways.met_ocean.advisory.v1|{}|{}",
        advisory.advisory_id,
        advisory.msg_type.wire()
    );
    let event_id = format!(
        "evt-metocean-{}",
        &crate::hex_lowercase(Sha256::digest(event_name.as_bytes()))[..16]
    );
    let bundle_id = format!(
        "bdl-metocean-{}",
        &crate::hex_lowercase(Sha256::digest(format!("bundle|{event_name}").as_bytes()))[..16]
    );
    let full_url = format!(
        "urn:uuid:{}",
        digest_uuid(&format!("advisory|{}", advisory.advisory_id))
    );
    let correlation_id = format!(
        "corr-metocean-{}",
        &crate::hex_lowercase(Sha256::digest(format!("corr|{event_name}").as_bytes()))[..16]
    );
    let resource = advisory_resource_value(advisory)?;
    let envelope = serde_json::json!({
        "envelopeVersion": "1.0",
        "eventId": event_id,
        "eventType": ADVISORY_EVENT_TYPE,
        "occurredAt": occurred_at,
        "producer": ADVISORY_PRODUCER,
        "correlationId": correlation_id,
        "fhir": {
            "resourceType": "Bundle",
            "type": "message",
            "bundleId": bundle_id,
            "entry": [{ "fullUrl": full_url, "resource": resource }],
        },
        "provenance": {
            "principalId": context.principal_id,
            "principalRole": ADVISORY_PRINCIPAL_ROLE,
            "ledgerCommitHash": "",
        },
        "classification": "INTERNAL",
    });
    let canonical = crate::provenance::canonicalize(&envelope).map_err(|canonical_error| {
        error("envelope_canonicalization_failed", canonical_error.message)
    })?;
    let signature = context.signer.sign(&canonical);
    let mut signed = envelope.as_object().expect("envelope object").clone();
    let provenance = signed
        .get_mut("provenance")
        .and_then(Value::as_object_mut)
        .expect("provenance object");
    provenance.insert("signature".to_owned(), Value::String(signature));
    serde_json::to_vec(&Value::Object(signed))
        .map_err(|serde_error| error("envelope_encode_failed", serde_error.to_string()))
}

/// A verified advisory envelope (consumer side).
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedAdvisoryEnvelope {
    pub event_id: String,
    pub advisory_id: String,
    pub msg_type: CapMessageType,
    pub zone_id: String,
    pub severity: String,
    pub source: String,
    pub bulletin_reference: String,
    pub references_advisory_id: String,
    pub attribution_text: String,
    pub producer: String,
    pub signature_key_id: String,
}

fn require_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, ValidationError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| error("malformed_envelope", field))
}

/// Verify one advisory envelope per `docs/envelope-signature.md` §4: JWS
/// shape, EdDSA-only, kid resolution from the key directory, payload
/// byte-match against the re-canonicalized envelope, Ed25519 verification.
/// Then fail-closed contract checks: envelope version, topic/eventType
/// allowlist, CAP category and msgType sets, digest binding format.
pub fn verify_envelope(
    raw: &[u8],
    directory: &super::registry::KeyDirectory,
) -> Result<VerifiedAdvisoryEnvelope, ValidationError> {
    if raw.is_empty() || raw.len() > crate::MAX_JSON_BYTES {
        return Err(error(
            "malformed_envelope",
            "envelope size outside the accepted range",
        ));
    }
    let document: Value = serde_json::from_slice(raw)
        .map_err(|serde_error| error("malformed_envelope", serde_error.to_string()))?;
    let envelope = document
        .as_object()
        .ok_or_else(|| error("malformed_envelope", "envelope must be a JSON object"))?;
    let provenance = envelope
        .get("provenance")
        .and_then(Value::as_object)
        .ok_or_else(|| error("malformed_envelope", "provenance object required"))?;
    let jws = provenance
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| error("malformed-jws", "provenance.signature is required"))?;
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(error(
            "malformed-jws",
            "signature must be a three-segment JWS compact serialization",
        ));
    }
    let header_raw = URL_SAFE_NO_PAD
        .decode(parts[0].as_bytes())
        .map_err(|_| error("malformed-jws", "protected header is not base64url"))?;
    let header: Value = serde_json::from_slice(&header_raw)
        .map_err(|_| error("malformed-jws", "protected header is not JSON"))?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err(error("unsupported-alg", "envelope alg is not EdDSA"));
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| error("malformed-jws", "protected header kid required"))?;
    let key = directory.resolve(kid).ok_or_else(|| {
        error(
            "unknown-kid",
            "envelope signing key not in the key directory",
        )
    })?;

    // Payload byte-match: re-canonicalize the envelope minus the signature.
    let mut unsigned = envelope.clone();
    let unsigned_provenance = unsigned
        .get_mut("provenance")
        .and_then(Value::as_object_mut)
        .expect("provenance object");
    unsigned_provenance.remove("signature");
    let canonical = crate::provenance::canonicalize(&Value::Object(unsigned))
        .map_err(|canonical_error| error("malformed_envelope", canonical_error.message))?;
    let payload_segment = URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .map_err(|_| error("malformed-jws", "payload is not base64url"))?;
    if payload_segment != canonical {
        return Err(error(
            "payload-mismatch",
            "signed payload does not byte-match the canonical envelope",
        ));
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map_err(|_| error("malformed-jws", "signature is not base64url"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| error("malformed-jws", "signature is not an Ed25519 signature"))?;
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .map_err(|_| error("invalid-signature", "envelope signature does not verify"))?;

    // Contract checks (fail closed on any unknown value).
    if require_string(envelope, "envelopeVersion")? != "1.0" {
        return Err(error("unsupported_envelope_version", "only envelope 1.0"));
    }
    if require_string(envelope, "eventType")? != ADVISORY_EVENT_TYPE {
        return Err(error(
            "unknown_event_type",
            "eventType is not in the advisory allowlist",
        ));
    }
    let producer = require_string(envelope, "producer")?.to_owned();
    if producer != ADVISORY_PRODUCER {
        return Err(error("unknown_producer", "unexpected advisory producer"));
    }
    if require_string(envelope, "classification")? != "INTERNAL" {
        return Err(error(
            "invalid_classification",
            "advisories are classification INTERNAL",
        ));
    }
    let entries = envelope
        .get("fhir")
        .and_then(Value::as_object)
        .and_then(|bundle| bundle.get("entry"))
        .and_then(Value::as_array)
        .ok_or_else(|| error("malformed_envelope", "fhir.entry required"))?;
    if entries.len() != 1 {
        return Err(error(
            "malformed_envelope",
            "advisory envelopes carry exactly one entry",
        ));
    }
    let resource = entries[0]
        .get("resource")
        .and_then(Value::as_object)
        .ok_or_else(|| error("malformed_envelope", "entry.resource required"))?;
    if require_string(resource, "@type")? != ADVISORY_RESOURCE_TYPE {
        return Err(error(
            "unknown_event_type",
            "unexpected entry resource type",
        ));
    }
    if require_string(resource, "category")? != "Met" {
        return Err(error("invalid_category", "CAP category is fixed to Met"));
    }
    let msg_type = match require_string(resource, "msgType")? {
        "Alert" => CapMessageType::Alert,
        "Update" => CapMessageType::Update,
        "Cancel" => CapMessageType::Cancel,
        _ => return Err(error("invalid_msg_type", "unknown CAP msgType")),
    };
    let source = require_string(resource, "source")?.to_owned();
    if source != "FEED" && source != "OPERATOR_OVERRIDE" {
        return Err(error("invalid_source", "unknown advisory source"));
    }
    let attribution_text = require_string(resource, "attributionText")?.to_owned();
    if source == "FEED" && attribution_text.trim().is_empty() {
        return Err(error(
            "missing_attribution",
            "feed-derived advisories must carry attribution",
        ));
    }
    let bulletin_reference = require_string(resource, "bulletinReference")?.to_owned();
    super::evaluate::validate_bulletin_reference(&bulletin_reference)?;
    let references_advisory_id = require_string(resource, "referencesAdvisoryId")?.to_owned();
    match msg_type {
        CapMessageType::Alert if !references_advisory_id.is_empty() => {
            return Err(error(
                "invalid_msg_type",
                "ALERT must not reference another advisory",
            ))
        }
        CapMessageType::Update | CapMessageType::Cancel if references_advisory_id.is_empty() => {
            return Err(error(
                "invalid_msg_type",
                "UPDATE/CANCEL must reference the terminated advisory",
            ))
        }
        _ => {}
    }
    Ok(VerifiedAdvisoryEnvelope {
        event_id: require_string(envelope, "eventId")?.to_owned(),
        advisory_id: require_string(resource, "advisoryId")?.to_owned(),
        msg_type,
        zone_id: require_string(resource, "zoneId")?.to_owned(),
        severity: require_string(resource, "severity")?.to_owned(),
        source,
        bulletin_reference,
        references_advisory_id,
        attribution_text,
        producer,
        signature_key_id: kid.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metocean::evaluate::{
        build_cancel_advisory, build_feed_advisory, AdvisorySource, CancelReason, CapSeverity,
    };
    use crate::metocean::registry::tests::signed_registry_and_policy;
    use crate::metocean::registry::{combined_policy_digest, KeyDirectory};
    use crate::metocean::{FeedKind, FeedSourceConfig, NormalizedReading, READING_SCHEMA_VERSION};
    use chrono::{DateTime, Utc};
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;

    fn signing_context() -> EnvelopeSigningContext {
        let signer =
            ProvenanceSigner::new("blueeconomy-waterway-safety-0", &[41u8; 32]).expect("signer");
        EnvelopeSigningContext::new(signer, "f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("context")
    }

    fn directory() -> KeyDirectory {
        let mut entries = BTreeMap::new();
        entries.insert(
            "blueeconomy-waterway-safety-0".to_owned(),
            SigningKey::from_bytes(&[41u8; 32]).verifying_key(),
        );
        KeyDirectory::from_entries(entries)
    }

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

    fn reading() -> NormalizedReading {
        NormalizedReading {
            schema_version: READING_SCHEMA_VERSION.to_owned(),
            reading_id: "mor-fixture".to_owned(),
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
            source_payload_sha256: "c".repeat(64),
            attribution_text: "Weather data by Open-Meteo.com".to_owned(),
        }
    }

    fn alert_advisory() -> Advisory {
        let (registry, policy, _) = signed_registry_and_policy();
        let digest = combined_policy_digest(&policy, &registry);
        let now = DateTime::parse_from_rfc3339("2026-08-30T12:00:00Z")
            .expect("time")
            .with_timezone(&Utc);
        build_feed_advisory(
            &crate::metocean::evaluate::FeedAdvisorySpec {
                msg_type: CapMessageType::Alert,
                zone_id: "hz-lagos-approach",
                param: crate::metocean::registry::ThresholdParam::WaveHeightM,
                severity: CapSeverity::Moderate,
                duration_min: 180,
                references_advisory_id: "",
            },
            &[reading()],
            &feed(),
            &digest,
            now,
        )
        .expect("advisory")
    }

    #[test]
    fn signed_envelope_round_trips_through_verify() {
        let context = signing_context();
        let advisory = alert_advisory();
        let envelope = build_signed_envelope(&context, &advisory).expect("envelope");
        let verified = verify_envelope(&envelope, &directory()).expect("verifies");
        assert_eq!(verified.advisory_id, advisory.advisory_id);
        assert_eq!(verified.msg_type, CapMessageType::Alert);
        assert_eq!(verified.zone_id, "hz-lagos-approach");
        assert_eq!(verified.severity, "Moderate");
        assert_eq!(verified.source, "FEED");
        assert_eq!(verified.attribution_text, "Weather data by Open-Meteo.com");
        assert_eq!(verified.signature_key_id, "blueeconomy-waterway-safety-0");
        assert_eq!(verified.producer, ADVISORY_PRODUCER);
        assert!(verified.event_id.starts_with("evt-metocean-"));
        // Deterministic: same advisory yields the same envelope bytes.
        let again = build_signed_envelope(&context, &advisory).expect("envelope");
        assert_eq!(envelope, again);
    }

    #[test]
    fn tampered_envelopes_fail_closed_with_reason_codes() {
        let context = signing_context();
        let advisory = alert_advisory();
        let envelope = build_signed_envelope(&context, &advisory).expect("envelope");
        let mut document: Value = serde_json::from_slice(&envelope).expect("json");

        // Tampered severity breaks the payload byte-match.
        let mut tampered = document.clone();
        tampered["fhir"]["entry"][0]["resource"]["severity"] = Value::String("Extreme".into());
        assert_eq!(
            verify_envelope(
                serde_json::to_vec(&tampered).expect("encode").as_slice(),
                &directory()
            )
            .unwrap_err()
            .code,
            "payload-mismatch"
        );

        // Unknown kid.
        let other_signer =
            ProvenanceSigner::new("blueeconomy-waterway-safety-9", &[42u8; 32]).expect("signer");
        let other_context =
            EnvelopeSigningContext::new(other_signer, "principal").expect("context");
        let forged = build_signed_envelope(&other_context, &advisory).expect("envelope");
        assert_eq!(
            verify_envelope(&forged, &directory()).unwrap_err().code,
            "unknown-kid"
        );

        // Unknown event type is refused even with a valid signature: sign a
        // structurally complete envelope with a different eventType.
        document["eventType"] = Value::String("waterways.met_ocean.advisory.v0".to_owned());
        document["provenance"]
            .as_object_mut()
            .expect("provenance")
            .remove("signature");
        let canonical = crate::provenance::canonicalize(&document).expect("canonicalize");
        let signature = context.signer.sign(&canonical);
        document["provenance"]["signature"] = Value::String(signature);
        assert_eq!(
            verify_envelope(
                serde_json::to_vec(&document).expect("encode").as_slice(),
                &directory()
            )
            .unwrap_err()
            .code,
            "unknown_event_type"
        );
    }

    #[test]
    fn cancel_envelope_carries_reference_and_reason_binding() {
        let context = signing_context();
        let alert = alert_advisory();
        let (registry, policy, _) = signed_registry_and_policy();
        let digest = combined_policy_digest(&policy, &registry);
        let now = DateTime::parse_from_rfc3339("2026-08-30T15:00:00Z")
            .expect("time")
            .with_timezone(&Utc);
        let cancel = build_cancel_advisory(&alert, CancelReason::FeedUnavailable, &digest, now)
            .expect("cancel advisory");
        assert_eq!(cancel.source, AdvisorySource::Feed);
        let envelope = build_signed_envelope(&context, &cancel).expect("envelope");
        let verified = verify_envelope(&envelope, &directory()).expect("verifies");
        assert_eq!(verified.msg_type, CapMessageType::Cancel);
        assert_eq!(verified.references_advisory_id, alert.advisory_id);
        assert_ne!(verified.bulletin_reference, alert.bulletin_reference);
    }

    #[test]
    fn signing_context_env_resolution_is_fail_closed() {
        assert_eq!(
            EnvelopeSigningContext::from_env_with(|_| None)
                .unwrap_err()
                .code,
            "missing_signing_key"
        );
        let key = URL_SAFE_NO_PAD.encode([41u8; 32]);
        let lookup = move |name: &str| match name {
            crate::provenance::ENV_SIGNING_KEY => Some(key.clone()),
            _ => None,
        };
        assert_eq!(
            EnvelopeSigningContext::from_env_with(lookup)
                .unwrap_err()
                .code,
            "missing_principal_id"
        );
    }
}
