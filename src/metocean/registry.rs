//! Signed, schema-versioned governed configuration for the met-ocean
//! subsystem: the hazard-zone registry (WGS-84 polygons, monitored points,
//! route references) and the advisory threshold policy.
//!
//! Both artifacts load only as Ed25519-signed documents verified against a
//! governance key directory, mirroring the device-registry discipline in
//! `lib.rs` and the envelope verification algorithm in
//! `docs/envelope-signature.md` (re-canonicalize, byte-compare, verify).
//! Threshold changes arrive only through a newly signed policy document —
//! never through runtime flags.

use super::{
    error, MonitoredPoint, ADVISORY_POLICY_SCHEMA_VERSION, HAZARD_ZONE_REGISTRY_SCHEMA_VERSION,
};
use crate::geo::{GeoPosition, SafetyZone, ZoneKind, MAX_ZONE_VERTICES};
use crate::ValidationError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

pub const MAX_GOVERNED_DOCUMENT_BYTES: usize = 4_194_304;
pub const MAX_REGISTRY_ZONES: usize = 1_024;
pub const MAX_MONITORED_POINTS_PER_ZONE: usize = 64;
pub const MAX_ROUTE_REFS_PER_ZONE: usize = 64;
pub const MAX_POLICY_THRESHOLDS: usize = 64;

/// Environment variable carrying the path of the governance public-key
/// directory (JSON object `{kid: base64url-ed25519-pubkey}`), loaded
/// fail-closed exactly like the platform envelope key directory.
pub const ENV_REGISTRY_KEY_DIRECTORY: &str = "MET_OCEAN_REGISTRY_KEY_DIRECTORY";

/// Governance public-key directory for signed configuration documents.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyDirectory {
    keys: BTreeMap<String, VerifyingKey>,
}

impl KeyDirectory {
    pub fn from_entries(entries: BTreeMap<String, VerifyingKey>) -> Self {
        Self { keys: entries }
    }

    pub fn resolve(&self, kid: &str) -> Option<&VerifyingKey> {
        self.keys.get(kid)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Parse the directory JSON shape `{kid: base64url-ed25519-pubkey}`.
    pub fn from_json(raw: &[u8]) -> Result<Self, ValidationError> {
        if raw.is_empty() || raw.len() > MAX_GOVERNED_DOCUMENT_BYTES {
            return Err(error(
                "invalid_key_directory",
                format!(
                    "key directory must contain between 1 and {MAX_GOVERNED_DOCUMENT_BYTES} bytes"
                ),
            ));
        }
        let entries: BTreeMap<String, String> = serde_json::from_slice(raw)
            .map_err(|serde_error| error("invalid_key_directory", serde_error.to_string()))?;
        if entries.is_empty() {
            return Err(error(
                "invalid_key_directory",
                "key directory must contain at least one key",
            ));
        }
        let mut keys = BTreeMap::new();
        for (kid, encoded) in entries {
            crate::validate_identifier("key_directory.kid", &kid, 256)?;
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded.as_bytes())
                .map_err(|_| error("invalid_key_directory", "key is not base64url"))?;
            let encoded_key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| error("invalid_key_directory", "Ed25519 key must be 32 bytes"))?;
            keys.insert(
                kid,
                VerifyingKey::from_bytes(&encoded_key)
                    .map_err(|key_error| error("invalid_key_directory", key_error.to_string()))?,
            );
        }
        Ok(Self { keys })
    }

    /// Load from a mounted file: fail closed on absence, symlinks and
    /// irregular files (envelope-signature.md §3 discipline).
    pub fn load(path: &Path) -> Result<Self, ValidationError> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|fs_error| error("key_directory_read_failed", fs_error.to_string()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(error(
                "invalid_key_directory_path",
                "key directory path must be a regular file and not a symbolic link",
            ));
        }
        let raw = std::fs::read(path)
            .map_err(|fs_error| error("key_directory_read_failed", fs_error.to_string()))?;
        Self::from_json(&raw)
    }
}

/// Verify a signed governed document and return its payload object and the
/// digest binding (`sha256:<hex>` of the canonical payload). The document
/// shape is `{...payload fields, "signature_key_id": kid, "signature": JWS}`
/// where the JWS payload is the RFC 8785 canonicalization of the document
/// minus the `signature` field (the key id stays inside the signed payload,
/// so key-id substitution fails verification).
pub fn verify_signed_document(
    raw: &[u8],
    expected_schema_version: &str,
    directory: &KeyDirectory,
) -> Result<(serde_json::Map<String, serde_json::Value>, String), ValidationError> {
    if raw.is_empty() || raw.len() > MAX_GOVERNED_DOCUMENT_BYTES {
        return Err(error(
            "invalid_governed_document",
            format!(
                "governed document must contain between 1 and {MAX_GOVERNED_DOCUMENT_BYTES} bytes"
            ),
        ));
    }
    let document: serde_json::Value = serde_json::from_slice(raw)
        .map_err(|serde_error| error("invalid_governed_document", serde_error.to_string()))?;
    let object = document.as_object().ok_or_else(|| {
        error(
            "invalid_governed_document",
            "document must be a JSON object",
        )
    })?;
    match object
        .get("schema_version")
        .and_then(|value| value.as_str())
    {
        Some(version) if version == expected_schema_version => {}
        _ => {
            return Err(error(
                "invalid_registry_schema",
                "governed document schema_version is not supported",
            ))
        }
    }
    let kid = object
        .get("signature_key_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| error("invalid_signature", "signature_key_id is required"))?;
    crate::validate_identifier("signature_key_id", kid, 256)?;
    let jws = object
        .get("signature")
        .and_then(|value| value.as_str())
        .ok_or_else(|| error("invalid_signature", "signature is required"))?;
    let key = directory.resolve(kid).ok_or_else(|| {
        error(
            "unknown_kid",
            "governance signing key is not in the key directory",
        )
    })?;

    let mut payload_object = object.clone();
    payload_object.remove("signature");
    let canonical =
        crate::provenance::canonicalize(&serde_json::Value::Object(payload_object.clone()))
            .map_err(|canonical_error| {
                error("invalid_governed_document", canonical_error.message)
            })?;

    // JWS compact verification with payload byte-match (§4 steps 1–5).
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(error(
            "malformed_jws",
            "signature must be a three-segment JWS compact serialization",
        ));
    }
    let header_raw = URL_SAFE_NO_PAD
        .decode(parts[0].as_bytes())
        .map_err(|_| error("malformed_jws", "protected header is not base64url"))?;
    let header: serde_json::Value = serde_json::from_slice(&header_raw)
        .map_err(|_| error("malformed_jws", "protected header is not JSON"))?;
    if header.get("alg").and_then(|value| value.as_str()) != Some("EdDSA") {
        return Err(error("unsupported_alg", "signature algorithm is not EdDSA"));
    }
    if header.get("kid").and_then(|value| value.as_str()) != Some(kid) {
        return Err(error(
            "unknown_kid",
            "protected-header kid does not match the document key id",
        ));
    }
    let payload_segment = URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .map_err(|_| error("malformed_jws", "payload is not base64url"))?;
    if payload_segment != canonical {
        return Err(error(
            "payload_mismatch",
            "signed payload does not byte-match the canonical document",
        ));
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map_err(|_| error("malformed_jws", "signature is not base64url"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| error("malformed_jws", "signature is not an Ed25519 signature"))?;
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .map_err(|_| {
            error(
                "signature_verification_failed",
                "governance signature does not verify the canonical document",
            )
        })?;
    Ok((
        payload_object,
        format!(
            "sha256:{}",
            crate::hex_lowercase(Sha256::digest(&canonical))
        ),
    ))
}

/// Sign a governed document payload (producer/governance tooling side; used
/// by tests and by the offline registry/policy authoring flow). The returned
/// document carries `signature_key_id` and `signature` fields.
pub fn sign_document(
    mut payload: serde_json::Map<String, serde_json::Value>,
    signer: &crate::provenance::ProvenanceSigner,
) -> Result<serde_json::Value, ValidationError> {
    payload.insert(
        "signature_key_id".to_owned(),
        serde_json::Value::String(signer.key_id().to_owned()),
    );
    let canonical = crate::provenance::canonicalize(&serde_json::Value::Object(payload.clone()))
        .map_err(|canonical_error| error("invalid_governed_document", canonical_error.message))?;
    let jws = signer.sign(&canonical);
    payload.insert("signature".to_owned(), serde_json::Value::String(jws));
    Ok(serde_json::Value::Object(payload))
}

/// One hazard zone of the signed registry. `polygon` is a WGS-84 ring
/// (boundary-inclusive containment via the `geo.rs` machinery);
/// `monitored_points` are where feeds are sampled for this zone.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HazardZone {
    pub zone_id: String,
    pub name: String,
    pub polygon: Vec<MonitoredPoint>,
    pub monitored_points: Vec<MonitoredPoint>,
    #[serde(default)]
    pub route_refs: Vec<String>,
}

impl HazardZone {
    /// The zone as a `geo::SafetyZone` for containment evaluation. Hazard
    /// zones are operational alerting geometry, classified `Restricted` so
    /// boundary positions count as inside (fail-closed for alerting).
    pub fn safety_zone(&self) -> Result<SafetyZone, ValidationError> {
        let mut vertices = Vec::with_capacity(self.polygon.len());
        for point in &self.polygon {
            vertices.push(point.position()?);
        }
        SafetyZone::new(self.zone_id.clone(), ZoneKind::Restricted, vertices)
    }
}

/// The verified hazard-zone registry.
#[derive(Clone, Debug)]
pub struct HazardZoneRegistry {
    pub registry_version: String,
    pub zones: Vec<HazardZone>,
    /// Digest binding of the signed registry document (`sha256:<hex>`).
    pub registry_digest_sha256: String,
}

impl HazardZoneRegistry {
    pub fn zone(&self, zone_id: &str) -> Option<&HazardZone> {
        self.zones.iter().find(|zone| zone.zone_id == zone_id)
    }

    /// Every zone containing `position` (zone matching reuses the geo
    /// boundary-inclusive containment test).
    pub fn zones_containing(
        &self,
        position: GeoPosition,
    ) -> Result<Vec<&HazardZone>, ValidationError> {
        let mut matched = Vec::new();
        for zone in &self.zones {
            if zone.safety_zone()?.contains(position) {
                matched.push(zone);
            }
        }
        Ok(matched)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHazardZoneRegistry {
    schema_version: String,
    registry_version: String,
    zones: Vec<HazardZone>,
}

/// Load and verify a signed hazard-zone registry document.
pub fn load_hazard_zone_registry(
    raw: &[u8],
    directory: &KeyDirectory,
) -> Result<HazardZoneRegistry, ValidationError> {
    let (mut payload, digest) =
        verify_signed_document(raw, HAZARD_ZONE_REGISTRY_SCHEMA_VERSION, directory)?;
    payload.remove("signature_key_id");
    let parsed: RawHazardZoneRegistry = serde_json::from_value(serde_json::Value::Object(payload))
        .map_err(|serde_error| error("invalid_registry", serde_error.to_string()))?;
    let _ = &parsed.schema_version;
    crate::validate_identifier("registry_version", &parsed.registry_version, 128)?;
    if parsed.zones.is_empty() || parsed.zones.len() > MAX_REGISTRY_ZONES {
        return Err(error(
            "invalid_registry",
            format!("registry must contain between 1 and {MAX_REGISTRY_ZONES} zones"),
        ));
    }
    for (index, zone) in parsed.zones.iter().enumerate() {
        crate::validate_identifier("zone.zone_id", &zone.zone_id, 128)?;
        crate::validate_identifier("zone.name", &zone.name, 256)?;
        if parsed.zones[..index]
            .iter()
            .any(|previous| previous.zone_id == zone.zone_id)
        {
            return Err(error("invalid_registry", "zone identifiers must be unique"));
        }
        if zone.polygon.len() < 3 || zone.polygon.len() > MAX_ZONE_VERTICES {
            return Err(error(
                "invalid_zone_geometry",
                format!("zone polygon must contain between 3 and {MAX_ZONE_VERTICES} vertices"),
            ));
        }
        if zone.monitored_points.is_empty()
            || zone.monitored_points.len() > MAX_MONITORED_POINTS_PER_ZONE
        {
            return Err(error(
                "invalid_registry",
                format!(
                    "zone must declare between 1 and {MAX_MONITORED_POINTS_PER_ZONE} monitored points"
                ),
            ));
        }
        if zone.route_refs.len() > MAX_ROUTE_REFS_PER_ZONE {
            return Err(error(
                "invalid_registry",
                format!("zone must declare at most {MAX_ROUTE_REFS_PER_ZONE} route references"),
            ));
        }
        for route_ref in &zone.route_refs {
            crate::validate_identifier("zone.route_refs", route_ref, 128)?;
        }
        let safety = zone.safety_zone()?;
        // Fail closed: a monitored point outside its zone would sample the
        // wrong water and issue advisories for geometry it does not cover.
        for point in &zone.monitored_points {
            if !safety.contains(point.position()?) {
                return Err(error(
                    "invalid_registry",
                    "monitored points must lie inside their zone polygon",
                ));
            }
        }
    }
    Ok(HazardZoneRegistry {
        registry_version: parsed.registry_version,
        zones: parsed.zones,
        registry_digest_sha256: digest,
    })
}

/// The threshold parameters the policy may govern. Free-text parameters are
/// prohibited; each maps to exactly one reading field.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdParam {
    WaveHeightM,
    SwellHeightM,
    SwellPeriodS,
    WindSpeedMs,
    WindGustMs,
}

impl ThresholdParam {
    pub fn phenomenon_code(&self) -> &'static str {
        match self {
            Self::WaveHeightM => "HIGH_SIGNIFICANT_WAVE_HEIGHT",
            Self::SwellHeightM => "HIGH_SWELL",
            Self::SwellPeriodS => "LONG_PERIOD_SWELL",
            Self::WindSpeedMs => "HIGH_WIND",
            Self::WindGustMs => "HIGH_WIND_GUST",
        }
    }

    pub fn value_of(&self, reading: &super::NormalizedReading) -> Option<f64> {
        match self {
            Self::WaveHeightM => reading.wave_height_m,
            Self::SwellHeightM => reading.swell_height_m,
            Self::SwellPeriodS => reading.swell_period_s,
            Self::WindSpeedMs => reading.wind_speed_ms,
            Self::WindGustMs => reading.wind_gust_ms,
        }
    }
}

/// One threshold rule: at or above `warn` the phenomenon warrants an
/// advisory (Moderate), at or above `severe` a Severe advisory, and — when
/// present — at or above `extreme` an Extreme advisory.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRule {
    pub param: ThresholdParam,
    pub warn: f64,
    pub severe: f64,
    #[serde(default)]
    pub extreme: Option<f64>,
    /// Advisory validity in minutes from issuance.
    pub duration_min: i64,
}

/// The verified advisory threshold policy.
#[derive(Clone, Debug)]
pub struct AdvisoryPolicy {
    pub policy_version: String,
    pub thresholds: Vec<ThresholdRule>,
    /// Digest binding of the signed policy document (`sha256:<hex>`).
    pub policy_digest_sha256: String,
}

impl AdvisoryPolicy {
    pub fn rule_for(&self, param: ThresholdParam) -> Option<&ThresholdRule> {
        self.thresholds.iter().find(|rule| rule.param == param)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAdvisoryPolicy {
    schema_version: String,
    policy_version: String,
    thresholds: Vec<ThresholdRule>,
}

/// Load and verify a signed advisory policy document.
pub fn load_advisory_policy(
    raw: &[u8],
    directory: &KeyDirectory,
) -> Result<AdvisoryPolicy, ValidationError> {
    let (mut payload, digest) =
        verify_signed_document(raw, ADVISORY_POLICY_SCHEMA_VERSION, directory)?;
    payload.remove("signature_key_id");
    let parsed: RawAdvisoryPolicy = serde_json::from_value(serde_json::Value::Object(payload))
        .map_err(|serde_error| error("invalid_policy", serde_error.to_string()))?;
    let _ = &parsed.schema_version;
    crate::validate_identifier("policy_version", &parsed.policy_version, 128)?;
    if parsed.thresholds.is_empty() || parsed.thresholds.len() > MAX_POLICY_THRESHOLDS {
        return Err(error(
            "invalid_policy",
            format!("policy must contain between 1 and {MAX_POLICY_THRESHOLDS} thresholds"),
        ));
    }
    for (index, rule) in parsed.thresholds.iter().enumerate() {
        if parsed.thresholds[..index]
            .iter()
            .any(|previous| previous.param == rule.param)
        {
            return Err(error(
                "invalid_policy",
                "threshold parameters must be unique",
            ));
        }
        let ordered = rule.warn.is_finite()
            && rule.severe.is_finite()
            && rule.warn > 0.0
            && rule.warn < rule.severe
            && rule
                .extreme
                .map(|extreme| extreme.is_finite() && extreme > rule.severe)
                .unwrap_or(true);
        if !ordered {
            return Err(error(
                "invalid_policy",
                "thresholds must satisfy 0 < warn < severe (< extreme)",
            ));
        }
        if rule.duration_min <= 0 || rule.duration_min > 10_080 {
            return Err(error(
                "invalid_policy",
                "threshold duration_min must be between 1 and 10080 minutes",
            ));
        }
    }
    Ok(AdvisoryPolicy {
        policy_version: parsed.policy_version,
        thresholds: parsed.thresholds,
        policy_digest_sha256: digest,
    })
}

/// The combined governance digest carried on every advisory
/// (`policy_digest_sha256`): binds the policy and registry versions applied.
pub fn combined_policy_digest(policy: &AdvisoryPolicy, registry: &HazardZoneRegistry) -> String {
    let mut digest = Sha256::new();
    digest.update(policy.policy_digest_sha256.as_bytes());
    digest.update([0]);
    digest.update(registry.registry_digest_sha256.as_bytes());
    format!("sha256:{}", crate::hex_lowercase(digest.finalize()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::provenance::ProvenanceSigner;
    use ed25519_dalek::SigningKey;

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

    pub(crate) fn zone_registry_payload() -> serde_json::Map<String, serde_json::Value> {
        serde_json::json!({
            "schema_version": HAZARD_ZONE_REGISTRY_SCHEMA_VERSION,
            "registry_version": "2026-08-30r1",
            "zones": [{
                "zone_id": "hz-lagos-approach",
                "name": "Lagos approach corridor",
                "polygon": [
                    {"latitude": 5.5, "longitude": 2.5},
                    {"latitude": 5.5, "longitude": 3.5},
                    {"latitude": 6.5, "longitude": 3.5},
                    {"latitude": 6.5, "longitude": 2.5}
                ],
                "monitored_points": [{"latitude": 6.0, "longitude": 3.0}],
                "route_refs": ["route-lagos-apapa-takwa"]
            }]
        })
        .as_object()
        .expect("object")
        .clone()
    }

    pub(crate) fn policy_payload() -> serde_json::Map<String, serde_json::Value> {
        serde_json::json!({
            "schema_version": ADVISORY_POLICY_SCHEMA_VERSION,
            "policy_version": "2026-08-30p1",
            "thresholds": [
                {"param": "wave_height_m", "warn": 2.5, "severe": 4.0, "extreme": 6.0, "duration_min": 180},
                {"param": "wind_speed_ms", "warn": 10.8, "severe": 17.2, "duration_min": 120},
                {"param": "wind_gust_ms", "warn": 15.0, "severe": 24.5, "duration_min": 120},
                {"param": "swell_height_m", "warn": 2.0, "severe": 3.5, "duration_min": 180}
            ]
        })
        .as_object()
        .expect("object")
        .clone()
    }

    pub(crate) fn signed_registry_and_policy() -> (HazardZoneRegistry, AdvisoryPolicy, KeyDirectory)
    {
        let (signer, directory) = governance();
        let registry_document = sign_document(zone_registry_payload(), &signer).expect("sign");
        let policy_document = sign_document(policy_payload(), &signer).expect("sign");
        let registry = load_hazard_zone_registry(
            serde_json::to_vec(&registry_document)
                .expect("encode")
                .as_slice(),
            &directory,
        )
        .expect("registry verifies");
        let policy = load_advisory_policy(
            serde_json::to_vec(&policy_document)
                .expect("encode")
                .as_slice(),
            &directory,
        )
        .expect("policy verifies");
        (registry, policy, directory)
    }

    #[test]
    fn signed_registry_and_policy_round_trip() {
        let (registry, policy, _) = signed_registry_and_policy();
        assert_eq!(registry.zones.len(), 1);
        assert!(registry.registry_digest_sha256.starts_with("sha256:"));
        assert!(policy.policy_digest_sha256.starts_with("sha256:"));
        let digest = combined_policy_digest(&policy, &registry);
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), 7 + 64);
        let zone = registry.zone("hz-lagos-approach").expect("zone");
        assert_eq!(zone.route_refs, vec!["route-lagos-apapa-takwa"]);
    }

    #[test]
    fn tampered_or_wrongly_signed_documents_fail_closed() {
        let (signer, directory) = governance();
        let document = sign_document(zone_registry_payload(), &signer).expect("sign");
        let raw = serde_json::to_vec(&document).expect("encode");
        // Tamper with the polygon after signing.
        let mut tampered = document.clone();
        tampered["zones"][0]["name"] = serde_json::json!("tampered");
        assert_eq!(
            load_hazard_zone_registry(
                serde_json::to_vec(&tampered).expect("encode").as_slice(),
                &directory
            )
            .unwrap_err()
            .code,
            "payload_mismatch"
        );
        // Unknown signing key.
        let other_signer = ProvenanceSigner::new("metocean-governance-2", &[24u8; 32]).expect("k");
        let forged = sign_document(zone_registry_payload(), &other_signer).expect("sign");
        assert_eq!(
            load_hazard_zone_registry(
                serde_json::to_vec(&forged).expect("encode").as_slice(),
                &directory
            )
            .unwrap_err()
            .code,
            "unknown_kid"
        );
        // Wrong schema version is rejected before signature work.
        let mut wrong_schema = zone_registry_payload();
        wrong_schema.insert(
            "schema_version".to_owned(),
            serde_json::json!("blueeconomy.waterway-safety.hazard-zone-registry.v0"),
        );
        let wrong = sign_document(wrong_schema, &signer).expect("sign");
        assert_eq!(
            load_hazard_zone_registry(
                serde_json::to_vec(&wrong).expect("encode").as_slice(),
                &directory
            )
            .unwrap_err()
            .code,
            "invalid_registry_schema"
        );
        let _ = raw;
    }

    #[test]
    fn monitored_points_must_lie_inside_the_zone() {
        let (signer, directory) = governance();
        let mut payload = zone_registry_payload();
        payload["zones"][0]["monitored_points"] =
            serde_json::json!([{"latitude": 8.0, "longitude": 3.0}]);
        let document = sign_document(payload, &signer).expect("sign");
        assert_eq!(
            load_hazard_zone_registry(
                serde_json::to_vec(&document).expect("encode").as_slice(),
                &directory
            )
            .unwrap_err()
            .code,
            "invalid_registry"
        );
    }

    #[test]
    fn policy_thresholds_must_be_ordered_and_unique() {
        let (signer, directory) = governance();
        let mut payload = policy_payload();
        payload["thresholds"][0]["warn"] = serde_json::json!(9.9);
        let document = sign_document(payload, &signer).expect("sign");
        assert_eq!(
            load_advisory_policy(
                serde_json::to_vec(&document).expect("encode").as_slice(),
                &directory
            )
            .unwrap_err()
            .code,
            "invalid_policy"
        );
        let mut duplicate = policy_payload();
        duplicate["thresholds"]
            .as_array_mut()
            .expect("array")
            .push(serde_json::json!({"param": "wave_height_m", "warn": 3.0, "severe": 5.0, "duration_min": 60}));
        let document = sign_document(duplicate, &signer).expect("sign");
        assert_eq!(
            load_advisory_policy(
                serde_json::to_vec(&document).expect("encode").as_slice(),
                &directory
            )
            .unwrap_err()
            .code,
            "invalid_policy"
        );
    }

    #[test]
    fn zone_matching_uses_geo_containment() {
        let (registry, _, _) = signed_registry_and_policy();
        let inside = GeoPosition::new(6.0, 3.0).expect("position");
        let outside = GeoPosition::new(7.5, 3.0).expect("position");
        let boundary = GeoPosition::new(5.5, 3.0).expect("position");
        assert_eq!(registry.zones_containing(inside).expect("match").len(), 1);
        assert!(registry
            .zones_containing(outside)
            .expect("match")
            .is_empty());
        // Boundary-inclusive (fail-closed for alerting).
        assert_eq!(registry.zones_containing(boundary).expect("match").len(), 1);
    }
}
