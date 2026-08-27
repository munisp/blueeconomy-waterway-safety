#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, FixedOffset};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter, Write};
use std::fs;
use std::path::Path;

pub mod geo;
pub mod ingest;
pub mod store;

pub const MAX_PAYLOAD_BYTES: usize = 1_048_576;
pub const MAX_JSON_BYTES: usize = 1_500_000;
const MAX_BASE64_BYTES: usize = ((MAX_PAYLOAD_BYTES + 2) / 3) * 4;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryFrame {
    pub device_id: String,
    pub gateway_id: String,
    pub source_sequence: u64,
    pub observed_at: String,
    pub received_at: String,
    pub data_classification: String,
    pub payload_base64: String,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TelemetryStreamCursor {
    pub device_id: String,
    pub gateway_id: String,
    pub last_source_sequence: u64,
    pub last_observed_at: String,
    pub last_received_at: String,
    pub last_batch_digest_sha256: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct TelemetryBatchEvidence {
    pub schema_version: String,
    pub device_id: String,
    pub gateway_id: String,
    pub first_source_sequence: u64,
    pub last_source_sequence: u64,
    pub first_observed_at: String,
    pub last_observed_at: String,
    pub records_validated: usize,
    pub batch_digest_sha256: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ValidatedTelemetry {
    pub device_id: String,
    pub gateway_id: String,
    pub source_sequence: u64,
    pub observed_at: String,
    pub received_at: String,
    pub data_classification: String,
    pub payload_sha256: String,
    pub payload_byte_count: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ValidationError {
    pub code: &'static str,
    pub message: String,
}

impl Display for ValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ValidationError {}

pub fn validate_json(input: &[u8]) -> Result<ValidatedTelemetry, ValidationError> {
    if input.is_empty() || input.len() > MAX_JSON_BYTES {
        return Err(ValidationError {
            code: "invalid_input_size",
            message: format!("telemetry JSON must contain between 1 and {MAX_JSON_BYTES} bytes"),
        });
    }
    let frame: TelemetryFrame = serde_json::from_slice(input).map_err(|error| ValidationError {
        code: "invalid_json",
        message: error.to_string(),
    })?;
    validate(frame)
}

pub fn validate_ordered_frames(
    frames: &[TelemetryFrame],
) -> Result<Vec<ValidatedTelemetry>, ValidationError> {
    if frames.is_empty() {
        return Err(ValidationError {
            code: "empty_telemetry_batch",
            message: "telemetry batch must contain at least one frame".to_owned(),
        });
    }
    let mut validated: Vec<ValidatedTelemetry> = Vec::with_capacity(frames.len());
    for frame in frames {
        let current = validate(frame.clone())?;
        if let Some(previous) = validated.last() {
            if current.device_id != previous.device_id || current.gateway_id != previous.gateway_id
            {
                return Err(ValidationError {
                    code: "telemetry_stream_identity_changed",
                    message: "ordered telemetry batch must use one device and gateway".to_owned(),
                });
            }
            if current.source_sequence != previous.source_sequence.saturating_add(1) {
                return Err(ValidationError {
                    code: "telemetry_sequence_gap",
                    message: "source_sequence must increase by exactly one".to_owned(),
                });
            }
            if current.observed_at < previous.observed_at
                || current.received_at < previous.received_at
            {
                return Err(ValidationError {
                    code: "telemetry_time_regression",
                    message: "observed_at and received_at must not regress".to_owned(),
                });
            }
        }
        validated.push(current);
    }
    Ok(validated)
}

pub fn validate_batch_evidence(
    frames: &[TelemetryFrame],
) -> Result<TelemetryBatchEvidence, ValidationError> {
    let validated = validate_ordered_frames(frames)?;
    let first = validated.first().ok_or_else(|| ValidationError {
        code: "empty_telemetry_batch",
        message: "telemetry batch must contain at least one frame".to_owned(),
    })?;
    let last = validated.last().ok_or_else(|| ValidationError {
        code: "empty_telemetry_batch",
        message: "telemetry batch must contain at least one frame".to_owned(),
    })?;
    let mut digest = Sha256::new();
    for record in &validated {
        digest.update(record.device_id.as_bytes());
        digest.update([0]);
        digest.update(record.gateway_id.as_bytes());
        digest.update([0]);
        digest.update(record.source_sequence.to_be_bytes());
        digest.update(record.observed_at.as_bytes());
        digest.update([0]);
        digest.update(record.received_at.as_bytes());
        digest.update([0]);
        digest.update(record.data_classification.as_bytes());
        digest.update([0]);
        digest.update(record.payload_sha256.as_bytes());
        digest.update([0]);
    }
    Ok(TelemetryBatchEvidence {
        schema_version: "blueeconomy.waterway-safety.batch-evidence.v1".to_owned(),
        device_id: first.device_id.clone(),
        gateway_id: first.gateway_id.clone(),
        first_source_sequence: first.source_sequence,
        last_source_sequence: last.source_sequence,
        first_observed_at: first.observed_at.clone(),
        last_observed_at: last.observed_at.clone(),
        records_validated: validated.len(),
        batch_digest_sha256: hex_lowercase(digest.finalize()),
    })
}

pub fn load_stream_cursor(path: &Path) -> Result<TelemetryStreamCursor, ValidationError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| ValidationError {
        code: "cursor_read_failed",
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ValidationError {
            code: "invalid_cursor_path",
            message: "cursor path must be a regular file and not a symbolic link".to_owned(),
        });
    }
    let raw = fs::read(path).map_err(|error| ValidationError {
        code: "cursor_read_failed",
        message: error.to_string(),
    })?;
    let cursor: TelemetryStreamCursor =
        serde_json::from_slice(&raw).map_err(|error| ValidationError {
            code: "invalid_cursor_json",
            message: error.to_string(),
        })?;
    validate_stream_cursor(&cursor)?;
    Ok(cursor)
}

fn validate_stream_cursor(cursor: &TelemetryStreamCursor) -> Result<(), ValidationError> {
    validate_identifier("cursor.device_id", &cursor.device_id, 256)?;
    validate_identifier("cursor.gateway_id", &cursor.gateway_id, 256)?;
    if cursor.last_source_sequence == 0 {
        return Err(ValidationError {
            code: "invalid_cursor_sequence",
            message: "cursor source sequence must be greater than zero".to_owned(),
        });
    }
    validate_timestamp("cursor.last_observed_at", &cursor.last_observed_at)?;
    validate_timestamp("cursor.last_received_at", &cursor.last_received_at)?;
    validate_sha256(&cursor.last_batch_digest_sha256)?;
    Ok(())
}

pub fn save_stream_cursor(
    path: &Path,
    cursor: &TelemetryStreamCursor,
) -> Result<(), ValidationError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| ValidationError {
            code: "cursor_write_failed",
            message: error.to_string(),
        })?;
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ValidationError {
                code: "invalid_cursor_path",
                message: "cursor path must be a regular file and not a symbolic link".to_owned(),
            });
        }
    }
    let encoded = serde_json::to_vec(cursor).map_err(|error| ValidationError {
        code: "cursor_encode_failed",
        message: error.to_string(),
    })?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, encoded).map_err(|error| ValidationError {
        code: "cursor_write_failed",
        message: error.to_string(),
    })?;
    fs::rename(&temporary, path).map_err(|error| ValidationError {
        code: "cursor_write_failed",
        message: error.to_string(),
    })?;
    Ok(())
}

pub fn validate_continuation(
    cursor: &TelemetryStreamCursor,
    frames: &[TelemetryFrame],
) -> Result<(TelemetryBatchEvidence, TelemetryStreamCursor), ValidationError> {
    let evidence = validate_batch_evidence(frames)?;
    if evidence.device_id != cursor.device_id || evidence.gateway_id != cursor.gateway_id {
        return Err(ValidationError {
            code: "telemetry_cursor_identity_changed",
            message: "continuation must use the cursor device and gateway".to_owned(),
        });
    }
    if evidence.first_source_sequence != cursor.last_source_sequence.saturating_add(1) {
        return Err(ValidationError {
            code: "telemetry_cursor_sequence_gap",
            message: "continuation must start at the next source sequence".to_owned(),
        });
    }
    let first_received_at = frames
        .first()
        .ok_or_else(|| ValidationError {
            code: "empty_telemetry_batch",
            message: "telemetry batch must contain at least one frame".to_owned(),
        })?
        .received_at
        .as_str();
    if validate_timestamp("first_observed_at", &evidence.first_observed_at)?
        < validate_timestamp("last_observed_at", &cursor.last_observed_at)?
        || validate_timestamp("first_received_at", first_received_at)?
            < validate_timestamp("last_received_at", &cursor.last_received_at)?
    {
        return Err(ValidationError {
            code: "telemetry_cursor_time_regression",
            message: "continuation timestamps must not regress".to_owned(),
        });
    }
    let next = TelemetryStreamCursor {
        device_id: evidence.device_id.clone(),
        gateway_id: evidence.gateway_id.clone(),
        last_source_sequence: evidence.last_source_sequence,
        last_observed_at: evidence.last_observed_at.clone(),
        last_received_at: frames
            .last()
            .ok_or_else(|| ValidationError {
                code: "empty_telemetry_batch",
                message: "telemetry batch must contain at least one frame".to_owned(),
            })?
            .received_at
            .clone(),
        last_batch_digest_sha256: evidence.batch_digest_sha256.clone(),
    };
    Ok((evidence, next))
}

pub fn validate(frame: TelemetryFrame) -> Result<ValidatedTelemetry, ValidationError> {
    validate_identifier("device_id", &frame.device_id, 256)?;
    if frame.source_sequence == 0 {
        return Err(ValidationError {
            code: "invalid_source_sequence",
            message: "source_sequence must be greater than zero".to_owned(),
        });
    }
    validate_identifier("gateway_id", &frame.gateway_id, 256)?;
    let observed_at = validate_timestamp("observed_at", &frame.observed_at)?;
    let received_at = validate_timestamp("received_at", &frame.received_at)?;
    if observed_at > received_at {
        return Err(ValidationError {
            code: "invalid_timestamp_order",
            message: "observed_at must not be later than received_at".to_owned(),
        });
    }
    validate_classification(&frame.data_classification)?;
    validate_sha256(&frame.payload_sha256)?;
    if frame.payload_base64.len() > MAX_BASE64_BYTES {
        return Err(ValidationError {
            code: "payload_too_large",
            message: format!(
                "encoded payload exceeds the limit for {MAX_PAYLOAD_BYTES} decoded bytes"
            ),
        });
    }

    let payload = STANDARD
        .decode(frame.payload_base64.as_bytes())
        .map_err(|error| ValidationError {
            code: "invalid_payload_encoding",
            message: error.to_string(),
        })?;
    if payload.is_empty() {
        return Err(ValidationError {
            code: "empty_payload",
            message: "payload_base64 decodes to zero bytes".to_owned(),
        });
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ValidationError {
            code: "payload_too_large",
            message: format!("payload exceeds {MAX_PAYLOAD_BYTES} bytes"),
        });
    }

    let observed_digest = hex_lowercase(Sha256::digest(&payload));
    if observed_digest != frame.payload_sha256 {
        return Err(ValidationError {
            code: "payload_digest_mismatch",
            message: "calculated SHA-256 does not equal payload_sha256".to_owned(),
        });
    }

    Ok(ValidatedTelemetry {
        device_id: frame.device_id,
        gateway_id: frame.gateway_id,
        source_sequence: frame.source_sequence,
        observed_at: frame.observed_at,
        received_at: frame.received_at,
        data_classification: frame.data_classification,
        payload_sha256: observed_digest,
        payload_byte_count: payload.len(),
    })
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    limit: usize,
) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > limit
        || value != value.trim()
        || value.chars().any(char::is_control)
    {
        return Err(ValidationError {
            code: "invalid_identifier",
            message: format!(
                "{field} must be canonical non-control text between 1 and {limit} bytes"
            ),
        });
    }
    Ok(())
}

fn validate_timestamp(
    field: &'static str,
    value: &str,
) -> Result<DateTime<FixedOffset>, ValidationError> {
    DateTime::parse_from_rfc3339(value).map_err(|error| ValidationError {
        code: "invalid_timestamp",
        message: format!("{field}: {error}"),
    })
}

fn validate_classification(value: &str) -> Result<(), ValidationError> {
    match value {
        "public" | "internal" | "confidential" | "restricted" | "highly_restricted" => Ok(()),
        _ => Err(ValidationError {
            code: "invalid_classification",
            message: "data_classification is not an approved value".to_owned(),
        }),
    }
}

fn validate_sha256(value: &str) -> Result<(), ValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ValidationError {
            code: "invalid_digest",
            message: "payload_sha256 must be a lower-case 64-character hexadecimal SHA-256 digest"
                .to_owned(),
        });
    }
    Ok(())
}

fn hex_lowercase(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

pub const MAX_DEVICE_REGISTRY_BYTES: usize = 4_194_304;
pub const MAX_DEVICE_REGISTRY_ENTRIES: usize = 10_000;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTelemetryFrame {
    pub frame: TelemetryFrame,
    pub signature_key_id: String,
    pub signature_base64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistry {
    pub schema_version: String,
    pub registry_version: String,
    pub devices: Vec<DeviceRegistryEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistryEntry {
    pub device_id: String,
    pub gateway_id: String,
    pub key_id: String,
    pub public_key_base64: String,
    pub status: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ValidatedSignedTelemetry {
    pub schema_version: String,
    pub registry_version: String,
    pub device_id: String,
    pub gateway_id: String,
    pub source_sequence: u64,
    pub observed_at: String,
    pub received_at: String,
    pub data_classification: String,
    pub payload_sha256: String,
    pub payload_byte_count: usize,
    pub signature_key_id: String,
}

pub fn validate_signed_json(
    input: &[u8],
    registry: &DeviceRegistry,
) -> Result<ValidatedSignedTelemetry, ValidationError> {
    if input.is_empty() || input.len() > MAX_JSON_BYTES {
        return Err(ValidationError {
            code: "invalid_input_size",
            message: format!(
                "signed telemetry JSON must contain between 1 and {MAX_JSON_BYTES} bytes"
            ),
        });
    }
    let frame: SignedTelemetryFrame =
        serde_json::from_slice(input).map_err(|error| ValidationError {
            code: "invalid_json",
            message: error.to_string(),
        })?;
    validate_signed_frame(frame, registry)
}

pub fn load_device_registry(path: &Path) -> Result<DeviceRegistry, ValidationError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| ValidationError {
        code: "registry_read_failed",
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ValidationError {
            code: "invalid_registry_path",
            message: "device registry path must be a regular file and not a symbolic link"
                .to_owned(),
        });
    }
    if metadata.len() == 0 || metadata.len() > MAX_DEVICE_REGISTRY_BYTES as u64 {
        return Err(ValidationError {
            code: "invalid_registry_size",
            message: format!(
                "device registry must contain between 1 and {MAX_DEVICE_REGISTRY_BYTES} bytes"
            ),
        });
    }
    let raw = fs::read(path).map_err(|error| ValidationError {
        code: "registry_read_failed",
        message: error.to_string(),
    })?;
    let registry: DeviceRegistry =
        serde_json::from_slice(&raw).map_err(|error| ValidationError {
            code: "invalid_registry_json",
            message: error.to_string(),
        })?;
    validate_device_registry(&registry)?;
    Ok(registry)
}

pub fn validate_signed_frame(
    frame: SignedTelemetryFrame,
    registry: &DeviceRegistry,
) -> Result<ValidatedSignedTelemetry, ValidationError> {
    validate_device_registry(registry)?;
    let validated = validate(frame.frame.clone())?;
    validate_identifier("signature_key_id", &frame.signature_key_id, 256)?;
    let entry = registry
        .devices
        .iter()
        .find(|candidate| {
            candidate.device_id == validated.device_id
                && candidate.gateway_id == validated.gateway_id
                && candidate.key_id == frame.signature_key_id
        })
        .ok_or_else(|| ValidationError {
            code: "unknown_device_key",
            message: "device, gateway, and signing key are not registered together".to_owned(),
        })?;
    if entry.status != "active" {
        return Err(ValidationError {
            code: "device_not_active",
            message: "registered device signing key is not active".to_owned(),
        });
    }
    let public_key = decode_verifying_key(&entry.public_key_base64)?;
    let signature_bytes = STANDARD
        .decode(frame.signature_base64.as_bytes())
        .map_err(|error| ValidationError {
            code: "invalid_signature_encoding",
            message: error.to_string(),
        })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|error| ValidationError {
        code: "invalid_signature",
        message: error.to_string(),
    })?;
    let preimage = signed_telemetry_preimage(&frame.frame, &frame.signature_key_id)?;
    public_key
        .verify(&preimage, &signature)
        .map_err(|_| ValidationError {
            code: "signature_verification_failed",
            message: "Ed25519 signature does not verify the canonical telemetry preimage"
                .to_owned(),
        })?;
    Ok(ValidatedSignedTelemetry {
        schema_version: "blueeconomy.waterway-safety.signed-telemetry.v1".to_owned(),
        registry_version: registry.registry_version.clone(),
        device_id: validated.device_id,
        gateway_id: validated.gateway_id,
        source_sequence: validated.source_sequence,
        observed_at: validated.observed_at,
        received_at: validated.received_at,
        data_classification: validated.data_classification,
        payload_sha256: validated.payload_sha256,
        payload_byte_count: validated.payload_byte_count,
        signature_key_id: frame.signature_key_id,
    })
}

pub fn validate_signed_continuation(
    cursor: &TelemetryStreamCursor,
    frame: SignedTelemetryFrame,
    registry: &DeviceRegistry,
) -> Result<(ValidatedSignedTelemetry, TelemetryStreamCursor), ValidationError> {
    let validated = validate_signed_frame(frame.clone(), registry)?;
    let (_, next) = validate_continuation(cursor, &[frame.frame])?;
    Ok((validated, next))
}

pub fn signed_telemetry_preimage(
    frame: &TelemetryFrame,
    signature_key_id: &str,
) -> Result<Vec<u8>, ValidationError> {
    validate_identifier("signature_key_id", signature_key_id, 256)?;
    validate_identifier("device_id", &frame.device_id, 256)?;
    validate_identifier("gateway_id", &frame.gateway_id, 256)?;
    validate_timestamp("observed_at", &frame.observed_at)?;
    validate_timestamp("received_at", &frame.received_at)?;
    validate_classification(&frame.data_classification)?;
    validate_sha256(&frame.payload_sha256)?;
    let fields = [
        "blueeconomy.waterway-safety.signed-telemetry.v1",
        signature_key_id,
        frame.device_id.as_str(),
        frame.gateway_id.as_str(),
        frame.observed_at.as_str(),
        frame.received_at.as_str(),
        frame.data_classification.as_str(),
        frame.payload_sha256.as_str(),
    ];
    let mut preimage = Vec::with_capacity(
        fields.iter().map(|field| field.len() + 1).sum::<usize>() + std::mem::size_of::<u64>(),
    );
    for field in fields {
        preimage.extend_from_slice(field.as_bytes());
        preimage.push(0);
    }
    preimage.extend_from_slice(&frame.source_sequence.to_be_bytes());
    Ok(preimage)
}

fn validate_device_registry(registry: &DeviceRegistry) -> Result<(), ValidationError> {
    if registry.schema_version != "blueeconomy.waterway-safety.device-registry.v1" {
        return Err(ValidationError {
            code: "invalid_registry_schema",
            message: "device registry schema_version is not supported".to_owned(),
        });
    }
    validate_identifier("registry_version", &registry.registry_version, 256)?;
    if registry.devices.is_empty() || registry.devices.len() > MAX_DEVICE_REGISTRY_ENTRIES {
        return Err(ValidationError {
            code: "invalid_registry_entries",
            message: format!(
                "device registry must contain between 1 and {MAX_DEVICE_REGISTRY_ENTRIES} entries"
            ),
        });
    }
    for (index, entry) in registry.devices.iter().enumerate() {
        validate_identifier("registry.device_id", &entry.device_id, 256)?;
        validate_identifier("registry.gateway_id", &entry.gateway_id, 256)?;
        validate_identifier("registry.key_id", &entry.key_id, 256)?;
        if !matches!(entry.status.as_str(), "active" | "suspended" | "revoked") {
            return Err(ValidationError {
                code: "invalid_device_status",
                message: "device registry status must be active, suspended, or revoked".to_owned(),
            });
        }
        decode_verifying_key(&entry.public_key_base64)?;
        if registry.devices[..index].iter().any(|previous| {
            previous.device_id == entry.device_id
                && previous.gateway_id == entry.gateway_id
                && previous.key_id == entry.key_id
        }) {
            return Err(ValidationError {
                code: "duplicate_device_key",
                message: "device registry has a duplicate device, gateway, and key identifier"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

fn decode_verifying_key(value: &str) -> Result<VerifyingKey, ValidationError> {
    let bytes = STANDARD
        .decode(value.as_bytes())
        .map_err(|error| ValidationError {
            code: "invalid_public_key_encoding",
            message: error.to_string(),
        })?;
    let encoded: [u8; 32] = bytes.try_into().map_err(|_| ValidationError {
        code: "invalid_public_key_length",
        message: "Ed25519 public key must contain exactly 32 bytes".to_owned(),
    })?;
    VerifyingKey::from_bytes(&encoded).map_err(|error| ValidationError {
        code: "invalid_public_key",
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_frame() -> TelemetryFrame {
        TelemetryFrame {
            device_id: "device-001".to_owned(),
            gateway_id: "gateway-001".to_owned(),
            source_sequence: 1,
            observed_at: "2026-08-12T00:00:00Z".to_owned(),
            received_at: "2026-08-12T00:00:01Z".to_owned(),
            data_classification: "internal".to_owned(),
            payload_base64: "Ynl0ZXM=".to_owned(),
            payload_sha256: hex_lowercase(Sha256::digest(b"bytes")),
        }
    }

    #[test]
    fn accepts_valid_frame_without_exposing_payload() {
        let result = validate(valid_frame()).expect("valid frame should pass");
        assert_eq!(result.payload_byte_count, 5);
        assert_eq!(result.device_id, "device-001");
    }

    #[test]
    fn rejects_digest_that_does_not_match_decoded_bytes() {
        let mut frame = valid_frame();
        frame.payload_sha256 =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        assert_eq!(validate(frame).unwrap_err().code, "payload_digest_mismatch");
    }

    #[test]
    fn rejects_non_hexadecimal_digest() {
        let mut frame = valid_frame();
        frame.payload_sha256 =
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg".to_owned();
        assert_eq!(validate(frame).unwrap_err().code, "invalid_digest");
    }

    #[test]
    fn rejects_unknown_classification() {
        let mut frame = valid_frame();
        frame.data_classification = "undeclared".to_owned();
        assert_eq!(validate(frame).unwrap_err().code, "invalid_classification");
    }

    #[test]
    fn rejects_noncanonical_identifier() {
        let mut frame = valid_frame();
        frame.device_id = " device-001".to_owned();
        assert_eq!(validate(frame).unwrap_err().code, "invalid_identifier");
    }

    #[test]
    fn rejects_observation_after_receipt() {
        let mut frame = valid_frame();
        frame.observed_at = "2026-08-12T00:00:02Z".to_owned();
        assert_eq!(validate(frame).unwrap_err().code, "invalid_timestamp_order");
    }

    #[test]
    fn rejects_oversized_json_before_deserialization() {
        let input = vec![b' '; MAX_JSON_BYTES + 1];
        assert_eq!(
            validate_json(&input).unwrap_err().code,
            "invalid_input_size"
        );
    }

    #[test]
    fn rejects_unknown_json_field() {
        let input = br#"{"device_id":"device-001","gateway_id":"gateway-001","source_sequence":1,"observed_at":"2026-08-12T00:00:00Z","received_at":"2026-08-12T00:00:01Z","data_classification":"internal","payload_base64":"Ynl0ZXM=","payload_sha256":"277089d91c0bdf4f2e6862ba7e4a07605119431f9b16585ad4a9603d98d75a44","undeclared":true}"#;
        assert_eq!(validate_json(input).unwrap_err().code, "invalid_json");
    }

    #[test]
    fn accepts_ordered_telemetry_frames() {
        let first = valid_frame();
        let mut second = valid_frame();
        second.source_sequence = 2;
        second.observed_at = "2026-08-12T00:00:02Z".to_owned();
        second.received_at = "2026-08-12T00:00:03Z".to_owned();
        let result = validate_ordered_frames(&[first, second]).expect("ordered frames should pass");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn emits_hash_bound_batch_evidence_for_ordered_telemetry() {
        let first = valid_frame();
        let mut second = valid_frame();
        second.source_sequence = 2;
        second.observed_at = "2026-08-12T00:00:02Z".to_owned();
        second.received_at = "2026-08-12T00:00:03Z".to_owned();
        let evidence = validate_batch_evidence(&[first.clone(), second.clone()])
            .expect("batch should validate");
        assert_eq!(evidence.records_validated, 2);
        assert_eq!(evidence.first_source_sequence, 1);
        assert_eq!(evidence.last_source_sequence, 2);
        assert_eq!(
            evidence.schema_version,
            "blueeconomy.waterway-safety.batch-evidence.v1"
        );
        assert_eq!(evidence.batch_digest_sha256.len(), 64);
        assert_eq!(
            evidence,
            validate_batch_evidence(&[first, second]).expect("same batch should be deterministic")
        );
    }

    #[test]
    fn accepts_next_batch_from_stream_cursor() {
        let first = valid_frame();
        let first_evidence =
            validate_batch_evidence(&[first.clone()]).expect("first batch should validate");
        let cursor = TelemetryStreamCursor {
            device_id: first_evidence.device_id,
            gateway_id: first_evidence.gateway_id,
            last_source_sequence: first_evidence.last_source_sequence,
            last_observed_at: first_evidence.last_observed_at,
            last_received_at: first.received_at,
            last_batch_digest_sha256: first_evidence.batch_digest_sha256,
        };
        let mut second = valid_frame();
        second.source_sequence = 2;
        second.observed_at = "2026-08-12T00:00:02Z".to_owned();
        second.received_at = "2026-08-12T00:00:03Z".to_owned();
        let (_, next) =
            validate_continuation(&cursor, &[second]).expect("next batch should validate");
        assert_eq!(next.last_source_sequence, 2);
    }

    #[test]
    fn persists_and_reloads_stream_cursor() {
        let first = valid_frame();
        let evidence = validate_batch_evidence(&[first.clone()]).expect("batch should validate");
        let cursor = TelemetryStreamCursor {
            device_id: evidence.device_id,
            gateway_id: evidence.gateway_id,
            last_source_sequence: evidence.last_source_sequence,
            last_observed_at: evidence.last_observed_at,
            last_received_at: first.received_at,
            last_batch_digest_sha256: evidence.batch_digest_sha256,
        };
        let path = std::env::temp_dir().join(format!(
            "blueeconomy-cursor-{}-{}.json",
            std::process::id(),
            cursor.last_source_sequence
        ));
        save_stream_cursor(&path, &cursor).expect("cursor should persist");
        assert_eq!(
            load_stream_cursor(&path).expect("cursor should reload"),
            cursor
        );
        std::fs::remove_file(path).expect("cursor should be removable");
    }

    #[test]
    fn rejects_replayed_batch_from_stream_cursor() {
        let first = valid_frame();
        let first_evidence =
            validate_batch_evidence(&[first.clone()]).expect("first batch should validate");
        let cursor = TelemetryStreamCursor {
            device_id: first_evidence.device_id,
            gateway_id: first_evidence.gateway_id,
            last_source_sequence: first_evidence.last_source_sequence,
            last_observed_at: first_evidence.last_observed_at,
            last_received_at: first.received_at,
            last_batch_digest_sha256: first_evidence.batch_digest_sha256,
        };
        let replay = valid_frame();
        assert_eq!(
            validate_continuation(&cursor, &[replay]).unwrap_err().code,
            "telemetry_cursor_sequence_gap"
        );
    }

    #[test]
    fn rejects_ordered_telemetry_sequence_gap() {
        let first = valid_frame();
        let mut second = valid_frame();
        second.source_sequence = 3;
        assert_eq!(
            validate_ordered_frames(&[first, second]).unwrap_err().code,
            "telemetry_sequence_gap"
        );
    }

    #[test]
    fn rejects_ordered_telemetry_identity_change() {
        let first = valid_frame();
        let mut second = valid_frame();
        second.source_sequence = 2;
        second.device_id = "device-002".to_owned();
        assert_eq!(
            validate_ordered_frames(&[first, second]).unwrap_err().code,
            "telemetry_stream_identity_changed"
        );
    }

    #[test]
    fn rejects_zero_source_sequence() {
        let mut frame = valid_frame();
        frame.source_sequence = 0;
        assert_eq!(validate(frame).unwrap_err().code, "invalid_source_sequence");
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyRulePolicy {
    pub policy_version: String,
    pub max_batch_records: usize,
    pub allowed_classifications: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SafetyRuleEvaluation {
    pub policy_version: String,
    pub decision: String,
    pub reasons: Vec<String>,
    pub batch_digest_sha256: String,
}

pub fn evaluate_safety_policy(
    policy: &SafetyRulePolicy,
    frames: &[TelemetryFrame],
) -> Result<SafetyRuleEvaluation, ValidationError> {
    if policy.policy_version.trim().is_empty() || policy.policy_version.len() > 128 {
        return Err(ValidationError {
            code: "invalid_policy_version",
            message: "policy_version must be nonempty and at most 128 bytes".to_owned(),
        });
    }
    if policy.max_batch_records == 0 || policy.allowed_classifications.is_empty() {
        return Err(ValidationError {
            code: "invalid_safety_policy",
            message: "policy must define positive max_batch_records and allowed classifications"
                .to_owned(),
        });
    }
    let evidence = validate_batch_evidence(frames)?;
    let mut reasons = Vec::new();
    if evidence.records_validated > policy.max_batch_records {
        reasons.push("batch_record_limit_exceeded".to_owned());
    }
    for frame in frames {
        if !policy
            .allowed_classifications
            .iter()
            .any(|value| value == &frame.data_classification)
        {
            reasons.push("classification_not_allowed".to_owned());
            break;
        }
    }
    Ok(SafetyRuleEvaluation {
        policy_version: policy.policy_version.clone(),
        decision: if reasons.is_empty() {
            "ACCEPT".to_owned()
        } else {
            "REJECT".to_owned()
        },
        reasons,
        batch_digest_sha256: evidence.batch_digest_sha256,
    })
}

#[cfg(test)]
mod safety_policy_tests {
    use super::*;
    fn frame() -> TelemetryFrame {
        TelemetryFrame {
            device_id: "device-001".to_owned(),
            gateway_id: "gateway-001".to_owned(),
            source_sequence: 1,
            observed_at: "2026-08-12T00:00:00Z".to_owned(),
            received_at: "2026-08-12T00:00:01Z".to_owned(),
            data_classification: "internal".to_owned(),
            payload_base64: "Ynl0ZXM=".to_owned(),
            payload_sha256: hex_lowercase(Sha256::digest(b"bytes")),
        }
    }
    #[test]
    fn evaluates_versioned_policy_without_embedded_thresholds() {
        let policy = SafetyRulePolicy {
            policy_version: "ministry-policy-v1".to_owned(),
            max_batch_records: 1,
            allowed_classifications: vec!["internal".to_owned()],
        };
        let result = evaluate_safety_policy(&policy, &[frame()]).expect("valid policy evaluation");
        assert_eq!(result.decision, "ACCEPT");
        assert_eq!(result.policy_version, "ministry-policy-v1");
    }
    #[test]
    fn rejects_policy_violations_deterministically() {
        let policy = SafetyRulePolicy {
            policy_version: "ministry-policy-v1".to_owned(),
            max_batch_records: 1,
            allowed_classifications: vec!["restricted".to_owned()],
        };
        let result = evaluate_safety_policy(&policy, &[frame()]).expect("valid evidence");
        assert_eq!(result.decision, "REJECT");
        assert_eq!(result.reasons, vec!["classification_not_allowed"]);
    }
}

#[cfg(test)]
mod signed_telemetry_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn telemetry_frame(sequence: u64) -> TelemetryFrame {
        TelemetryFrame {
            device_id: "device-signed-001".to_owned(),
            gateway_id: "gateway-signed-001".to_owned(),
            source_sequence: sequence,
            observed_at: if sequence == 1 {
                "2026-08-21T00:00:00Z".to_owned()
            } else {
                "2026-08-21T00:00:02Z".to_owned()
            },
            received_at: if sequence == 1 {
                "2026-08-21T00:00:01Z".to_owned()
            } else {
                "2026-08-21T00:00:03Z".to_owned()
            },
            data_classification: "internal".to_owned(),
            payload_base64: "Ynl0ZXM=".to_owned(),
            payload_sha256: hex_lowercase(Sha256::digest(b"bytes")),
        }
    }

    fn signed_fixture(sequence: u64, status: &str) -> (SignedTelemetryFrame, DeviceRegistry) {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let frame = telemetry_frame(sequence);
        let key_id = "device-key-2026-01".to_owned();
        let preimage = signed_telemetry_preimage(&frame, &key_id).expect("fixture preimage");
        let signature = signing_key.sign(&preimage);
        let signed = SignedTelemetryFrame {
            frame: frame.clone(),
            signature_key_id: key_id.clone(),
            signature_base64: STANDARD.encode(signature.to_bytes()),
        };
        let registry = DeviceRegistry {
            schema_version: "blueeconomy.waterway-safety.device-registry.v1".to_owned(),
            registry_version: "local-fixture-v1".to_owned(),
            devices: vec![DeviceRegistryEntry {
                device_id: frame.device_id,
                gateway_id: frame.gateway_id,
                key_id,
                public_key_base64: STANDARD.encode(signing_key.verifying_key().as_bytes()),
                status: status.to_owned(),
            }],
        };
        (signed, registry)
    }

    #[test]
    fn accepts_active_registered_ed25519_signed_telemetry() {
        let (signed, registry) = signed_fixture(1, "active");
        let validated = validate_signed_frame(signed, &registry).expect("signed fixture is valid");
        assert_eq!(
            validated.schema_version,
            "blueeconomy.waterway-safety.signed-telemetry.v1"
        );
        assert_eq!(validated.registry_version, "local-fixture-v1");
        assert_eq!(validated.source_sequence, 1);
        assert_eq!(validated.signature_key_id, "device-key-2026-01");
    }

    #[test]
    fn rejects_suspended_or_revoked_device_keys() {
        for status in ["suspended", "revoked"] {
            let (signed, registry) = signed_fixture(1, status);
            assert_eq!(
                validate_signed_frame(signed, &registry).unwrap_err().code,
                "device_not_active"
            );
        }
    }

    #[test]
    fn rejects_signature_after_sequence_tampering() {
        let (mut signed, registry) = signed_fixture(1, "active");
        signed.frame.source_sequence = 2;
        assert_eq!(
            validate_signed_frame(signed, &registry).unwrap_err().code,
            "signature_verification_failed"
        );
    }

    #[test]
    fn rejects_unregistered_signing_key() {
        let (mut signed, registry) = signed_fixture(1, "active");
        signed.signature_key_id = "unregistered-key".to_owned();
        assert_eq!(
            validate_signed_frame(signed, &registry).unwrap_err().code,
            "unknown_device_key"
        );
    }

    #[test]
    fn validates_signed_cursor_continuation_without_replay() {
        let (first, registry) = signed_fixture(1, "active");
        let first_validated =
            validate_signed_frame(first.clone(), &registry).expect("first signed frame");
        let cursor = TelemetryStreamCursor {
            device_id: first_validated.device_id,
            gateway_id: first_validated.gateway_id,
            last_source_sequence: first_validated.source_sequence,
            last_observed_at: first_validated.observed_at,
            last_received_at: first_validated.received_at,
            last_batch_digest_sha256: validate_batch_evidence(&[first.frame])
                .expect("first evidence")
                .batch_digest_sha256,
        };
        let (second, _) = signed_fixture(2, "active");
        let (_, next) = validate_signed_continuation(&cursor, second, &registry)
            .expect("next signed frame should continue the cursor");
        assert_eq!(next.last_source_sequence, 2);
    }
}

#[cfg(test)]
mod signed_registry_loading_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use std::path::PathBuf;

    fn temporary_registry_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blueeconomy-waterway-safety-{label}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ))
    }

    fn signed_registry_document(status: &str, schema_version: &str) -> (Vec<u8>, Vec<u8>) {
        let signing_key = SigningKey::from_bytes(&[19_u8; 32]);
        let frame = TelemetryFrame {
            device_id: "device-registry-001".to_owned(),
            gateway_id: "gateway-registry-001".to_owned(),
            source_sequence: 4,
            observed_at: "2026-08-21T00:00:00Z".to_owned(),
            received_at: "2026-08-21T00:00:01Z".to_owned(),
            data_classification: "internal".to_owned(),
            payload_base64: "Ynl0ZXM=".to_owned(),
            payload_sha256: hex_lowercase(Sha256::digest(b"bytes")),
        };
        let key_id = "registry-file-key-v1";
        let signature =
            signing_key.sign(&signed_telemetry_preimage(&frame, key_id).expect("fixture preimage"));
        let registry = serde_json::json!({
            "schema_version": schema_version,
            "registry_version": "registry-file-fixture-v1",
            "devices": [{
                "device_id": frame.device_id,
                "gateway_id": frame.gateway_id,
                "key_id": key_id,
                "public_key_base64": STANDARD.encode(signing_key.verifying_key().as_bytes()),
                "status": status
            }]
        });
        let signed = serde_json::json!({
            "frame": {
                "device_id": "device-registry-001",
                "gateway_id": "gateway-registry-001",
                "source_sequence": 4,
                "observed_at": "2026-08-21T00:00:00Z",
                "received_at": "2026-08-21T00:00:01Z",
                "data_classification": "internal",
                "payload_base64": "Ynl0ZXM=",
                "payload_sha256": hex_lowercase(Sha256::digest(b"bytes"))
            },
            "signature_key_id": key_id,
            "signature_base64": STANDARD.encode(signature.to_bytes())
        });
        (
            serde_json::to_vec(&registry).expect("encode registry fixture"),
            serde_json::to_vec(&signed).expect("encode signed fixture"),
        )
    }

    #[test]
    fn loads_registry_file_and_validates_serialized_signed_input() {
        let (registry_document, signed_document) =
            signed_registry_document("active", "blueeconomy.waterway-safety.device-registry.v1");
        let path = temporary_registry_path("load");
        fs::write(&path, registry_document).expect("write registry fixture");
        let registry = load_device_registry(&path).expect("load valid registry fixture");
        let result =
            validate_signed_json(&signed_document, &registry).expect("signed document passes");
        assert_eq!(result.source_sequence, 4);
        fs::remove_file(path).expect("remove registry fixture");
    }

    #[test]
    fn rejects_unsupported_registry_schema_before_signature_validation() {
        let (registry_document, _) = signed_registry_document("active", "unsupported-registry-v1");
        let path = temporary_registry_path("schema");
        fs::write(&path, registry_document).expect("write registry fixture");
        assert_eq!(
            load_device_registry(&path).unwrap_err().code,
            "invalid_registry_schema"
        );
        fs::remove_file(path).expect("remove registry fixture");
    }

    #[test]
    fn rejects_duplicate_registry_key_tuple() {
        let (registry_document, signed_document) =
            signed_registry_document("active", "blueeconomy.waterway-safety.device-registry.v1");
        let registry: DeviceRegistry =
            serde_json::from_slice(&registry_document).expect("fixture registry");
        let signed: SignedTelemetryFrame =
            serde_json::from_slice(&signed_document).expect("fixture signed telemetry");
        let duplicate = registry.devices[0].clone();
        let registry = DeviceRegistry {
            schema_version: registry.schema_version,
            registry_version: registry.registry_version,
            devices: vec![registry.devices[0].clone(), duplicate],
        };
        assert_eq!(
            validate_signed_frame(signed, &registry).unwrap_err().code,
            "duplicate_device_key"
        );
    }

    #[test]
    fn rejects_invalid_registered_public_key_before_signature_validation() {
        let (registry_document, signed_document) =
            signed_registry_document("active", "blueeconomy.waterway-safety.device-registry.v1");
        let mut registry: DeviceRegistry =
            serde_json::from_slice(&registry_document).expect("fixture registry");
        let signed: SignedTelemetryFrame =
            serde_json::from_slice(&signed_document).expect("fixture signed telemetry");
        registry.devices[0].public_key_base64 = "AA==".to_owned();
        assert_eq!(
            validate_signed_frame(signed, &registry).unwrap_err().code,
            "invalid_public_key_length"
        );
    }
}

#[cfg(test)]
mod p0_error_path_regressions {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use std::path::PathBuf;

    fn temporary_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blueeconomy-waterway-safety-p0-{label}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ))
    }

    fn frame(sequence: u64) -> TelemetryFrame {
        TelemetryFrame {
            device_id: "device-p0-001".to_owned(),
            gateway_id: "gateway-p0-001".to_owned(),
            source_sequence: sequence,
            observed_at: if sequence == 1 {
                "2026-08-21T00:00:00Z".to_owned()
            } else {
                "2026-08-21T00:00:02Z".to_owned()
            },
            received_at: if sequence == 1 {
                "2026-08-21T00:00:01Z".to_owned()
            } else {
                "2026-08-21T00:00:03Z".to_owned()
            },
            data_classification: "internal".to_owned(),
            payload_base64: "Ynl0ZXM=".to_owned(),
            payload_sha256: hex_lowercase(Sha256::digest(b"bytes")),
        }
    }

    fn valid_cursor() -> TelemetryStreamCursor {
        let first = frame(1);
        let evidence = validate_batch_evidence(&[first.clone()]).expect("fixture evidence");
        TelemetryStreamCursor {
            device_id: first.device_id,
            gateway_id: first.gateway_id,
            last_source_sequence: 1,
            last_observed_at: first.observed_at,
            last_received_at: first.received_at,
            last_batch_digest_sha256: evidence.batch_digest_sha256,
        }
    }

    fn signed_fixture() -> (SignedTelemetryFrame, DeviceRegistry) {
        let signing_key = SigningKey::from_bytes(&[31_u8; 32]);
        let unsigned = frame(1);
        let key_id = "p0-key-v1".to_owned();
        let signature = signing_key
            .sign(&signed_telemetry_preimage(&unsigned, &key_id).expect("fixture preimage"));
        let signed = SignedTelemetryFrame {
            frame: unsigned.clone(),
            signature_key_id: key_id.clone(),
            signature_base64: STANDARD.encode(signature.to_bytes()),
        };
        let registry = DeviceRegistry {
            schema_version: "blueeconomy.waterway-safety.device-registry.v1".to_owned(),
            registry_version: "p0-registry-v1".to_owned(),
            devices: vec![DeviceRegistryEntry {
                device_id: unsigned.device_id,
                gateway_id: unsigned.gateway_id,
                key_id,
                public_key_base64: STANDARD.encode(signing_key.verifying_key().as_bytes()),
                status: "active".to_owned(),
            }],
        };
        (signed, registry)
    }

    #[test]
    fn rejects_empty_malformed_and_oversized_signed_json_before_signature_processing() {
        let (_, registry) = signed_fixture();
        assert_eq!(
            validate_signed_json(&[], &registry).unwrap_err().code,
            "invalid_input_size"
        );
        assert_eq!(
            validate_signed_json(b"{", &registry).unwrap_err().code,
            "invalid_json"
        );
        assert_eq!(
            validate_signed_json(&vec![b' '; MAX_JSON_BYTES + 1], &registry)
                .unwrap_err()
                .code,
            "invalid_input_size"
        );
    }

    #[test]
    fn rejects_registry_read_path_size_and_json_failures() {
        let missing = temporary_path("missing");
        assert_eq!(
            load_device_registry(&missing).unwrap_err().code,
            "registry_read_failed"
        );

        let directory = temporary_path("directory");
        fs::create_dir(&directory).expect("create directory fixture");
        assert_eq!(
            load_device_registry(&directory).unwrap_err().code,
            "invalid_registry_path"
        );
        fs::remove_dir(&directory).expect("remove directory fixture");

        let empty = temporary_path("empty");
        fs::write(&empty, []).expect("write empty registry");
        assert_eq!(
            load_device_registry(&empty).unwrap_err().code,
            "invalid_registry_size"
        );
        fs::remove_file(&empty).expect("remove empty registry");

        let malformed = temporary_path("malformed");
        fs::write(&malformed, b"{").expect("write malformed registry");
        assert_eq!(
            load_device_registry(&malformed).unwrap_err().code,
            "invalid_registry_json"
        );
        fs::remove_file(&malformed).expect("remove malformed registry");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_registry_and_cursor_symbolic_links() {
        use std::os::unix::fs::symlink;

        let target = temporary_path("symlink-target");
        fs::write(&target, b"{}").expect("write target");
        let registry_link = temporary_path("registry-link");
        symlink(&target, &registry_link).expect("create registry link");
        assert_eq!(
            load_device_registry(&registry_link).unwrap_err().code,
            "invalid_registry_path"
        );

        let cursor_link = temporary_path("cursor-link");
        symlink(&target, &cursor_link).expect("create cursor link");
        assert_eq!(
            load_stream_cursor(&cursor_link).unwrap_err().code,
            "invalid_cursor_path"
        );
        assert_eq!(
            save_stream_cursor(&cursor_link, &valid_cursor())
                .unwrap_err()
                .code,
            "invalid_cursor_path"
        );

        fs::remove_file(&registry_link).expect("remove registry link");
        fs::remove_file(&cursor_link).expect("remove cursor link");
        fs::remove_file(&target).expect("remove target");
    }

    #[test]
    fn rejects_invalid_signature_and_registry_status_before_acceptance() {
        let (mut signed, registry) = signed_fixture();
        signed.signature_base64 = "!not-base64!".to_owned();
        assert_eq!(
            validate_signed_frame(signed, &registry).unwrap_err().code,
            "invalid_signature_encoding"
        );

        let (mut signed, mut registry) = signed_fixture();
        signed.signature_base64 = "AA==".to_owned();
        assert_eq!(
            validate_signed_frame(signed, &registry).unwrap_err().code,
            "invalid_signature"
        );

        let (signed, _) = signed_fixture();
        registry.devices[0].status = "retired".to_owned();
        assert_eq!(
            validate_signed_frame(signed, &registry).unwrap_err().code,
            "invalid_device_status"
        );
    }

    #[test]
    fn rejects_invalid_cursor_json_sequence_and_continuation_time_regression() {
        let malformed = temporary_path("cursor-malformed");
        fs::write(&malformed, b"{").expect("write malformed cursor");
        assert_eq!(
            load_stream_cursor(&malformed).unwrap_err().code,
            "invalid_cursor_json"
        );
        fs::remove_file(&malformed).expect("remove malformed cursor");

        let zero = temporary_path("cursor-zero");
        let mut cursor = valid_cursor();
        cursor.last_source_sequence = 0;
        fs::write(
            &zero,
            serde_json::to_vec(&cursor).expect("serialize cursor"),
        )
        .expect("write zero cursor");
        assert_eq!(
            load_stream_cursor(&zero).unwrap_err().code,
            "invalid_cursor_sequence"
        );
        fs::remove_file(&zero).expect("remove zero cursor");

        let cursor = valid_cursor();
        let mut next = frame(2);
        next.observed_at = "2026-08-20T23:59:59Z".to_owned();
        next.received_at = "2026-08-21T00:00:02Z".to_owned();
        assert_eq!(
            validate_continuation(&cursor, &[next]).unwrap_err().code,
            "telemetry_cursor_time_regression"
        );
    }

    #[test]
    fn rejects_empty_batches_and_refuses_cursor_write_to_directory() {
        assert_eq!(
            validate_ordered_frames(&[]).unwrap_err().code,
            "empty_telemetry_batch"
        );
        let directory = temporary_path("cursor-directory");
        fs::create_dir(&directory).expect("create cursor directory");
        assert_eq!(
            save_stream_cursor(&directory, &valid_cursor())
                .unwrap_err()
                .code,
            "invalid_cursor_path"
        );
        fs::remove_dir(&directory).expect("remove cursor directory");
    }
}
