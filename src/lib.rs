#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter, Write};

pub const MAX_PAYLOAD_BYTES: usize = 1_048_576;
pub const MAX_JSON_BYTES: usize = 1_500_000;
const MAX_BASE64_BYTES: usize = ((MAX_PAYLOAD_BYTES + 2) / 3) * 4;

#[derive(Clone, Debug, Deserialize)]
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

#[derive(Debug, Serialize, PartialEq, Eq)]
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
