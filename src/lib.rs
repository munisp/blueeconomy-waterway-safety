#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter, Write};

pub const MAX_PAYLOAD_BYTES: usize = 1_048_576;
pub const MAX_JSON_BYTES: usize = 1_500_000;
const MAX_BASE64_BYTES: usize = ((MAX_PAYLOAD_BYTES + 2) / 3) * 4;

#[derive(Debug, Deserialize)]
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

pub fn validate(frame: TelemetryFrame) -> Result<ValidatedTelemetry, ValidationError> {
    validate_identifier("device_id", &frame.device_id, 256)?;
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
}
