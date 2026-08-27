//! LoRaWAN sensor uplink decoding for vessel engine, bilge, and life-jacket
//! IoT sensors (Workstream B §3.2).
//!
//! ## Frame format (schema `blueeconomy.waterway-safety.lorawan-uplink.v1`)
//!
//! The LoRaWAN network server (or its MQTT/HTTP bridge on the vessel-side
//! gateway) delivers one JSON envelope per uplink:
//!
//! ```json
//! {
//!   "schema_version": "blueeconomy.waterway-safety.lorawan-uplink.v1",
//!   "dev_eui": "0018b2aabbccddee",
//!   "fport": 10,
//!   "payload_base64": "AAE9BK4CAw=="
//! }
//! ```
//!
//! `payload_base64` carries a compact big-endian binary measurement whose
//! layout is selected by the LoRaWAN FPort:
//!
//! | FPort | Sensor       | Layout (bytes, big-endian)                                  |
//! |-------|--------------|-------------------------------------------------------------|
//! | 10    | Engine       | rpm u16, coolant deci-°C i16, oil pressure kPa u16 (6 B)    |
//! | 11    | Bilge        | water level mm u16, pump active u8 (0/1) (3 B)              |
//! | 12    | Life jacket  | total u16, present u16, tamper flags u8 (5 B)               |
//!
//! Life-jacket tamper flags: bit 0 = enclosure opened, bit 1 = unexpected
//! motion, bit 2 = strap/buckle fault. Bits 3-7 are reserved and must be 0.
//!
//! Every malformed, truncated, out-of-range, or unknown-port frame is a
//! structured [`SensorError`] so the gateway dead-letters it explicitly;
//! decoding never panics and never fabricates a measurement.

use crate::MAX_PAYLOAD_BYTES;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;

pub const LORAWAN_UPLINK_SCHEMA_VERSION: &str = "blueeconomy.waterway-safety.lorawan-uplink.v1";
pub const FPORT_ENGINE: u8 = 10;
pub const FPORT_BILGE: u8 = 11;
pub const FPORT_LIFE_JACKET: u8 = 12;
pub const MAX_UPLINK_JSON_BYTES: usize = 4_096;
/// LoRaWAN application payloads are at most 250 bytes (largest regional
/// maximum); anything larger is malformed by definition.
pub const MAX_LORAWAN_PAYLOAD_BYTES: usize = 250;

pub const MAX_ENGINE_RPM: u16 = 10_000;
pub const MAX_OIL_PRESSURE_KPA: u16 = 2_000;
pub const MAX_BILGE_LEVEL_MILLIMETERS: u16 = 10_000;
pub const MAX_LIFE_JACKET_COUNT: u16 = 5_000;

const ENGINE_PAYLOAD_BYTES: usize = 6;
const BILGE_PAYLOAD_BYTES: usize = 3;
const LIFE_JACKET_PAYLOAD_BYTES: usize = 5;
const TAMPER_FLAG_MASK: u8 = 0b0000_0111;

/// A structured decode failure. `code` is stable for dead-letter routing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SensorError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for SensorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SensorError {}

fn error(code: &'static str, message: impl Into<String>) -> SensorError {
    SensorError {
        code,
        message: message.into(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UplinkEnvelope {
    schema_version: String,
    dev_eui: String,
    fport: u8,
    payload_base64: String,
}

/// One decoded measurement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SensorReading {
    Engine {
        rpm: u16,
        coolant_temp_celsius_tenths: i16,
        oil_pressure_kpa: u16,
    },
    Bilge {
        level_millimeters: u16,
        pump_active: bool,
    },
    LifeJacket {
        total_count: u16,
        present_count: u16,
        tamper_flags: u8,
    },
}

/// A validated uplink: the sensor node identity plus its decoded measurement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SensorUplink {
    pub dev_eui: String,
    pub fport: u8,
    pub reading: SensorReading,
}

/// Decode one LoRaWAN uplink JSON document. Any deviation from the
/// documented format is a structured error.
pub fn decode_uplink(input: &[u8]) -> Result<SensorUplink, SensorError> {
    if input.is_empty() || input.len() > MAX_UPLINK_JSON_BYTES {
        return Err(error(
            "invalid_uplink_size",
            format!("uplink JSON must contain between 1 and {MAX_UPLINK_JSON_BYTES} bytes"),
        ));
    }
    let envelope: UplinkEnvelope =
        serde_json::from_slice(input).map_err(|serde_error| SensorError {
            code: "invalid_uplink_json",
            message: serde_error.to_string(),
        })?;
    if envelope.schema_version != LORAWAN_UPLINK_SCHEMA_VERSION {
        return Err(error(
            "invalid_uplink_schema",
            "uplink schema_version is not supported",
        ));
    }
    let dev_eui = envelope.dev_eui;
    if dev_eui.len() != 16
        || !dev_eui
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(error(
            "invalid_dev_eui",
            "dev_eui must be 16 lower-case hexadecimal characters",
        ));
    }
    let payload = STANDARD
        .decode(envelope.payload_base64.as_bytes())
        .map_err(|base64_error| SensorError {
            code: "invalid_uplink_payload_encoding",
            message: base64_error.to_string(),
        })?;
    if payload.len() > MAX_LORAWAN_PAYLOAD_BYTES {
        return Err(error(
            "invalid_uplink_size",
            format!("LoRaWAN payload exceeds {MAX_LORAWAN_PAYLOAD_BYTES} bytes"),
        ));
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(error(
            "invalid_uplink_size",
            "payload exceeds the crate payload limit",
        ));
    }
    let reading = match envelope.fport {
        FPORT_ENGINE => decode_engine(&payload)?,
        FPORT_BILGE => decode_bilge(&payload)?,
        FPORT_LIFE_JACKET => decode_life_jacket(&payload)?,
        other => {
            return Err(error(
                "unsupported_fport",
                format!("FPort {other} carries no documented sensor measurement"),
            ))
        }
    };
    Ok(SensorUplink {
        dev_eui,
        fport: envelope.fport,
        reading,
    })
}

fn require_length(
    payload: &[u8],
    expected: usize,
    sensor: &'static str,
) -> Result<(), SensorError> {
    if payload.len() != expected {
        return Err(error(
            "invalid_payload_length",
            format!(
                "{sensor} payload must be exactly {expected} bytes, got {}",
                payload.len()
            ),
        ));
    }
    Ok(())
}

fn be_u16(payload: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([payload[offset], payload[offset + 1]])
}

fn be_i16(payload: &[u8], offset: usize) -> i16 {
    i16::from_be_bytes([payload[offset], payload[offset + 1]])
}

fn decode_engine(payload: &[u8]) -> Result<SensorReading, SensorError> {
    require_length(payload, ENGINE_PAYLOAD_BYTES, "engine")?;
    let rpm = be_u16(payload, 0);
    let coolant_temp_celsius_tenths = be_i16(payload, 2);
    let oil_pressure_kpa = be_u16(payload, 4);
    if rpm > MAX_ENGINE_RPM {
        return Err(error("invalid_measurement", "engine rpm out of range"));
    }
    if !(-400..=1500).contains(&coolant_temp_celsius_tenths) {
        return Err(error(
            "invalid_measurement",
            "coolant temperature out of range (-40.0..=150.0 °C)",
        ));
    }
    if oil_pressure_kpa > MAX_OIL_PRESSURE_KPA {
        return Err(error("invalid_measurement", "oil pressure out of range"));
    }
    Ok(SensorReading::Engine {
        rpm,
        coolant_temp_celsius_tenths,
        oil_pressure_kpa,
    })
}

fn decode_bilge(payload: &[u8]) -> Result<SensorReading, SensorError> {
    require_length(payload, BILGE_PAYLOAD_BYTES, "bilge")?;
    let level_millimeters = be_u16(payload, 0);
    if level_millimeters > MAX_BILGE_LEVEL_MILLIMETERS {
        return Err(error("invalid_measurement", "bilge level out of range"));
    }
    let pump_active = match payload[2] {
        0 => false,
        1 => true,
        _ => {
            return Err(error(
                "invalid_measurement",
                "bilge pump state must be 0 or 1",
            ))
        }
    };
    Ok(SensorReading::Bilge {
        level_millimeters,
        pump_active,
    })
}

fn decode_life_jacket(payload: &[u8]) -> Result<SensorReading, SensorError> {
    require_length(payload, LIFE_JACKET_PAYLOAD_BYTES, "life-jacket")?;
    let total_count = be_u16(payload, 0);
    let present_count = be_u16(payload, 2);
    let tamper_flags = payload[4];
    if total_count == 0 || total_count > MAX_LIFE_JACKET_COUNT {
        return Err(error(
            "invalid_measurement",
            "life-jacket total count out of range",
        ));
    }
    if present_count > total_count {
        return Err(error(
            "invalid_measurement",
            "life-jacket present count exceeds total count",
        ));
    }
    if tamper_flags & !TAMPER_FLAG_MASK != 0 {
        return Err(error(
            "invalid_measurement",
            "life-jacket tamper flags use reserved bits",
        ));
    }
    Ok(SensorReading::LifeJacket {
        total_count,
        present_count,
        tamper_flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uplink(dev_eui: &str, fport: u8, payload: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": LORAWAN_UPLINK_SCHEMA_VERSION,
            "dev_eui": dev_eui,
            "fport": fport,
            "payload_base64": STANDARD.encode(payload),
        }))
        .expect("encode uplink")
    }

    #[test]
    fn decodes_engine_uplink() {
        let payload = [0x0B, 0xB8, 0x03, 0x5C, 0x01, 0x90]; // 3000 rpm, 86.0 °C, 400 kPa
        let decoded = decode_uplink(&uplink("0018b2aabbccddee", FPORT_ENGINE, &payload))
            .expect("valid engine uplink");
        assert_eq!(decoded.dev_eui, "0018b2aabbccddee");
        assert_eq!(
            decoded.reading,
            SensorReading::Engine {
                rpm: 3000,
                coolant_temp_celsius_tenths: 860,
                oil_pressure_kpa: 400,
            }
        );
    }

    #[test]
    fn decodes_bilge_and_life_jacket_uplinks() {
        let bilge = decode_uplink(&uplink(
            "0018b2aabbccddee",
            FPORT_BILGE,
            &[0x00, 0xFA, 0x01],
        ))
        .expect("valid bilge uplink");
        assert_eq!(
            bilge.reading,
            SensorReading::Bilge {
                level_millimeters: 250,
                pump_active: true,
            }
        );
        let jackets = decode_uplink(&uplink(
            "0018b2aabbccddee",
            FPORT_LIFE_JACKET,
            &[0x00, 0x64, 0x00, 0x63, 0x02],
        ))
        .expect("valid life-jacket uplink");
        assert_eq!(
            jackets.reading,
            SensorReading::LifeJacket {
                total_count: 100,
                present_count: 99,
                tamper_flags: 0x02,
            }
        );
    }

    #[test]
    fn rejects_truncated_and_oversized_payloads() {
        let truncated = decode_uplink(&uplink("0018b2aabbccddee", FPORT_ENGINE, &[0x0B, 0xB8]));
        assert_eq!(truncated.unwrap_err().code, "invalid_payload_length");
        let oversized = decode_uplink(&uplink(
            "0018b2aabbccddee",
            FPORT_BILGE,
            &[0u8; MAX_LORAWAN_PAYLOAD_BYTES + 1],
        ));
        assert_eq!(oversized.unwrap_err().code, "invalid_uplink_size");
    }

    #[test]
    fn rejects_out_of_range_measurements() {
        let rpm = decode_uplink(&uplink(
            "0018b2aabbccddee",
            FPORT_ENGINE,
            &[0xFF, 0xFF, 0x03, 0x5C, 0x01, 0x90],
        ));
        assert_eq!(rpm.unwrap_err().code, "invalid_measurement");
        let pump = decode_uplink(&uplink(
            "0018b2aabbccddee",
            FPORT_BILGE,
            &[0x00, 0x0A, 0x07],
        ));
        assert_eq!(pump.unwrap_err().code, "invalid_measurement");
        let present = decode_uplink(&uplink(
            "0018b2aabbccddee",
            FPORT_LIFE_JACKET,
            &[0x00, 0x64, 0x00, 0x65, 0x00],
        ));
        assert_eq!(present.unwrap_err().code, "invalid_measurement");
        let tamper = decode_uplink(&uplink(
            "0018b2aabbccddee",
            FPORT_LIFE_JACKET,
            &[0x00, 0x64, 0x00, 0x64, 0x80],
        ));
        assert_eq!(tamper.unwrap_err().code, "invalid_measurement");
    }

    #[test]
    fn rejects_bad_envelopes_and_ports() {
        assert_eq!(decode_uplink(b"").unwrap_err().code, "invalid_uplink_size");
        assert_eq!(decode_uplink(b"{").unwrap_err().code, "invalid_uplink_json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&uplink("0018b2aabbccddee", FPORT_ENGINE, &[0; 6]))
                .expect("decode fixture");
        value["schema_version"] = serde_json::Value::String("other-v9".to_owned());
        assert_eq!(
            decode_uplink(&serde_json::to_vec(&value).expect("encode"))
                .unwrap_err()
                .code,
            "invalid_uplink_schema"
        );
        assert_eq!(
            decode_uplink(&uplink("0018B2AABBCCDDEE", FPORT_ENGINE, &[0; 6]))
                .unwrap_err()
                .code,
            "invalid_dev_eui"
        );
        assert_eq!(
            decode_uplink(&uplink("0018b2aabbccddee", 99, &[0; 6]))
                .unwrap_err()
                .code,
            "unsupported_fport"
        );
        let bad_base64 = br#"{"schema_version":"blueeconomy.waterway-safety.lorawan-uplink.v1","dev_eui":"0018b2aabbccddee","fport":10,"payload_base64":"!!"}"#;
        assert_eq!(
            decode_uplink(bad_base64).unwrap_err().code,
            "invalid_uplink_payload_encoding"
        );
    }
}
