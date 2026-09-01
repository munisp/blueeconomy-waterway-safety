#![forbid(unsafe_code)]

//! Integration tests for the axum telemetry validation service.

use std::future::IntoFuture;
use std::io::{Read, Write};
use std::net::TcpStream;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use blueeconomy_waterway_safety::server;
use blueeconomy_waterway_safety::{
    signed_telemetry_preimage, DeviceRegistry, DeviceRegistryEntry, SignedTelemetryFrame,
    TelemetryFrame,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

fn frame(sequence: u64) -> TelemetryFrame {
    TelemetryFrame {
        device_id: "device-http-001".to_owned(),
        gateway_id: "gateway-http-001".to_owned(),
        source_sequence: sequence,
        observed_at: "2026-08-21T00:00:00Z".to_owned(),
        received_at: "2026-08-21T00:00:01Z".to_owned(),
        data_classification: "internal".to_owned(),
        payload_base64: "Ynl0ZXM=".to_owned(),
        payload_sha256: hex(&Sha256::digest(b"bytes")),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn signed_fixture() -> (SignedTelemetryFrame, DeviceRegistry) {
    let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
    let frame = frame(1);
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
        registry_version: "http-fixture-v1".to_owned(),
        devices: vec![DeviceRegistryEntry {
            device_id: frame.device_id,
            gateway_id: frame.gateway_id,
            key_id,
            public_key_base64: STANDARD.encode(signing_key.verifying_key().as_bytes()),
            status: "active".to_owned(),
        }],
    };
    (signed, registry)
}

/// Start the service on an ephemeral localhost port and return the address.
fn spawn(registry: Option<DeviceRegistry>) -> String {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind");
    let addr = listener.local_addr().expect("local addr").to_string();
    std::thread::spawn(move || {
        runtime
            .block_on(axum::serve(listener, server::router(registry)).into_future())
            .expect("serve");
    });
    addr
}

fn request(addr: &str, method: &str, path: &str, body: Option<&[u8]>) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    let body = body.unwrap_or(b"");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write head");
    stream.write_all(body).expect("write body");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    let status: u16 = response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status code");
    (status, response)
}

#[test]
fn health_returns_ok() {
    let addr = spawn(None);
    let (status, response) = request(&addr, "GET", "/health", None);
    assert_eq!(status, 200);
    assert!(response.contains("\"status\":\"ok\""), "body: {response}");
}

#[test]
fn validates_unsigned_telemetry_without_registry() {
    let addr = spawn(None);
    let body = serde_json::to_vec(&serde_json::json!({
        "device_id": "device-http-001",
        "gateway_id": "gateway-http-001",
        "source_sequence": 1,
        "observed_at": "2026-08-21T00:00:00Z",
        "received_at": "2026-08-21T00:00:01Z",
        "data_classification": "internal",
        "payload_base64": "Ynl0ZXM=",
        "payload_sha256": frame(1).payload_sha256,
    }))
    .expect("serialize");
    let (status, response) = request(&addr, "POST", "/v1/telemetry/validate", Some(&body));
    assert_eq!(status, 200, "response: {response}");
    assert!(response.contains("\"device_id\":\"device-http-001\""));
    // The raw payload must never be emitted back.
    assert!(!response.contains("Ynl0ZXM="), "payload leaked: {response}");
}

#[test]
fn rejects_invalid_telemetry_fail_closed_422() {
    let addr = spawn(None);
    let (status, response) = request(
        &addr,
        "POST",
        "/v1/telemetry/validate",
        Some(br#"{"device_id":"device-http-001"}"#),
    );
    assert_eq!(status, 422, "response: {response}");
    assert!(response.contains("\"error\""), "response: {response}");
}

#[test]
fn validates_signed_telemetry_with_registry() {
    let (signed, registry) = signed_fixture();
    let addr = spawn(Some(registry));
    let body = serde_json::json!({
        "frame": {
            "device_id": signed.frame.device_id,
            "gateway_id": signed.frame.gateway_id,
            "source_sequence": signed.frame.source_sequence,
            "observed_at": signed.frame.observed_at,
            "received_at": signed.frame.received_at,
            "data_classification": signed.frame.data_classification,
            "payload_base64": signed.frame.payload_base64,
            "payload_sha256": signed.frame.payload_sha256,
        },
        "signature_key_id": signed.signature_key_id,
        "signature_base64": signed.signature_base64,
    });
    let body = serde_json::to_vec(&body).expect("serialize");
    let (status, response) = request(&addr, "POST", "/v1/telemetry/validate", Some(&body));
    assert_eq!(status, 200, "response: {response}");
    assert!(response.contains("\"signature_key_id\":\"device-key-2026-01\""));
    assert!(!response.contains("Ynl0ZXM="), "payload leaked: {response}");
}

#[test]
fn rejects_tampered_signed_telemetry_fail_closed_422() {
    let (mut signed, registry) = signed_fixture();
    signed.frame.source_sequence = 2; // tamper after signing
    let addr = spawn(Some(registry));
    let body = serde_json::json!({
        "frame": {
            "device_id": signed.frame.device_id,
            "gateway_id": signed.frame.gateway_id,
            "source_sequence": signed.frame.source_sequence,
            "observed_at": signed.frame.observed_at,
            "received_at": signed.frame.received_at,
            "data_classification": signed.frame.data_classification,
            "payload_base64": signed.frame.payload_base64,
            "payload_sha256": signed.frame.payload_sha256,
        },
        "signature_key_id": signed.signature_key_id,
        "signature_base64": signed.signature_base64,
    });
    let body = serde_json::to_vec(&body).expect("serialize");
    let (status, response) = request(&addr, "POST", "/v1/telemetry/validate", Some(&body));
    assert_eq!(status, 422, "response: {response}");
    assert!(response.contains("\"error\""), "response: {response}");
}
