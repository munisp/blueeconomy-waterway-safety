#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use blueeconomy_waterway_safety::{signed_telemetry_preimage, TelemetryFrame};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

struct TemporaryFile(PathBuf);

impl TemporaryFile {
    fn create(contents: &[u8]) -> Self {
        let identifier = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "blueeconomy-waterway-safety-{}-{identifier}.json",
            std::process::id()
        ));
        fs::write(&path, contents).expect("write temporary telemetry fixture");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_blueeconomy-waterway-safety")
}

fn run_with(path: &Path) -> Output {
    Command::new(binary())
        .arg(path)
        .output()
        .expect("run waterway safety binary")
}

fn run_signed_with(registry_path: &Path, input_path: &Path) -> Output {
    Command::new(binary())
        .arg("--device-registry")
        .arg(registry_path)
        .arg(input_path)
        .output()
        .expect("run signed waterway safety binary")
}

fn signed_registry_and_input() -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let frame = TelemetryFrame {
        device_id: "device-cli-signed-001".to_owned(),
        gateway_id: "gateway-cli-signed-001".to_owned(),
        source_sequence: 7,
        observed_at: "2026-08-21T00:00:00Z".to_owned(),
        received_at: "2026-08-21T00:00:01Z".to_owned(),
        data_classification: "internal".to_owned(),
        payload_base64: "Ynl0ZXM=".to_owned(),
        payload_sha256: "277089d91c0bdf4f2e6862ba7e4a07605119431f5d13f726dd352b06f1b206a9"
            .to_owned(),
    };
    let key_id = "cli-fixture-key-v1";
    let signature = signing_key.sign(
        &signed_telemetry_preimage(&frame, key_id)
            .expect("construct local-only signature preimage"),
    );
    let registry = json!({
        "schema_version": "blueeconomy.waterway-safety.device-registry.v1",
        "registry_version": "local-cli-fixture-v1",
        "devices": [{
            "device_id": frame.device_id.clone(),
            "gateway_id": frame.gateway_id.clone(),
            "key_id": key_id,
            "public_key_base64": STANDARD.encode(signing_key.verifying_key().as_bytes()),
            "status": "active"
        }]
    });
    let input = json!({
        "frame": {
            "device_id": frame.device_id,
            "gateway_id": frame.gateway_id,
            "source_sequence": frame.source_sequence,
            "observed_at": frame.observed_at,
            "received_at": frame.received_at,
            "data_classification": frame.data_classification,
            "payload_base64": frame.payload_base64,
            "payload_sha256": frame.payload_sha256
        },
        "signature_key_id": key_id,
        "signature_base64": STANDARD.encode(signature.to_bytes())
    });
    (
        serde_json::to_vec(&registry).expect("encode local registry fixture"),
        serde_json::to_vec(&input).expect("encode local signed telemetry fixture"),
    )
}

fn valid_input() -> &'static [u8] {
    br#"{"device_id":"device-001","gateway_id":"gateway-001","source_sequence":1,"observed_at":"2026-08-12T00:00:00Z","received_at":"2026-08-12T00:00:01Z","data_classification":"internal","payload_base64":"Ynl0ZXM=","payload_sha256":"277089d91c0bdf4f2e6862ba7e4a07605119431f5d13f726dd352b06f1b206a9"}"#
}

#[test]
fn validates_real_input_file_without_emitting_payload() {
    let input = TemporaryFile::create(valid_input());
    let output = run_with(input.path());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(document["device_id"], "device-001");
    assert_eq!(document["payload_byte_count"], 5);
    assert!(document.get("payload_base64").is_none());
}

#[test]
fn validates_signed_telemetry_against_explicit_local_registry_without_emitting_payload() {
    let (registry_document, input_document) = signed_registry_and_input();
    let registry = TemporaryFile::create(&registry_document);
    let input = TemporaryFile::create(&input_document);
    let output = run_signed_with(registry.path(), input.path());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(
        document["schema_version"],
        "blueeconomy.waterway-safety.signed-telemetry.v1"
    );
    assert_eq!(document["registry_version"], "local-cli-fixture-v1");
    assert_eq!(document["signature_key_id"], "cli-fixture-key-v1");
    assert!(document.get("payload_base64").is_none());
}

#[test]
fn rejects_missing_input_argument() {
    let output = Command::new(binary()).output().expect("run binary");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
}

#[test]
fn rejects_oversized_input_before_deserialization() {
    let input = TemporaryFile::create(&vec![b' '; 1_500_001]);
    let output = run_with(input.path());
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("between 1 and 1500000 bytes"));
}

#[test]
fn rejects_invalid_telemetry_document() {
    let input = TemporaryFile::create(br#"{"device_id":"device-001"}"#);
    let output = run_with(input.path());
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid_json"));
}

#[cfg(unix)]
#[test]
fn rejects_symbolic_link_input() {
    use std::os::unix::fs::symlink;

    let target = TemporaryFile::create(valid_input());
    let link = TemporaryFile::create(b"placeholder");
    fs::remove_file(link.path()).expect("remove placeholder");
    symlink(target.path(), link.path()).expect("create symlink");
    let output = run_with(link.path());
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a symbolic link"));
}
