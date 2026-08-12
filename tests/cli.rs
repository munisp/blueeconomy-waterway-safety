#![forbid(unsafe_code)]

use serde_json::Value;
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
