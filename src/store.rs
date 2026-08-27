//! Durable, fail-closed persistence for ingestion stream cursors and vessel
//! track registry state. The file-backed store writes atomically
//! (write-tempfile, fsync, rename, fsync parent), detects corruption with a
//! SHA-256 payload checksum, and never silently resets state: any read,
//! checksum, schema, or validation failure is returned as an error.

use crate::geo::{TrackPoint, MAX_TRACK_POINTS};
use crate::{
    hex_lowercase, validate_identifier, validate_stream_cursor, validate_timestamp,
    TelemetryStreamCursor, ValidationError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub const STATE_STORE_SCHEMA_VERSION: &str = "blueeconomy.waterway-safety.state-store.v1";
pub const MAX_STATE_STORE_BYTES: usize = 8_388_608;
pub const MAX_STATE_STORE_CURSORS: usize = 10_000;
pub const MAX_STATE_STORE_VESSELS: usize = 10_000;

/// Persisted vessel track registry state for corridor and freshness analytics.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VesselTrackState {
    pub vessel_id: String,
    pub device_id: String,
    pub gateway_id: String,
    pub last_source_sequence: u64,
    pub last_observed_at: String,
    pub last_received_at: String,
    pub last_position: TrackPoint,
    pub track: Vec<TrackPoint>,
}

/// The full durable snapshot: ingestion cursors plus vessel registry state.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StateStoreSnapshot {
    pub cursors: Vec<TelemetryStreamCursor>,
    pub vessels: Vec<VesselTrackState>,
}

impl StateStoreSnapshot {
    /// An explicitly constructed empty snapshot. Callers must opt in to a
    /// fresh state; loading never fabricates one after a failure.
    pub fn empty() -> Self {
        Self::default()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StateStoreEnvelope {
    schema_version: String,
    payload_sha256: String,
    payload: StateStoreSnapshot,
}

/// Pluggable durable state backend. Implementations must fail closed: any
/// corruption, unavailability, or validation failure is an error, never a
/// silent reset to empty state.
pub trait StateStore {
    fn load(&self) -> Result<StateStoreSnapshot, ValidationError>;
    fn save(&self, snapshot: &StateStoreSnapshot) -> Result<(), ValidationError>;
}

/// File-backed [`StateStore`] using an atomic checksum-protected JSON envelope.
pub struct FileStateStore {
    path: PathBuf,
}

impl FileStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl StateStore for FileStateStore {
    fn load(&self) -> Result<StateStoreSnapshot, ValidationError> {
        let metadata = fs::symlink_metadata(&self.path).map_err(|error| ValidationError {
            code: "state_store_read_failed",
            message: error.to_string(),
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ValidationError {
                code: "invalid_state_store_path",
                message: "state store path must be a regular file and not a symbolic link"
                    .to_owned(),
            });
        }
        if metadata.len() == 0 || metadata.len() > MAX_STATE_STORE_BYTES as u64 {
            return Err(ValidationError {
                code: "invalid_state_store_size",
                message: format!(
                    "state store must contain between 1 and {MAX_STATE_STORE_BYTES} bytes"
                ),
            });
        }
        let raw = fs::read(&self.path).map_err(|error| ValidationError {
            code: "state_store_read_failed",
            message: error.to_string(),
        })?;
        let envelope: StateStoreEnvelope =
            serde_json::from_slice(&raw).map_err(|error| ValidationError {
                code: "invalid_state_store_json",
                message: error.to_string(),
            })?;
        if envelope.schema_version != STATE_STORE_SCHEMA_VERSION {
            return Err(ValidationError {
                code: "invalid_state_store_schema",
                message: "state store schema_version is not supported".to_owned(),
            });
        }
        let payload_bytes =
            serde_json::to_vec(&envelope.payload).map_err(|error| ValidationError {
                code: "state_store_encode_failed",
                message: error.to_string(),
            })?;
        let observed = hex_lowercase(Sha256::digest(&payload_bytes));
        if observed != envelope.payload_sha256 {
            return Err(ValidationError {
                code: "state_store_checksum_mismatch",
                message: "state store payload checksum does not match recorded digest; refusing to load possibly corrupt state"
                    .to_owned(),
            });
        }
        validate_snapshot(&envelope.payload)?;
        Ok(envelope.payload)
    }

    fn save(&self, snapshot: &StateStoreSnapshot) -> Result<(), ValidationError> {
        validate_snapshot(snapshot)?;
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| ValidationError {
                    code: "state_store_write_failed",
                    message: error.to_string(),
                })?;
            }
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ValidationError {
                    code: "invalid_state_store_path",
                    message: "state store path must be a regular file and not a symbolic link"
                        .to_owned(),
                });
            }
        }
        let payload_bytes = serde_json::to_vec(snapshot).map_err(|error| ValidationError {
            code: "state_store_encode_failed",
            message: error.to_string(),
        })?;
        let envelope = StateStoreEnvelope {
            schema_version: STATE_STORE_SCHEMA_VERSION.to_owned(),
            payload_sha256: hex_lowercase(Sha256::digest(&payload_bytes)),
            payload: snapshot.clone(),
        };
        let encoded = serde_json::to_vec(&envelope).map_err(|error| ValidationError {
            code: "state_store_encode_failed",
            message: error.to_string(),
        })?;
        let temporary = self
            .path
            .with_extension(format!("tmp-{}", std::process::id()));
        let write_result = (|| -> Result<(), ValidationError> {
            let mut file = fs::File::create(&temporary).map_err(|error| ValidationError {
                code: "state_store_write_failed",
                message: error.to_string(),
            })?;
            file.write_all(&encoded).map_err(|error| ValidationError {
                code: "state_store_write_failed",
                message: error.to_string(),
            })?;
            file.sync_all().map_err(|error| ValidationError {
                code: "state_store_write_failed",
                message: error.to_string(),
            })?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        fs::rename(&temporary, &self.path).map_err(|error| {
            let _ = fs::remove_file(&temporary);
            ValidationError {
                code: "state_store_write_failed",
                message: error.to_string(),
            }
        })?;
        sync_parent_directory(&self.path)?;
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), ValidationError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| ValidationError {
                code: "state_store_write_failed",
                message: error.to_string(),
            })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), ValidationError> {
    Ok(())
}

pub fn validate_snapshot(snapshot: &StateStoreSnapshot) -> Result<(), ValidationError> {
    if snapshot.cursors.len() > MAX_STATE_STORE_CURSORS {
        return Err(ValidationError {
            code: "invalid_state_store_entries",
            message: format!("state store must contain at most {MAX_STATE_STORE_CURSORS} cursors"),
        });
    }
    if snapshot.vessels.len() > MAX_STATE_STORE_VESSELS {
        return Err(ValidationError {
            code: "invalid_state_store_entries",
            message: format!("state store must contain at most {MAX_STATE_STORE_VESSELS} vessels"),
        });
    }
    for (index, cursor) in snapshot.cursors.iter().enumerate() {
        validate_stream_cursor(cursor)?;
        if snapshot.cursors[..index].iter().any(|previous| {
            previous.device_id == cursor.device_id && previous.gateway_id == cursor.gateway_id
        }) {
            return Err(ValidationError {
                code: "duplicate_cursor_stream",
                message: "state store has a duplicate device and gateway cursor".to_owned(),
            });
        }
    }
    for (index, vessel) in snapshot.vessels.iter().enumerate() {
        validate_vessel(vessel)?;
        if snapshot.vessels[..index]
            .iter()
            .any(|previous| previous.vessel_id == vessel.vessel_id)
        {
            return Err(ValidationError {
                code: "duplicate_vessel_id",
                message: "state store has a duplicate vessel identifier".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_vessel(vessel: &VesselTrackState) -> Result<(), ValidationError> {
    validate_identifier("vessel.vessel_id", &vessel.vessel_id, 256)?;
    validate_identifier("vessel.device_id", &vessel.device_id, 256)?;
    validate_identifier("vessel.gateway_id", &vessel.gateway_id, 256)?;
    if vessel.last_source_sequence == 0 {
        return Err(ValidationError {
            code: "invalid_vessel_sequence",
            message: "vessel source sequence must be greater than zero".to_owned(),
        });
    }
    let observed_at = validate_timestamp("vessel.last_observed_at", &vessel.last_observed_at)?;
    let received_at = validate_timestamp("vessel.last_received_at", &vessel.last_received_at)?;
    if observed_at > received_at {
        return Err(ValidationError {
            code: "invalid_vessel_timestamp_order",
            message: "vessel last_observed_at must not be later than last_received_at".to_owned(),
        });
    }
    if vessel.track.is_empty() || vessel.track.len() > MAX_TRACK_POINTS {
        return Err(ValidationError {
            code: "invalid_vessel_track",
            message: format!("vessel track must contain between 1 and {MAX_TRACK_POINTS} points"),
        });
    }
    crate::geo::validate_track_point("vessel.last_position", &vessel.last_position)?;
    let mut previous: Option<chrono::DateTime<chrono::FixedOffset>> = None;
    for point in &vessel.track {
        crate::geo::validate_track_point("vessel.track", point)?;
        let point_time = validate_timestamp("vessel.track.observed_at", &point.observed_at)?;
        if let Some(earlier) = previous {
            if point_time < earlier {
                return Err(ValidationError {
                    code: "invalid_vessel_track",
                    message: "vessel track points must be ordered by observed_at".to_owned(),
                });
            }
        }
        previous = Some(point_time);
    }
    let last_track_point = vessel.track.last().ok_or_else(|| ValidationError {
        code: "invalid_vessel_track",
        message: "vessel track must contain at least one point".to_owned(),
    })?;
    if last_track_point != &vessel.last_position
        || vessel.last_position.observed_at != vessel.last_observed_at
    {
        return Err(ValidationError {
            code: "inconsistent_vessel_state",
            message: "vessel last_position must equal the final track point and last_observed_at"
                .to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blueeconomy-waterway-safety-store-{label}-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ))
    }

    fn cursor() -> TelemetryStreamCursor {
        TelemetryStreamCursor {
            device_id: "device-001".to_owned(),
            gateway_id: "gateway-001".to_owned(),
            last_source_sequence: 7,
            last_observed_at: "2026-08-21T00:00:00Z".to_owned(),
            last_received_at: "2026-08-21T00:00:01Z".to_owned(),
            last_batch_digest_sha256:
                "277089d91c0bdf4f2e6862ba7e4a07605119431f5d13f726dd352b06f1b206a9".to_owned(),
        }
    }

    fn vessel(vessel_id: &str) -> VesselTrackState {
        let first = TrackPoint {
            observed_at: "2026-08-21T00:00:00Z".to_owned(),
            latitude: 6.0,
            longitude: 3.0,
        };
        let last = TrackPoint {
            observed_at: "2026-08-21T00:01:00Z".to_owned(),
            latitude: 6.001,
            longitude: 3.001,
        };
        VesselTrackState {
            vessel_id: vessel_id.to_owned(),
            device_id: "device-001".to_owned(),
            gateway_id: "gateway-001".to_owned(),
            last_source_sequence: 2,
            last_observed_at: last.observed_at.clone(),
            last_received_at: "2026-08-21T00:01:01Z".to_owned(),
            last_position: last.clone(),
            track: vec![first, last],
        }
    }

    fn snapshot() -> StateStoreSnapshot {
        StateStoreSnapshot {
            cursors: vec![cursor()],
            vessels: vec![vessel("vessel-001")],
        }
    }

    #[test]
    fn persists_and_reloads_snapshot_with_atomic_envelope() {
        let path = temporary_path("roundtrip");
        let store = FileStateStore::new(&path);
        let state = snapshot();
        store.save(&state).expect("snapshot should persist");
        assert_eq!(store.load().expect("snapshot should reload"), state);
        // No temporary file is left behind after an atomic rename.
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        assert!(!temporary.exists());
        fs::remove_file(path).expect("remove store fixture");
    }

    #[test]
    fn fails_closed_on_corrupted_payload_without_resetting() {
        let path = temporary_path("corrupt");
        let store = FileStateStore::new(&path);
        store.save(&snapshot()).expect("snapshot should persist");
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read store fixture"))
                .expect("envelope json");
        // Corrupt the payload while leaving valid JSON and the stale checksum.
        envelope["payload"]["cursors"][0]["last_source_sequence"] = serde_json::Value::from(8);
        fs::write(
            &path,
            serde_json::to_vec(&envelope).expect("encode corrupted"),
        )
        .expect("write corrupted store fixture");
        assert_eq!(
            store.load().unwrap_err().code,
            "state_store_checksum_mismatch"
        );
        fs::remove_file(path).expect("remove store fixture");
    }

    #[test]
    fn fails_closed_on_tampered_checksum_and_wrong_schema() {
        let path = temporary_path("tamper");
        let store = FileStateStore::new(&path);
        store.save(&snapshot()).expect("snapshot should persist");
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read store")).expect("envelope json");
        envelope["payload_sha256"] = serde_json::Value::String("0".repeat(64));
        fs::write(
            &path,
            serde_json::to_vec(&envelope).expect("encode tampered"),
        )
        .expect("write tampered store");
        assert_eq!(
            store.load().unwrap_err().code,
            "state_store_checksum_mismatch"
        );

        envelope["payload_sha256"] = serde_json::Value::String(hex_lowercase(Sha256::digest(
            serde_json::to_vec(&envelope["payload"]).expect("payload"),
        )));
        envelope["schema_version"] = serde_json::Value::String("unsupported-store-v9".to_owned());
        fs::write(
            &path,
            serde_json::to_vec(&envelope).expect("encode tampered"),
        )
        .expect("write tampered store");
        assert_eq!(store.load().unwrap_err().code, "invalid_state_store_schema");
        fs::remove_file(path).expect("remove store fixture");
    }

    #[test]
    fn rejects_missing_oversized_malformed_and_symlink_paths() {
        let store = FileStateStore::new(temporary_path("missing"));
        assert_eq!(store.load().unwrap_err().code, "state_store_read_failed");

        let malformed = temporary_path("malformed");
        fs::write(&malformed, b"{").expect("write malformed store");
        assert_eq!(
            FileStateStore::new(&malformed).load().unwrap_err().code,
            "invalid_state_store_json"
        );
        fs::remove_file(&malformed).expect("remove malformed store");

        let empty = temporary_path("empty");
        fs::write(&empty, []).expect("write empty store");
        assert_eq!(
            FileStateStore::new(&empty).load().unwrap_err().code,
            "invalid_state_store_size"
        );
        fs::remove_file(&empty).expect("remove empty store");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = temporary_path("symlink-target");
            fs::write(&target, b"{}").expect("write target");
            let link = temporary_path("store-link");
            symlink(&target, &link).expect("create link");
            assert_eq!(
                FileStateStore::new(&link).load().unwrap_err().code,
                "invalid_state_store_path"
            );
            assert_eq!(
                FileStateStore::new(&link)
                    .save(&snapshot())
                    .unwrap_err()
                    .code,
                "invalid_state_store_path"
            );
            fs::remove_file(&link).expect("remove link");
            fs::remove_file(&target).expect("remove target");
        }
    }

    #[test]
    fn rejects_invalid_snapshot_content_before_writing() {
        let path = temporary_path("invalid-content");
        let store = FileStateStore::new(&path);

        let mut duplicates = snapshot();
        duplicates.cursors.push(cursor());
        assert_eq!(
            store.save(&duplicates).unwrap_err().code,
            "duplicate_cursor_stream"
        );

        let mut bad_vessel = snapshot();
        bad_vessel.vessels[0].last_source_sequence = 0;
        assert_eq!(
            store.save(&bad_vessel).unwrap_err().code,
            "invalid_vessel_sequence"
        );

        let mut inconsistent = snapshot();
        inconsistent.vessels[0].last_position.latitude = 7.0;
        assert_eq!(
            store.save(&inconsistent).unwrap_err().code,
            "inconsistent_vessel_state"
        );

        let mut bad_coordinate = snapshot();
        bad_coordinate.vessels[0].track[0].latitude = 95.0;
        assert_eq!(
            store.save(&bad_coordinate).unwrap_err().code,
            "invalid_coordinate"
        );

        let mut duplicate_vessels = snapshot();
        duplicate_vessels.vessels.push(vessel("vessel-001"));
        assert_eq!(
            store.save(&duplicate_vessels).unwrap_err().code,
            "duplicate_vessel_id"
        );
        assert!(!path.exists(), "invalid snapshots must never be written");
    }

    #[test]
    fn reload_survives_interrupted_write_leaving_previous_state() {
        let path = temporary_path("interrupted");
        let store = FileStateStore::new(&path);
        let first = snapshot();
        store.save(&first).expect("first save");
        // Simulate an interrupted second write: a leftover temp file exists but
        // the committed state file is untouched and still loads.
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&temporary, b"{\"partial").expect("write partial temp");
        assert_eq!(store.load().expect("state survives"), first);
        fs::remove_file(&temporary).expect("remove temp");
        fs::remove_file(&path).expect("remove store");
    }
}
