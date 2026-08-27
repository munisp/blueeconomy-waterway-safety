//! Append-only, checksummed local disk journal for the intermittent
//! connectivity profile (Workstream B §3.2).
//!
//! When the uplink is down the vessel-side gateway spools normalized
//! [`TelemetryFrame`]s here. Guarantees:
//!
//! - **Durability**: every record is length-framed, carries a SHA-256
//!   checksum, and is fsynced before [`SpoolJournal::append`] returns.
//! - **Rotation**: segments roll at `max_segment_bytes`.
//! - **Bounded size**: the journal never exceeds `max_journal_bytes`. On
//!   overflow the *oldest* sealed segments are moved to an explicit
//!   `overflow-dead-letter.jsonl` file and counted
//!   ([`JournalCounters::records_dead_lettered_overflow`]); overflow is never
//!   silent and never discards the newest data. If the dead-letter sink is
//!   itself full, the append fails closed with
//!   [`JournalError`](code `journal_overflow`) and no state changes.
//! - **At-least-once replay**: records are replayed in record-id order and
//!   physically removed only after [`SpoolJournal::ack_through`] confirms
//!   uplink acknowledgement. The ack cursor is persisted atomically
//!   (write-tempfile, fsync, rename, fsync parent — the `FileStateStore`
//!   convention), so a crash can cause re-delivery but never loss of
//!   unacknowledged data.
//! - **Fail closed on corruption**: opening a journal with a bad magic,
//!   version, length, checksum, or a torn tail record is an explicit
//!   `journal_corruption` error. Nothing is skipped, reset, or repaired
//!   silently.

use crate::ingest::DEAD_LETTER_SCHEMA_VERSION;
use crate::{hex_lowercase, TelemetryFrame, MAX_JSON_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub const JOURNAL_RECORD_MAGIC: u8 = 0x4A;
pub const JOURNAL_FORMAT_VERSION: u8 = 1;
pub const ACK_CURSOR_SCHEMA_VERSION: &str = "blueeconomy.waterway-safety.journal-ack.v1";
pub const DEFAULT_MAX_SEGMENT_BYTES: u64 = 4 * 1_048_576;
pub const DEFAULT_MAX_JOURNAL_BYTES: u64 = 64 * 1_048_576;
pub const DEFAULT_MAX_OVERFLOW_BYTES: u64 = 16 * 1_048_576;
pub const MAX_JOURNAL_BYTES_LIMIT: u64 = 1_073_741_824;
/// One record holds one frame; the frame JSON limit bounds the record.
pub const MAX_RECORD_PAYLOAD_BYTES: usize = MAX_JSON_BYTES;

const RECORD_HEADER_BYTES: usize = 14; // magic(1) version(1) id(8) len(4)
const RECORD_CHECKSUM_BYTES: usize = 32;
const SEGMENT_FILE_PREFIX: &str = "seg-";
const ACK_CURSOR_FILE: &str = "ack.cursor";
const OVERFLOW_FILE: &str = "overflow-dead-letter.jsonl";

/// A structured journal failure. `code` is stable for alerting (the Wazuh
/// rules match on it); `message` is diagnostic only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for JournalError {}

fn error(code: &'static str, message: impl Into<String>) -> JournalError {
    JournalError {
        code,
        message: message.into(),
    }
}

/// Operational counters; every destructive or lossy action is visible here.
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub struct JournalCounters {
    pub records_appended: u64,
    pub records_acked: u64,
    pub records_dead_lettered_overflow: u64,
    pub segments_rotated: u64,
    pub bytes_spooled: u64,
}

/// One journaled frame returned by [`SpoolJournal::replay`].
#[derive(Clone, Debug)]
pub struct JournalRecord {
    pub record_id: u64,
    pub frame: TelemetryFrame,
}

#[derive(Clone, Debug)]
struct RecordMeta {
    record_id: u64,
    frame: TelemetryFrame,
}

#[derive(Clone, Debug)]
struct SegmentIndex {
    segment_index: u64,
    byte_len: u64,
    sealed: bool,
    records: Vec<RecordMeta>,
}

impl SegmentIndex {
    fn last_record_id(&self) -> Option<u64> {
        self.records.last().map(|record| record.record_id)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AckCursorEnvelope {
    schema_version: String,
    payload_sha256: String,
    payload: AckCursorPayload,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AckCursorPayload {
    acked_record_id: u64,
}

#[derive(Debug, Serialize)]
struct OverflowDeadLetter<'a> {
    schema_version: &'a str,
    reason: &'static str,
    journal_record_id: u64,
    frame: &'a TelemetryFrame,
}

/// The journal. Not `Sync`; the gateway drives it from one thread.
#[derive(Debug)]
pub struct SpoolJournal {
    dir: PathBuf,
    max_segment_bytes: u64,
    max_journal_bytes: u64,
    max_overflow_bytes: u64,
    acked_record_id: u64,
    next_record_id: u64,
    active_segment_index: u64,
    active_segment_len: u64,
    segments: Vec<SegmentIndex>,
    counters: JournalCounters,
}

impl SpoolJournal {
    /// Open (or explicitly create) the journal in `dir`, verifying every
    /// record checksum. Any corruption fails closed.
    pub fn open(
        dir: impl Into<PathBuf>,
        max_segment_bytes: u64,
        max_journal_bytes: u64,
        max_overflow_bytes: u64,
    ) -> Result<Self, JournalError> {
        if max_segment_bytes == 0 || max_journal_bytes == 0 || max_overflow_bytes == 0 {
            return Err(error(
                "invalid_journal_config",
                "journal byte limits must be greater than zero",
            ));
        }
        if max_segment_bytes > max_journal_bytes || max_journal_bytes > MAX_JOURNAL_BYTES_LIMIT {
            return Err(error(
                "invalid_journal_config",
                format!(
                    "require 0 < max_segment_bytes <= max_journal_bytes <= {MAX_JOURNAL_BYTES_LIMIT}"
                ),
            ));
        }
        let dir = dir.into();
        if let Ok(metadata) = fs::symlink_metadata(&dir) {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(error(
                    "invalid_journal_path",
                    "journal path must be a real directory and not a symbolic link",
                ));
            }
        } else {
            fs::create_dir_all(&dir).map_err(|io| JournalError {
                code: "journal_io_failed",
                message: io.to_string(),
            })?;
        }
        let acked_record_id = load_ack_cursor(&dir)?;
        let mut segment_files: Vec<(u64, PathBuf)> = Vec::new();
        let entries = fs::read_dir(&dir).map_err(|io| JournalError {
            code: "journal_io_failed",
            message: io.to_string(),
        })?;
        for entry in entries {
            let entry = entry.map_err(|io| JournalError {
                code: "journal_io_failed",
                message: io.to_string(),
            })?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(rest) = name.strip_prefix(SEGMENT_FILE_PREFIX) {
                if let Some(number) = rest.strip_suffix(".jrn") {
                    let index: u64 = number.parse().map_err(|_| {
                        error(
                            "journal_corruption",
                            format!("segment file {name} has a non-numeric index"),
                        )
                    })?;
                    segment_files.push((index, entry.path()));
                }
            }
        }
        segment_files.sort_by_key(|(index, _)| *index);
        let mut segments: Vec<SegmentIndex> = Vec::new();
        let mut total_bytes = 0u64;
        let mut max_record_id = 0u64;
        for (index, path) in &segment_files {
            let segment = scan_segment(*index, path)?;
            if let Some(last) = segment.records.last() {
                max_record_id = max_record_id.max(last.record_id);
            }
            total_bytes = total_bytes.saturating_add(segment.byte_len);
            segments.push(segment);
        }
        let (active_segment_index, active_segment_len) = match segment_files.last() {
            Some((index, _)) => (
                *index,
                segments.last().map_or(0, |segment| segment.byte_len),
            ),
            None => (0, 0),
        };
        if let Some(last) = segments.last_mut() {
            last.sealed = false;
        }
        Ok(Self {
            dir,
            max_segment_bytes,
            max_journal_bytes,
            max_overflow_bytes,
            acked_record_id,
            next_record_id: max_record_id.saturating_add(1).max(1),
            active_segment_index,
            active_segment_len,
            segments,
            counters: JournalCounters {
                bytes_spooled: total_bytes,
                ..JournalCounters::default()
            },
        })
    }

    pub fn counters(&self) -> JournalCounters {
        self.counters
    }

    pub fn acked_record_id(&self) -> u64 {
        self.acked_record_id
    }

    pub fn pending_count(&self) -> usize {
        self.segments
            .iter()
            .flat_map(|segment| segment.records.iter())
            .filter(|record| record.record_id > self.acked_record_id)
            .count()
    }

    /// Append one frame. Returns the assigned record id. Fsynced before
    /// return; overflow handling is explicit (see module docs).
    pub fn append(&mut self, frame: &TelemetryFrame) -> Result<u64, JournalError> {
        let payload = serde_json::to_vec(frame).map_err(|serde_error| JournalError {
            code: "journal_encode_failed",
            message: serde_error.to_string(),
        })?;
        if payload.is_empty() || payload.len() > MAX_RECORD_PAYLOAD_BYTES {
            return Err(error(
                "record_too_large",
                format!(
                    "record payload must contain between 1 and {MAX_RECORD_PAYLOAD_BYTES} bytes"
                ),
            ));
        }
        let record_id = self.next_record_id;
        let record_len = (RECORD_HEADER_BYTES + payload.len() + RECORD_CHECKSUM_BYTES) as u64;
        self.enforce_journal_budget(record_len, record_id)?;
        if self.active_segment_len > 0
            && self.active_segment_len + record_len > self.max_segment_bytes
        {
            self.rotate_segment()?;
        }
        if self.segments.is_empty() {
            self.rotate_segment()?;
        }
        let encoded = encode_record(record_id, &payload);
        let path = self.segment_path(self.active_segment_index);
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|io| JournalError {
                code: "journal_io_failed",
                message: io.to_string(),
            })?;
        file.write_all(&encoded).map_err(|io| JournalError {
            code: "journal_io_failed",
            message: io.to_string(),
        })?;
        file.sync_all().map_err(|io| JournalError {
            code: "journal_io_failed",
            message: io.to_string(),
        })?;
        let encoded_len = encoded.len() as u64;
        if let Some(segment) = self.segments.last_mut() {
            segment.byte_len = segment.byte_len.saturating_add(encoded_len);
            segment.records.push(RecordMeta {
                record_id,
                frame: frame.clone(),
            });
        }
        self.active_segment_len = self.active_segment_len.saturating_add(encoded_len);
        self.next_record_id = self.next_record_id.saturating_add(1);
        self.counters.records_appended = self.counters.records_appended.saturating_add(1);
        self.counters.bytes_spooled = self.counters.bytes_spooled.saturating_add(encoded_len);
        Ok(record_id)
    }

    /// All unacknowledged records in record-id order.
    pub fn replay(&self) -> Vec<JournalRecord> {
        let mut pending: Vec<JournalRecord> = self
            .segments
            .iter()
            .flat_map(|segment| segment.records.iter())
            .filter(|record| record.record_id > self.acked_record_id)
            .map(|record| JournalRecord {
                record_id: record.record_id,
                frame: record.frame.clone(),
            })
            .collect();
        pending.sort_by_key(|record| record.record_id);
        pending
    }

    /// Mark every record up to and including `record_id` as acknowledged by
    /// the uplink. The ack cursor is persisted atomically *before* any
    /// segment file is removed, and only fully acknowledged sealed segments
    /// are deleted.
    pub fn ack_through(&mut self, record_id: u64) -> Result<(), JournalError> {
        if record_id <= self.acked_record_id {
            return Ok(());
        }
        if record_id >= self.next_record_id {
            return Err(error(
                "invalid_ack",
                format!("record id {record_id} has never been journaled"),
            ));
        }
        save_ack_cursor(&self.dir, record_id)?;
        self.acked_record_id = record_id;
        let mut retained: Vec<SegmentIndex> = Vec::new();
        let mut deleted: Vec<(u64, u64)> = Vec::new();
        for mut segment in self.segments.drain(..) {
            let fully_acked = segment
                .last_record_id()
                .is_some_and(|last| last <= record_id);
            if fully_acked && segment.sealed {
                self.counters.bytes_spooled =
                    self.counters.bytes_spooled.saturating_sub(segment.byte_len);
                deleted.push((segment.segment_index, segment.byte_len));
                continue;
            }
            segment
                .records
                .retain(|record| record.record_id > record_id);
            retained.push(segment);
        }
        self.segments = retained;
        for (segment_index, _) in &deleted {
            let path = segment_path(&self.dir, *segment_index);
            fs::remove_file(&path).map_err(|io| JournalError {
                code: "journal_io_failed",
                message: io.to_string(),
            })?;
        }
        self.counters.records_acked = record_id;
        Ok(())
    }

    fn segment_path(&self, index: u64) -> PathBuf {
        segment_path(&self.dir, index)
    }

    fn rotate_segment(&mut self) -> Result<(), JournalError> {
        if let Some(segment) = self.segments.last_mut() {
            segment.sealed = true;
        }
        self.active_segment_index = self.active_segment_index.saturating_add(1);
        self.active_segment_len = 0;
        self.counters.segments_rotated = self.counters.segments_rotated.saturating_add(1);
        let path = self.segment_path(self.active_segment_index);
        if path.exists() {
            return Err(error(
                "journal_corruption",
                "rotation target segment already exists",
            ));
        }
        self.segments.push(SegmentIndex {
            segment_index: self.active_segment_index,
            byte_len: 0,
            sealed: false,
            records: Vec::new(),
        });
        Ok(())
    }

    /// Keep total journal bytes within budget by dead-lettering the oldest
    /// sealed segments into the bounded overflow file. The active segment is
    /// never evicted; if the budget still cannot fit, fail closed.
    fn enforce_journal_budget(
        &mut self,
        incoming_record_len: u64,
        incoming_record_id: u64,
    ) -> Result<(), JournalError> {
        let mut projected = self
            .counters
            .bytes_spooled
            .saturating_add(incoming_record_len);
        while projected > self.max_journal_bytes {
            let candidate = self
                .segments
                .iter()
                .position(|segment| segment.sealed && !segment.records.is_empty());
            let Some(position) = candidate else {
                break;
            };
            let segment = self.segments.remove(position);
            self.dead_letter_segment(&segment)?;
            self.counters.bytes_spooled =
                self.counters.bytes_spooled.saturating_sub(segment.byte_len);
            self.counters.records_dead_lettered_overflow = self
                .counters
                .records_dead_lettered_overflow
                .saturating_add(segment.records.len() as u64);
            let path = self.segment_path(segment.segment_index);
            fs::remove_file(&path).map_err(|io| JournalError {
                code: "journal_io_failed",
                message: io.to_string(),
            })?;
            projected = self
                .counters
                .bytes_spooled
                .saturating_add(incoming_record_len);
        }
        if projected > self.max_journal_bytes {
            return Err(error(
                "journal_overflow",
                format!(
                    "journal budget {} bytes cannot fit record {incoming_record_id}; refusing to drop newest data",
                    self.max_journal_bytes
                ),
            ));
        }
        Ok(())
    }

    fn dead_letter_segment(&self, segment: &SegmentIndex) -> Result<(), JournalError> {
        let overflow_path = self.dir.join(OVERFLOW_FILE);
        let existing = fs::metadata(&overflow_path).map_or(0, |metadata| metadata.len());
        let mut encoded: Vec<u8> = Vec::new();
        for record in &segment.records {
            let dead_letter = OverflowDeadLetter {
                schema_version: DEAD_LETTER_SCHEMA_VERSION,
                reason: "journal_overflow",
                journal_record_id: record.record_id,
                frame: &record.frame,
            };
            serde_json::to_writer(&mut encoded, &dead_letter).map_err(|serde_error| {
                JournalError {
                    code: "journal_encode_failed",
                    message: serde_error.to_string(),
                }
            })?;
            encoded.push(b'\n');
        }
        if existing.saturating_add(encoded.len() as u64) > self.max_overflow_bytes {
            return Err(error(
                "journal_overflow",
                "overflow dead-letter sink is full; refusing to evict oldest segment",
            ));
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&overflow_path)
            .map_err(|io| JournalError {
                code: "journal_io_failed",
                message: io.to_string(),
            })?;
        file.write_all(&encoded).map_err(|io| JournalError {
            code: "journal_io_failed",
            message: io.to_string(),
        })?;
        file.sync_all().map_err(|io| JournalError {
            code: "journal_io_failed",
            message: io.to_string(),
        })?;
        Ok(())
    }
}

fn segment_path(dir: &Path, index: u64) -> PathBuf {
    dir.join(format!("{SEGMENT_FILE_PREFIX}{index:016}.jrn"))
}

fn encode_record(record_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut encoded =
        Vec::with_capacity(RECORD_HEADER_BYTES + payload.len() + RECORD_CHECKSUM_BYTES);
    encoded.push(JOURNAL_RECORD_MAGIC);
    encoded.push(JOURNAL_FORMAT_VERSION);
    encoded.extend_from_slice(&record_id.to_le_bytes());
    encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    encoded.extend_from_slice(payload);
    encoded.extend_from_slice(Sha256::digest(&encoded).as_slice());
    encoded
}

fn scan_segment(segment_index: u64, path: &Path) -> Result<SegmentIndex, JournalError> {
    let raw = fs::read(path).map_err(|io| JournalError {
        code: "journal_io_failed",
        message: io.to_string(),
    })?;
    fn corrupt(segment_index: u64, offset: usize, detail: impl Into<String>) -> JournalError {
        error(
            "journal_corruption",
            format!(
                "segment {segment_index} at offset {offset}: {}",
                detail.into()
            ),
        )
    }
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < raw.len() {
        if raw.len() - offset < RECORD_HEADER_BYTES + RECORD_CHECKSUM_BYTES {
            return Err(corrupt(segment_index, offset, "truncated record header"));
        }
        if raw[offset] != JOURNAL_RECORD_MAGIC {
            return Err(corrupt(segment_index, offset, "bad record magic"));
        }
        if raw[offset + 1] != JOURNAL_FORMAT_VERSION {
            return Err(corrupt(
                segment_index,
                offset,
                "unsupported record format version",
            ));
        }
        let record_id = u64::from_le_bytes(
            raw[offset + 2..offset + 10]
                .try_into()
                .map_err(|_| corrupt(segment_index, offset, "bad record id"))?,
        );
        let payload_len = u32::from_le_bytes(
            raw[offset + 10..offset + 14]
                .try_into()
                .map_err(|_| corrupt(segment_index, offset, "bad record length"))?,
        ) as usize;
        if payload_len == 0 || payload_len > MAX_RECORD_PAYLOAD_BYTES {
            return Err(corrupt(
                segment_index,
                offset,
                format!("record length {payload_len} out of bounds"),
            ));
        }
        let record_end = offset + RECORD_HEADER_BYTES + payload_len + RECORD_CHECKSUM_BYTES;
        if record_end > raw.len() {
            return Err(corrupt(
                segment_index,
                offset,
                "torn tail record: journal was not fully flushed; refusing to continue",
            ));
        }
        let body = &raw[offset..offset + RECORD_HEADER_BYTES + payload_len];
        let checksum = &raw[offset + RECORD_HEADER_BYTES + payload_len..record_end];
        if Sha256::digest(body).as_slice() != checksum {
            return Err(corrupt(
                segment_index,
                offset,
                format!("record {record_id} checksum mismatch"),
            ));
        }
        let frame: TelemetryFrame = serde_json::from_slice(
            &raw[offset + RECORD_HEADER_BYTES..offset + RECORD_HEADER_BYTES + payload_len],
        )
        .map_err(|serde_error| {
            corrupt(
                segment_index,
                offset,
                format!("record payload is not a frame: {serde_error}"),
            )
        })?;
        records.push(RecordMeta { record_id, frame });
        offset = record_end;
    }
    Ok(SegmentIndex {
        segment_index,
        byte_len: raw.len() as u64,
        sealed: true,
        records,
    })
}

fn load_ack_cursor(dir: &Path) -> Result<u64, JournalError> {
    let path = dir.join(ACK_CURSOR_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(0), // No cursor: replay everything (at-least-once).
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(error(
            "invalid_journal_path",
            "ack cursor must be a regular file and not a symbolic link",
        ));
    }
    let raw = fs::read(&path).map_err(|io| JournalError {
        code: "journal_io_failed",
        message: io.to_string(),
    })?;
    let envelope: AckCursorEnvelope =
        serde_json::from_slice(&raw).map_err(|serde_error| JournalError {
            code: "journal_corruption",
            message: format!("ack cursor is not valid JSON: {serde_error}"),
        })?;
    if envelope.schema_version != ACK_CURSOR_SCHEMA_VERSION {
        return Err(error(
            "journal_corruption",
            "ack cursor schema_version is not supported",
        ));
    }
    let payload_bytes =
        serde_json::to_vec(&envelope.payload).map_err(|serde_error| JournalError {
            code: "journal_encode_failed",
            message: serde_error.to_string(),
        })?;
    if hex_lowercase(Sha256::digest(payload_bytes)) != envelope.payload_sha256 {
        return Err(error(
            "journal_corruption",
            "ack cursor checksum mismatch; refusing to guess acknowledged state",
        ));
    }
    Ok(envelope.payload.acked_record_id)
}

fn save_ack_cursor(dir: &Path, acked_record_id: u64) -> Result<(), JournalError> {
    let payload = AckCursorPayload { acked_record_id };
    let payload_bytes = serde_json::to_vec(&payload).map_err(|serde_error| JournalError {
        code: "journal_encode_failed",
        message: serde_error.to_string(),
    })?;
    let envelope = AckCursorEnvelope {
        schema_version: ACK_CURSOR_SCHEMA_VERSION.to_owned(),
        payload_sha256: hex_lowercase(Sha256::digest(payload_bytes)),
        payload,
    };
    let encoded = serde_json::to_vec(&envelope).map_err(|serde_error| JournalError {
        code: "journal_encode_failed",
        message: serde_error.to_string(),
    })?;
    let path = dir.join(ACK_CURSOR_FILE);
    let temporary = dir.join(format!("ack.tmp-{}", std::process::id()));
    let write_result = (|| -> Result<(), JournalError> {
        let mut file = fs::File::create(&temporary).map_err(|io| JournalError {
            code: "journal_io_failed",
            message: io.to_string(),
        })?;
        file.write_all(&encoded).map_err(|io| JournalError {
            code: "journal_io_failed",
            message: io.to_string(),
        })?;
        file.sync_all().map_err(|io| JournalError {
            code: "journal_io_failed",
            message: io.to_string(),
        })?;
        Ok(())
    })();
    if let Err(write_error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(write_error);
    }
    fs::rename(&temporary, path).map_err(|io| {
        let _ = fs::remove_file(&temporary);
        JournalError {
            code: "journal_io_failed",
            message: io.to_string(),
        }
    })?;
    fs::File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|io| JournalError {
            code: "journal_io_failed",
            message: io.to_string(),
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blueeconomy-waterway-safety-journal-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ))
    }

    fn frame(sequence: u64) -> TelemetryFrame {
        TelemetryFrame {
            device_id: "device-001".to_owned(),
            gateway_id: "gateway-001".to_owned(),
            source_sequence: sequence,
            observed_at: "2026-08-21T00:00:00Z".to_owned(),
            received_at: "2026-08-21T00:00:01Z".to_owned(),
            data_classification: "internal".to_owned(),
            payload_base64: "Ynl0ZXM=".to_owned(),
            payload_sha256: hex_lowercase(Sha256::digest(b"bytes")),
        }
    }

    fn open(dir: &Path, segment: u64, total: u64, overflow: u64) -> SpoolJournal {
        SpoolJournal::open(dir, segment, total, overflow).expect("open journal")
    }

    #[test]
    fn spools_and_replays_in_record_order_across_reopen() {
        let dir = temporary_dir("roundtrip");
        let mut journal = open(&dir, 1_048_576, 8_388_608, 4_194_304);
        for sequence in 1..=5 {
            assert_eq!(journal.append(&frame(sequence)).expect("append"), sequence);
        }
        assert_eq!(journal.pending_count(), 5);
        drop(journal);
        let journal = open(&dir, 1_048_576, 8_388_608, 4_194_304);
        let replayed = journal.replay();
        let sequences: Vec<u64> = replayed
            .iter()
            .map(|record| record.frame.source_sequence)
            .collect();
        assert_eq!(sequences, vec![1, 2, 3, 4, 5]);
        let ids: Vec<u64> = replayed.iter().map(|record| record.record_id).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn rotates_segments_and_deletes_fully_acked_sealed_segments() {
        let dir = temporary_dir("rotate");
        // One record is ~350 bytes; segment budget 600 forces rotation each record.
        let mut journal = open(&dir, 600, 64 * 1_048_576, 4_194_304);
        for sequence in 1..=6 {
            journal.append(&frame(sequence)).expect("append");
        }
        let segment_files = fs::read_dir(&dir)
            .expect("read dir")
            .filter(|entry| {
                entry
                    .as_ref()
                    .expect("entry")
                    .file_name()
                    .to_str()
                    .expect("name")
                    .starts_with(SEGMENT_FILE_PREFIX)
            })
            .count();
        assert!(
            segment_files >= 3,
            "expected multiple segments, got {segment_files}"
        );
        assert!(journal.counters().segments_rotated >= 3);

        journal.ack_through(4).expect("ack");
        assert_eq!(journal.acked_record_id(), 4);
        let remaining: Vec<u64> = journal
            .replay()
            .iter()
            .map(|record| record.frame.source_sequence)
            .collect();
        assert_eq!(remaining, vec![5, 6]);
        drop(journal);

        // Ack cursor survives reopen: acknowledged records are never replayed.
        let journal = open(&dir, 600, 64 * 1_048_576, 4_194_304);
        let remaining: Vec<u64> = journal
            .replay()
            .iter()
            .map(|record| record.frame.source_sequence)
            .collect();
        assert_eq!(remaining, vec![5, 6]);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn rejects_ack_beyond_appended_records() {
        let dir = temporary_dir("bad-ack");
        let mut journal = open(&dir, 1_048_576, 8_388_608, 4_194_304);
        journal.append(&frame(1)).expect("append");
        assert_eq!(journal.ack_through(9).unwrap_err().code, "invalid_ack");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn overflow_dead_letters_oldest_sealed_segments_with_counters() {
        let dir = temporary_dir("overflow");
        // Record ~350 bytes: segment 600 rotates per record; total 1200 fits
        // two records, so appending four forces overflow eviction of seg 1+2.
        let mut journal = open(&dir, 600, 1200, 4_194_304);
        for sequence in 1..=4 {
            journal
                .append(&frame(sequence))
                .expect("append within budget");
        }
        let counters = journal.counters();
        assert!(
            counters.records_dead_lettered_overflow >= 1,
            "expected overflow dead letters, got {counters:?}"
        );
        assert!(counters.bytes_spooled <= 1200);
        let overflow = fs::read_to_string(dir.join(OVERFLOW_FILE)).expect("overflow file");
        assert!(overflow.contains("\"reason\":\"journal_overflow\""));
        assert!(overflow.contains(DEAD_LETTER_SCHEMA_VERSION));
        // Newest data survives; only the oldest was dead-lettered.
        let remaining: Vec<u64> = journal
            .replay()
            .iter()
            .map(|record| record.frame.source_sequence)
            .collect();
        assert_eq!(remaining.last(), Some(&4));
        assert!(!remaining.contains(&1));
        // Dead-lettered records stay evicted across reopen.
        drop(journal);
        let journal = open(&dir, 600, 1200, 4_194_304);
        assert!(!journal
            .replay()
            .iter()
            .any(|record| record.frame.source_sequence == 1));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn refuses_append_when_budget_cannot_fit_and_nothing_is_evictable() {
        let dir = temporary_dir("refuse");
        let mut journal = open(&dir, 600, 600, 4_194_304);
        journal.append(&frame(1)).expect("first append");
        let error = journal.append(&frame(2)).unwrap_err();
        assert_eq!(error.code, "journal_overflow");
        // The failed append changed nothing.
        assert_eq!(journal.pending_count(), 1);
        assert_eq!(
            journal.replay()[0].frame.source_sequence,
            1,
            "original record retained"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn fails_closed_on_checksum_corruption_and_torn_tail() {
        let dir = temporary_dir("corrupt");
        let mut journal = open(&dir, 1_048_576, 8_388_608, 4_194_304);
        for sequence in 1..=3 {
            journal.append(&frame(sequence)).expect("append");
        }
        drop(journal);
        let segment = dir.join(format!("{SEGMENT_FILE_PREFIX}{:016}.jrn", 1));
        let mut raw = fs::read(&segment).expect("read segment");
        raw[20] ^= 0xFF;
        fs::write(&segment, &raw).expect("corrupt segment");
        let error = SpoolJournal::open(&dir, 1_048_576, 8_388_608, 4_194_304).unwrap_err();
        assert_eq!(error.code, "journal_corruption");
        fs::remove_dir_all(&dir).expect("cleanup");

        // Simulate a torn tail (crash mid-append).
        let dir = temporary_dir("torn");
        let mut journal = open(&dir, 1_048_576, 8_388_608, 4_194_304);
        journal.append(&frame(1)).expect("append");
        drop(journal);
        let segment = dir.join(format!("{SEGMENT_FILE_PREFIX}{:016}.jrn", 1));
        let raw = fs::read(&segment).expect("read segment");
        fs::write(&segment, &raw[..raw.len() - 10]).expect("truncate segment");
        let error = SpoolJournal::open(&dir, 1_048_576, 8_388_608, 4_194_304).unwrap_err();
        assert_eq!(error.code, "journal_corruption");
        assert!(error.message.contains("torn tail") || error.message.contains("truncated"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn fails_closed_on_tampered_ack_cursor_and_rejects_symlink_dir() {
        let dir = temporary_dir("ack-tamper");
        let mut journal = open(&dir, 1_048_576, 8_388_608, 4_194_304);
        journal.append(&frame(1)).expect("append");
        journal.ack_through(1).expect("ack");
        drop(journal);
        let cursor = dir.join(ACK_CURSOR_FILE);
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&cursor).expect("read cursor")).expect("json");
        envelope["payload"]["acked_record_id"] = serde_json::Value::from(0);
        fs::write(&cursor, serde_json::to_vec(&envelope).expect("encode")).expect("tamper");
        let error = SpoolJournal::open(&dir, 1_048_576, 8_388_608, 4_194_304).unwrap_err();
        assert_eq!(error.code, "journal_corruption");
        fs::remove_dir_all(&dir).expect("cleanup");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = temporary_dir("symlink-target");
            fs::create_dir_all(&target).expect("target dir");
            let link = temporary_dir("journal-link");
            symlink(&target, &link).expect("symlink");
            let error = SpoolJournal::open(&link, 1_048_576, 8_388_608, 4_194_304).unwrap_err();
            assert_eq!(error.code, "invalid_journal_path");
            fs::remove_file(&link).expect("remove link");
            fs::remove_dir_all(&target).expect("remove target");
        }
    }

    #[test]
    fn rejects_invalid_limits() {
        let dir = temporary_dir("limits");
        assert_eq!(
            SpoolJournal::open(&dir, 0, 1024, 1024).unwrap_err().code,
            "invalid_journal_config"
        );
        assert_eq!(
            SpoolJournal::open(&dir, 2048, 1024, 1024).unwrap_err().code,
            "invalid_journal_config"
        );
        assert_eq!(
            SpoolJournal::open(&dir, 1024, MAX_JOURNAL_BYTES_LIMIT + 1, 1024)
                .unwrap_err()
                .code,
            "invalid_journal_config"
        );
    }
}
