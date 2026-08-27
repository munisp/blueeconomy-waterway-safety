//! Vessel-side edge gateway orchestration (Workstream B §3.2).
//!
//! Three ingestion inputs sit behind traits so the vessel hardware binding
//! can change without touching normalization:
//!
//! - [`AisSentenceSource`]: NMEA 0183 sentences from the AIS receiver's
//!   TCP/serial feed (parsed by [`crate::nmea`], RMC/GGA).
//! - [`SensorUplinkSource`]: LoRaWAN uplink JSON documents from the network
//!   server bridge (decoded by [`crate::sensor`]).
//! - [`HeartbeatSource`]: periodic gateway health ticks.
//!
//! Everything is normalized into [`TelemetryFrame`] and gated through the
//! crate's [`ReorderIngestor`](crate::ingest::ReorderIngestor) (validation +
//! watermark lateness window, default 300 s to match the five-minute
//! freshness KPI). Ordered frames are either uploaded immediately
//! (connected profile) or spooled to the [`SpoolJournal`](crate::journal)
//! (intermittent profile) and replayed oldest-first on recovery; journal
//! records are truncated only after the uplink acknowledges the batch that
//! carried them.

use crate::ingest::{
    DeadLetterEvent, DeadLetterReason, IngestOutcome, ReorderIngestor, DEAD_LETTER_SCHEMA_VERSION,
};
use crate::journal::{JournalCounters, JournalError, JournalRecord, SpoolJournal};
use crate::nmea::{self, GgaFix, NmeaSentence};
use crate::sensor::{self, SensorReading};
use crate::uplink::{BatchBuilder, TelemetryUploader, UplinkError};
use crate::{hex_lowercase, TelemetryFrame};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration, FixedOffset};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration as StdDuration, Instant, SystemTime};

pub const POSITION_PAYLOAD_SCHEMA: &str = "blueeconomy.waterway-safety.position.v1";
pub const SENSOR_PAYLOAD_SCHEMA: &str = "blueeconomy.waterway-safety.sensor.v1";
pub const HEARTBEAT_PAYLOAD_SCHEMA: &str = "blueeconomy.waterway-safety.gateway-heartbeat.v1";
pub const DEFAULT_HEARTBEAT_INTERVAL_SECONDS: u64 = 30;
/// GPS timestamps further into the future than this are clamped to gateway
/// time and counted; the `TelemetryFrame` contract requires
/// `observed_at <= received_at`.
pub const MAX_FUTURE_CLOCK_SKEW_SECONDS: i64 = 120;
/// A GGA time-of-day is combined with the wall-clock date; if that lands in
/// the future (midnight rollover), the previous day is used. RMC, which
/// carries a full date, is always preferred.
pub const GGA_FUTURE_TOLERANCE_SECONDS: i64 = 60;

/// A structured gateway failure for infrastructural (non-telemetry) faults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for GatewayError {}

impl From<JournalError> for GatewayError {
    fn from(journal_error: JournalError) -> Self {
        Self {
            code: journal_error.code,
            message: journal_error.message,
        }
    }
}

impl From<UplinkError> for GatewayError {
    fn from(uplink_error: UplinkError) -> Self {
        Self {
            code: uplink_error.code,
            message: uplink_error.message,
        }
    }
}

/// Blocking source of raw NMEA 0183 sentences (one per line).
pub trait AisSentenceSource {
    fn next_sentence(&mut self) -> Result<String, GatewayError>;
}

/// Blocking source of raw LoRaWAN uplink JSON documents.
pub trait SensorUplinkSource {
    fn next_uplink(&mut self) -> Result<Vec<u8>, GatewayError>;
}

/// Periodic health tick source; the core composes the payload from its own
/// live counters so heartbeats can never report stale state.
pub trait HeartbeatSource {
    fn next_tick(&mut self) -> Result<(), GatewayError>;
}

/// What the core did with one input.
#[derive(Clone, Debug, PartialEq)]
pub enum GatewayEvent {
    /// A frame was validated and accepted into the reorder buffer.
    Accepted {
        device_id: String,
        source_sequence: u64,
    },
    /// Malformed input was rejected with an explicit dead-letter record.
    DeadLetter(DeadLetterEvent),
}

/// Operational counters; emitted inside every heartbeat payload and matched
/// by the Wazuh sensor-health rules.
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub struct GatewayCounters {
    pub sentences_dead_lettered: u64,
    pub uplinks_dead_lettered: u64,
    pub clock_skew_clamps: u64,
    pub frames_journaled: u64,
    pub batches_uploaded: u64,
    pub batches_failed: u64,
    pub heartbeats_emitted: u64,
}

/// Static gateway configuration (from environment in the binary; see the
/// README configuration table).
#[derive(Clone, Debug)]
pub struct GatewayConfig {
    pub gateway_id: String,
    pub vessel_device_id: String,
    pub data_classification: String,
    pub topic: String,
    pub lateness_window_seconds: i64,
    pub heartbeat_interval_seconds: u64,
    pub journal_dir: PathBuf,
    pub journal_max_segment_bytes: u64,
    pub journal_max_bytes: u64,
    pub journal_max_overflow_bytes: u64,
    pub batch_max_records: usize,
    pub batch_max_bytes: usize,
}

impl GatewayConfig {
    pub fn validate(&self) -> Result<(), GatewayError> {
        for (field, value) in [
            ("gateway_id", &self.gateway_id),
            ("vessel_device_id", &self.vessel_device_id),
        ] {
            if value.is_empty()
                || value.len() > 256
                || value.trim() != value
                || value.chars().any(char::is_control)
            {
                return Err(GatewayError {
                    code: "invalid_gateway_config",
                    message: format!("{field} must be canonical non-control text of 1..=256 bytes"),
                });
            }
        }
        match self.data_classification.as_str() {
            "public" | "internal" | "confidential" | "restricted" | "highly_restricted" => {}
            _ => {
                return Err(GatewayError {
                    code: "invalid_gateway_config",
                    message: "data_classification is not an approved value".to_owned(),
                })
            }
        }
        if self.lateness_window_seconds <= 0
            || self.lateness_window_seconds > crate::ingest::MAX_LATENESS_WINDOW_SECONDS
        {
            return Err(GatewayError {
                code: "invalid_gateway_config",
                message: "lateness window outside the ingest bounds".to_owned(),
            });
        }
        if self.heartbeat_interval_seconds == 0 {
            return Err(GatewayError {
                code: "invalid_gateway_config",
                message: "heartbeat interval must be greater than zero".to_owned(),
            });
        }
        Ok(())
    }
}

/// Monotonic+wall hybrid clock. Anchored once at startup; `now` is the wall
/// anchor plus monotonic elapsed time, so a backward wall-clock jump (NTP
/// step, RTC fault on an unpowered RasPi) can never regress stamps.
pub struct HybridClock {
    anchor_instant: Instant,
    anchor_wall: SystemTime,
}

impl HybridClock {
    pub fn new() -> Self {
        Self {
            anchor_instant: Instant::now(),
            anchor_wall: SystemTime::now(),
        }
    }

    pub fn uptime(&self) -> StdDuration {
        self.anchor_instant.elapsed()
    }

    /// Current time as seconds-precision RFC 3339 UTC.
    pub fn now_rfc3339(&self) -> String {
        let wall = self.anchor_wall + self.uptime();
        let datetime: DateTime<chrono::Utc> = wall.into();
        datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    fn now_fixed(&self) -> DateTime<FixedOffset> {
        // now_rfc3339 always emits a well-formed seconds-precision UTC stamp.
        DateTime::parse_from_rfc3339(&self.now_rfc3339())
            .expect("hybrid clock emits valid RFC 3339")
    }
}

impl Default for HybridClock {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize)]
struct PositionPayload<'a> {
    schema_version: &'a str,
    source: &'a str,
    latitude: f64,
    longitude: f64,
    speed_knots: Option<f64>,
    course_degrees: Option<f64>,
}

#[derive(Serialize)]
struct SensorPayload<'a> {
    schema_version: &'a str,
    sensor: &'a str,
    rpm: Option<u16>,
    coolant_temp_celsius_tenths: Option<i16>,
    oil_pressure_kpa: Option<u16>,
    bilge_level_millimeters: Option<u16>,
    bilge_pump_active: Option<bool>,
    life_jacket_total: Option<u16>,
    life_jacket_present: Option<u16>,
    life_jacket_tamper_flags: Option<u8>,
}

#[derive(Serialize)]
struct HeartbeatPayload {
    schema_version: &'static str,
    uptime_seconds: u64,
    uplink_available: bool,
    journal: JournalCounters,
    gateway: GatewayCounters,
}

/// The fail-closed pipeline: normalize, order-gate, spool/upload.
pub struct GatewayCore {
    config: GatewayConfig,
    clock: HybridClock,
    ingestor: ReorderIngestor,
    journal: SpoolJournal,
    batch_builder: BatchBuilder,
    sequences: HashMap<String, u64>,
    pending_frames: HashMap<(String, String, u64), TelemetryFrame>,
    last_rmc_date: Option<chrono::NaiveDate>,
    uplink_available: bool,
    counters: GatewayCounters,
}

impl GatewayCore {
    pub fn new(config: GatewayConfig, clock: HybridClock) -> Result<Self, GatewayError> {
        config.validate()?;
        let ingestor =
            ReorderIngestor::new(config.lateness_window_seconds).map_err(|error| GatewayError {
                code: error.code,
                message: error.message,
            })?;
        let journal = SpoolJournal::open(
            &config.journal_dir,
            config.journal_max_segment_bytes,
            config.journal_max_bytes,
            config.journal_max_overflow_bytes,
        )?;
        let batch_builder = BatchBuilder::new(
            &config.topic,
            config.batch_max_records,
            config.batch_max_bytes,
        )?;
        Ok(Self {
            config,
            clock,
            ingestor,
            journal,
            batch_builder,
            sequences: HashMap::new(),
            pending_frames: HashMap::new(),
            last_rmc_date: None,
            uplink_available: true,
            counters: GatewayCounters::default(),
        })
    }

    pub fn counters(&self) -> GatewayCounters {
        self.counters
    }

    pub fn journal_counters(&self) -> JournalCounters {
        self.journal.counters()
    }

    pub fn uplink_available(&self) -> bool {
        self.uplink_available
    }

    /// Handle one raw NMEA sentence. Malformed sentences are dead-lettered
    /// explicitly; this method never panics on input.
    pub fn handle_sentence(&mut self, raw: &str) -> GatewayEvent {
        match nmea::parse_sentence(raw) {
            Ok(NmeaSentence::Rmc(fix)) => {
                self.last_rmc_date = Some(fix.observed_at.date_naive());
                let observed_at = self.stamp_observed_at(Some(fix.observed_at));
                let payload = PositionPayload {
                    schema_version: POSITION_PAYLOAD_SCHEMA,
                    source: "ais_rmc",
                    latitude: fix.latitude,
                    longitude: fix.longitude,
                    speed_knots: fix.speed_knots,
                    course_degrees: fix.course_degrees,
                };
                let device_id = self.config.vessel_device_id.clone();
                self.emit_frame(&device_id, &payload, observed_at)
            }
            Ok(NmeaSentence::Gga(fix)) => {
                let observed_at = self.stamp_gga(&fix);
                let payload = PositionPayload {
                    schema_version: POSITION_PAYLOAD_SCHEMA,
                    source: "ais_gga",
                    latitude: fix.latitude,
                    longitude: fix.longitude,
                    speed_knots: None,
                    course_degrees: None,
                };
                let device_id = self.config.vessel_device_id.clone();
                self.emit_frame(&device_id, &payload, observed_at)
            }
            Err(parse_error) => {
                self.counters.sentences_dead_lettered =
                    self.counters.sentences_dead_lettered.saturating_add(1);
                GatewayEvent::DeadLetter(raw_dead_letter(
                    raw.as_bytes(),
                    parse_error.code,
                    &parse_error.message,
                ))
            }
        }
    }

    /// Handle one raw LoRaWAN uplink JSON document.
    pub fn handle_uplink(&mut self, raw: &[u8]) -> GatewayEvent {
        match sensor::decode_uplink(raw) {
            Ok(uplink) => {
                let device_id = format!("lorawan-{}", uplink.dev_eui);
                let payload = match &uplink.reading {
                    SensorReading::Engine {
                        rpm,
                        coolant_temp_celsius_tenths,
                        oil_pressure_kpa,
                    } => SensorPayload {
                        schema_version: SENSOR_PAYLOAD_SCHEMA,
                        sensor: "engine",
                        rpm: Some(*rpm),
                        coolant_temp_celsius_tenths: Some(*coolant_temp_celsius_tenths),
                        oil_pressure_kpa: Some(*oil_pressure_kpa),
                        bilge_level_millimeters: None,
                        bilge_pump_active: None,
                        life_jacket_total: None,
                        life_jacket_present: None,
                        life_jacket_tamper_flags: None,
                    },
                    SensorReading::Bilge {
                        level_millimeters,
                        pump_active,
                    } => SensorPayload {
                        schema_version: SENSOR_PAYLOAD_SCHEMA,
                        sensor: "bilge",
                        rpm: None,
                        coolant_temp_celsius_tenths: None,
                        oil_pressure_kpa: None,
                        bilge_level_millimeters: Some(*level_millimeters),
                        bilge_pump_active: Some(*pump_active),
                        life_jacket_total: None,
                        life_jacket_present: None,
                        life_jacket_tamper_flags: None,
                    },
                    SensorReading::LifeJacket {
                        total_count,
                        present_count,
                        tamper_flags,
                    } => SensorPayload {
                        schema_version: SENSOR_PAYLOAD_SCHEMA,
                        sensor: "life_jacket",
                        rpm: None,
                        coolant_temp_celsius_tenths: None,
                        oil_pressure_kpa: None,
                        bilge_level_millimeters: None,
                        bilge_pump_active: None,
                        life_jacket_total: Some(*total_count),
                        life_jacket_present: Some(*present_count),
                        life_jacket_tamper_flags: Some(*tamper_flags),
                    },
                };
                let observed_at = self.stamp_observed_at(None);
                self.emit_frame(&device_id, &payload, observed_at)
            }
            Err(decode_error) => {
                self.counters.uplinks_dead_lettered =
                    self.counters.uplinks_dead_lettered.saturating_add(1);
                GatewayEvent::DeadLetter(raw_dead_letter(
                    raw,
                    decode_error.code,
                    &decode_error.message,
                ))
            }
        }
    }

    /// Emit one gateway health heartbeat frame. The payload carries the live
    /// journal and gateway counters so pier-side monitoring (Wazuh rules
    /// 100101+) sees overflow, dead-letter, and failure transitions.
    pub fn handle_heartbeat_tick(&mut self) -> GatewayEvent {
        let device_id = format!("gateway-health-{}", self.config.gateway_id);
        let payload = HeartbeatPayload {
            schema_version: HEARTBEAT_PAYLOAD_SCHEMA,
            uptime_seconds: self.clock.uptime().as_secs(),
            uplink_available: self.uplink_available,
            journal: self.journal.counters(),
            gateway: self.counters,
        };
        self.counters.heartbeats_emitted = self.counters.heartbeats_emitted.saturating_add(1);
        let observed_at = self.stamp_observed_at(None);
        self.emit_frame(&device_id, &payload, observed_at)
    }

    /// Stamp `observed_at` from GPS/NMEA time when available (clamped to now
    /// minus nothing — future skew beyond [`MAX_FUTURE_CLOCK_SKEW_SECONDS`]
    /// is clamped and counted), otherwise from the hybrid clock.
    fn stamp_observed_at(&mut self, gps_time: Option<DateTime<FixedOffset>>) -> String {
        match gps_time {
            Some(time) => {
                let now = self.clock.now_fixed();
                if time > now + Duration::seconds(MAX_FUTURE_CLOCK_SKEW_SECONDS) {
                    self.counters.clock_skew_clamps =
                        self.counters.clock_skew_clamps.saturating_add(1);
                    self.clock.now_rfc3339()
                } else {
                    time.format("%Y-%m-%dT%H:%M:%SZ").to_string()
                }
            }
            None => self.clock.now_rfc3339(),
        }
    }

    /// Combine a GGA time-of-day with the most recent RMC date, or the
    /// wall-clock date when no RMC has been seen (documented heuristic).
    fn stamp_gga(&mut self, fix: &GgaFix) -> String {
        let now = self.clock.now_fixed();
        let date = self.last_rmc_date.unwrap_or_else(|| now.date_naive());
        let naive = date.and_time(fix.time_of_day);
        let offset = now.offset();
        let mut stamped: DateTime<FixedOffset> =
            DateTime::from_naive_utc_and_offset(naive, *offset);
        if stamped > now + Duration::seconds(GGA_FUTURE_TOLERANCE_SECONDS) {
            stamped -= Duration::days(1);
        }
        stamped.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    fn emit_frame(
        &mut self,
        device_id: &str,
        payload: &impl Serialize,
        observed_at: String,
    ) -> GatewayEvent {
        let payload_bytes = match serde_json::to_vec(payload) {
            Ok(bytes) => bytes,
            Err(serde_error) => {
                return GatewayEvent::DeadLetter(raw_dead_letter(
                    device_id.as_bytes(),
                    "payload_encode_failed",
                    &serde_error.to_string(),
                ))
            }
        };
        let sequence = self
            .sequences
            .entry(device_id.to_owned())
            .and_modify(|next| *next = next.saturating_add(1))
            .or_insert(1);
        let frame = TelemetryFrame {
            device_id: device_id.to_owned(),
            gateway_id: self.config.gateway_id.clone(),
            source_sequence: *sequence,
            observed_at,
            received_at: self.clock.now_rfc3339(),
            data_classification: self.config.data_classification.clone(),
            payload_base64: STANDARD.encode(&payload_bytes),
            payload_sha256: hex_lowercase(Sha256::digest(payload_bytes)),
        };
        match self.ingestor.ingest(frame.clone()) {
            IngestOutcome::Buffered => {
                self.pending_frames.insert(
                    (
                        frame.device_id.clone(),
                        frame.gateway_id.clone(),
                        frame.source_sequence,
                    ),
                    frame,
                );
                GatewayEvent::Accepted {
                    device_id: device_id.to_owned(),
                    source_sequence: *sequence,
                }
            }
            IngestOutcome::DeadLettered => {
                let dead_letter =
                    self.ingestor
                        .dead_letters()
                        .last()
                        .cloned()
                        .unwrap_or_else(|| {
                            raw_dead_letter(
                                device_id.as_bytes(),
                                "ingest_rejected",
                                "frame rejected",
                            )
                        });
                GatewayEvent::DeadLetter(dead_letter)
            }
        }
    }

    /// Frames that passed the lateness window, in `(observed_at,
    /// source_sequence)` order, with their payloads restored.
    pub fn drain_ready_frames(&mut self) -> Vec<TelemetryFrame> {
        let mut frames = Vec::new();
        for event in self.ingestor.drain_ready() {
            let key = (
                event.device_id.clone(),
                event.gateway_id.clone(),
                event.source_sequence,
            );
            if let Some(frame) = self.pending_frames.remove(&key) {
                frames.push(frame);
            }
        }
        frames
    }

    /// Flush all remaining buffered frames (end-of-stream only).
    pub fn finalize_frames(&mut self) -> Vec<TelemetryFrame> {
        let mut frames = Vec::new();
        for event in self.ingestor.finalize() {
            let key = (
                event.device_id.clone(),
                event.gateway_id.clone(),
                event.source_sequence,
            );
            if let Some(frame) = self.pending_frames.remove(&key) {
                frames.push(frame);
            }
        }
        frames
    }

    /// Spool frames to the journal (intermittent profile / uplink down).
    pub fn spool(&mut self, frames: &[TelemetryFrame]) -> Result<u64, GatewayError> {
        let mut last_record_id = 0;
        for frame in frames {
            last_record_id = self.journal.append(frame)?;
            self.counters.frames_journaled = self.counters.frames_journaled.saturating_add(1);
        }
        Ok(last_record_id)
    }

    /// Upload frames directly (connected profile). On failure the frames are
    /// spooled instead — the caller never loses data on an uplink fault.
    pub fn upload_or_spool(
        &mut self,
        uploader: &mut dyn TelemetryUploader,
        frames: &[TelemetryFrame],
    ) -> Result<(), GatewayError> {
        if frames.is_empty() {
            return Ok(());
        }
        if !self.uplink_available {
            self.spool(frames)?;
            return Ok(());
        }
        let batches = self.batch_builder.build(frames)?;
        let mut frame_offset = 0usize;
        for batch in &batches {
            match uploader.upload(batch) {
                Ok(_) => {
                    self.counters.batches_uploaded =
                        self.counters.batches_uploaded.saturating_add(1);
                    frame_offset += batch.frame_count;
                }
                Err(upload_error) => {
                    self.counters.batches_failed = self.counters.batches_failed.saturating_add(1);
                    self.uplink_available = false;
                    // Fail safe: everything not yet acknowledged is spooled.
                    self.spool(&frames[frame_offset..])?;
                    return Err(upload_error.into());
                }
            }
        }
        Ok(())
    }

    /// Replay the journal oldest-first after connectivity recovery; truncate
    /// records only after the batch carrying them is acknowledged. Stops at
    /// the first failure, leaving unacknowledged records spooled.
    pub fn replay_journal(
        &mut self,
        uploader: &mut dyn TelemetryUploader,
    ) -> Result<usize, GatewayError> {
        let pending: Vec<JournalRecord> = self.journal.replay();
        let mut uploaded = 0usize;
        let mut index = 0usize;
        while index < pending.len() {
            let end = (index + self.config.batch_max_records).min(pending.len());
            let chunk = &pending[index..end];
            let frames: Vec<TelemetryFrame> =
                chunk.iter().map(|record| record.frame.clone()).collect();
            let batches = self.batch_builder.build(&frames)?;
            let mut chunk_offset = 0usize;
            let mut failed = false;
            for batch in &batches {
                match uploader.upload(batch) {
                    Ok(_) => {
                        self.counters.batches_uploaded =
                            self.counters.batches_uploaded.saturating_add(1);
                        chunk_offset += batch.frame_count;
                        let acked_id = chunk[chunk_offset - 1].record_id;
                        self.journal.ack_through(acked_id)?;
                    }
                    Err(upload_error) => {
                        self.counters.batches_failed =
                            self.counters.batches_failed.saturating_add(1);
                        self.uplink_available = false;
                        let _ = upload_error;
                        failed = true;
                        break;
                    }
                }
            }
            uploaded += chunk_offset;
            if failed {
                break;
            }
            index = end;
        }
        if uploaded > 0 && self.journal.pending_count() == 0 {
            self.uplink_available = true;
        }
        Ok(uploaded)
    }

    /// Mark the uplink healthy again (e.g., after a successful probe).
    pub fn mark_uplink_recovered(&mut self) {
        self.uplink_available = true;
    }
}

fn raw_dead_letter(raw: &[u8], error_code: &'static str, detail: &str) -> DeadLetterEvent {
    let truncated = hex_lowercase(&raw[..raw.len().min(256)]);
    DeadLetterEvent {
        schema_version: DEAD_LETTER_SCHEMA_VERSION.to_owned(),
        reason: DeadLetterReason::InvalidFrame,
        error_code: error_code.to_owned(),
        device_id: String::new(),
        gateway_id: String::new(),
        source_sequence: 0,
        observed_at: String::new(),
        frame_digest_sha256: hex_lowercase(Sha256::digest(raw)),
        detail: format!("{detail}; raw_hex_prefix={truncated}"),
    }
}
