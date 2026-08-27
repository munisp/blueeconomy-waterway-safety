//! Out-of-order tolerant ingestion for `ferries.telemetry.v1` streams.
//!
//! Telemetry frames are validated, buffered, and re-emitted ordered by
//! `(observed_at, source_sequence)`. A watermark equal to the maximum observed
//! `observed_at` drives the configurable lateness window: an event is emitted
//! only once it is older than `watermark - window`, and any event arriving
//! later than the window is rejected to an explicit dead-letter outcome and is
//! never silently applied.

use crate::{hex_lowercase, validate, TelemetryFrame, ValidatedTelemetry, ValidationError};
use chrono::{DateTime, FixedOffset, TimeDelta};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const DEFAULT_LATENESS_WINDOW_SECONDS: i64 = 120;
pub const MAX_LATENESS_WINDOW_SECONDS: i64 = 86_400;
pub const MAX_PENDING_EVENTS: usize = 100_000;
pub const DEAD_LETTER_SCHEMA_VERSION: &str = "blueeconomy.waterway-safety.dead-letter.v1";
const DEAD_LETTER_FIELD_LIMIT: usize = 256;

/// Why an event was rejected to the dead-letter outcome.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeadLetterReason {
    InvalidFrame,
    LateBeyondWindow,
    BufferCapacityExceeded,
}

/// Durable, explicit record of a rejected event. Field values are truncated to
/// a bounded length because rejected frames may carry malformed identifiers.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DeadLetterEvent {
    pub schema_version: String,
    pub reason: DeadLetterReason,
    pub error_code: String,
    pub device_id: String,
    pub gateway_id: String,
    pub source_sequence: u64,
    pub observed_at: String,
    pub frame_digest_sha256: String,
    pub detail: String,
}

/// The outcome of offering one frame to the ingestor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestOutcome {
    Buffered,
    DeadLettered,
}

/// Stateful reorder buffer with a watermark-driven lateness window.
#[derive(Debug)]
pub struct ReorderIngestor {
    lateness_window_seconds: i64,
    watermark: Option<DateTime<FixedOffset>>,
    pending: Vec<ValidatedTelemetry>,
    dead_letters: Vec<DeadLetterEvent>,
}

impl ReorderIngestor {
    pub fn new(lateness_window_seconds: i64) -> Result<Self, ValidationError> {
        if lateness_window_seconds <= 0 || lateness_window_seconds > MAX_LATENESS_WINDOW_SECONDS {
            return Err(ValidationError {
                code: "invalid_lateness_window",
                message: format!(
                    "lateness window must be between 1 and {MAX_LATENESS_WINDOW_SECONDS} seconds"
                ),
            });
        }
        Ok(Self {
            lateness_window_seconds,
            watermark: None,
            pending: Vec::new(),
            dead_letters: Vec::new(),
        })
    }

    pub fn lateness_window_seconds(&self) -> i64 {
        self.lateness_window_seconds
    }

    pub fn watermark(&self) -> Option<DateTime<FixedOffset>> {
        self.watermark
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn dead_letters(&self) -> &[DeadLetterEvent] {
        &self.dead_letters
    }

    /// Validate and buffer one frame. Returns [`IngestOutcome::DeadLettered`]
    /// (recording an explicit [`DeadLetterEvent`]) for invalid frames, frames
    /// observed earlier than `watermark - lateness_window`, and frames offered
    /// while the buffer is at capacity. Valid in-window frames are buffered
    /// for ordered emission.
    pub fn ingest(&mut self, frame: TelemetryFrame) -> IngestOutcome {
        let validated = match validate(frame.clone()) {
            Ok(validated) => validated,
            Err(error) => {
                self.dead_letters.push(dead_letter(
                    &frame,
                    DeadLetterReason::InvalidFrame,
                    error.code,
                    &error.message,
                ));
                return IngestOutcome::DeadLettered;
            }
        };
        let observed_at = DateTime::parse_from_rfc3339(&validated.observed_at)
            .expect("validated frames carry RFC 3339 timestamps");
        if let Some(watermark) = self.watermark {
            let lateness_threshold = watermark - TimeDelta::seconds(self.lateness_window_seconds);
            if observed_at < lateness_threshold {
                self.dead_letters.push(dead_letter(
                    &frame,
                    DeadLetterReason::LateBeyondWindow,
                    "event_late_beyond_window",
                    "observed_at is older than watermark minus the lateness window",
                ));
                return IngestOutcome::DeadLettered;
            }
        }
        if self.pending.len() >= MAX_PENDING_EVENTS {
            self.dead_letters.push(dead_letter(
                &frame,
                DeadLetterReason::BufferCapacityExceeded,
                "reorder_buffer_capacity_exceeded",
                "reorder buffer is at capacity; event refused rather than evicting another",
            ));
            return IngestOutcome::DeadLettered;
        }
        self.watermark = Some(match self.watermark {
            Some(watermark) => watermark.max(observed_at),
            None => observed_at,
        });
        self.pending.push(validated);
        IngestOutcome::Buffered
    }

    /// Emits every buffered event that is older than
    /// `watermark - lateness_window`, ordered by `(observed_at,
    /// source_sequence)`. Such events can no longer be reordered: anything
    /// older arriving later is dead-lettered by [`Self::ingest`].
    pub fn drain_ready(&mut self) -> Vec<ValidatedTelemetry> {
        let Some(watermark) = self.watermark else {
            return Vec::new();
        };
        let threshold = watermark - TimeDelta::seconds(self.lateness_window_seconds);
        let mut ready: Vec<ValidatedTelemetry> = Vec::new();
        let mut retained: Vec<ValidatedTelemetry> = Vec::new();
        for event in self.pending.drain(..) {
            let observed_at = DateTime::parse_from_rfc3339(&event.observed_at)
                .expect("validated frames carry RFC 3339 timestamps");
            if observed_at <= threshold {
                ready.push(event);
            } else {
                retained.push(event);
            }
        }
        self.pending = retained;
        sort_events(&mut ready);
        ready
    }

    /// Flushes every remaining buffered event in `(observed_at,
    /// source_sequence)` order. Call only at end-of-stream; after finalization
    /// no reordering protection remains for the flushed events.
    pub fn finalize(&mut self) -> Vec<ValidatedTelemetry> {
        let mut remaining: Vec<ValidatedTelemetry> = std::mem::take(&mut self.pending);
        sort_events(&mut remaining);
        remaining
    }
}

fn sort_events(events: &mut [ValidatedTelemetry]) {
    events.sort_by(|left, right| {
        (&left.observed_at, left.source_sequence).cmp(&(&right.observed_at, right.source_sequence))
    });
}

fn dead_letter(
    frame: &TelemetryFrame,
    reason: DeadLetterReason,
    error_code: &'static str,
    detail: &str,
) -> DeadLetterEvent {
    let encoded = serde_json::to_vec(frame).unwrap_or_default();
    DeadLetterEvent {
        schema_version: DEAD_LETTER_SCHEMA_VERSION.to_owned(),
        reason,
        error_code: error_code.to_owned(),
        device_id: truncate_field(&frame.device_id),
        gateway_id: truncate_field(&frame.gateway_id),
        source_sequence: frame.source_sequence,
        observed_at: truncate_field(&frame.observed_at),
        frame_digest_sha256: hex_lowercase(Sha256::digest(encoded)),
        detail: detail.to_owned(),
    }
}

fn truncate_field(value: &str) -> String {
    if value.len() <= DEAD_LETTER_FIELD_LIMIT {
        return value.to_owned();
    }
    let mut end = DEAD_LETTER_FIELD_LIMIT;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(sequence: u64, observed_at: &str, received_at: &str) -> TelemetryFrame {
        TelemetryFrame {
            device_id: "device-001".to_owned(),
            gateway_id: "gateway-001".to_owned(),
            source_sequence: sequence,
            observed_at: observed_at.to_owned(),
            received_at: received_at.to_owned(),
            data_classification: "internal".to_owned(),
            payload_base64: "Ynl0ZXM=".to_owned(),
            payload_sha256: hex_lowercase(Sha256::digest(b"bytes")),
        }
    }

    #[test]
    fn reorders_out_of_order_events_within_lateness_window() {
        let mut ingestor = ReorderIngestor::new(60).expect("window");
        // Watermark advances to 00:02:00.
        assert_eq!(
            ingestor.ingest(frame(3, "2026-08-21T00:02:00Z", "2026-08-21T00:02:01Z")),
            IngestOutcome::Buffered
        );
        // Arrives out of order but within the 60-second window.
        assert_eq!(
            ingestor.ingest(frame(1, "2026-08-21T00:01:20Z", "2026-08-21T00:02:02Z")),
            IngestOutcome::Buffered
        );
        assert_eq!(
            ingestor.ingest(frame(2, "2026-08-21T00:01:40Z", "2026-08-21T00:02:03Z")),
            IngestOutcome::Buffered
        );
        // Threshold is 00:01:00; nothing is old enough to emit yet.
        assert!(ingestor.drain_ready().is_empty());
        // Advance the watermark so the threshold passes all buffered events.
        assert_eq!(
            ingestor.ingest(frame(4, "2026-08-21T00:03:30Z", "2026-08-21T00:03:31Z")),
            IngestOutcome::Buffered
        );
        let ready = ingestor.drain_ready();
        let sequences: Vec<u64> = ready.iter().map(|event| event.source_sequence).collect();
        assert_eq!(sequences, vec![1, 2, 3]);
        assert_eq!(ingestor.pending_count(), 1);
        let remaining = ingestor.finalize();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].source_sequence, 4);
        assert!(ingestor.dead_letters().is_empty());
    }

    #[test]
    fn rejects_late_beyond_window_events_to_dead_letter_never_applied() {
        let mut ingestor = ReorderIngestor::new(30).expect("window");
        assert_eq!(
            ingestor.ingest(frame(2, "2026-08-21T00:02:00Z", "2026-08-21T00:02:01Z")),
            IngestOutcome::Buffered
        );
        // Threshold is 00:01:30; this event at 00:01:00 is too late.
        assert_eq!(
            ingestor.ingest(frame(1, "2026-08-21T00:01:00Z", "2026-08-21T00:02:02Z")),
            IngestOutcome::DeadLettered
        );
        assert_eq!(ingestor.pending_count(), 1);
        let dead_letters = ingestor.dead_letters();
        assert_eq!(dead_letters.len(), 1);
        assert_eq!(dead_letters[0].reason, DeadLetterReason::LateBeyondWindow);
        assert_eq!(dead_letters[0].error_code, "event_late_beyond_window");
        assert_eq!(dead_letters[0].source_sequence, 1);
        assert_eq!(dead_letters[0].frame_digest_sha256.len(), 64);
        // The late event is not present in any emission.
        assert!(ingestor
            .finalize()
            .iter()
            .all(|event| event.source_sequence != 1));
    }

    #[test]
    fn accepts_event_exactly_at_lateness_threshold() {
        let mut ingestor = ReorderIngestor::new(30).expect("window");
        ingestor.ingest(frame(2, "2026-08-21T00:02:00Z", "2026-08-21T00:02:01Z"));
        // Exactly watermark - window: still inside the window.
        assert_eq!(
            ingestor.ingest(frame(1, "2026-08-21T00:01:30Z", "2026-08-21T00:02:02Z")),
            IngestOutcome::Buffered
        );
        assert_eq!(ingestor.dead_letters().len(), 0);
    }

    #[test]
    fn dead_letters_invalid_frames_with_truncated_metadata() {
        let mut ingestor = ReorderIngestor::new(30).expect("window");
        let mut bad = frame(0, "2026-08-21T00:02:00Z", "2026-08-21T00:02:01Z");
        bad.device_id = format!("{}🚢", "x".repeat(600));
        assert_eq!(ingestor.ingest(bad), IngestOutcome::DeadLettered);
        let dead_letters = ingestor.dead_letters();
        assert_eq!(dead_letters.len(), 1);
        assert_eq!(dead_letters[0].reason, DeadLetterReason::InvalidFrame);
        assert_eq!(dead_letters[0].error_code, "invalid_identifier");
        assert!(dead_letters[0].device_id.len() <= DEAD_LETTER_FIELD_LIMIT);
        assert!(dead_letters[0]
            .device_id
            .is_char_boundary(dead_letters[0].device_id.len()));
    }

    #[test]
    fn rejects_invalid_lateness_window_configuration() {
        assert_eq!(
            ReorderIngestor::new(0).unwrap_err().code,
            "invalid_lateness_window"
        );
        assert_eq!(
            ReorderIngestor::new(-5).unwrap_err().code,
            "invalid_lateness_window"
        );
        assert_eq!(
            ReorderIngestor::new(MAX_LATENESS_WINDOW_SECONDS + 1)
                .unwrap_err()
                .code,
            "invalid_lateness_window"
        );
        assert!(ReorderIngestor::new(DEFAULT_LATENESS_WINDOW_SECONDS).is_ok());
    }
}
