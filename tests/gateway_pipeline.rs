//! End-to-end gateway pipeline tests: NMEA/sensor normalization, reorder
//! integration, and journal spool/replay with acknowledgement-gated
//! truncation. Uses an in-test uploader (test-only; production builds ship
//! no in-memory transport).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use blueeconomy_waterway_safety::gateway::{GatewayConfig, GatewayCore, GatewayEvent, HybridClock};
use blueeconomy_waterway_safety::ingest::DeadLetterReason;
use blueeconomy_waterway_safety::sensor::LORAWAN_UPLINK_SCHEMA_VERSION;
use blueeconomy_waterway_safety::uplink::{
    TelemetryBatch, TelemetryUploader, UplinkError, UploadReceipt, TELEMETRY_TOPIC,
};
use blueeconomy_waterway_safety::TelemetryFrame;
use chrono::{DateTime, Duration, Utc};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn temporary_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "blueeconomy-waterway-safety-gateway-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ))
}

fn config(dir: &Path) -> GatewayConfig {
    GatewayConfig {
        gateway_id: "gateway-test-001".to_owned(),
        vessel_device_id: "vessel-001".to_owned(),
        data_classification: "internal".to_owned(),
        topic: TELEMETRY_TOPIC.to_owned(),
        lateness_window_seconds: 300,
        heartbeat_interval_seconds: 30,
        journal_dir: dir.to_path_buf(),
        journal_max_segment_bytes: 1_048_576,
        journal_max_bytes: 8_388_608,
        journal_max_overflow_bytes: 4_194_304,
        batch_max_records: 128,
        batch_max_bytes: 900_000,
    }
}

fn checksummed(content: &str) -> String {
    let checksum = content.bytes().fold(0u8, |acc, byte| acc ^ byte);
    format!("${content}*{checksum:02X}\r\n")
}

/// A valid RMC sentence stamped `offset` seconds from wall-clock now.
fn rmc(offset_seconds: i64) -> String {
    let time: DateTime<Utc> = Utc::now() + Duration::seconds(offset_seconds);
    checksummed(&format!(
        "GPRMC,{},A,0622.417,N,00307.512,E,012.0,090.0,{},,,A",
        time.format("%H%M%S"),
        time.format("%d%m%y"),
    ))
}

fn engine_uplink() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": LORAWAN_UPLINK_SCHEMA_VERSION,
        "dev_eui": "0018b2aabbccddee",
        "fport": 10,
        "payload_base64": STANDARD.encode([0x0B, 0xB8, 0x03, 0x5C, 0x01, 0x90]),
    }))
    .expect("encode uplink")
}

fn decode_payload(frame: &TelemetryFrame) -> serde_json::Value {
    let raw = STANDARD
        .decode(frame.payload_base64.as_bytes())
        .expect("base64");
    serde_json::from_slice(&raw).expect("payload json")
}

struct MemoryUploader {
    /// Number of uploads that succeed; every later upload fails.
    succeed: usize,
    batches: Vec<TelemetryBatch>,
}

impl MemoryUploader {
    fn working() -> Self {
        Self {
            succeed: usize::MAX,
            batches: Vec::new(),
        }
    }

    fn failing_immediately() -> Self {
        Self {
            succeed: 0,
            batches: Vec::new(),
        }
    }

    fn succeed_then_fail(succeed: usize) -> Self {
        Self {
            succeed,
            batches: Vec::new(),
        }
    }
}

impl TelemetryUploader for MemoryUploader {
    fn upload(&mut self, batch: &TelemetryBatch) -> Result<UploadReceipt, UplinkError> {
        if self.batches.len() >= self.succeed {
            return Err(UplinkError {
                code: "uplink_send_failed",
                message: "scripted outage".to_owned(),
            });
        }
        self.batches.push(batch.clone());
        Ok(UploadReceipt {
            batch_key: batch.batch_key.clone(),
            topic: batch.topic.clone(),
            frame_count: batch.frame_count,
        })
    }
}

#[test]
fn rmc_sentence_normalizes_to_gps_stamped_position_frame() {
    let dir = temporary_dir("rmc");
    let mut core = GatewayCore::new(config(&dir), HybridClock::new()).expect("core");
    let sentence = rmc(-30);
    let event = core.handle_sentence(&sentence);
    let GatewayEvent::Accepted {
        device_id,
        source_sequence,
    } = event
    else {
        panic!("expected acceptance, got {event:?}");
    };
    assert_eq!(device_id, "vessel-001");
    assert_eq!(source_sequence, 1);
    let frames = core.finalize_frames();
    assert_eq!(frames.len(), 1);
    let frame = &frames[0];
    blueeconomy_waterway_safety::validate(frame.clone()).expect("frame must validate");
    let payload = decode_payload(frame);
    assert_eq!(payload["source"], "ais_rmc");
    assert!((payload["latitude"].as_f64().expect("lat") - 6.3736167).abs() < 1e-4);
    assert!((payload["longitude"].as_f64().expect("lon") - 3.1252).abs() < 1e-4);
    assert_eq!(payload["speed_knots"], 12.0);
    // observed_at comes from GPS time, not the gateway clock.
    assert!(frame.observed_at < frame.received_at);
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn malformed_sentences_are_dead_lettered_never_panic() {
    let dir = temporary_dir("malformed");
    let mut core = GatewayCore::new(config(&dir), HybridClock::new()).expect("core");
    for raw in [
        "$GPRMC,bad*00\r\n".to_owned(),
        "not a sentence at all".to_owned(),
        "!AIVDM,1,1,,B,33P@?P0000PD;88MD5MTDwwP0000,0*5C\r\n".to_owned(),
        String::new(),
    ] {
        let event = core.handle_sentence(&raw);
        let GatewayEvent::DeadLetter(dead_letter) = event else {
            panic!("expected dead letter, got {event:?}");
        };
        assert_eq!(dead_letter.reason, DeadLetterReason::InvalidFrame);
        assert_eq!(dead_letter.frame_digest_sha256.len(), 64);
    }
    assert_eq!(core.counters().sentences_dead_lettered, 4);
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn sensor_uplink_normalizes_and_bad_uplinks_dead_letter() {
    let dir = temporary_dir("sensor");
    let mut core = GatewayCore::new(config(&dir), HybridClock::new()).expect("core");
    let event = core.handle_uplink(&engine_uplink());
    assert!(matches!(event, GatewayEvent::Accepted { .. }));
    let frames = core.finalize_frames();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].device_id, "lorawan-0018b2aabbccddee");
    let payload = decode_payload(&frames[0]);
    assert_eq!(payload["sensor"], "engine");
    assert_eq!(payload["rpm"], 3000);
    assert_eq!(payload["coolant_temp_celsius_tenths"], 860);

    let event = core.handle_uplink(b"{not json");
    assert!(matches!(event, GatewayEvent::DeadLetter(_)));
    assert_eq!(core.counters().uplinks_dead_lettered, 1);
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn reorder_integration_emits_frames_in_observed_time_order() {
    let dir = temporary_dir("reorder");
    let mut core = GatewayCore::new(config(&dir), HybridClock::new()).expect("core");
    // Arrival order: -540s, -600s (out of order), 0s. The 300-second
    // lateness window tolerates the inversion; the watermark driven to `now`
    // makes both stale frames ready, emitted in observed-time order.
    assert!(matches!(
        core.handle_sentence(&rmc(-540)),
        GatewayEvent::Accepted { .. }
    ));
    assert!(matches!(
        core.handle_sentence(&rmc(-600)),
        GatewayEvent::Accepted { .. }
    ));
    assert!(matches!(
        core.handle_sentence(&rmc(0)),
        GatewayEvent::Accepted { .. }
    ));
    let ready = core.drain_ready_frames();
    let sequences: Vec<u64> = ready.iter().map(|frame| frame.source_sequence).collect();
    assert_eq!(sequences, vec![2, 1], "older observation emits first");
    let remaining = core.finalize_frames();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].source_sequence, 3);
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn stale_frame_beyond_freshness_window_is_dead_lettered() {
    let dir = temporary_dir("stale");
    let mut core = GatewayCore::new(config(&dir), HybridClock::new()).expect("core");
    assert!(matches!(
        core.handle_sentence(&rmc(0)),
        GatewayEvent::Accepted { .. }
    ));
    // An hour old: beyond the 5-minute KPI window once the watermark is now.
    let event = core.handle_sentence(&rmc(-3600));
    let GatewayEvent::DeadLetter(dead_letter) = event else {
        panic!("expected stale dead letter, got {event:?}");
    };
    assert_eq!(dead_letter.reason, DeadLetterReason::LateBeyondWindow);
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn outage_spools_then_recovery_replays_and_truncates_after_ack() {
    let dir = temporary_dir("outage");
    let mut core = GatewayCore::new(config(&dir), HybridClock::new()).expect("core");
    for offset in [-120, -60, 0] {
        core.handle_sentence(&rmc(offset));
    }
    let frames = core.finalize_frames();
    assert_eq!(frames.len(), 3);

    // Uplink down: frames are spooled, nothing is lost.
    let mut down = MemoryUploader::failing_immediately();
    let error = core
        .upload_or_spool(&mut down, &frames)
        .expect_err("outage surfaces");
    assert_eq!(error.code, "uplink_send_failed");
    assert!(!core.uplink_available());
    assert_eq!(core.counters().frames_journaled, 3);
    assert_eq!(core.journal_counters().records_appended, 3);

    // Recovery: replay in order, truncate only after acknowledgement.
    core.mark_uplink_recovered();
    let mut up = MemoryUploader::working();
    let replayed = core.replay_journal(&mut up).expect("replay");
    assert_eq!(replayed, 3);
    assert_eq!(core.journal_counters().records_acked, 3);
    assert!(core.uplink_available());
    let delivered: Vec<u64> = up
        .batches
        .iter()
        .flat_map(|batch| batch.payload.split(|byte| *byte == b'\n'))
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice::<TelemetryFrame>(line)
                .expect("frame")
                .source_sequence
        })
        .collect();
    assert_eq!(delivered, vec![1, 2, 3], "replayed oldest first");
    drop(core);

    // A restarted gateway must not redeliver acknowledged records.
    let mut core = GatewayCore::new(config(&dir), HybridClock::new()).expect("core");
    let mut up = MemoryUploader::working();
    assert_eq!(core.replay_journal(&mut up).expect("replay"), 0);
    assert!(up.batches.is_empty());
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn partial_replay_failure_acks_only_confirmed_records() {
    let dir = temporary_dir("partial");
    let mut cfg = config(&dir);
    cfg.batch_max_records = 1; // one frame per batch to force per-batch acks
    let mut core = GatewayCore::new(cfg, HybridClock::new()).expect("core");
    for offset in [-120, -60, 0] {
        core.handle_sentence(&rmc(offset));
    }
    let frames = core.finalize_frames();
    let mut down = MemoryUploader::failing_immediately();
    let _ = core.upload_or_spool(&mut down, &frames);
    assert_eq!(core.journal_counters().records_appended, 3);

    // Replay with the second batch failing: exactly one record is acked and
    // truncated; the rest stay spooled.
    core.mark_uplink_recovered();
    let mut flaky = MemoryUploader::succeed_then_fail(1);
    let replayed = core.replay_journal(&mut flaky).expect("partial replay");
    assert_eq!(replayed, 1);
    assert_eq!(core.journal_counters().records_acked, 1);
    assert!(!core.uplink_available());
    assert!(core.journal_counters().bytes_spooled > 0);
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn future_gps_time_is_clamped_and_counted() {
    let dir = temporary_dir("skew");
    let mut core = GatewayCore::new(config(&dir), HybridClock::new()).expect("core");
    // GPS claims a time two hours in the future (RTC/satellite fault).
    let event = core.handle_sentence(&rmc(7200));
    assert!(matches!(event, GatewayEvent::Accepted { .. }));
    let frames = core.finalize_frames();
    assert_eq!(core.counters().clock_skew_clamps, 1);
    // Clamped to gateway time so observed_at never exceeds received_at.
    assert!(frames[0].observed_at <= frames[0].received_at);
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn heartbeat_carries_live_counters() {
    let dir = temporary_dir("heartbeat");
    let mut core = GatewayCore::new(config(&dir), HybridClock::new()).expect("core");
    let event = core.handle_heartbeat_tick();
    assert!(matches!(event, GatewayEvent::Accepted { .. }));
    let frames = core.finalize_frames();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].device_id, "gateway-health-gateway-test-001");
    let payload = decode_payload(&frames[0]);
    assert_eq!(
        payload["schema_version"],
        "blueeconomy.waterway-safety.gateway-heartbeat.v1"
    );
    assert_eq!(payload["uplink_available"], true);
    assert!(payload["journal"]["records_appended"].is_u64());
    assert_eq!(core.counters().heartbeats_emitted, 1);
    std::fs::remove_dir_all(dir).expect("cleanup");
}
