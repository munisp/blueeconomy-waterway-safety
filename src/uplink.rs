//! Uplink transports for the `ferries.telemetry.v1` ingestion surface
//! (Workstream B §3.2).
//!
//! The transport is selected by configuration only — a Dapr-style swap: the
//! same normalized [`TelemetryFrame`] batches flow through
//! [`TelemetryUploader`] regardless of whether the vessel talks to the pier
//! Fluvio cluster (connected profile) or replays its journal to the Kafka
//! fallback topic (intermittent profile).
//!
//! - `fluvio` (primary): real producer behind the `fluvio-transport` cargo
//!   feature. Fluvio applies producer-side compression (`compress` feature)
//!   and the pier-side SmartModule batches further.
//! - `kafka` (fallback): real blocking producer behind the `kafka-transport`
//!   cargo feature, for sites where only the Kafka topic
//!   `ferries.telemetry.v1` is reachable.
//!
//! Building without a transport feature is supported; selecting that
//! transport in configuration then fails closed with `transport_unavailable`.
//! There is intentionally no built-in loopback or in-memory transport in
//! production paths.
//!
//! ## Batching and compression
//!
//! [`BatchBuilder`] packs frames into JSON-lines batches bounded by record
//! count and byte size. Every batch carries a deterministic key: the SHA-256
//! of the schema domain, topic, and each frame's identity fields and payload
//! digest, so identical frame sequences always produce identical keys
//! (idempotent re-delivery after journal replay). Payload compression is
//! delegated to the transport layer — the Fluvio producer compresses records
//! natively and the Workstream B SmartModule compresses and batches
//! pier-side; adding a gateway-local `zstd` pass requires governance sign-off
//! for the new dependency and is deliberately not included yet.

use crate::{hex_lowercase, TelemetryFrame};
use sha2::{Digest, Sha256};

pub const BATCH_SCHEMA_DOMAIN: &str = "blueeconomy.waterway-safety.gateway-batch.v1";
pub const TELEMETRY_TOPIC: &str = "ferries.telemetry.v1";
pub const DEFAULT_BATCH_MAX_RECORDS: usize = 128;
pub const MAX_BATCH_RECORDS: usize = 4_096;
pub const DEFAULT_BATCH_MAX_BYTES: usize = 900_000;
pub const MAX_BATCH_BYTES: usize = 8_388_608;

/// A structured uplink failure. `code` is stable for alerting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UplinkError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for UplinkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for UplinkError {}

fn error(code: &'static str, message: impl Into<String>) -> UplinkError {
    UplinkError {
        code,
        message: message.into(),
    }
}

/// Config-selectable transports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    Fluvio,
    Kafka,
}

impl TransportKind {
    pub fn parse(value: &str) -> Result<Self, UplinkError> {
        match value {
            "fluvio" => Ok(Self::Fluvio),
            "kafka" => Ok(Self::Kafka),
            _ => Err(error(
                "invalid_transport_config",
                "transport must be 'fluvio' or 'kafka'",
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fluvio => "fluvio",
            Self::Kafka => "kafka",
        }
    }
}

/// Payload encoding of a batch. Only JSON-lines is emitted today; transport
/// compression is negotiated by the client (see module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchEncoding {
    JsonLines,
}

/// One deterministic, ready-to-send batch.
#[derive(Clone, Debug, PartialEq)]
pub struct TelemetryBatch {
    /// Deterministic idempotency key (hex SHA-256); also used as the
    /// Fluvio/Kafka record key.
    pub batch_key: String,
    pub topic: String,
    pub frame_count: usize,
    pub encoding: BatchEncoding,
    pub payload: Vec<u8>,
}

/// Explicit acknowledgement returned by a successful upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadReceipt {
    pub batch_key: String,
    pub topic: String,
    pub frame_count: usize,
}

/// The production uplink surface. Implementations must return an error
/// unless the batch was durably accepted; there is no fire-and-forget.
pub trait TelemetryUploader {
    fn upload(&mut self, batch: &TelemetryBatch) -> Result<UploadReceipt, UplinkError>;
}

/// Packs validated frames into bounded batches with deterministic keys.
#[derive(Clone, Debug)]
pub struct BatchBuilder {
    topic: String,
    max_records: usize,
    max_payload_bytes: usize,
}

impl BatchBuilder {
    pub fn new(
        topic: impl Into<String>,
        max_records: usize,
        max_payload_bytes: usize,
    ) -> Result<Self, UplinkError> {
        let topic = topic.into();
        if topic.is_empty() || topic.len() > 249 || topic.trim() != topic {
            return Err(error(
                "invalid_transport_config",
                "topic must be non-empty canonical text of at most 249 bytes",
            ));
        }
        if max_records == 0 || max_records > MAX_BATCH_RECORDS {
            return Err(error(
                "invalid_transport_config",
                format!("batch record limit must be between 1 and {MAX_BATCH_RECORDS}"),
            ));
        }
        if max_payload_bytes == 0 || max_payload_bytes > MAX_BATCH_BYTES {
            return Err(error(
                "invalid_transport_config",
                format!("batch byte limit must be between 1 and {MAX_BATCH_BYTES}"),
            ));
        }
        Ok(Self {
            topic,
            max_records,
            max_payload_bytes,
        })
    }

    /// Split `frames` into batches, preserving order. Empty input yields no
    /// batches. Deterministic: the same frames in the same order always
    /// produce byte-identical batches and keys.
    pub fn build(&self, frames: &[TelemetryFrame]) -> Result<Vec<TelemetryBatch>, UplinkError> {
        let mut batches: Vec<TelemetryBatch> = Vec::new();
        let mut current: Vec<&TelemetryFrame> = Vec::new();
        let mut current_bytes = 0usize;
        for frame in frames {
            let encoded = serde_json::to_vec(frame).map_err(|serde_error| UplinkError {
                code: "batch_encode_failed",
                message: serde_error.to_string(),
            })?;
            let line_bytes = encoded.len() + 1;
            if !current.is_empty()
                && (current.len() >= self.max_records
                    || current_bytes + line_bytes > self.max_payload_bytes)
            {
                batches.push(self.finish_batch(&current)?);
                current = Vec::new();
                current_bytes = 0;
            }
            current.push(frame);
            current_bytes += line_bytes;
        }
        if !current.is_empty() {
            batches.push(self.finish_batch(&current)?);
        }
        Ok(batches)
    }

    fn finish_batch(&self, frames: &[&TelemetryFrame]) -> Result<TelemetryBatch, UplinkError> {
        let mut payload: Vec<u8> = Vec::new();
        let mut digest = Sha256::new();
        digest.update(BATCH_SCHEMA_DOMAIN.as_bytes());
        digest.update([0]);
        digest.update(self.topic.as_bytes());
        digest.update([0]);
        for frame in frames {
            serde_json::to_writer(&mut payload, frame).map_err(|serde_error| UplinkError {
                code: "batch_encode_failed",
                message: serde_error.to_string(),
            })?;
            payload.push(b'\n');
            digest.update(frame.device_id.as_bytes());
            digest.update([0]);
            digest.update(frame.gateway_id.as_bytes());
            digest.update([0]);
            digest.update(frame.source_sequence.to_be_bytes());
            digest.update(frame.payload_sha256.as_bytes());
            digest.update([0]);
        }
        Ok(TelemetryBatch {
            batch_key: hex_lowercase(digest.finalize()),
            topic: self.topic.clone(),
            frame_count: frames.len(),
            encoding: BatchEncoding::JsonLines,
            payload,
        })
    }
}

/// Connect the configured transport. Fails closed with
/// `transport_unavailable` when the binary was built without the matching
/// cargo feature.
pub fn connect(
    kind: TransportKind,
    topic: &str,
    endpoint: &str,
) -> Result<Box<dyn TelemetryUploader>, UplinkError> {
    match kind {
        TransportKind::Fluvio => connect_fluvio(topic, endpoint),
        TransportKind::Kafka => connect_kafka(topic, endpoint),
    }
}

#[cfg(feature = "fluvio-transport")]
fn connect_fluvio(topic: &str, _endpoint: &str) -> Result<Box<dyn TelemetryUploader>, UplinkError> {
    Ok(Box::new(FluvioUploader::connect(topic)?))
}

#[cfg(not(feature = "fluvio-transport"))]
fn connect_fluvio(
    _topic: &str,
    _endpoint: &str,
) -> Result<Box<dyn TelemetryUploader>, UplinkError> {
    Err(error(
        "transport_unavailable",
        "fluvio transport requires rebuilding with --features fluvio-transport",
    ))
}

#[cfg(feature = "kafka-transport")]
fn connect_kafka(_topic: &str, endpoint: &str) -> Result<Box<dyn TelemetryUploader>, UplinkError> {
    Ok(Box::new(KafkaUploader::connect(endpoint)?))
}

#[cfg(not(feature = "kafka-transport"))]
fn connect_kafka(_topic: &str, _endpoint: &str) -> Result<Box<dyn TelemetryUploader>, UplinkError> {
    Err(error(
        "transport_unavailable",
        "kafka transport requires rebuilding with --features kafka-transport",
    ))
}

/// Primary transport: Fluvio producer for `ferries.telemetry.v1`.
#[cfg(feature = "fluvio-transport")]
pub struct FluvioUploader {
    producer: fluvio::TopicProducerPool,
}

#[cfg(feature = "fluvio-transport")]
impl FluvioUploader {
    /// Connect using the ambient Fluvio profile (`~/.fluvio/config`, managed
    /// by deployment). `endpoint`, when non-empty, overrides the profile
    /// host:port. The producer enables native record compression.
    pub fn connect(topic: &str) -> Result<Self, UplinkError> {
        Self::connect_with_endpoint(topic, "")
    }

    pub fn connect_with_endpoint(topic: &str, endpoint: &str) -> Result<Self, UplinkError> {
        let config = if endpoint.is_empty() {
            None
        } else {
            Some(fluvio::FluvioConfig::new(endpoint))
        };
        let fluvio = fluvio_future::task::run_block_on(async {
            match config {
                Some(config) => fluvio::Fluvio::connect_with_config(&config).await,
                None => fluvio::Fluvio::connect().await,
            }
        })
        .map_err(|fluvio_error| UplinkError {
            code: "uplink_connect_failed",
            message: fluvio_error.to_string(),
        })?;
        let producer_config = fluvio::TopicProducerConfigBuilder::default()
            .compression(fluvio::Compression::Zstd)
            .build()
            .map_err(|config_error| UplinkError {
                code: "invalid_transport_config",
                message: config_error.to_string(),
            })?;
        let topic_owned = topic.to_owned();
        let producer = fluvio_future::task::run_block_on({
            let topic = topic_owned.clone();
            async move {
                fluvio
                    .topic_producer_with_config(topic, producer_config)
                    .await
            }
        })
        .map_err(|fluvio_error| UplinkError {
            code: "uplink_connect_failed",
            message: fluvio_error.to_string(),
        })?;
        Ok(Self { producer })
    }
}

#[cfg(feature = "fluvio-transport")]
impl TelemetryUploader for FluvioUploader {
    fn upload(&mut self, batch: &TelemetryBatch) -> Result<UploadReceipt, UplinkError> {
        fluvio_future::task::run_block_on(async {
            self.producer
                .send(batch.batch_key.clone(), batch.payload.clone())
                .await
        })
        .map_err(|fluvio_error| UplinkError {
            code: "uplink_send_failed",
            message: fluvio_error.to_string(),
        })?;
        // send() is accepted-by-leader once its ProduceOutput resolves; an
        // explicit flush surfaces any asynchronous delivery error before we
        // acknowledge journal truncation.
        fluvio_future::task::run_block_on(self.producer.flush()).map_err(|fluvio_error| {
            UplinkError {
                code: "uplink_send_failed",
                message: fluvio_error.to_string(),
            }
        })?;
        Ok(UploadReceipt {
            batch_key: batch.batch_key.clone(),
            topic: batch.topic.clone(),
            frame_count: batch.frame_count,
        })
    }
}

/// Fallback transport: blocking Kafka producer for the same
/// `ferries.telemetry.v1` topic. Built on the `kafka` crate (Kafka protocol
/// 0.8.2-0.10); brokers that have dropped pre-1.0 Produce API versions need
/// the Fluvio path instead — this is a documented corridor fallback, not the
/// primary surface.
#[cfg(feature = "kafka-transport")]
pub struct KafkaUploader {
    producer: kafka::producer::Producer,
}

#[cfg(feature = "kafka-transport")]
impl KafkaUploader {
    /// `endpoint` is a comma-separated host:port bootstrap list.
    pub fn connect(endpoint: &str) -> Result<Self, UplinkError> {
        let hosts: Vec<String> = endpoint
            .split(',')
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(str::to_owned)
            .collect();
        if hosts.is_empty() {
            return Err(error(
                "invalid_transport_config",
                "kafka transport requires at least one bootstrap host",
            ));
        }
        let producer = kafka::producer::Producer::from_hosts(hosts)
            .with_required_acks(kafka::producer::RequiredAcks::All)
            .with_ack_timeout(std::time::Duration::from_secs(10))
            .create()
            .map_err(|kafka_error| UplinkError {
                code: "uplink_connect_failed",
                message: kafka_error.to_string(),
            })?;
        Ok(Self { producer })
    }
}

#[cfg(feature = "kafka-transport")]
impl TelemetryUploader for KafkaUploader {
    fn upload(&mut self, batch: &TelemetryBatch) -> Result<UploadReceipt, UplinkError> {
        let record = kafka::producer::Record {
            key: batch.batch_key.as_str(),
            value: batch.payload.as_slice(),
            topic: batch.topic.as_str(),
            partition: -1,
        };
        self.producer
            .send(&record)
            .map_err(|kafka_error| UplinkError {
                code: "uplink_send_failed",
                message: kafka_error.to_string(),
            })?;
        Ok(UploadReceipt {
            batch_key: batch.batch_key.clone(),
            topic: batch.topic.clone(),
            frame_count: batch.frame_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn batch_keys_are_deterministic_and_order_sensitive() {
        let builder = BatchBuilder::new(TELEMETRY_TOPIC, 128, 900_000).expect("builder");
        let frames: Vec<TelemetryFrame> = (1..=5).map(frame).collect();
        let first = builder.build(&frames).expect("batch");
        let second = builder.build(&frames).expect("batch");
        assert_eq!(first, second, "same frames must produce identical batches");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].batch_key.len(), 64);
        assert_eq!(first[0].frame_count, 5);
        assert_eq!(first[0].topic, TELEMETRY_TOPIC);

        let mut reversed = frames.clone();
        reversed.reverse();
        let reordered = builder.build(&reversed).expect("batch");
        assert_ne!(
            first[0].batch_key, reordered[0].batch_key,
            "different order must produce a different key"
        );
    }

    #[test]
    fn batch_builder_splits_on_record_and_byte_limits() {
        let frames: Vec<TelemetryFrame> = (1..=6).map(frame).collect();
        let by_count = BatchBuilder::new(TELEMETRY_TOPIC, 2, 900_000).expect("builder");
        let batches = by_count.build(&frames).expect("batches");
        assert_eq!(batches.len(), 3);
        assert!(batches.iter().all(|batch| batch.frame_count == 2));

        let one_line = serde_json::to_vec(&frame(1)).expect("encode").len() + 1;
        let by_bytes = BatchBuilder::new(TELEMETRY_TOPIC, 128, one_line * 2 + 1).expect("builder");
        let batches = by_bytes.build(&frames).expect("batches");
        assert_eq!(batches.len(), 3);
        assert!(batches
            .iter()
            .all(|batch| batch.payload.len() <= one_line * 2 + 1));
    }

    #[test]
    fn batch_payload_is_json_lines_of_frames() {
        let builder = BatchBuilder::new(TELEMETRY_TOPIC, 128, 900_000).expect("builder");
        let frames: Vec<TelemetryFrame> = (1..=3).map(frame).collect();
        let batches = builder.build(&frames).expect("batches");
        let lines: Vec<&[u8]> = batches[0]
            .payload
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(lines.len(), 3);
        for (line, frame) in lines.iter().zip(frames.iter()) {
            let decoded: TelemetryFrame = serde_json::from_slice(line).expect("frame json");
            assert_eq!(&decoded, frame);
        }
    }

    #[test]
    fn rejects_invalid_builder_and_transport_config() {
        assert_eq!(
            BatchBuilder::new("", 128, 900_000).unwrap_err().code,
            "invalid_transport_config"
        );
        assert_eq!(
            BatchBuilder::new(TELEMETRY_TOPIC, 0, 900_000)
                .unwrap_err()
                .code,
            "invalid_transport_config"
        );
        assert_eq!(
            BatchBuilder::new(TELEMETRY_TOPIC, 128, MAX_BATCH_BYTES + 1)
                .unwrap_err()
                .code,
            "invalid_transport_config"
        );
        assert_eq!(
            TransportKind::parse("mqtt").unwrap_err().code,
            "invalid_transport_config"
        );
        assert_eq!(TransportKind::parse("fluvio"), Ok(TransportKind::Fluvio));
        assert_eq!(TransportKind::parse("kafka"), Ok(TransportKind::Kafka));
    }

    #[cfg(not(feature = "fluvio-transport"))]
    #[test]
    fn uncompiled_transport_fails_closed() {
        let error = connect(TransportKind::Fluvio, TELEMETRY_TOPIC, "")
            .err()
            .expect("uncompiled fluvio transport must fail");
        assert_eq!(error.code, "transport_unavailable");
        let error = connect(TransportKind::Kafka, TELEMETRY_TOPIC, "127.0.0.1:9092")
            .err()
            .expect("uncompiled kafka transport must fail");
        assert_eq!(error.code, "transport_unavailable");
    }
}
