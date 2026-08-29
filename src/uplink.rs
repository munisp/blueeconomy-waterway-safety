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
//! - `mqtt` (device-plane, PRA-088): MQTT publish to the EMQX broker behind
//!   the `mqtt-transport` cargo feature. The gateway authenticates AS A
//!   REGISTERED DEVICE against the geo-service device plane via the broker's
//!   HTTP authn webhook (`/v1/devices/mqtt-auth`): the MQTT client id is the
//!   registered device id and the password is the Ed25519 signed proof over
//!   the JCS-canonical `{"action":"MQTT_AUTH","deviceId":...,"keyEpoch":N}`
//!   payload (JWS kid `geo-device-<deviceId>-<epoch>`) — the same contract
//!   the geo `devices.Verifier.VerifyProof` enforces. The connection is
//!   driven to CONNACK at startup, so an unreachable broker or a rejected
//!   device credential fails closed before any frame is accepted.
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

use crate::provenance::{ProvenanceSigner, PRODUCER};
use crate::{hex_lowercase, TelemetryFrame};
use sha2::{Digest, Sha256};

/// JSON-lines record type tag of the batch provenance header line.
pub const BATCH_PROVENANCE_RECORD_TYPE: &str = "blueeconomy.waterway-safety.batch-provenance.v1";

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
    Mqtt,
}

impl TransportKind {
    pub fn parse(value: &str) -> Result<Self, UplinkError> {
        match value {
            "fluvio" => Ok(Self::Fluvio),
            "kafka" => Ok(Self::Kafka),
            "mqtt" => Ok(Self::Mqtt),
            _ => Err(error(
                "invalid_transport_config",
                "transport must be 'fluvio', 'kafka' or 'mqtt'",
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fluvio => "fluvio",
            Self::Kafka => "kafka",
            Self::Mqtt => "mqtt",
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
    /// When the builder holds a provenance signer, the payload is a
    /// self-describing provenance header line (record type
    /// [`BATCH_PROVENANCE_RECORD_TYPE`]) followed by the frame lines, and
    /// these fields carry the fleet provenance signature (JWS EdDSA over the
    /// JCS-canonicalized batch document). Without a signer the payload is
    /// exactly the frame lines and both fields are `None`.
    pub payload: Vec<u8>,
    pub signature_key_id: Option<String>,
    pub provenance_signature: Option<String>,
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
    signer: Option<ProvenanceSigner>,
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
            signer: None,
        })
    }

    /// Attaches the fleet provenance signer. Once attached, every batch
    /// carries a signed provenance header line; the production gateway wires
    /// this fail-closed from `PROVENANCE_SIGNING_KEY` at startup.
    pub fn set_signer(&mut self, signer: ProvenanceSigner) {
        self.signer = Some(signer);
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
        let batch_key = hex_lowercase(digest.finalize());
        let mut signature_key_id = None;
        let mut provenance_signature = None;
        if let Some(signer) = &self.signer {
            let document = self.batch_document(&batch_key, frames)?;
            let canonical = crate::provenance::canonicalize(&document).map_err(|e| UplinkError {
                code: "provenance_signing_failed",
                message: e.message,
            })?;
            let signature = signer.sign(&canonical);
            let header = serde_json::json!({
                "record_type": BATCH_PROVENANCE_RECORD_TYPE,
                "batch_key": batch_key,
                "frame_count": frames.len(),
                "producer": PRODUCER,
                "schema": BATCH_SCHEMA_DOMAIN,
                "topic": self.topic,
                "signature_key_id": signer.key_id(),
                "signature": signature,
            });
            let mut header_line = serde_json::to_vec(&header).map_err(|serde_error| UplinkError {
                code: "batch_encode_failed",
                message: serde_error.to_string(),
            })?;
            header_line.push(b'\n');
            header_line.extend_from_slice(&payload);
            payload = header_line;
            signature_key_id = Some(signer.key_id().to_owned());
            provenance_signature = Some(signature);
        }
        Ok(TelemetryBatch {
            batch_key,
            topic: self.topic.clone(),
            frame_count: frames.len(),
            encoding: BatchEncoding::JsonLines,
            payload,
            signature_key_id,
            provenance_signature,
        })
    }

    /// The signed batch document: the full batch envelope excluding the
    /// signature field, JCS-canonicalized for the JWS payload.
    fn batch_document(
        &self,
        batch_key: &str,
        frames: &[&TelemetryFrame],
    ) -> Result<serde_json::Value, UplinkError> {
        let mut frame_values = Vec::with_capacity(frames.len());
        for frame in frames {
            frame_values
                .push(serde_json::to_value(frame).map_err(|serde_error| UplinkError {
                    code: "batch_encode_failed",
                    message: serde_error.to_string(),
                })?);
        }
        Ok(serde_json::json!({
            "batchKey": batch_key,
            "encoding": "json-lines",
            "frameCount": frames.len(),
            "frames": frame_values,
            "producer": PRODUCER,
            "schema": BATCH_SCHEMA_DOMAIN,
            "topic": self.topic,
        }))
    }
}

/// Environment variables of the device-plane MQTT credential (PRA-088).
pub const ENV_MQTT_DEVICE_ID: &str = "UPLINK_MQTT_DEVICE_ID";
pub const ENV_MQTT_KEY_EPOCH: &str = "UPLINK_MQTT_KEY_EPOCH";
pub const ENV_MQTT_DEVICE_PRIVATE_KEY: &str = "UPLINK_MQTT_DEVICE_PRIVATE_KEY";
pub const ENV_MQTT_TLS_CA_CERT: &str = "UPLINK_MQTT_TLS_CA_CERT";

/// Proof action the geo device plane expects for broker authentication
/// (`devices.ProofActionMQTTAuth`).
pub const MQTT_PROOF_ACTION: &str = "MQTT_AUTH";

/// Device-plane MQTT credential (geo-service `/v1/devices/mqtt-auth`
/// contract): the gateway's registered device identity plus the signed
/// proof it presents as the MQTT password. Built fail-closed at startup —
/// an absent or malformed credential is a startup error, never a runtime
/// surprise.
#[derive(Clone, Debug)]
pub struct MqttDeviceAuth {
    device_id: String,
    key_epoch: u32,
    /// JWS compact proof: EdDSA over the JCS-canonical
    /// `{"action":"MQTT_AUTH","deviceId":...,"keyEpoch":N}` payload with kid
    /// `geo-device-<deviceId>-<epoch>`.
    proof: String,
    /// Optional PEM CA path enabling the MQTTS listener (8883).
    tls_ca_cert_path: Option<String>,
}

impl MqttDeviceAuth {
    /// Resolves the credential from the environment (fail-closed): the
    /// device id, the registered key epoch and the device private key are
    /// all required; the TLS CA path is optional.
    pub fn from_env() -> Result<Self, UplinkError> {
        Self::from_env_with(|name| std::env::var(name).ok())
    }

    /// Test seam for environment resolution.
    pub fn from_env_with(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, UplinkError> {
        let read = |name: &str| -> Result<String, UplinkError> {
            lookup(name)
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty())
                .ok_or_else(|| {
                    error(
                        "invalid_transport_config",
                        format!(
                            "{name} is required for the mqtt transport (device-plane broker \
                             authentication is mandatory — no anonymous uplink exists)"
                        ),
                    )
                })
        };
        let device_id = read(ENV_MQTT_DEVICE_ID)?;
        let epoch_raw = read(ENV_MQTT_KEY_EPOCH)?;
        let key_epoch: u32 = epoch_raw.parse().map_err(|_| {
            error(
                "invalid_transport_config",
                format!("{ENV_MQTT_KEY_EPOCH} must be a positive integer key epoch"),
            )
        })?;
        let key_b64 = read(ENV_MQTT_DEVICE_PRIVATE_KEY)?;
        let key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            key_b64.as_bytes(),
        )
        .map_err(|_| {
            error(
                "invalid_transport_config",
                format!("{ENV_MQTT_DEVICE_PRIVATE_KEY} must be base64url Ed25519 key material"),
            )
        })?;
        let tls_ca_cert_path = lookup(ENV_MQTT_TLS_CA_CERT)
            .map(|raw| raw.trim().to_owned())
            .filter(|raw| !raw.is_empty());
        Self::from_parts(&device_id, key_epoch, &key_bytes, tls_ca_cert_path)
    }

    /// Validates the parts and builds the signed broker proof.
    pub fn from_parts(
        device_id: &str,
        key_epoch: u32,
        key_bytes: &[u8],
        tls_ca_cert_path: Option<String>,
    ) -> Result<Self, UplinkError> {
        let device_id = device_id.trim();
        if !is_uuid(device_id) {
            return Err(error(
                "invalid_transport_config",
                format!("{ENV_MQTT_DEVICE_ID} must be the registered device UUID"),
            ));
        }
        if key_epoch == 0 {
            return Err(error(
                "invalid_transport_config",
                format!("{ENV_MQTT_KEY_EPOCH} must be a positive integer key epoch"),
            ));
        }
        let kid = mqtt_proof_key_id(device_id, key_epoch);
        let signer = ProvenanceSigner::new(&kid, key_bytes).map_err(|key_error| {
            error(
                "invalid_transport_config",
                format!("{ENV_MQTT_DEVICE_PRIVATE_KEY} is invalid: {}", key_error.message),
            )
        })?;
        let proof_payload = serde_json::json!({
            "action": MQTT_PROOF_ACTION,
            "deviceId": device_id,
            "keyEpoch": key_epoch,
        });
        let canonical = crate::provenance::canonicalize(&proof_payload).map_err(|e| {
            error(
                "invalid_transport_config",
                format!("failed to canonicalize the MQTT auth proof: {}", e.message),
            )
        })?;
        let proof = signer.sign(&canonical);
        Ok(Self {
            device_id: device_id.to_owned(),
            key_epoch,
            proof,
            tls_ca_cert_path,
        })
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn key_epoch(&self) -> u32 {
        self.key_epoch
    }

    /// The JWS compact proof presented as the MQTT password.
    pub fn proof(&self) -> &str {
        &self.proof
    }

    pub fn tls_ca_cert_path(&self) -> Option<&str> {
        self.tls_ca_cert_path.as_deref()
    }
}

/// The JWS kid the geo device plane binds to one device key epoch
/// (`devices.KeyID`).
pub fn mqtt_proof_key_id(device_id: &str, key_epoch: u32) -> String {
    format!("geo-device-{device_id}-{key_epoch}")
}

/// RFC 4122 UUID shape check (the geo registry keys devices by UUID).
fn is_uuid(value: &str) -> bool {
    let segments: Vec<&str> = value.split('-').collect();
    let lengths = [8usize, 4, 4, 4, 12];
    if segments.len() != 5 {
        return false;
    }
    segments
        .iter()
        .zip(lengths.iter())
        .all(|(segment, length)| {
            segment.len() == *length && segment.chars().all(|c| c.is_ascii_hexdigit())
        })
}

/// Connect the configured transport. Fails closed with
/// `transport_unavailable` when the binary was built without the matching
/// cargo feature, and with `invalid_transport_config` when the mqtt
/// transport is selected without its device-plane credential (or a
/// credential is supplied to a transport that does not consume one).
pub fn connect(
    kind: TransportKind,
    topic: &str,
    endpoint: &str,
    auth: Option<&MqttDeviceAuth>,
) -> Result<Box<dyn TelemetryUploader>, UplinkError> {
    match kind {
        TransportKind::Fluvio | TransportKind::Kafka => {
            if auth.is_some() {
                return Err(error(
                    "invalid_transport_config",
                    "the mqtt device credential is only valid with the mqtt transport",
                ));
            }
            match kind {
                TransportKind::Fluvio => connect_fluvio(topic, endpoint),
                TransportKind::Kafka => connect_kafka(topic, endpoint),
                TransportKind::Mqtt => unreachable!(),
            }
        }
        TransportKind::Mqtt => {
            let auth = auth.ok_or_else(|| {
                error(
                    "invalid_transport_config",
                    "the mqtt transport requires the device-plane credential \
                     (UPLINK_MQTT_DEVICE_ID / UPLINK_MQTT_KEY_EPOCH / \
                     UPLINK_MQTT_DEVICE_PRIVATE_KEY)",
                )
            })?;
            connect_mqtt(topic, endpoint, auth)
        }
    }
}

#[cfg(feature = "fluvio-transport")]
fn connect_fluvio(topic: &str, endpoint: &str) -> Result<Box<dyn TelemetryUploader>, UplinkError> {
    Ok(Box::new(FluvioUploader::connect_with_endpoint(
        topic, endpoint,
    )?))
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

/// Resolve the Fluvio client configuration for `UPLINK_ENDPOINT`. An empty
/// (or whitespace-only) value selects the ambient Fluvio profile managed by
/// deployment; a non-empty value must be a single `host:port` override with a
/// numeric port. Anything else is rejected as `invalid_transport_config`
/// before any network I/O — fail-closed at startup, consistent with the
/// Kafka path, instead of silently ignoring a mistyped endpoint.
#[cfg(feature = "fluvio-transport")]
fn fluvio_config_for_endpoint(endpoint: &str) -> Result<Option<fluvio::FluvioConfig>, UplinkError> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let (host, port) = trimmed.rsplit_once(':').ok_or_else(|| {
        error(
            "invalid_transport_config",
            "fluvio endpoint must be a single host:port override",
        )
    })?;
    let port_number = port.parse::<u16>().unwrap_or(0);
    if host.trim().is_empty() || port_number == 0 {
        return Err(error(
            "invalid_transport_config",
            "fluvio endpoint must be host:port with a port between 1 and 65535",
        ));
    }
    Ok(Some(fluvio::FluvioConfig::new(trimmed)))
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
        let config = fluvio_config_for_endpoint(endpoint)?;
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

#[cfg(feature = "mqtt-transport")]
fn connect_mqtt(
    topic: &str,
    endpoint: &str,
    auth: &MqttDeviceAuth,
) -> Result<Box<dyn TelemetryUploader>, UplinkError> {
    Ok(Box::new(MqttUploader::connect(topic, endpoint, auth)?))
}

#[cfg(not(feature = "mqtt-transport"))]
fn connect_mqtt(
    _topic: &str,
    _endpoint: &str,
    _auth: &MqttDeviceAuth,
) -> Result<Box<dyn TelemetryUploader>, UplinkError> {
    Err(error(
        "transport_unavailable",
        "mqtt transport requires rebuilding with --features mqtt-transport",
    ))
}

/// Device-plane MQTT uploader (PRA-088): publishes every provenance-signed
/// batch to the EMQX broker at QoS 1 and waits for the broker's PUBACK —
/// there is no fire-and-forget, consistent with the Fluvio/Kafka doctrine.
/// Authentication is the geo device-plane contract carried by
/// [`MqttDeviceAuth`]: client id = registered device UUID, password =
/// Ed25519 signed proof (`geo-device-<deviceId>-<epoch>` kid); the broker's
/// HTTP authn webhook at geo-service `/v1/devices/mqtt-auth` verifies it
/// against the device registry (ACTIVE status, CURRENT or PREVIOUS-in-grace
/// key epoch) and never grants superuser.
///
/// The embedded single-threaded tokio runtime exists only to drive the
/// rumqttc event loop; the public surface stays synchronous like the Kafka
/// fallback.
#[cfg(feature = "mqtt-transport")]
pub struct MqttUploader {
    runtime: tokio::runtime::Runtime,
    client: rumqttc::AsyncClient,
    eventloop: rumqttc::EventLoop,
    topic: String,
}

#[cfg(feature = "mqtt-transport")]
impl MqttUploader {
    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
    const PUBACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    /// `endpoint` is a single `host:port` broker address. The connection is
    /// driven to CONNACK here: an unreachable broker or a rejected device
    /// credential is a startup error, not a first-publish surprise.
    pub fn connect(topic: &str, endpoint: &str, auth: &MqttDeviceAuth) -> Result<Self, UplinkError> {
        let trimmed = endpoint.trim();
        let (host, port) = trimmed.rsplit_once(':').ok_or_else(|| {
            error(
                "invalid_transport_config",
                "mqtt transport requires UPLINK_ENDPOINT as a single host:port broker address",
            )
        })?;
        let host = host.trim();
        let port: u16 = port.trim().parse().map_err(|_| {
            error(
                "invalid_transport_config",
                "mqtt transport requires UPLINK_ENDPOINT with a numeric port",
            )
        })?;
        if host.is_empty() || port == 0 {
            return Err(error(
                "invalid_transport_config",
                "mqtt transport requires UPLINK_ENDPOINT with a non-empty host and non-zero port",
            ));
        }
        let mut options = rumqttc::MqttOptions::new(auth.device_id(), host, port);
        options.set_credentials(auth.device_id(), auth.proof());
        options.set_keep_alive(std::time::Duration::from_secs(30));
        options.set_clean_session(true);
        if let Some(ca_path) = auth.tls_ca_cert_path() {
            let ca = std::fs::read(ca_path).map_err(|io_error| {
                error(
                    "invalid_transport_config",
                    format!("{ENV_MQTT_TLS_CA_CERT} ({ca_path}) is unreadable: {io_error}"),
                )
            })?;
            options.set_transport(rumqttc::Transport::Tls(rumqttc::TlsConfiguration::Simple {
                ca,
                alpn: None,
                client_auth: None,
            }));
        }
        let (client, eventloop) = rumqttc::AsyncClient::new(options, 16);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|io_error| {
                error(
                    "transport_unavailable",
                    format!("failed to start the mqtt event runtime: {io_error}"),
                )
            })?;
        let mut uploader = Self {
            runtime,
            client,
            eventloop,
            topic: topic.to_owned(),
        };
        uploader.wait_for_connack()?;
        Ok(uploader)
    }

    /// Pumps the event loop until the broker's CONNACK arrives (or the
    /// timeout/error path fails closed). A non-success return code means the
    /// device credential was rejected — surfaced as `uplink_connect_failed`.
    fn wait_for_connack(&mut self) -> Result<(), UplinkError> {
        self.runtime.block_on(async {
            let deadline = tokio::time::Instant::now() + Self::CONNECT_TIMEOUT;
            loop {
                match tokio::time::timeout_at(deadline, self.eventloop.poll()).await {
                    Ok(Ok(rumqttc::Event::Incoming(rumqttc::Incoming::ConnAck(connack)))) => {
                        if connack.code == rumqttc::ConnectReturnCode::Success {
                            return Ok(());
                        }
                        return Err(error(
                            "uplink_connect_failed",
                            format!(
                                "mqtt broker rejected the device credential: {:?} \
                                 (geo device-plane authentication failed)",
                                connack.code
                            ),
                        ));
                    }
                    Ok(Ok(_)) => continue,
                    Ok(Err(connection_error)) => {
                        return Err(error(
                            "uplink_connect_failed",
                            format!("mqtt broker connection failed: {connection_error}"),
                        ));
                    }
                    Err(_) => {
                        return Err(error(
                            "uplink_connect_failed",
                            "mqtt broker connection timed out waiting for CONNACK",
                        ));
                    }
                }
            }
        })
    }
}

#[cfg(feature = "mqtt-transport")]
impl TelemetryUploader for MqttUploader {
    fn upload(&mut self, batch: &TelemetryBatch) -> Result<UploadReceipt, UplinkError> {
        self.runtime.block_on(async {
            self.client
                .publish(
                    batch.topic.as_str(),
                    rumqttc::QoS::AtLeastOnce,
                    false,
                    batch.payload.clone(),
                )
                .await
                .map_err(|client_error| {
                    error(
                        "uplink_send_failed",
                        format!("mqtt publish failed: {client_error}"),
                    )
                })?;
            let deadline = tokio::time::Instant::now() + Self::PUBACK_TIMEOUT;
            loop {
                // Exactly one publish is in flight at a time (sequential
                // uploader), so the first PUBACK after the send is this
                // batch's broker acknowledgement.
                match tokio::time::timeout_at(deadline, self.eventloop.poll()).await {
                    Ok(Ok(rumqttc::Event::Incoming(rumqttc::Incoming::PubAck(_)))) => {
                        return Ok(UploadReceipt {
                            batch_key: batch.batch_key.clone(),
                            topic: batch.topic.clone(),
                            frame_count: batch.frame_count,
                        });
                    }
                    Ok(Ok(_)) => continue,
                    Ok(Err(connection_error)) => {
                        return Err(error(
                            "uplink_send_failed",
                            format!("mqtt broker connection lost before PUBACK: {connection_error}"),
                        ));
                    }
                    Err(_) => {
                        return Err(error(
                            "uplink_send_failed",
                            "mqtt broker did not acknowledge the publish (PUBACK timeout)",
                        ));
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

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

    fn test_signer() -> ProvenanceSigner {
        ProvenanceSigner::new(crate::provenance::SIGNING_KEY_ID, &[9u8; 32]).expect("valid seed")
    }

    fn signed_batch_document(batch: &TelemetryBatch, frames: &[TelemetryFrame]) -> serde_json::Value {
        serde_json::json!({
            "batchKey": batch.batch_key,
            "encoding": "json-lines",
            "frameCount": frames.len(),
            "frames": frames,
            "producer": crate::provenance::PRODUCER,
            "schema": BATCH_SCHEMA_DOMAIN,
            "topic": batch.topic,
        })
    }

    #[test]
    fn signed_batches_carry_verifiable_provenance_header() {
        let mut builder = BatchBuilder::new(TELEMETRY_TOPIC, 128, 900_000).expect("builder");
        builder.set_signer(test_signer());
        let frames: Vec<TelemetryFrame> = (1..=3).map(frame).collect();
        let batches = builder.build(&frames).expect("batches");
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(
            batch.signature_key_id.as_deref(),
            Some(crate::provenance::SIGNING_KEY_ID)
        );
        assert!(batch.provenance_signature.is_some());

        let mut lines = batch.payload.split(|byte| *byte == b'\n');
        let header_line = lines.next().expect("header line");
        let header: serde_json::Value =
            serde_json::from_slice(header_line).expect("header json");
        assert_eq!(
            header["record_type"].as_str(),
            Some(BATCH_PROVENANCE_RECORD_TYPE)
        );
        assert_eq!(header["batch_key"].as_str(), Some(batch.batch_key.as_str()));
        assert_eq!(
            header["signature"].as_str(),
            batch.provenance_signature.as_deref()
        );
        // Frame lines follow the header unchanged.
        for (line, frame) in lines.filter(|l| !l.is_empty()).zip(frames.iter()) {
            let decoded: TelemetryFrame = serde_json::from_slice(line).expect("frame json");
            assert_eq!(&decoded, frame);
        }

        // The JWS verifies over the JCS-canonicalized batch document.
        let signer = test_signer();
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(
            &URL_SAFE_NO_PAD
                .decode(signer.public_key_base64url())
                .expect("pubkey")
                .try_into()
                .map(|b: [u8; 32]| b)
                .expect("32 bytes"),
        )
        .expect("verifying key");
        let document = signed_batch_document(batch, &frames);
        let canonical = crate::provenance::canonicalize(&document).expect("canonical");
        crate::provenance::verify(
            &verifying,
            crate::provenance::SIGNING_KEY_ID,
            &canonical,
            batch.provenance_signature.as_deref().unwrap(),
        )
        .expect("batch provenance signature verifies");

        // Tampering with the batch key breaks verification.
        let mut tampered = signed_batch_document(batch, &frames);
        tampered["batchKey"] = serde_json::Value::String("f".repeat(64));
        let canonical = crate::provenance::canonicalize(&tampered).expect("canonical");
        let outcome = crate::provenance::verify(
            &verifying,
            crate::provenance::SIGNING_KEY_ID,
            &canonical,
            batch.provenance_signature.as_deref().unwrap(),
        )
        .expect_err("tampered batch document must not verify");
        assert_eq!(outcome.code, "signature_verification_failed");
    }

    #[test]
    fn unsigned_batches_keep_legacy_wire_format() {
        let builder = BatchBuilder::new(TELEMETRY_TOPIC, 128, 900_000).expect("builder");
        let frames: Vec<TelemetryFrame> = (1..=2).map(frame).collect();
        let batch = &builder.build(&frames).expect("batches")[0];
        assert!(batch.provenance_signature.is_none());
        assert!(batch.signature_key_id.is_none());
        // First line is a frame, not a provenance header.
        let first_line = batch.payload.split(|b| *b == b'\n').next().unwrap();
        let decoded: TelemetryFrame = serde_json::from_slice(first_line).expect("frame json");
        assert_eq!(decoded, frames[0]);
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
            TransportKind::parse("gopher").unwrap_err().code,
            "invalid_transport_config"
        );
        assert_eq!(TransportKind::parse("fluvio"), Ok(TransportKind::Fluvio));
        assert_eq!(TransportKind::parse("kafka"), Ok(TransportKind::Kafka));
        assert_eq!(TransportKind::parse("mqtt"), Ok(TransportKind::Mqtt));
        assert_eq!(TransportKind::Mqtt.as_str(), "mqtt");
    }

    #[cfg(feature = "fluvio-transport")]
    #[test]
    fn fluvio_endpoint_override_is_propagated_to_client_config() {
        let config = fluvio_config_for_endpoint("pier-fluvio.example.gov:9003")
            .expect("valid endpoint")
            .expect("endpoint override must produce an explicit client config");
        assert_eq!(config.endpoint, "pier-fluvio.example.gov:9003");

        assert!(
            fluvio_config_for_endpoint("")
                .expect("empty endpoint")
                .is_none(),
            "empty endpoint must select the ambient profile"
        );
        assert!(
            fluvio_config_for_endpoint("   ")
                .expect("blank endpoint")
                .is_none(),
            "whitespace-only endpoint must select the ambient profile"
        );
    }

    #[cfg(feature = "fluvio-transport")]
    #[test]
    fn fluvio_invalid_endpoint_fails_closed_before_network_io() {
        for invalid in [
            "not-an-endpoint",
            ":9003",
            "pier-fluvio:abc",
            "pier-fluvio:",
            "pier-fluvio:0",
            "pier-fluvio:65536",
        ] {
            let config_error = fluvio_config_for_endpoint(invalid)
                .err()
                .unwrap_or_else(|| panic!("endpoint {invalid:?} must be rejected"));
            assert_eq!(
                config_error.code, "invalid_transport_config",
                "endpoint {invalid:?} must be a configuration error"
            );
            let connect_error = connect(TransportKind::Fluvio, TELEMETRY_TOPIC, invalid, None)
                .err()
                .unwrap_or_else(|| panic!("connect with endpoint {invalid:?} must fail"));
            assert_eq!(
                connect_error.code, "invalid_transport_config",
                "connect with endpoint {invalid:?} must fail closed at startup"
            );
        }
    }

    #[cfg(not(feature = "fluvio-transport"))]
    #[test]
    fn uncompiled_transport_fails_closed() {
        let error = connect(TransportKind::Fluvio, TELEMETRY_TOPIC, "", None)
            .err()
            .expect("uncompiled fluvio transport must fail");
        assert_eq!(error.code, "transport_unavailable");
        let error = connect(TransportKind::Kafka, TELEMETRY_TOPIC, "127.0.0.1:9092", None)
            .err()
            .expect("uncompiled kafka transport must fail");
        assert_eq!(error.code, "transport_unavailable");
    }

    // -----------------------------------------------------------------
    // Device-plane MQTT uplink (PRA-088): credential construction against
    // the geo /v1/devices/mqtt-auth contract, fail-closed config gates and
    // the transport dispatch rules. Broker-dependent behaviour is covered
    // by the WWS_TEST_MQTT_BROKER-gated round-trip below — honestly gated,
    // never skipped silently.
    // -----------------------------------------------------------------

    const TEST_DEVICE_ID: &str = "2f4b6c80-1234-5678-9abc-deadbeef0001";

    fn test_device_key() -> ([u8; 32], ed25519_dalek::SigningKey) {
        let seed = [7u8; 32];
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        (seed, key)
    }

    #[test]
    fn mqtt_auth_builds_geo_contract_proof() {
        let (seed, key) = test_device_key();
        let auth = MqttDeviceAuth::from_parts(TEST_DEVICE_ID, 3, &seed, None)
            .expect("valid device credential");

        // kid binds the registered device id and epoch.
        assert_eq!(
            mqtt_proof_key_id(TEST_DEVICE_ID, 3),
            "geo-device-2f4b6c80-1234-5678-9abc-deadbeef0001-3"
        );

        // The proof is a three-segment JWS over the JCS-canonical
        // {"action":"MQTT_AUTH",...} payload — byte-identical to what the
        // Go devices.Verifier.VerifyProof re-canonicalizes and checks.
        let parts: Vec<&str> = auth.proof().split('.').collect();
        assert_eq!(parts.len(), 3, "proof must be a JWS compact serialization");
        let header = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            parts[0],
        )
        .expect("header decodes");
        let header: serde_json::Value = serde_json::from_slice(&header).expect("header is JSON");
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(
            header["kid"],
            "geo-device-2f4b6c80-1234-5678-9abc-deadbeef0001-3"
        );
        let payload = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            parts[1],
        )
        .expect("payload decodes");
        assert_eq!(
            payload,
            br#"{"action":"MQTT_AUTH","deviceId":"2f4b6c80-1234-5678-9abc-deadbeef0001","keyEpoch":3}"#
                .to_vec(),
            "payload must be the exact JCS-canonical proof document"
        );
        // And it verifies against the device public key.
        crate::provenance::verify(
            &key.verifying_key(),
            "geo-device-2f4b6c80-1234-5678-9abc-deadbeef0001-3",
            &payload,
            auth.proof(),
        )
        .expect("proof must verify against the device public key");
    }

    #[test]
    fn mqtt_auth_config_fails_closed() {
        let (seed, _) = test_device_key();
        // Non-UUID device id.
        let error = MqttDeviceAuth::from_parts("gateway-001", 1, &seed, None).unwrap_err();
        assert_eq!(error.code, "invalid_transport_config");
        // Zero epoch.
        let error = MqttDeviceAuth::from_parts(TEST_DEVICE_ID, 0, &seed, None).unwrap_err();
        assert_eq!(error.code, "invalid_transport_config");
        // Bad key material.
        let error = MqttDeviceAuth::from_parts(TEST_DEVICE_ID, 1, &[1u8; 7], None).unwrap_err();
        assert_eq!(error.code, "invalid_transport_config");

        // Environment resolution: every required variable is mandatory.
        let error = MqttDeviceAuth::from_env_with(|_| None).unwrap_err();
        assert_eq!(error.code, "invalid_transport_config");
        assert!(error.message.contains(ENV_MQTT_DEVICE_ID));
        let error = MqttDeviceAuth::from_env_with(|name| match name {
            ENV_MQTT_DEVICE_ID => Some(TEST_DEVICE_ID.to_owned()),
            _ => None,
        })
        .unwrap_err();
        assert!(error.message.contains(ENV_MQTT_KEY_EPOCH));
        let error = MqttDeviceAuth::from_env_with(|name| match name {
            ENV_MQTT_DEVICE_ID => Some(TEST_DEVICE_ID.to_owned()),
            ENV_MQTT_KEY_EPOCH => Some("not-a-number".to_owned()),
            _ => None,
        })
        .unwrap_err();
        assert_eq!(error.code, "invalid_transport_config");
        let error = MqttDeviceAuth::from_env_with(|name| match name {
            ENV_MQTT_DEVICE_ID => Some(TEST_DEVICE_ID.to_owned()),
            ENV_MQTT_KEY_EPOCH => Some("1".to_owned()),
            ENV_MQTT_DEVICE_PRIVATE_KEY => Some("not base64url !!!".to_owned()),
            _ => None,
        })
        .unwrap_err();
        assert_eq!(error.code, "invalid_transport_config");

        // Full environment resolves.
        let auth = MqttDeviceAuth::from_env_with(|name| match name {
            ENV_MQTT_DEVICE_ID => Some(TEST_DEVICE_ID.to_owned()),
            ENV_MQTT_KEY_EPOCH => Some("2".to_owned()),
            ENV_MQTT_DEVICE_PRIVATE_KEY => Some(base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                seed,
            )),
            _ => None,
        })
        .expect("complete environment resolves");
        assert_eq!(auth.device_id(), TEST_DEVICE_ID);
        assert_eq!(auth.key_epoch(), 2);
        assert!(auth.tls_ca_cert_path().is_none());
    }

    #[test]
    fn mqtt_transport_dispatch_gates() {
        let (seed, _) = test_device_key();
        let auth = MqttDeviceAuth::from_parts(TEST_DEVICE_ID, 1, &seed, None).expect("auth");

        // A device credential on a non-mqtt transport is a misconfiguration.
        let error = connect(TransportKind::Kafka, TELEMETRY_TOPIC, "127.0.0.1:9092", Some(&auth))
            .err()
            .expect("device credential on kafka must fail");
        assert_eq!(error.code, "invalid_transport_config");
        let error = connect(TransportKind::Fluvio, TELEMETRY_TOPIC, "", Some(&auth))
            .err()
            .expect("device credential on fluvio must fail");
        assert_eq!(error.code, "invalid_transport_config");

        // mqtt without the credential fails closed.
        let error = connect(TransportKind::Mqtt, TELEMETRY_TOPIC, "emqx:1883", None)
            .err()
            .expect("mqtt without the credential must fail");
        assert_eq!(error.code, "invalid_transport_config");
    }

    #[cfg(feature = "mqtt-transport")]
    #[test]
    fn mqtt_invalid_endpoint_fails_closed_before_network_io() {
        let (seed, _) = test_device_key();
        let auth = MqttDeviceAuth::from_parts(TEST_DEVICE_ID, 1, &seed, None).expect("auth");
        for invalid in ["not-an-endpoint", ":1883", "emqx:abc", "emqx:", "emqx:0"] {
            let error = connect(TransportKind::Mqtt, TELEMETRY_TOPIC, invalid, Some(&auth))
                .err()
                .unwrap_or_else(|| panic!("endpoint {invalid:?} must be rejected"));
            assert_eq!(
                error.code, "invalid_transport_config",
                "endpoint {invalid:?} must be a configuration error"
            );
        }
    }

    #[cfg(feature = "mqtt-transport")]
    #[test]
    fn mqtt_unreachable_broker_fails_closed_at_startup() {
        let (seed, _) = test_device_key();
        let auth = MqttDeviceAuth::from_parts(TEST_DEVICE_ID, 1, &seed, None).expect("auth");
        // Nothing listens here: CONNACK never arrives.
        let error = connect(TransportKind::Mqtt, TELEMETRY_TOPIC, "127.0.0.1:1", Some(&auth))
            .err()
            .expect("unreachable broker must fail closed");
        assert_eq!(error.code, "uplink_connect_failed");
    }

    #[cfg(not(feature = "mqtt-transport"))]
    #[test]
    fn uncompiled_mqtt_transport_fails_closed() {
        let (seed, _) = test_device_key();
        let auth = MqttDeviceAuth::from_parts(TEST_DEVICE_ID, 1, &seed, None).expect("auth");
        let error = connect(TransportKind::Mqtt, TELEMETRY_TOPIC, "emqx:1883", Some(&auth))
            .err()
            .expect("uncompiled mqtt transport must fail");
        assert_eq!(error.code, "transport_unavailable");
    }

    /// Broker-gated round trip: runs ONLY when WWS_TEST_MQTT_BROKER points
    /// at a live broker that accepts the test device credential (e.g. an
    /// EMQX wired to a geo-service with the device provisioned). Absent the
    /// environment the test is skipped explicitly — the unit matrix above
    /// covers everything that does not require a broker.
    #[cfg(feature = "mqtt-transport")]
    #[test]
    fn mqtt_upload_round_trip_with_live_broker() {
        let endpoint = match std::env::var("WWS_TEST_MQTT_BROKER") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                eprintln!(
                    "skipping mqtt_upload_round_trip_with_live_broker: \
                     WWS_TEST_MQTT_BROKER is not set (broker-gated by design)"
                );
                return;
            }
        };
        let (seed, _) = test_device_key();
        let auth = MqttDeviceAuth::from_parts(TEST_DEVICE_ID, 1, &seed, None).expect("auth");
        let mut uploader = MqttUploader::connect(TELEMETRY_TOPIC, endpoint.trim(), &auth)
            .expect("live broker must accept the device credential");
        let builder = BatchBuilder::new(TELEMETRY_TOPIC, 128, 900_000).expect("builder");
        let batches = builder.build(&[frame(1)]).expect("batch");
        let receipt = uploader.upload(&batches[0]).expect("PUBACK");
        assert_eq!(receipt.batch_key, batches[0].batch_key);
        assert_eq!(receipt.topic, TELEMETRY_TOPIC);
    }
}
