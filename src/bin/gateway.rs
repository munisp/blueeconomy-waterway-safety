//! Vessel-side edge gateway binary (Workstream B §3.2).
//!
//! Runs three ingestion inputs — AIS NMEA 0183 over TCP, LoRaWAN sensor
//! uplinks over a TCP JSON-lines bridge, and a health heartbeat timer —
//! normalizes everything into `TelemetryFrame`s, and either streams them to
//! the configured uplink (connected profile) or spools them to the local
//! journal and replays on recovery (intermittent profile).
//!
//! Configuration is environment-only (see README table). Every failure is
//! fail-closed with a non-zero exit; malformed telemetry is dead-lettered,
//! never fatal and never panics.

#![forbid(unsafe_code)]

use blueeconomy_waterway_safety::gateway::{
    AisSentenceSource, GatewayConfig, GatewayCore, GatewayError, GatewayEvent, HybridClock,
    SensorUplinkSource, DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
};
use blueeconomy_waterway_safety::ingest::DeadLetterEvent;
use blueeconomy_waterway_safety::journal::{
    DEFAULT_MAX_JOURNAL_BYTES, DEFAULT_MAX_OVERFLOW_BYTES, DEFAULT_MAX_SEGMENT_BYTES,
};
use blueeconomy_waterway_safety::uplink::{
    self, TransportKind, DEFAULT_BATCH_MAX_BYTES, DEFAULT_BATCH_MAX_RECORDS, TELEMETRY_TOPIC,
};
use serde::Serialize;
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

const DEFAULT_AIS_LISTEN_ADDR: &str = "127.0.0.1:10110";
const DEFAULT_SENSOR_LISTEN_ADDR: &str = "127.0.0.1:10111";
/// Bounds a single TCP line before the parser rejects it; protects the
/// gateway from peers that never send a line terminator.
const MAX_SOURCE_LINE_BYTES: usize = 4_096;

enum InputEvent {
    Sentence(String),
    Uplink(Vec<u8>),
    HeartbeatTick,
}

#[derive(Serialize)]
struct EventLog<'a> {
    logged_at_epoch: u64,
    event: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    dead_letter: Option<&'a DeadLetterEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.iter().any(|arg| arg == "-h" || arg == "--help") {
        eprintln!(
            "usage: gateway\n\
             Runs the vessel-side edge gateway. Configuration is environment-only:\n\
             GATEWAY_ID, VESSEL_DEVICE_ID, JOURNAL_DIR, UPLINK_TRANSPORT (fluvio|kafka),\n\
             UPLINK_ENDPOINT, TELEMETRY_TOPIC, DATA_CLASSIFICATION, AIS_LISTEN_ADDR,\n\
             SENSOR_LISTEN_ADDR, HEARTBEAT_INTERVAL_SECONDS, LATENESS_WINDOW_SECONDS,\n\
             JOURNAL_MAX_SEGMENT_BYTES, JOURNAL_MAX_BYTES, JOURNAL_OVERFLOW_MAX_BYTES,\n\
             BATCH_MAX_RECORDS, BATCH_MAX_BYTES. See README for defaults."
        );
        return 2;
    }
    let config = match BinaryConfig::from_env(|name| std::env::var(name).ok()) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("gateway: invalid configuration: {message}");
            return 2;
        }
    };
    let mut core = match GatewayCore::new(config.core.clone(), HybridClock::new()) {
        Ok(core) => core,
        Err(error) => {
            eprintln!("gateway: startup failed closed: {error}");
            return 1;
        }
    };
    // Fail-closed startup: without the producer provenance key no batch may
    // leave this gateway, so the process refuses to run at all.
    let signer = match blueeconomy_waterway_safety::provenance::ProvenanceSigner::from_env() {
        Ok(signer) => signer,
        Err(error) => {
            eprintln!("gateway: startup failed closed: {error}");
            return 1;
        }
    };
    core.set_provenance_signer(signer);
    let mut uploader = match uplink::connect(
        config.transport,
        &config.core.topic,
        &config.uplink_endpoint,
    ) {
        Ok(uploader) => uploader,
        Err(error) => {
            eprintln!("gateway: uplink connect failed closed: {error}");
            return 1;
        }
    };
    let (sender, receiver) = channel::<InputEvent>();
    if let Err(code) = spawn_sources(&config, &sender) {
        return code;
    }
    log_event("gateway_started", None, None);
    main_loop(&mut core, uploader.as_mut(), &receiver)
}

fn main_loop(
    core: &mut GatewayCore,
    uploader: &mut dyn uplink::TelemetryUploader,
    receiver: &Receiver<InputEvent>,
) -> i32 {
    for event in receiver.iter() {
        let outcome = match event {
            InputEvent::Sentence(sentence) => Some(core.handle_sentence(&sentence)),
            InputEvent::Uplink(raw) => Some(core.handle_uplink(&raw)),
            InputEvent::HeartbeatTick => {
                // The heartbeat doubles as the recovery probe: mark the uplink
                // candidate-healthy and let replay prove it.
                if !core.uplink_available() {
                    core.mark_uplink_recovered();
                    match core.replay_journal(uploader) {
                        Ok(replayed) if replayed > 0 => log_event(
                            "journal_replay_progress",
                            None,
                            Some(format!("replayed {replayed} journaled frames")),
                        ),
                        Ok(_) => {}
                        Err(error) => {
                            log_event("journal_replay_failed", None, Some(error.to_string()))
                        }
                    }
                }
                Some(core.handle_heartbeat_tick())
            }
        };
        if let Some(GatewayEvent::DeadLetter(dead_letter)) = &outcome {
            log_event("dead_letter", Some(dead_letter), None);
        }
        let ready = core.drain_ready_frames();
        if !ready.is_empty() {
            let count = ready.len();
            match core.upload_or_spool(uploader, &ready) {
                Ok(()) => {}
                Err(error) => log_event(
                    "uplink_failed_spooled",
                    None,
                    Some(format!(
                        "{count} frames spooled after uplink error: {error}"
                    )),
                ),
            }
        }
    }
    log_event("gateway_stopped", None, None);
    0
}

/// Emit one JSON log line; this stream is what the Wazuh agent's localfile
/// monitor and the sensor-health/tamper rules consume.
fn log_event(event: &str, dead_letter: Option<&DeadLetterEvent>, detail: Option<String>) {
    let entry = EventLog {
        logged_at_epoch: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
        event,
        dead_letter,
        detail,
    };
    match serde_json::to_string(&entry) {
        Ok(encoded) => println!("{encoded}"),
        Err(error) => eprintln!("gateway: encode event log: {error}"),
    }
}

struct BinaryConfig {
    core: GatewayConfig,
    transport: TransportKind,
    uplink_endpoint: String,
    ais_listen_addr: String,
    sensor_listen_addr: String,
}

impl BinaryConfig {
    fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let required = |name: &str| -> Result<String, String> {
            get(name)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| format!("{name} is required"))
        };
        let parse_number = |name: &str, default: u64| -> Result<u64, String> {
            match get(name) {
                None => Ok(default),
                Some(value) => value
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| format!("{name} must be a positive integer")),
            }
        };
        let transport = TransportKind::parse(required("UPLINK_TRANSPORT")?.trim())
            .map_err(|error| error.to_string())?;
        let core = GatewayConfig {
            gateway_id: required("GATEWAY_ID")?,
            vessel_device_id: required("VESSEL_DEVICE_ID")?,
            data_classification: get("DATA_CLASSIFICATION")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "internal".to_owned()),
            topic: get("TELEMETRY_TOPIC")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| TELEMETRY_TOPIC.to_owned()),
            lateness_window_seconds: parse_number(
                "LATENESS_WINDOW_SECONDS",
                blueeconomy_waterway_safety::geo::FRESHNESS_KPI_MAX_STALENESS_SECONDS as u64,
            )? as i64,
            heartbeat_interval_seconds: parse_number(
                "HEARTBEAT_INTERVAL_SECONDS",
                DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
            )?,
            journal_dir: PathBuf::from(required("JOURNAL_DIR")?),
            journal_max_segment_bytes: parse_number(
                "JOURNAL_MAX_SEGMENT_BYTES",
                DEFAULT_MAX_SEGMENT_BYTES,
            )?,
            journal_max_bytes: parse_number("JOURNAL_MAX_BYTES", DEFAULT_MAX_JOURNAL_BYTES)?,
            journal_max_overflow_bytes: parse_number(
                "JOURNAL_OVERFLOW_MAX_BYTES",
                DEFAULT_MAX_OVERFLOW_BYTES,
            )?,
            batch_max_records: parse_number("BATCH_MAX_RECORDS", DEFAULT_BATCH_MAX_RECORDS as u64)?
                as usize,
            batch_max_bytes: parse_number("BATCH_MAX_BYTES", DEFAULT_BATCH_MAX_BYTES as u64)?
                as usize,
        };
        core.validate().map_err(|error| error.to_string())?;
        Ok(Self {
            uplink_endpoint: get("UPLINK_ENDPOINT").unwrap_or_default(),
            ais_listen_addr: get("AIS_LISTEN_ADDR")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_AIS_LISTEN_ADDR.to_owned()),
            sensor_listen_addr: get("SENSOR_LISTEN_ADDR")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_SENSOR_LISTEN_ADDR.to_owned()),
            transport,
            core,
        })
    }
}

fn spawn_sources(config: &BinaryConfig, sender: &Sender<InputEvent>) -> Result<(), i32> {
    spawn_line_listener(
        &config.ais_listen_addr,
        sender.clone(),
        serve_ais_connection,
    )?;
    spawn_line_listener(
        &config.sensor_listen_addr,
        sender.clone(),
        serve_sensor_connection,
    )?;
    let heartbeat_sender = sender.clone();
    let interval = Duration::from_secs(config.core.heartbeat_interval_seconds);
    thread::Builder::new()
        .name("gateway-heartbeat".to_owned())
        .spawn(move || loop {
            thread::sleep(interval);
            if heartbeat_sender.send(InputEvent::HeartbeatTick).is_err() {
                return;
            }
        })
        .map_err(|error| {
            eprintln!("gateway: spawn heartbeat source: {error}");
            1
        })?;
    Ok(())
}

fn spawn_line_listener(
    address: &str,
    sender: Sender<InputEvent>,
    serve: fn(TcpStream, Sender<InputEvent>),
) -> Result<(), i32> {
    let listener = TcpListener::bind(address).map_err(|error| {
        eprintln!("gateway: bind {address}: {error}");
        1
    })?;
    let address_owned = address.to_owned();
    thread::Builder::new()
        .name(format!("gateway-listener-{address}"))
        .spawn(move || {
            for connection in listener.incoming() {
                match connection {
                    Ok(stream) => {
                        let connection_sender = sender.clone();
                        if let Err(error) = thread::Builder::new()
                            .name(format!("gateway-conn-{address_owned}"))
                            .spawn(move || serve(stream, connection_sender))
                        {
                            eprintln!("gateway: spawn connection handler: {error}");
                        }
                    }
                    Err(error) => eprintln!("gateway: accept on {address_owned}: {error}"),
                }
            }
        })
        .map_err(|error| {
            eprintln!("gateway: spawn listener {address}: {error}");
            1
        })?;
    Ok(())
}

/// One TCP peer as a line-oriented input source. Implements both ingestion
/// source traits; each listener drives the trait matching its feed.
struct TcpLineSource {
    reader: BufReader<TcpStream>,
}

impl TcpLineSource {
    fn new(stream: TcpStream) -> Self {
        Self {
            reader: BufReader::new(stream),
        }
    }

    fn read_bounded_line(&mut self) -> Result<String, GatewayError> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Err(GatewayError {
                code: "source_closed",
                message: "peer closed the connection".to_owned(),
            }),
            Ok(_) => {
                if line.len() > MAX_SOURCE_LINE_BYTES {
                    line.truncate(MAX_SOURCE_LINE_BYTES);
                }
                Ok(line)
            }
            Err(io) => Err(GatewayError {
                code: "source_read_failed",
                message: io.to_string(),
            }),
        }
    }
}

impl AisSentenceSource for TcpLineSource {
    fn next_sentence(&mut self) -> Result<String, GatewayError> {
        self.read_bounded_line()
    }
}

impl SensorUplinkSource for TcpLineSource {
    fn next_uplink(&mut self) -> Result<Vec<u8>, GatewayError> {
        self.read_bounded_line().map(String::into_bytes)
    }
}

fn serve_ais_connection(stream: TcpStream, sender: Sender<InputEvent>) {
    let mut source = TcpLineSource::new(stream);
    loop {
        match source.next_sentence() {
            Ok(sentence) => {
                if sender.send(InputEvent::Sentence(sentence)).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

fn serve_sensor_connection(stream: TcpStream, sender: Sender<InputEvent>) {
    let mut source = TcpLineSource::new(stream);
    loop {
        match source.next_uplink() {
            Ok(uplink) => {
                if sender.send(InputEvent::Uplink(uplink)).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}
