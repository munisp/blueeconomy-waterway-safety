//! OpenTelemetry wiring for the waterway-safety gateway (Phase-7 OTel wave).
//!
//! Contract (OTEL_DESIGN.md §1/§2 Rust row):
//!
//! - `OTEL_EXPORTER_OTLP_ENDPOINT` unset => telemetry is DISABLED; every
//!   entry point here is a no-op that never breaks boot or any upload.
//!   This is the platform's one sanctioned fail-open.
//! - When set: OTLP gRPC (tonic) span export, batched on a dedicated worker
//!   thread (non-blocking producers). A collector that is down means spans
//!   are dropped and counted (`telemetry_dropped_total`, also logged) —
//!   never an upload failure.
//! - Graceful shutdown flushes with a hard 5s bound.
//! - Propagation is W3C tracecontext + baggage. `tenant.id`/`agency`
//!   baggage extracted from an incoming carrier lands on server-side spans
//!   as attributes; the gateway's own batches carry `traceparent` (and
//!   `tracestate`) in the provenance header metadata — additive fields
//!   only, envelope v1.0 compatible.
//!
//! Span surface: `provenance.sign_batch` around batch signing, and
//! `uplink.upload` per transport (fluvio / kafka / mqtt) with
//! low-cardinality attributes (transport, topic, frame count — never
//! device ids or payload hashes).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use opentelemetry::propagation::{
    Extractor, Injector, TextMapCompositePropagator, TextMapPropagator,
};
use opentelemetry::trace::{TraceContextExt, TracerProvider as _};
use opentelemetry::{global, Context, KeyValue};
use opentelemetry_otlp::SpanExporter as OtlpSpanExporter;
use opentelemetry_sdk::export::trace::{ExportResult, SpanData, SpanExporter};
use opentelemetry_sdk::propagation::{BaggagePropagator, TraceContextPropagator};
use opentelemetry_sdk::trace::TracerProvider;
use opentelemetry_sdk::Resource;

/// Same shape as `futures_util::future::BoxFuture` (kept local so the
/// exporter shim needs no extra dependency).
type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Graceful-shutdown flush bound (contract: <=5s).
pub const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounded span queue: telemetry backpressure never blocks the uplink path.
const SPAN_QUEUE_BOUND: usize = 4096;

static DROPPED_SPANS: AtomicU64 = AtomicU64::new(0);
static PROVIDER: OnceLock<TracerProvider> = OnceLock::new();
static WORKER: Mutex<Option<WorkerHandle>> = Mutex::new(None);

/// Total telemetry items dropped because the collector was unavailable.
pub fn dropped_spans_total() -> u64 {
    DROPPED_SPANS.load(Ordering::Relaxed)
}

/// W3C tracecontext + baggage composite propagator.
pub fn composite_propagator() -> TextMapCompositePropagator {
    TextMapCompositePropagator::new(vec![
        Box::new(TraceContextPropagator::new()),
        Box::new(BaggagePropagator::new()),
    ])
}

/// Plain-text carrier for W3C propagation (batch metadata, tests).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Carrier {
    pub fields: HashMap<String, String>,
}

impl Carrier {
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }
}

impl Injector for Carrier {
    fn set(&mut self, key: &str, value: String) {
        self.fields.insert(key.to_ascii_lowercase(), value);
    }
}

impl Extractor for Carrier {
    fn get(&self, key: &str) -> Option<&str> {
        self.get(key)
    }

    fn keys(&self) -> Vec<&str> {
        self.fields.keys().map(String::as_str).collect()
    }
}

/// Inject an explicit OpenTelemetry context into a carrier.
pub fn inject_context(context: &Context, carrier: &mut Carrier) {
    composite_propagator().inject_context(context, carrier);
}

/// Extract an OpenTelemetry context from a carrier.
pub fn extract_context(carrier: &Carrier) -> Context {
    composite_propagator().extract(carrier)
}

/// Inject the *current tracing span's* context (traceparent, tracestate,
/// baggage) into a carrier. Empty carrier when telemetry is disabled or no
/// recording span is active — callers treat empty as "no carrier fields".
pub fn inject_current_context(carrier: &mut Carrier) {
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let context = tracing::Span::current().context();
    let span_context = context.span().span_context().clone();
    if !span_context.is_valid() {
        return;
    }
    inject_context(&context, carrier);
}

/// tenant.id / agency baggage entries from an extracted context, for
/// server-side span attributes (traces only — metrics stay off tenants).
pub fn tenant_attributes(context: &Context) -> Vec<KeyValue> {
    use opentelemetry::baggage::BaggageExt;

    let mut attributes = Vec::new();
    for key in ["tenant.id", "agency"] {
        if let Some(value) = context.baggage().get(key) {
            attributes.push(KeyValue::new(key, value.to_string()));
        }
    }
    attributes
}

struct WorkerHandle {
    stop: SyncSender<()>,
    join: Option<std::thread::JoinHandle<()>>,
}

enum SpanWork {
    Batch(Vec<SpanData>),
}

/// SpanExporter shim: span-end only does a bounded, non-blocking channel
/// send; the real OTLP gRPC export runs batched on the worker thread with
/// its own single-thread tokio runtime (tonic needs a reactor).
#[derive(Debug)]
struct ChannelExporter {
    sender: SyncSender<SpanWork>,
}

impl SpanExporter for ChannelExporter {
    fn export(&mut self, batch: Vec<SpanData>) -> BoxFuture<'static, ExportResult> {
        match self.sender.try_send(SpanWork::Batch(batch)) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(SpanWork::Batch(spans))) => {
                // Queue full: drop-with-metric, never block the business path.
                DROPPED_SPANS.fetch_add(spans.len() as u64, Ordering::Relaxed);
            }
            Err(_) => {}
        }
        Box::pin(std::future::ready(Ok(())))
    }
}

fn spawn_export_worker(
    mut exporter: OtlpSpanExporter,
) -> (SyncSender<SpanWork>, WorkerHandle) {
    let (work_sender, work_receiver) = sync_channel::<SpanWork>(SPAN_QUEUE_BOUND);
    let (stop_sender, stop_receiver) = sync_channel::<()>(1);
    let join = std::thread::Builder::new()
        .name("otel-otlp-export".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("otel export runtime");
            // Batch: accumulate whatever is queued, export every 5s at most.
            let mut pending: Vec<SpanData> = Vec::new();
            loop {
                match work_receiver.recv_timeout(Duration::from_secs(5)) {
                    Ok(SpanWork::Batch(batch)) => pending.extend(batch),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        export_pending(&runtime, &mut exporter, &mut pending);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
                if stop_receiver.try_recv().is_ok() {
                    drain(&work_receiver, &mut pending);
                    export_pending(&runtime, &mut exporter, &mut pending);
                    break;
                }
            }
        })
        .expect("spawn otel export worker");
    (
        work_sender,
        WorkerHandle {
            stop: stop_sender,
            join: Some(join),
        },
    )
}

fn drain(receiver: &Receiver<SpanWork>, pending: &mut Vec<SpanData>) {
    while let Ok(SpanWork::Batch(batch)) = receiver.try_recv() {
        pending.extend(batch);
    }
}

fn export_pending(
    runtime: &tokio::runtime::Runtime,
    exporter: &mut OtlpSpanExporter,
    pending: &mut Vec<SpanData>,
) {
    if pending.is_empty() {
        return;
    }
    let batch = std::mem::take(pending);
    let count = batch.len() as u64;
    // Collector-down / slow-collector = drop-with-metric, bounded at 5s.
    let outcome = runtime.block_on(async move {
        tokio::time::timeout(SHUTDOWN_FLUSH_TIMEOUT, exporter.export(batch)).await
    });
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            DROPPED_SPANS.fetch_add(count, Ordering::Relaxed);
            eprintln!("waterway-safety: otel export dropped {count} span(s): {error}");
        }
        Err(_) => {
            DROPPED_SPANS.fetch_add(count, Ordering::Relaxed);
            eprintln!(
                "waterway-safety: otel export dropped {count} span(s) (collector timeout)"
            );
        }
    }
}

/// True when OTLP export is configured (`OTEL_EXPORTER_OTLP_ENDPOINT`).
pub fn telemetry_enabled() -> bool {
    std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

/// Guard returned by [`init_telemetry`]; `drop`/`shutdown` flushes <=5s.
pub struct TelemetryGuard {
    enabled: bool,
}

/// Initialise telemetry. Never fails: a misconfigured collector is logged
/// and telemetry degrades to disabled (the sanctioned fail-open).
pub fn init_telemetry(service_name: &str) -> TelemetryGuard {
    if !telemetry_enabled() {
        return TelemetryGuard { enabled: false };
    }
    match try_init(service_name) {
        Ok(()) => TelemetryGuard { enabled: true },
        Err(error) => {
            eprintln!("waterway-safety: otel init failed; telemetry disabled: {error}");
            TelemetryGuard { enabled: false }
        }
    }
}

fn try_init(service_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()?;
    let (sender, worker) = spawn_export_worker(exporter);
    *WORKER.lock().expect("worker lock") = Some(worker);

    let resource = Resource::new(vec![
        KeyValue::new(
            "service.name",
            std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| service_name.to_owned()),
        ),
        KeyValue::new("service.namespace", "blueeconomy"),
        KeyValue::new(
            "deployment.environment",
            std::env::var("OTEL_ENVIRONMENT").unwrap_or_else(|_| "production".to_owned()),
        ),
    ]);
    let provider = TracerProvider::builder()
        .with_resource(resource)
        .with_simple_exporter(ChannelExporter { sender })
        .build();
    global::set_tracer_provider(provider.clone());
    global::set_text_map_propagator(composite_propagator());
    let _ = PROVIDER.set(provider.clone());

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let tracer = provider.tracer("blueeconomy-waterway-safety");
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    tracing_subscriber::registry()
        .with(otel_layer)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(false),
        )
        .try_init()?;
    Ok(())
}

/// Graceful shutdown: stop the export worker, flush pending spans with the
/// 5s bound, then shut the provider down. No-op when disabled.
pub fn shutdown_telemetry(guard: TelemetryGuard) {
    if !guard.enabled {
        return;
    }
    if let Some(mut worker) = WORKER.lock().expect("worker lock").take() {
        let _ = worker.stop.send(());
        if let Some(join) = worker.join.take() {
            let _ = join.join();
        }
    }
    if let Some(provider) = PROVIDER.get() {
        let _ = provider.shutdown();
    }
    let dropped = dropped_spans_total();
    if dropped > 0 {
        eprintln!("waterway-safety: telemetry_dropped_total={dropped}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::{SpanContext, SpanId, TraceFlags, TraceId, TraceState};
    use opentelemetry::trace::TraceContextExt;

    fn remote_context(trace_id: u128, span_id: u64) -> Context {
        Context::new().with_remote_span_context(SpanContext::new(
            TraceId::from_bytes(trace_id.to_be_bytes()),
            SpanId::from_bytes(span_id.to_be_bytes()),
            TraceFlags::SAMPLED,
            true,
            TraceState::NONE,
        ))
    }

    #[test]
    fn carrier_round_trip_preserves_trace_and_baggage() {
        use opentelemetry::baggage::BaggageExt;

        let context = remote_context(0x4bf92f3577b34da6a3ce929d0e0e4736, 0x00f067aa0ba902b7)
            .with_baggage([KeyValue::new("tenant.id", "tenant-1"), KeyValue::new("agency", "NIWA")]);
        let mut carrier = Carrier::default();
        inject_context(&context, &mut carrier);
        let traceparent = carrier.get("traceparent").expect("traceparent header");
        assert!(traceparent.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));
        assert!(carrier.get("baggage").expect("baggage").contains("tenant.id=tenant-1"));

        let extracted = extract_context(&carrier);
        assert_eq!(
            extracted.span().span_context().trace_id(),
            TraceId::from_bytes(0x4bf92f3577b34da6a3ce929d0e0e4736u128.to_be_bytes())
        );
        assert_eq!(
            tenant_attributes(&extracted),
            vec![
                KeyValue::new("tenant.id", "tenant-1"),
                KeyValue::new("agency", "NIWA")
            ]
        );
    }

    #[test]
    fn extract_of_empty_carrier_is_invalid_and_attribute_free() {
        let extracted = extract_context(&Carrier::default());
        assert!(!extracted.span().span_context().is_valid());
        assert!(tenant_attributes(&extracted).is_empty());
    }

    #[test]
    fn malformed_traceparent_is_rejected() {
        let mut carrier = Carrier::default();
        carrier.fields.insert("traceparent".to_owned(), "garbage".to_owned());
        let extracted = extract_context(&carrier);
        assert!(!extracted.span().span_context().is_valid());
    }

    #[test]
    fn disabled_mode_is_noop() {
        // No subscriber, no endpoint: inject is empty, guard shutdown is a
        // no-op, nothing panics — boot and uploads are never broken.
        let mut carrier = Carrier::default();
        inject_current_context(&mut carrier);
        assert!(carrier.is_empty());
        shutdown_telemetry(TelemetryGuard { enabled: false });
        assert_eq!(dropped_spans_total(), 0);
    }

    type SharedSpans = std::sync::Arc<std::sync::Mutex<Vec<SpanData>>>;

    #[derive(Debug, Clone, Default)]
    struct MemoryExporter {
        spans: SharedSpans,
    }

    impl SpanExporter for MemoryExporter {
        fn export(&mut self, batch: Vec<SpanData>) -> BoxFuture<'static, ExportResult> {
            self.spans.lock().expect("spans").extend(batch);
            Box::pin(std::future::ready(Ok(())))
        }
    }

    /// Full propagation carrier round-trip through real tracing spans: the
    /// producer span injects traceparent into a carrier (exactly what the
    /// batch metadata header carries), the consumer span continues the
    /// trace as a child of the extracted context.
    #[test]
    fn tracing_span_carrier_round_trip() {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        use tracing_subscriber::layer::SubscriberExt;

        let exported: SharedSpans = Default::default();
        let provider = TracerProvider::builder()
            .with_simple_exporter(MemoryExporter {
                spans: exported.clone(),
            })
            .build();
        let tracer = provider.tracer("test");
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(tracer));

        let mut carrier = Carrier::default();
        tracing::subscriber::with_default(subscriber, || {
            let parent = tracing::info_span!("uplink.upload", transport = "mqtt");
            {
                let _guard = parent.enter();
                inject_current_context(&mut carrier);
            }
            assert!(carrier.get("traceparent").is_some());
            drop(parent);

            let extracted = extract_context(&carrier);
            let child = tracing::info_span!("lakehouse.pipeline.kafka_ingest");
            child.set_parent(extracted);
            drop(child);
        });

        let spans = exported.lock().expect("spans");
        assert_eq!(spans.len(), 2, "both spans must be exported: {spans:?}");
        let parent = spans
            .iter()
            .find(|span| span.name == "uplink.upload")
            .expect("producer span");
        let child = spans
            .iter()
            .find(|span| span.name == "lakehouse.pipeline.kafka_ingest")
            .expect("consumer span");
        assert_eq!(child.span_context.trace_id(), parent.span_context.trace_id());
        assert_eq!(child.parent_span_id, parent.span_context.span_id());
        // The carrier's traceparent names the producer span.
        let traceparent = carrier.get("traceparent").expect("traceparent");
        assert!(traceparent.contains(&format!("{:032x}", parent.span_context.trace_id())));
    }
}
