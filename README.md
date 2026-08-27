# Blue Economy Waterway Safety

This repository implements a Rust telemetry-integrity validator and a cryptographically signed-device validation path for the first-release waterway-safety capability. It accepts only explicitly supplied telemetry and registry files; it has no default gateway, device, certificate, topic, database, geofence, alert, incident, or field endpoint.

## Telemetry integrity baseline

The base command accepts one approved telemetry record, verifies strict RFC 3339 times and their order, approved classification, canonical device/gateway identifiers, base64 decoding, and the SHA-256 calculated from decoded payload bytes. It emits metadata only and never emits the raw payload.

```bash
blueeconomy-waterway-safety /approved/input/telemetry.json
```

The implementation rejects absent, empty, oversized, symbolic-link, unknown-field, control/whitespace-altered identifier, non-hex digest, oversized encoded/decoded payload, observation-after-receipt, invalid classification, and digest-mismatch input.

## Signed-device validation

The signed path validates a versioned device registry, enforces the registered device/gateway/key tuple and active key state, builds a canonical domain-separated preimage, and verifies an **Ed25519** signature before emitting redacted validated metadata.

```bash
blueeconomy-waterway-safety \
  --device-registry /approved/registry/device-registry.json \
  /approved/input/signed-telemetry.json
```

The registry is a regular, non-symlink JSON file with schema version `blueeconomy.waterway-safety.device-registry.v1`. Each unique `(device_id, gateway_id, key_id)` entry supplies an Ed25519 public key and has status `active`, `suspended`, or `revoked`. Only `active` entries validate. The signed telemetry input uses a nested `frame`, `signature_key_id`, and base64 Ed25519 `signature_base64`; the signature binds the schema domain, key ID, device ID, gateway ID, source sequence, timestamps, classification, and payload SHA-256.

The library also exposes `validate_signed_continuation`, which combines signature/registry verification with strict cursor continuity. It rejects replay, sequence gap, device/gateway change, and timestamp regression before returning the next redacted stream cursor. A real deployment must persist this cursor in an approved durable store with concurrency control.

## Durable cursor and vessel registry store

The `store` module provides `FileStateStore` (behind the pluggable `StateStore` trait) for durable ingestion cursors and vessel track registry state. Writes are atomic (write-tempfile, fsync, rename, fsync parent directory) and each record is protected by a SHA-256 payload checksum and a versioned schema envelope. Any read, size, schema, checksum, or content-validation failure is returned as an error; the store never silently resets to empty state. `StateStoreSnapshot::empty()` exists so that initializing a fresh deployment is an explicit caller decision.

## Geospatial safety analytics

The `geo` module implements the corridor-safety analytics feeding the NIMASA dashboard: boundary-inclusive EEZ/restricted-zone overlap detection on vessel positions (`SafetyZone`, `detect_zone_overlaps`), corridor safety polygon construction from vessel tracks (`build_corridor_polygon`, a conservative buffered convex hull that never under-covers the sailed corridor, with a SHA-256 construction digest for audit evidence), and track freshness evaluation (`evaluate_track_freshness`) against the five-minute KPI (`FRESHNESS_KPI_MAX_STALENESS_SECONDS`). Stale and future-dated tracks are reported explicitly and fail the report closed. Zones and tracks are caller-supplied; the crate ships no built-in geofences.

## Out-of-order telemetry ingestion

The `ingest` module tolerates out-of-order `ferries.telemetry.v1` delivery. `ReorderIngestor` buffers validated frames and re-emits them ordered by `(observed_at, source_sequence)` once they fall outside a watermark-driven, configurable lateness window. Frames arriving later than the window, invalid frames, and frames offered at buffer capacity are rejected to an explicit `DeadLetterEvent` outcome and are never silently applied.

## Vessel-side edge gateway (Workstream B)

The `gateway` binary (`src/bin/gateway.rs`) is the reference edge gateway for
the connected/intermittent vessel telemetry profiles. Three inputs sit behind
traits — AIS NMEA 0183 sentences (`AisSentenceSource`, RMC/GGA with mandatory
checksums; malformed sentences are dead-lettered, never fatal), LoRaWAN sensor
uplinks (`SensorUplinkSource`, JSON envelope + documented binary payloads for
engine/bilge/life-jacket sensors, see `src/sensor.rs`), and a health heartbeat
(`HeartbeatSource`). Everything is normalized into `TelemetryFrame`.

```
 AIS receiver ──NMEA 0183/TCP──► ┌────────────── gateway (RasPi) ───────────────┐
                                 │ nmea.rs: RMC/GGA parse, checksum enforced     │
 LoRaWAN NS bridge ─JSONL/TCP──► │ sensor.rs: engine/bilge/life-jacket decode    │
                                 │ gateway.rs: normalize → TelemetryFrame        │
 health timer ──────────────────► │   observed_at: GPS time else hybrid clock     │
                                 │ ingest.rs: ReorderIngestor (300 s window,     │
                                 │   watermark; late ⇒ explicit dead letter)     │
                                 └───────┬───────────────────────┬──────────────┘
                       uplink up         │                       │ uplink down
                            ┌────────────▼─────────┐   ┌─────────▼─────────────┐
                            │ uplink.rs            │   │ journal.rs            │
                            │ BatchBuilder         │   │ append-only segments, │
                            │ (deterministic keys, │   │ SHA-256 records,      │
                            │  JSON-lines batches) │   │ rotation, bounded:    │
                            └──────────┬───────────┘   │ overflow ⇒ oldest to  │
                 ┌─────────────────────┴─────────┐     │ overflow-dead-letter  │
                 │ fluvio (feature) / kafka       │◄────│ replay oldest-first,  │
                 │ (feature) — config-only swap   │ ack │ truncate only after   │
                 └─────────────────┬───────────────┘     │ acknowledged        │
                                   ▼                     └─────────────────────┘
                        ferries.telemetry.v1
                        (Fluvio pier cluster; SmartModule compresses+batches;
                         Kafka fallback surface)
```

Transport is selected by configuration only (`UPLINK_TRANSPORT`), Dapr-style:
the same frames flow either way. The Fluvio producer is a real client behind
`--features fluvio-transport`; the Kafka fallback producer behind
`--features kafka-transport`. Building without a transport feature is allowed,
but selecting that transport at startup fails closed (`transport_unavailable`).
Batch payload compression is delegated to the transport/SmartModule (see
`src/uplink.rs` module docs); no gateway-local zstd pass is compiled (would be
a new dependency requiring governance sign-off).

### Gateway configuration (environment)

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `GATEWAY_ID` | yes | — | gateway identity on every frame |
| `VESSEL_DEVICE_ID` | yes | — | device identity for AIS position frames |
| `JOURNAL_DIR` | yes | — | local spool journal directory |
| `UPLINK_TRANSPORT` | yes | — | `fluvio` or `kafka` |
| `UPLINK_ENDPOINT` | no | `""` | kafka bootstrap `host:port,...`; fluvio profile override |
| `TELEMETRY_TOPIC` | no | `ferries.telemetry.v1` | unified ingestion topic |
| `DATA_CLASSIFICATION` | no | `internal` | approved classification value |
| `AIS_LISTEN_ADDR` | no | `127.0.0.1:10110` | NMEA TCP listener |
| `SENSOR_LISTEN_ADDR` | no | `127.0.0.1:10111` | LoRaWAN bridge JSON-lines listener |
| `HEARTBEAT_INTERVAL_SECONDS` | no | `30` | health heartbeat period (doubles as recovery probe) |
| `LATENESS_WINDOW_SECONDS` | no | `300` | reorder window; keep aligned with the 5-minute freshness KPI |
| `JOURNAL_MAX_SEGMENT_BYTES` | no | `4194304` | journal segment rotation size |
| `JOURNAL_MAX_BYTES` | no | `67108864` | total journal budget (bounded) |
| `JOURNAL_OVERFLOW_MAX_BYTES` | no | `16777216` | overflow dead-letter sink budget |
| `BATCH_MAX_RECORDS` / `BATCH_MAX_BYTES` | no | `128` / `900000` | uplink batch bounds |

Journal overflow policy: the oldest *sealed* segments are moved to
`overflow-dead-letter.jsonl` with counters (`records_dead_lettered_overflow`)
— never silent; if the sink is full the append fails closed and the newest
data is retained. Replay truncates segments only after the uplink
acknowledges the batch that carried them; the ack cursor is persisted
atomically. Any journal corruption (bad checksum, torn tail, tampered ack
cursor) halts the gateway closed with `journal_corruption`.

### Wazuh integration and deployment

`wazuh/` ships the agent `ossec.conf` fragment (JSON log monitoring, FIM
tamper detection on the binary/config/journal, rootcheck) and custom manager
rules 100101+ for sensor-health and tamper detection, aligned with the
blueeconomy-security-operations ruleset convention. The RasPi deployment
runbook — armv7/aarch64 cross-compile, systemd unit, Wazuh agent setup,
recovery drill — is in `docs/raspi-gateway-deployment.md`.

## Schema contract

`schemas/gateway-telemetry-profile.schema.json` mirrors the `TelemetryFrame` contract in `src/lib.rs` (the code is authoritative). `tests/schema_contract.rs` runs in CI and fails on drift: it compares the schema field set with serializer output and round-trips valid and invalid documents through both the schema and the validator.

## Container image

The `Dockerfile` builds a locked release binary and runs it as `nonroot` on a distroless base. Both base images are pinned by digest (the retrieval source is documented inline). The `Docker image` workflow statically validates the Dockerfile, verifies the digest pins, and builds the image on every relevant change.

## Local fixtures versus agency evidence

The repository includes deterministic local-only Ed25519 fixtures for the unit and CLI tests. They prove code behavior only. They are **not** Ministry device identities, certificates, registry approvals, payload authorisations, gateway connections, or safety-response acceptance evidence.

## Reproducible local verification

The crate declares Rust 1.75 as its minimum toolchain. Python 3.11 or later is used only by the saved OSV audit helper.

```bash
chmod +x scripts/verify-local.sh scripts/audit_osv.py
./scripts/verify-local.sh
```

The script runs locked formatting, all-target tests, Clippy with warnings denied, an optimized release build, and an OSV query for every registry package in `Cargo.lock`. Generated audit output is written under `artifacts/` and is excluded from Git.

## Required agency integration evidence

External-agency readiness still requires the actual gateway protocol and endpoint; device and gateway certificate/identity authority; an approved registry lifecycle and key-rotation/revocation policy; payload schema; offline buffer and sequencing rules; permitted records; classification and retention; Kafka/Fluvio contract; authoritative geofences and thresholds; incident workflow; operator ownership; escalation SOP; observability destinations; recovery behavior; and non-production acceptance.

The code supplies a strict interface for those controls but does not invent them or represent a local signing key as an approved agency credential.
