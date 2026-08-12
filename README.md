# Blue Economy Waterway Safety

This repository implements a Rust **telemetry-integrity validator** for the first-release waterway-safety capability. It accepts one explicitly supplied, approved telemetry record, verifies strict RFC 3339 times and their order, approved classification, canonical device/gateway identifiers, base64 decoding and the SHA-256 calculated from the decoded payload. It emits validated metadata only and never emits the raw payload.

## Implemented boundary

The command accepts a regular, non-symlink input file and rejects absent, empty or oversized JSON before deserialization:

```bash
blueeconomy-waterway-safety /approved/input/telemetry.json
```

The implementation forbids unsafe Rust. Unknown JSON fields, control/whitespace-altered identifiers, non-hexadecimal digests, oversized encoded or decoded payloads, observations later than receipt time, invalid classifications and digest mismatches fail closed. The result contains device/gateway identifiers, source sequence, timestamps, classification, verified digest and payload byte count.

The component deliberately has no default gateway, device registry, sample device, generated telemetry record, Kafka/Fluvio topic, database, geofence, operator case or alert rule. It must not be represented as a live vessel, waterway, IoT, AIS, sensor or safety-response integration until authorised target evidence exists.

## Reproducible local verification

The crate declares Rust 1.75 as its minimum toolchain. Python 3.11 or later is used only by the saved OSV audit helper.

```bash
chmod +x scripts/verify-local.sh scripts/audit_osv.py
./scripts/verify-local.sh
```

The script runs locked formatting, all-target tests, Clippy with warnings denied, an optimized release build and an OSV query for every registry package in `Cargo.lock`. Generated audit output is written under `artifacts/` and is excluded from Git.

## Required agency integration evidence

External-agency readiness requires the actual gateway protocol and endpoint; device and gateway certificates/identities; payload schema and signature policy; sequence, replay, clock-skew and offline-buffer rules; permitted records; classification and retention; Kafka/Fluvio contract; authoritative geofences and thresholds; Temporal incident workflow; operator ownership; escalation/SOP; metrics/log/trace destinations; recovery behavior and non-production acceptance.

A SHA-256 digest proves payload consistency, not device authenticity. Device signatures, mTLS and registry status must be verified at the approved gateway or added from an authoritative protocol specification. Stateful replay/sequence detection also requires a durable device registry or event store and cannot be inferred by this stateless validator.
