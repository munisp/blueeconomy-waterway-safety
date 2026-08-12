# Blue Economy Waterway Safety

This repository implements a Rust **telemetry-integrity validator** for the first-release waterway-safety capability. It accepts one explicitly supplied, approved telemetry record, verifies RFC 3339 timestamps, classification, base64 payload decoding and an actual SHA-256 digest calculated from the received payload bytes. It emits validated metadata only; it does not retain or print the raw telemetry payload.

## Current implementation boundary

The component deliberately has no default gateway endpoint, device registry, sample device, generated telemetry record, Kafka topic, database, operator case or alert rule. It must not be represented as a live vessel, waterway, IoT, AIS, sensor or safety-case integration until an authorised non-production source/gateway contract, device identity model, network path, payload format, data classification and target-side evidence are supplied.

The current command accepts a path to an approved real input file:

```bash
blueeconomy-waterway-safety /approved/input/telemetry.json
```

Invalid source metadata, timestamps, classifications, encodings, payload sizes and payload digests fail closed. The emitted JSON includes the identifiers, sequence, timestamps, classification, verified digest and payload byte count; it never includes raw payload bytes.

## Required next integration evidence

The Ministry must provide the actual safety-source/gateway interface, device/gateway identity and credential process, schema/protocol, permitted non-production records, ordering/deduplication policy, alert thresholds, case-management workflow, event topic/contract and operational support owner. When provided, the verified validator will be connected to the real source and exercised against the approved non-production environment rather than a fabricated simulation.
