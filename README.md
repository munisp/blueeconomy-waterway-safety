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
