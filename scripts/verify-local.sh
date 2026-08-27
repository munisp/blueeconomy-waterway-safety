#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

cargo fmt --check
cargo test --locked --all-targets
# Default features keep the declared Rust 1.75 MSRV. The optional uplink
# transport stacks are heavier and require a newer toolchain; verify them on
# stable with:
#   cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release
# Advisory exceptions (all informational "unmaintained" notices present only
# in the optional `fluvio-transport` client tree; no known vulnerability;
# reviewed 2026-08):
#   RUSTSEC-2025-0052 async-std (discontinued) via fluvio-future
#   RUSTSEC-2024-0384 instant (unmaintained) via parking_lot_core (wasm/win)
#   RUSTSEC-2024-0436 paste (unmaintained) via fluvio-sc-schema
python3 scripts/audit_osv.py --lock Cargo.lock --output artifacts/osv-audit.json \
  --allow-advisory RUSTSEC-2025-0052 \
  --allow-advisory RUSTSEC-2024-0384 \
  --allow-advisory RUSTSEC-2024-0436

git diff --check
printf '%s\n' 'Blue Economy waterway safety local verification completed successfully.'
