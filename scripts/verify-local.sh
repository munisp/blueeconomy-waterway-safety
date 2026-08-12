#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

cargo fmt --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --locked --release
python3 scripts/audit_osv.py --lock Cargo.lock --output artifacts/osv-audit.json

git diff --check
printf '%s\n' 'Blue Economy waterway safety local verification completed successfully.'
