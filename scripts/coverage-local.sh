#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
output="${1:-$root/target/coverage-report}"
target="$root/target/coverage-instrumented"

for command in cargo jq llvm-profdata-17 llvm-cov-17; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command missing: $command" >&2
    exit 1
  }
done

rm -rf "$output" "$target"
mkdir -p "$output"
cd "$root"

export CARGO_TARGET_DIR="$target"
export RUSTFLAGS='-C instrument-coverage'
export LLVM_PROFILE_FILE="$output/%p-%m.profraw"

cargo test --locked --all-targets --no-run --message-format=json > "$output/build-messages.json"
jq -r 'select(.profile.test == true and .executable != null) | .executable' \
  "$output/build-messages.json" | sort -u > "$output/test-objects.txt"
cargo test --locked --all-targets 2>&1 | tee "$output/test.log"

llvm-profdata-17 merge -sparse "$output"/*.profraw -o "$output/coverage.profdata"
mapfile -t test_objects < "$output/test-objects.txt"
[[ "${#test_objects[@]}" -gt 0 ]] || {
  echo 'no instrumented Rust test objects found' >&2
  exit 1
}

application="$target/debug/blueeconomy-waterway-safety"
[[ -x "$application" ]] || {
  echo "instrumented application binary missing: $application" >&2
  exit 1
}

objects=(--object "$application")
for object in "${test_objects[@]:1}"; do
  objects+=(--object "$object")
done

common=(
  "${test_objects[0]}"
  "${objects[@]}"
  --instr-profile="$output/coverage.profdata"
  --ignore-filename-regex='(/.cargo/registry/|/library/)'
)
llvm-cov-17 report "${common[@]}" > "$output/coverage-summary.txt"
llvm-cov-17 export "${common[@]}" -format=text > "$output/coverage.json"
llvm-cov-17 export "${common[@]}" -format=lcov > "$output/coverage.lcov"
cat "$output/coverage-summary.txt"
