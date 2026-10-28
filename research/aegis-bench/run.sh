#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-micro}"
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$BENCH_DIR" rev-parse --show-toplevel)"
SOURCE_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
SOURCE_SHORT="$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD)"
ENVIRONMENT_ID="${AEGIS_BENCH_ENVIRONMENT_ID:-macmini-m2-macos26.5.2-rust1.97.1-aarch64-20260814}"
KEYGEN_ITERATIONS="${AEGIS_BENCH_KEYGEN_ITERATIONS:-30}"
OPERATION_ITERATIONS="${AEGIS_BENCH_OPERATION_ITERATIONS:-500}"
WARMUP_ITERATIONS="${AEGIS_BENCH_WARMUP_ITERATIONS:-10}"
COLD_PROCESSES="${AEGIS_BENCH_COLD_PROCESSES:-30}"
PYTHON="${AEGIS_BENCH_PYTHON:-python3}"
GENESIS_FILE="${SYNERGY_GENESIS_FILE:-$REPO_ROOT/launch/chain1266-promotable-rc30/release/genesis.json}"
EXPECTED_GENESIS_SHA256="ee554c197a878cbfdaf7d470a0274ab2859a7a0c14c87e425908a69c6fbb51cf"
EXPECTED_SYNQ_TARGET="$REPO_ROOT/runtime/synq-language"
SYNQ_LAYOUT_SHIM="$REPO_ROOT/../synq-language"
RUN_ID="${AEGIS_BENCH_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$SOURCE_SHORT-$MODE}"
OUTPUT_DIR="$BENCH_DIR/results/runs/$RUN_ID"
RAW_DIR="$OUTPUT_DIR/raw"
DERIVED_DIR="$OUTPUT_DIR/derived"
LOG_DIR="$BENCH_DIR/logs"
PLOT_DIR="$BENCH_DIR/plots/$RUN_ID"

case "$MODE" in
  micro|protocol|load-local|live-observation|all-safe) ;;
  *)
    echo "usage: $0 {micro|protocol|load-local|live-observation|all-safe}" >&2
    exit 2
    ;;
esac

if [[ "$MODE" == "live-observation" ]]; then
  exec "$BENCH_DIR/scripts/live-observation.sh" \
    "$BENCH_DIR/results/$RUN_ID-live-observation.txt"
fi

if [[ ! -f "$GENESIS_FILE" ]]; then
  echo "canonical Genesis is missing: $GENESIS_FILE" >&2
  exit 1
fi
ACTUAL_GENESIS_SHA256="$(shasum -a 256 "$GENESIS_FILE" | awk '{print $1}')"
if [[ "$ACTUAL_GENESIS_SHA256" != "$EXPECTED_GENESIS_SHA256" ]]; then
  echo "canonical Genesis SHA-256 mismatch: $ACTUAL_GENESIS_SHA256" >&2
  exit 1
fi
if [[ ! -d "$EXPECTED_SYNQ_TARGET" ]]; then
  echo "commit-bound runtime/synq-language is missing" >&2
  exit 1
fi
if [[ -L "$SYNQ_LAYOUT_SHIM" ]]; then
  if [[ "$(cd "$SYNQ_LAYOUT_SHIM" && pwd -P)" != "$(cd "$EXPECTED_SYNQ_TARGET" && pwd -P)" ]]; then
    echo "existing synq-language layout shim points elsewhere: $SYNQ_LAYOUT_SHIM" >&2
    exit 1
  fi
elif [[ -e "$SYNQ_LAYOUT_SHIM" ]]; then
  echo "refusing to replace existing non-symlink path: $SYNQ_LAYOUT_SHIM" >&2
  exit 1
else
  ln -s "$EXPECTED_SYNQ_TARGET" "$SYNQ_LAYOUT_SHIM"
fi

mkdir -p "$RAW_DIR" "$DERIVED_DIR" "$LOG_DIR" "$PLOT_DIR"
ENVIRONMENT_LOGS=()

capture_environment() {
  local role="$1"
  local output="$LOG_DIR/$RUN_ID-$role-environment.txt"
  {
    echo "classification=MEASURED"
    echo "capture_role=$role"
    echo "mode=$MODE"
    echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    uname -a
    sw_vers
    rustc -Vv
    cargo -V
    uptime
    sysctl -n hw.model
    sysctl -n hw.machine
    sysctl -n hw.physicalcpu
    sysctl -n hw.logicalcpu
    sysctl -n hw.memsize
    sysctl vm.swapusage
    pmset -g batt
    git -C "$REPO_ROOT" status --short -- runtime
  } > "$output"
  ENVIRONMENT_LOGS+=("$output")
}

capture_environment pre_build

cargo build --release --locked --manifest-path "$BENCH_DIR/Cargo.toml" --bins
BENCH_BINARY="$BENCH_DIR/target/release/synergy-aegis-bench"
COLD_BINARY="$BENCH_DIR/target/release/cold_start"
RAW_INPUTS=()
capture_environment pre_measurement

run_suite() {
  local suite="$1"
  local output="$RAW_DIR/$RUN_ID-$suite.csv"
  SYNERGY_GENESIS_FILE="$GENESIS_FILE" "$BENCH_BINARY" \
    --suite "$suite" \
    --output "$output" \
    --environment-id "$ENVIRONMENT_ID" \
    --source-commit "$SOURCE_COMMIT" \
    --keygen-iterations "$KEYGEN_ITERATIONS" \
    --operation-iterations "$OPERATION_ITERATIONS" \
    --warmup-iterations "$WARMUP_ITERATIONS"
  RAW_INPUTS+=("$output")
}

run_cold_start() {
  local part_dir="$RAW_DIR/cold-processes"
  local combined="$RAW_DIR/$RUN_ID-cold-start.csv"
  mkdir -p "$part_dir"
  local iteration
  for ((iteration=0; iteration<COLD_PROCESSES; iteration++)); do
    SYNERGY_GENESIS_FILE="$GENESIS_FILE" "$COLD_BINARY" \
      --output "$part_dir/$RUN_ID-cold-$iteration.csv" \
      --environment-id "$ENVIRONMENT_ID" \
      --source-commit "$SOURCE_COMMIT" \
      --iteration "$iteration"
  done
  awk 'FNR == 1 && NR != 1 { next } { print }' "$part_dir"/*.csv > "$combined"
  RAW_INPUTS+=("$combined")
}

run_controlled_load() {
  local workers
  for workers in 1 2 4; do
    local output="$RAW_DIR/$RUN_ID-load-workers$workers.csv"
    SYNERGY_PQC_VERIFY_WORKERS="$workers" SYNERGY_GENESIS_FILE="$GENESIS_FILE" "$BENCH_BINARY" \
      --suite load \
      --output "$output" \
      --environment-id "$ENVIRONMENT_ID-workers$workers" \
      --source-commit "$SOURCE_COMMIT" \
      --keygen-iterations "$KEYGEN_ITERATIONS" \
      --operation-iterations "$OPERATION_ITERATIONS" \
      --warmup-iterations "$WARMUP_ITERATIONS"
    RAW_INPUTS+=("$output")
  done
}

case "$MODE" in
  micro)
    run_suite primitive
    run_suite aegis
    run_suite lifecycle
    run_cold_start
    ;;
  protocol)
    run_suite protocol
    ;;
  load-local)
    run_controlled_load
    ;;
  all-safe)
    run_suite primitive
    run_suite aegis
    run_suite lifecycle
    run_cold_start
    run_suite protocol
    run_controlled_load
    ;;
esac

capture_environment post_measurement

ANALYZE_ARGS=()
for input in "${RAW_INPUTS[@]}"; do
  ANALYZE_ARGS+=(--input "$input")
done
"$PYTHON" "$BENCH_DIR/analyze.py" "${ANALYZE_ARGS[@]}" --output-dir "$DERIVED_DIR"
cp "$DERIVED_DIR/summary.csv" "$BENCH_DIR/results/summary.csv"
cp "$DERIVED_DIR/summary.json" "$BENCH_DIR/results/summary.json"
cp "$DERIVED_DIR"/*.svg "$PLOT_DIR/" 2>/dev/null || true

{
  echo "classification=MEASURED_AND_DERIVED"
  echo "run_id=$RUN_ID"
  echo "mode=$MODE"
  echo "source_commit=$SOURCE_COMMIT"
  echo "environment_id=$ENVIRONMENT_ID"
  echo "genesis_sha256=$ACTUAL_GENESIS_SHA256"
  echo "keygen_iterations=$KEYGEN_ITERATIONS"
  echo "operation_iterations=$OPERATION_ITERATIONS"
  echo "warmup_iterations=$WARMUP_ITERATIONS"
  echo "cold_processes=$COLD_PROCESSES"
  echo "completed_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$OUTPUT_DIR/run-manifest.txt"

{
  shasum -a 256 "$BENCH_DIR/Cargo.toml"
  shasum -a 256 "$BENCH_DIR/Cargo.lock"
  shasum -a 256 "$BENCH_DIR/src/main.rs"
  shasum -a 256 "$BENCH_DIR/src/bin/cold_start.rs"
  shasum -a 256 "$BENCH_DIR/analyze.py"
  shasum -a 256 "$BENCH_DIR/report.py"
  shasum -a 256 "$BENCH_BINARY"
  shasum -a 256 "$COLD_BINARY"
  shasum -a 256 "$GENESIS_FILE"
  while IFS= read -r evidence_file; do
    shasum -a 256 "$evidence_file"
  done < <(find "$OUTPUT_DIR" -type f ! -name SHA256SUMS | LC_ALL=C sort)
  for environment_log in "${ENVIRONMENT_LOGS[@]}"; do
    shasum -a 256 "$environment_log"
  done
} > "$OUTPUT_DIR/SHA256SUMS"

echo "Aegis benchmark evidence: $OUTPUT_DIR"
