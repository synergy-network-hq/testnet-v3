#!/usr/bin/env bash
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRIMARY_RUN="${1:-$BENCH_DIR/results/runs/publication-m2-20260815-v1}"
LOAD_RUN_2="${2:-$BENCH_DIR/results/runs/publication-load-m2-20260815-v2}"
LOAD_RUN_3="${3:-$BENCH_DIR/results/runs/publication-load-m2-20260815-v3}"
OUTPUT_DIR="$BENCH_DIR/results/publication"
PLOT_DIR="$BENCH_DIR/plots/publication-m2-20260815"

analysis_args=()
for input in "$PRIMARY_RUN"/raw/*.csv; do
  analysis_args+=(--input "$input")
done
for input in "$LOAD_RUN_2"/raw/*load-workers*.csv "$LOAD_RUN_3"/raw/*load-workers*.csv; do
  analysis_args+=(--input "$input")
done

python3 "$BENCH_DIR/analyze.py" "${analysis_args[@]}" --output-dir "$OUTPUT_DIR"
python3 "$BENCH_DIR/report.py" \
  --primary-run "$PRIMARY_RUN" \
  --load-run "$LOAD_RUN_2" \
  --load-run "$LOAD_RUN_3" \
  --output-dir "$OUTPUT_DIR"

cp "$OUTPUT_DIR/summary.csv" "$BENCH_DIR/results/summary.csv"
cp "$OUTPUT_DIR/summary.json" "$BENCH_DIR/results/summary.json"
mkdir -p "$PLOT_DIR"
cp "$OUTPUT_DIR"/*.svg "$PLOT_DIR/"

find "$OUTPUT_DIR" -type f ! -name SHA256SUMS -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 shasum -a 256 > "$OUTPUT_DIR/SHA256SUMS"
