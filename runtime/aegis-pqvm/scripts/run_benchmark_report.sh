#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/docs/benchmark"
mkdir -p "$OUT_DIR"

iterations="${AEGIS_BENCH_ITERATIONS:-100}"
profile="${AEGIS_BENCH_PROFILE:-dev}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
raw="$OUT_DIR/pqvm_bench_raw_${stamp}.log"
csv="$OUT_DIR/pqvm_benchmarks.csv"
json="$OUT_DIR/pqvm_benchmarks.json"
report="$OUT_DIR/PQVM_COMPARATIVE_BENCHMARK_REPORT.md"

(
  cd "$ROOT_DIR"
  if [[ "$profile" == "release" ]]; then
    cargo run --release --bin pqvm_bench -- --iterations "$iterations"
  else
    cargo run --bin pqvm_bench -- --iterations "$iterations"
  fi
) | tee "$raw"

echo "module,algorithm,operation,iterations,avg_duration" > "$csv"
awk -v iter="$iterations" '
  /^[A-Z0-9-]+:$/ {
    alg = $0;
    sub(/:$/, "", alg);
    next;
  }
  /^[a-zA-Z][^:]*: [0-9]+ iters in / {
    op = $1;
    sub(/:$/, "", op);
    avg = $NF;
    gsub(/[()]/, "", avg);
    print "aegis-pqvm," alg "," op "," iter "," avg;
  }
' "$raw" >> "$csv"

echo "[" > "$json"
first=1
while IFS=, read -r module algorithm operation iters avg; do
  if [[ "$module" == "module" ]]; then
    continue
  fi
  if [[ $first -eq 0 ]]; then
    echo "," >> "$json"
  fi
  first=0
  printf '  {"module":"%s","algorithm":"%s","operation":"%s","iterations":%s,"avg_duration":"%s"}' \
    "$module" "$algorithm" "$operation" "$iters" "$avg" >> "$json"
done < "$csv"
echo "" >> "$json"
echo "]" >> "$json"

cat > "$report" <<REPORT
# Aegis PQVM Comparative Benchmark Report

This report is reproducible from:
- \`scripts/run_benchmark_report.sh\`
- binary: \`src/bin/pqvm_bench.rs\`

Execution metadata:
- UTC timestamp: ${stamp}
- iterations per operation: ${iterations}
- Cargo profile: ${profile}

Peer-comparison policy:
- Internal benchmark data is generated in controlled CI for reproducibility.
- External peer baselines are maintained by security review under change-control.

Output artifacts:
- \`docs/benchmark/pqvm_benchmarks.csv\`
- \`docs/benchmark/pqvm_benchmarks.json\`
- \`docs/benchmark/pqvm_bench_raw_${stamp}.log\`
REPORT

echo "Benchmark report refreshed under $OUT_DIR"
