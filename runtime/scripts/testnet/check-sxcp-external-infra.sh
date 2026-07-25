#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEFAULT_EXTERNAL_DIR="$ROOT_DIR/sxcp/sxcp_external_chains"
EXTERNAL_DIR="${1:-$DEFAULT_EXTERNAL_DIR}"
REPORT_DIR="$ROOT_DIR/testnet/runtime/reports"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
REPORT_FILE="$REPORT_DIR/sxcp-external-infra-audit-${TIMESTAMP}.txt"

mkdir -p "$REPORT_DIR"

log() {
  echo "$*" | tee -a "$REPORT_FILE"
}

if [[ ! -d "$EXTERNAL_DIR" ]]; then
  echo "External SXCP directory not found: $EXTERNAL_DIR" >&2
  exit 1
fi

log "SXCP External Infra Audit"
log "========================="
log "Generated at (UTC): $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
log "Source path: $EXTERNAL_DIR"
log "Report file: $REPORT_FILE"
log ""

log "1) File Inventory"
for chain in evm solana cosmos substrate bitcoin; do
  chain_dir="$EXTERNAL_DIR/$chain"
  if [[ -d "$chain_dir" ]]; then
    count="$(find "$chain_dir" -type f | wc -l | tr -d ' ')"
    log "- ${chain}: ${count} files"
  else
    log "- ${chain}: MISSING DIRECTORY"
  fi
done
log ""

log "2) Build/Project Metadata Discovery"
manifest_hits="$(find "$EXTERNAL_DIR" -type f \( -name "Cargo.toml" -o -name "go.mod" -o -name "Anchor.toml" -o -name "hardhat.config.*" -o -name "foundry.toml" -o -name "package.json" \) | sort || true)"
manifest_count="$(printf "%s\n" "$manifest_hits" | sed '/^$/d' | wc -l | tr -d ' ')"
log "- Manifest count: $manifest_count"
if [[ "$manifest_count" -gt 0 ]]; then
  printf "%s\n" "$manifest_hits" | sed '/^$/d' | sed 's/^/  - /' | tee -a "$REPORT_FILE" >/dev/null
else
  log "  - No chain-project manifests detected."
fi
log ""

log "3) Placeholder/Stub Scan"
stub_pattern='TODO|placeholder|simplified|skeleton|not production|dummy|stub|always returns true|not implemented|omits|example only'
stub_hits="$(grep -RniE "$stub_pattern" "$EXTERNAL_DIR" || true)"
stub_count="$(printf "%s\n" "$stub_hits" | sed '/^$/d' | wc -l | tr -d ' ')"
log "- Stub-pattern hit count: $stub_count"
if [[ "$stub_count" -gt 0 ]]; then
  log "  - Top matches (first 80):"
  printf "%s\n" "$stub_hits" | sed '/^$/d' | head -n 80 | sed 's/^/    /' | tee -a "$REPORT_FILE" >/dev/null
fi
log ""

log "4) Critical Risk Signature Scan"
risk_pattern='always returns true|TODO: verify aggregated PQC signature|not production ready|Placeholder program ID|Not implemented'
risk_hits="$(grep -RniE "$risk_pattern" "$EXTERNAL_DIR" || true)"
risk_count="$(printf "%s\n" "$risk_hits" | sed '/^$/d' | wc -l | tr -d ' ')"
log "- Critical risk hit count: $risk_count"
if [[ "$risk_count" -gt 0 ]]; then
  printf "%s\n" "$risk_hits" | sed '/^$/d' | head -n 80 | sed 's/^/    /' | tee -a "$REPORT_FILE" >/dev/null
fi
log ""

log "5) Verdict"
blocking=0

if [[ "$manifest_count" -eq 0 ]]; then
  log "- BLOCKER: No deployable project manifests were found."
  blocking=1
fi

if [[ "$risk_count" -gt 0 ]]; then
  log "- BLOCKER: Critical risk patterns indicate non-production logic."
  blocking=1
fi

if [[ "$stub_count" -gt 0 ]]; then
  log "- WARNING: Placeholder/stub patterns are present."
fi

if [[ "$blocking" -eq 1 ]]; then
  log "- RESULT: FAIL (external SXCP infra is not production-ready)."
  exit 2
fi

log "- RESULT: PASS (no blocking issues detected by this static audit)."
