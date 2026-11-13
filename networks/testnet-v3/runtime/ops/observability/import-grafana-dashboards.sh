#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DASHBOARD_DIR="$ROOT_DIR/ops/observability/grafana"
GRAFANA_URL="${GRAFANA_URL:-http://127.0.0.1:3000}"
GRAFANA_FOLDER_ID="${GRAFANA_FOLDER_ID:-0}"

if [[ -n "${GRAFANA_API_TOKEN:-}" ]]; then
  AUTH_ARGS=(-H "Authorization: Bearer ${GRAFANA_API_TOKEN}")
else
  GRAFANA_USER="${GRAFANA_USER:-admin}"
  GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-admin}"
  AUTH_ARGS=(-u "${GRAFANA_USER}:${GRAFANA_PASSWORD}")
fi

for dashboard in "$DASHBOARD_DIR"/*.json; do
  title="$(jq -r '.title' "$dashboard")"
  payload="$(jq --argjson folderId "$GRAFANA_FOLDER_ID" '{dashboard: ., folderId: $folderId, overwrite: true}' "$dashboard")"
  curl -fsS \
    "${AUTH_ARGS[@]}" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "$payload" \
    "$GRAFANA_URL/api/dashboards/db" >/dev/null
  echo "Imported: $title"
done
