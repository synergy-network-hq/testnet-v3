#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STACK_DIR="$ROOT_DIR/testnet/runtime/observability"
COMPOSE_FILE="$STACK_DIR/docker-compose.yml"

if [[ ! -f "$COMPOSE_FILE" ]]; then
  echo "Missing observability stack: $COMPOSE_FILE" >&2
  exit 1
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  docker compose -f "$COMPOSE_FILE" up -d
elif command -v docker-compose >/dev/null 2>&1; then
  docker-compose -f "$COMPOSE_FILE" up -d
else
  echo "Docker Compose is required" >&2
  exit 1
fi

echo "Observability stack started."
echo "Prometheus: http://127.0.0.1:6030"
echo "Grafana:    http://127.0.0.1:3000 (admin/admin)"
echo "Loki:       http://127.0.0.1:3100"
