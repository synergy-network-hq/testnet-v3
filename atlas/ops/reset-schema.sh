#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
network_config=""
evidence_dir=""
apply=false
offline_reset=false

while (($#)); do
  case "$1" in
    --network-config) network_config="${2:?missing network config}"; shift 2 ;;
    --evidence-dir) evidence_dir="${2:?missing evidence directory}"; shift 2 ;;
    --offline-reset) offline_reset=true; shift ;;
    --apply) apply=true; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ "$apply" == true ]] || {
  echo "Atlas schema reset requires --apply" >&2
  exit 2
}
[[ -n "$network_config" && -f "$network_config" ]] || {
  echo "A finalized Atlas network config is required" >&2
  exit 2
}
[[ -n "$evidence_dir" ]] || {
  echo "An evidence directory is required" >&2
  exit 2
}
[[ -n "${ATLAS_DATABASE_URL:-}" ]] || {
  echo "ATLAS_DATABASE_URL is required" >&2
  exit 2
}
for command in node jq psql sha256sum; do
  command -v "$command" >/dev/null || {
    echo "Atlas reset requires $command" >&2
    exit 1
  }
done

mkdir -p "$evidence_dir"
[[ -z "$(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
  echo "Atlas reset evidence directory must be empty" >&2
  exit 1
}

node "$root/atlas/scripts/validate-network-config.mjs" "$network_config" \
  >"$evidence_dir/network-config-validation.json"
if [[ "$offline_reset" == false ]]; then
  node "$root/atlas/scripts/preflight-live-rpc.mjs" "$network_config" \
    >"$evidence_dir/live-rpc-preflight.json"
else
  printf '%s\n' '{"preflight":"deferred_until_operational_gate"}' \
    >"$evidence_dir/live-rpc-preflight.json"
fi
jq -e '
  .chain_id == 1266
  and .chain_incarnation == 4
  and .network_id == "synergy-testnet-v3"
  and (.genesis_hash | test("^[0-9a-f]{64}$"))
' "$network_config" >/dev/null

printf '%s\n' 'RESET ATLAS CHAIN 1266 INCARNATION 4' \
  >"$evidence_dir/confirmation.txt"
# Atlas shares its PostgreSQL database with user-facing data.  Reset only the
# explicit chain-derived relation set: dropping `public` would also erase
# profiles and administrative records.  RESTRICT is intentional; an unknown
# dependency must stop this destructive operation rather than be cascaded.
chain_tables=(
  etdag_edges
  internal_transfers
  approvals
  fee_collections
  token_holders
  transactions
  indexer_checkpoints
  indexer_state
  aggregate_metrics
  chart_points
  activity_records
  reward_distributions
  validators
  contracts
  tokens
  accounts
  blocks
  etdag_vertices
  atlas_network
)
printf '%s\n' "${chain_tables[@]}" >"$evidence_dir/chain-derived-tables.txt"
chain_table_literals="$(printf "'%s'," "${chain_tables[@]}")"
chain_table_literals="${chain_table_literals%,}"
psql "$ATLAS_DATABASE_URL" -At -v ON_ERROR_STOP=1 \
  -c "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' AND table_name NOT IN (${chain_table_literals}) ORDER BY table_name" \
  >"$evidence_dir/preserved-public-tables.txt"
{
  for table in "${chain_tables[@]}"; do
    printf 'DROP TABLE IF EXISTS public.%s RESTRICT;\n' "$table"
  done
  sed -e '1{/^BEGIN;$/d;}' -e '${/^COMMIT;$/d;}' \
    "$root/atlas/schema/001_atlas_v3.sql"
} | psql "$ATLAS_DATABASE_URL" --single-transaction -v ON_ERROR_STOP=1 \
  >"$evidence_dir/schema-reset.log"

genesis_hash="$(jq -er .genesis_hash "$network_config")"
manifest_sha256="$(sha256sum "$network_config" | awk '{print $1}')"
rpc_url="$(jq -er .endpoints.rpc "$network_config")"
api_url="$(jq -er .endpoints.api "$network_config")"
websocket_url="$(jq -er .endpoints.websocket "$network_config")"
if [[ "$offline_reset" == false ]]; then
  psql "$ATLAS_DATABASE_URL" -v ON_ERROR_STOP=1 \
    --set=genesis_hash="$genesis_hash" \
    --set=manifest_sha256="$manifest_sha256" \
    --set=rpc_url="$rpc_url" \
    --set=api_url="$api_url" \
    --set=websocket_url="$websocket_url" <<'SQL' \
    >"$evidence_dir/network-binding.log"
INSERT INTO atlas_network (
  chain_id, chain_incarnation, network_id, genesis_hash, network_magic,
  rpc_url, api_url, websocket_url, manifest_sha256
) VALUES (
  1266, 4, 'synergy-testnet-v3', :'genesis_hash', 'c1266004',
  :'rpc_url', :'api_url', :'websocket_url', :'manifest_sha256'
);
SQL
else
  printf '%s\n' 'DEFERRED_UNTIL_RPC_OPERATIONAL' \
    >"$evidence_dir/network-binding.log"
fi

psql "$ATLAS_DATABASE_URL" -At -v ON_ERROR_STOP=1 \
  -c "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' AND table_name IN (${chain_table_literals}) AND NOT EXISTS (SELECT 1 FROM information_schema.columns c WHERE c.table_schema='public' AND c.table_name=information_schema.tables.table_name AND c.column_name='chain_incarnation') ORDER BY table_name" \
  >"$evidence_dir/tables-without-incarnation.txt"
[[ ! -s "$evidence_dir/tables-without-incarnation.txt" ]] || {
  echo "Atlas schema contains a table without chain_incarnation" >&2
  exit 1
}
find "$evidence_dir" -type f ! -name SHA256SUMS -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  | sed "s#  $evidence_dir/#  #" >"$evidence_dir/SHA256SUMS"
if [[ "$offline_reset" == true ]]; then
  echo "ATLAS_CHAIN1266_INCARNATION4_OFFLINE_EMPTY_SCHEMA_READY evidence=$evidence_dir"
else
  echo "ATLAS_CHAIN1266_INCARNATION4_EMPTY_SCHEMA_READY evidence=$evidence_dir"
fi
