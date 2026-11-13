#!/usr/bin/env bash
set -euo pipefail

SOURCE_DATA_DIR="${SOURCE_DATA_DIR:-/opt/synergy/Node-RPC/data}"
QRPC_URL="${QRPC_URL:-http://127.0.0.1:5641}"
OUTPUT_ROOT="${OUTPUT_ROOT:-/tmp}"
SOURCE_NODE_LABEL="${SOURCE_NODE_LABEL:-RPC Gateway row9}"
PAUSE_SERVICE="${PAUSE_SERVICE:-}"

command -v jq >/dev/null
command -v curl >/dev/null
command -v tar >/dev/null
command -v zstd >/dev/null
command -v sha256sum >/dev/null

[[ -d "${SOURCE_DATA_DIR}" ]] || {
  echo "source data dir not found: ${SOURCE_DATA_DIR}" >&2
  exit 1
}

now="$(date -u +%Y%m%dT%H%M%SZ)"
latest="$(curl -s --max-time 5 -H "content-type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getLatestBlock","params":[]}' \
  "${QRPC_URL}")"
height="$(printf '%s' "${latest}" | jq -r '.result.block_index')"
hash="$(printf '%s' "${latest}" | jq -r '.result.hash')"

[[ "${height}" =~ ^[0-9]+$ ]] || {
  echo "could not read source height from qRPC: ${latest}" >&2
  exit 1
}
[[ -n "${hash}" && "${hash}" != "null" ]] || {
  echo "could not read source hash from qRPC: ${latest}" >&2
  exit 1
}

stage="${OUTPUT_ROOT}/synergy-archive-bootstrap-data-h${height}-${now}"
artifact="${stage}.tar.zst"
rm -rf "${stage}" "${artifact}" "${artifact}.sha256"
mkdir -p "${stage}"

jq -n \
  --arg schema "synergy-archive-bootstrap-data-v1" \
  --arg created_at_utc "${now}" \
  --arg source_node "${SOURCE_NODE_LABEL}" \
  --arg source_data_dir "${SOURCE_DATA_DIR}" \
  --arg source_qrpc "${QRPC_URL}" \
  --arg source_hash "${hash}" \
  --arg note "manual archive bootstrap only; not a published majority-proof snapshot" \
  --argjson source_height "${height}" \
  '{
    schema: $schema,
    created_at_utc: $created_at_utc,
    source_node: $source_node,
    source_data_dir: $source_data_dir,
    source_qrpc: $source_qrpc,
    source_height: $source_height,
    source_hash: $source_hash,
    note: $note,
    includes: [
      "data/chain.json",
      "data/committed_qcs.jsonl",
      "data/committed_blocks.jsonl",
      "data/canonical_locks.json",
      "data/canonical_locks.jsonl",
      "data/committed_qcs.json",
      "data/dag_state.json",
      "data/token_state.json",
      "data/validator_registry.json",
      "data/synid_registry.json",
      "data/chain/",
      "data/consensus_proposals/"
    ],
    excludes: [
      "keys",
      "config",
      "genesis",
      "node.env",
      "role-runtime.json",
      "rpc-gateway.json",
      "logs",
      "evidence",
      "recovery-evidence",
      "recovery-rollback",
      "self-heal-evidence",
      "support-state-quarantine",
      "pid files"
    ]
  }' > "${stage}/BOOTSTRAP-MANIFEST.json"

service_paused=0
restart_paused_service() {
  if [[ "${service_paused}" == "1" && -n "${PAUSE_SERVICE}" ]]; then
    systemctl start "${PAUSE_SERVICE}" || true
  fi
}
trap restart_paused_service EXIT

if [[ -n "${PAUSE_SERVICE}" ]]; then
  systemctl stop "${PAUSE_SERVICE}"
  service_paused=1
fi

cd "$(dirname "${SOURCE_DATA_DIR}")"
tar -I "zstd -6 -T0" -cf "${artifact}" \
  -C "${stage}" BOOTSTRAP-MANIFEST.json \
  -C "$(dirname "${SOURCE_DATA_DIR}")" \
  data/chain.json \
  data/committed_qcs.jsonl \
  data/committed_blocks.jsonl \
  data/canonical_locks.json \
  data/canonical_locks.jsonl \
  data/committed_qcs.json \
  data/dag_state.json \
  data/token_state.json \
  data/validator_registry.json \
  data/synid_registry.json \
  data/chain \
  data/consensus_proposals

if [[ "${service_paused}" == "1" ]]; then
  systemctl start "${PAUSE_SERVICE}"
  service_paused=0
fi
trap - EXIT

sha256sum "${artifact}" > "${artifact}.sha256"
ls -lh "${artifact}" "${artifact}.sha256"
cat "${artifact}.sha256"
printf 'bootstrap_artifact=%s\nbootstrap_checksum=%s\nbootstrap_manifest=%s\nsource_height=%s\nsource_hash=%s\n' \
  "${artifact}" "${artifact}.sha256" "${stage}/BOOTSTRAP-MANIFEST.json" "${height}" "${hash}"
