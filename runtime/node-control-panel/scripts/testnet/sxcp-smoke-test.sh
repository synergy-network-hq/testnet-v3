#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INVENTORY_FILE="$ROOT_DIR/testnet/runtime/node-inventory.csv"
KEYS_DIR="$ROOT_DIR/testnet/runtime/keys"
SIGNER_BIN="$ROOT_DIR/target/release/wallet-pqc-cli"
default_rpc_port="$(awk -F, 'NR > 1 && tolower($5)=="rpc-gateway" {print $8; exit}' "$INVENTORY_FILE" 2>/dev/null || true)"
default_rpc_port="${default_rpc_port:-5646}"
RPC_URL="${1:-http://127.0.0.1:${default_rpc_port}}"

rpc_call() {
  local method="$1"
  local params_json="$2"
  local id="$3"

  curl -sS -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params_json},\"id\":${id}}"
}

ensure_signer() {
  if [[ -x "$SIGNER_BIN" ]]; then
    return
  fi
  (cd "$ROOT_DIR" && cargo build --release --bin wallet-pqc-cli >/dev/null)
}

find_private_key_for_address() {
  local address="$1"
  local key_path
  key_path="$(python3 - "$KEYS_DIR" "$address" <<'PY'
import pathlib
import sys

keys_dir = pathlib.Path(sys.argv[1])
address = sys.argv[2].strip()

for address_file in keys_dir.glob("machine-*/address.txt"):
    try:
        value = address_file.read_text(encoding="utf-8").strip()
    except Exception:
        continue
    if value == address:
        private_key = address_file.parent / "private.key"
        if private_key.exists():
            print(private_key)
            sys.exit(0)

print("")
PY
)"
  if [[ -z "$key_path" ]]; then
    return 1
  fi
  echo "$key_path"
}

sign_event_hash_for_relayer() {
  local relayer_address="$1"
  local event_hash="$2"
  local private_key_file
  private_key_file="$(find_private_key_for_address "$relayer_address")" || {
    echo "Missing private key for relayer address: $relayer_address" >&2
    return 1
  }

  local private_key_b64
  private_key_b64="$(cat "$private_key_file")"

  local output
  output="$("$SIGNER_BIN" sign-message \
    --private-key-b64 "$private_key_b64" \
    --message "$event_hash" \
    --algo fndsa)"

  python3 - "$output" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
print(payload["signature_base64"])
PY
}

echo "Running SXCP quorum smoke test against: $RPC_URL"

relayer_set="$(rpc_call "synergy_getRelayerSet" "[]" 1)"
sxcp_status="$(rpc_call "synergy_getSxcpStatus" "[]" 2)"

if command -v jq >/dev/null 2>&1; then
  echo "$relayer_set" | jq
  echo "$sxcp_status" | jq
else
  echo "$relayer_set"
  echo "$sxcp_status"
fi

selection_json="$(python3 - "$relayer_set" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
result = payload.get("result", {})
quorum = result.get("quorum", {})
t = int(quorum.get("t", 0))
relayers = result.get("relayers", [])

eligible = []
for relayer in relayers:
    if relayer.get("active") and (not relayer.get("slashed")) and relayer.get("online", True):
        eligible.append(relayer.get("address"))

eligible = [address for address in eligible if isinstance(address, str) and address]
eligible.sort()

if t <= 0:
    print(json.dumps({"ok": False, "error": "quorum threshold is 0", "threshold": t, "eligible": eligible}))
    sys.exit(0)

if len(eligible) < t:
    print(json.dumps({"ok": False, "error": "not enough eligible relayers", "threshold": t, "eligible": eligible}))
    sys.exit(0)

selected = eligible[:t]
print(json.dumps({"ok": True, "threshold": t, "selected": selected, "eligible": eligible}))
PY
)"

if [[ "$(python3 - "$selection_json" <<'PY'
import json, sys
print("true" if json.loads(sys.argv[1]).get("ok") else "false")
PY
)" != "true" ]]; then
  echo "Unable to run smoke test: $selection_json" >&2
  exit 1
fi

threshold="$(python3 - "$selection_json" <<'PY'
import json, sys
print(json.loads(sys.argv[1])["threshold"])
PY
)"

selected_relayers="$(python3 - "$selection_json" <<'PY'
import json, sys
print(",".join(json.loads(sys.argv[1])["selected"]))
PY
)"

event_seed="sxcp-testnet-intent-$(date +%s)"
event_hash="$(printf '%s' "$event_seed" | shasum -a 256 | awk '{print $1}')"

echo "Event seed: $event_seed"
echo "Event hash: $event_hash"
echo "Threshold (t): $threshold"
echo "Selected relayers: $selected_relayers"

ensure_signer

id=10
IFS=',' read -r -a relayer_array <<< "$selected_relayers"
for index in "${!relayer_array[@]}"; do
  relayer="${relayer_array[$index]}"
  partial_sig="$(sign_event_hash_for_relayer "$relayer" "$event_hash")"
  metadata="{\"source_chain\":\"sepolia\",\"destination_chain\":\"synergy-testnet\",\"intent_id\":\"$event_seed\",\"proof_type\":\"quorum-smoke\",\"signature_algorithm\":\"fndsa\",\"step\":$((index + 1)),\"threshold\":$threshold}"

  response="$(rpc_call "synergy_submitAttestation" "[\"$relayer\",\"$event_hash\",\"$partial_sig\",$metadata]" "$id")"
  id=$((id + 1))

  if command -v jq >/dev/null 2>&1; then
    echo "$response" | jq
  else
    echo "$response"
  fi
done

echo "Checking event state..."
event_state="$(rpc_call "synergy_getEventAttestation" "[\"$event_hash\"]" "$id")"
id=$((id + 1))
if command -v jq >/dev/null 2>&1; then
  echo "$event_state" | jq
else
  echo "$event_state"
fi

finalized="$(python3 - "$event_state" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
result = payload.get("result", {})
event = result.get("event", {})
print("true" if event.get("finalized") else "false")
PY
)"

if [[ "$finalized" != "true" ]]; then
  echo "SXCP smoke test failed: event did not finalize at quorum." >&2
  exit 1
fi

echo "Verifying replay rejection..."
replay_sig="$(sign_event_hash_for_relayer "${relayer_array[0]}" "$event_hash")"
replay_response="$(rpc_call "synergy_submitAttestation" "[\"${relayer_array[0]}\",\"$event_hash\",\"$replay_sig\",{\"proof_type\":\"replay\",\"signature_algorithm\":\"fndsa\"}]" "$id")"
id=$((id + 1))
if command -v jq >/dev/null 2>&1; then
  echo "$replay_response" | jq
else
  echo "$replay_response"
fi

replay_ok="$(python3 - "$replay_response" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
result = payload.get("result", {})
print("true" if result.get("success") is False else "false")
PY
)"

if [[ "$replay_ok" != "true" ]]; then
  echo "SXCP smoke test failed: replay submission was not rejected." >&2
  exit 1
fi

echo "Fetching recent finalized attestations..."
attestations="$(rpc_call "synergy_getAttestations" "[5]" "$id")"
if command -v jq >/dev/null 2>&1; then
  echo "$attestations" | jq
else
  echo "$attestations"
fi

echo "SXCP quorum smoke test complete."
