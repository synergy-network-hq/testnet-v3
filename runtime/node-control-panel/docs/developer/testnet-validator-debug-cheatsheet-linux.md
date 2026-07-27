# Testnet Validator Debug Cheat Sheet (Linux)

Use this file when debugging a control-panel-managed validator appliance on Linux.

These commands assume the validator appliance root is:

- `/var/lib/synergy/validator`

Important:

- Local validator peer inspection uses JSON-RPC `synergy_getPeerInfo` on `http://127.0.0.1:5640`
- Do not use `http://127.0.0.1:5640/peers` for the local validator RPC
- Replace the validator address or hostname examples as needed

## Set Common Variables

Run this block first if you want to use the `$APPLIANCE`, `$RPC`, and `$LOG` shortcuts shown below.

```bash
APPLIANCE="/var/lib/synergy/validator"
RPC="http://127.0.0.1:5640"
LOG="$APPLIANCE/logs/control-start.stdout.log"
```

## Show Full Peer Payload

```bash
curl -s "$RPC" \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getPeerInfo","params":[]}' \
  | jq '.result'
```

## Show Only Validator Peers

```bash
curl -s "$RPC" \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getPeerInfo","params":[]}' \
  | jq '[.result.peers[] | select((.validator_address // "") != "") | {public_address, validator_address, genesis_hash}]'
```

## Show Only Status-Ready Validator Peers

```bash
curl -s "$RPC" \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getPeerInfo","params":[]}' \
  | jq '[.result.peers[] | select((.validator_address // "") != "" and (.genesis_hash // "") != "") | {public_address, validator_address, genesis_hash}]'
```

## Show Remote Validator Counts

This does not include the local validator. Add `1` if you want the same self-inclusive mental model used by the control panel.

```bash
curl -s "$RPC" \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getPeerInfo","params":[]}' \
  | jq '{
      peer_count: .result.peer_count,
      remote_connected_validators: ([.result.peers[] | select((.validator_address // "") != "") | .validator_address] | unique | length),
      remote_status_ready_validators: ([.result.peers[] | select((.validator_address // "") != "" and (.genesis_hash // "") != "") | .validator_address] | unique | length)
    }'
```

## Watch Validator Peer State Live

This version uses the `$RPC` variable from the block above.

```bash
watch -n 2 "curl -s $RPC -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"synergy_getPeerInfo\",\"params\":[]}' | jq '[.result.peers[] | select((.validator_address // \"\") != \"\") | {public_address, validator_address, genesis_hash}]'"
```

Copy-paste version without shell variables:

```bash
watch -n 2 "curl -s http://127.0.0.1:5640 -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"synergy_getPeerInfo\",\"params\":[]}' | jq '[.result.peers[] | select((.validator_address // \"\") != \"\") | {public_address, validator_address, genesis_hash}]'"
```

## Show Advertised Addresses And Consensus Thresholds

```bash
grep -nE 'public_host|public_address|validator_address|min_validators|status_ready_min_validators|persistent_peers' "$APPLIANCE/config/node.toml"
```

## Show Bootstrap And Peer Overlay Inputs

```bash
grep -nE 'bootnodes|seed_servers|additional_dial_targets|persistent_peers' "$APPLIANCE/config/peers.toml"
```

## Show The Current Latest Block Response

```bash
curl -s "$RPC" \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getLatestBlock","params":[]}' \
  | jq '.result'
```

## Tail The Validator Log

```bash
tail -n 120 "$LOG"
```

## Follow The Validator Log Live

```bash
tail -F "$LOG"
```

## Show Handshake, Status, Disconnect, And Dial Failures

```bash
grep -nE 'Handshake received|Received status|Peer disconnected|Failed to dial peer' "$LOG" | tail -n 120
```

## Show Events For One Specific Validator Address

Example for validator `#1`:

```bash
grep -n 'synv11yc4cjehqjm6fp0ey4ppjptv0p3cwdy6r79t' "$LOG" | tail -n 80
```

## Show Listening Sockets On Validator Ports

```bash
ss -ltn '( sport = :5622 or sport = :5640 )'
```

## Show The Running Validator Process

```bash
pgrep -af synergy-testnet
```

## Test Reachability To Another Validator

Example for validator `#1`:

```bash
nc -vz genesisval1.synergy-network.io 5622
```

## Quick Interpretation

- `validator_address = ""` or `null`: peer transport exists, but validator identity handshake is not complete
- `genesis_hash = ""`: validator identity is known, but status sync has not completed yet
- Repeated `Handshake received` followed by `Peer disconnected`: the validator session is flapping
- `Failed to dial peer`: outbound dial path is failing
- Stable validator mesh requires the validator peer to stay visible in the JSON-RPC output, not only in old startup log lines
