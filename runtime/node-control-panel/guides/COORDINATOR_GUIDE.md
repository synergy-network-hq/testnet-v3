# Synergy Testnet - Coordinator Operations Guide
**For Managing Validator Onboarding & Token Distribution**

> Current post-fork onboarding requires the Synergy Node Control Panel flow, explicit FN-DSA validator keys, and `50,000 SNRG` bonded stake. Legacy coordinator instructions below are historical; use `guides/CONTROL_PANEL_INSTALL_AND_NEW_VALIDATOR_ONBOARDING.md` for launch-current validator setup.

---

## 🎯 Overview

This guide is for the testnet coordinator who manages:
- Validator registration requests
- SNRG token distribution
- Network monitoring
- Team member onboarding

---

## 📋 Prerequisites

- Access to the testnet server running bootnodes
- Faucet wallet keys: `config/faucet/identity.json`
- Treasury wallet keys: `config/treasury/identity.json`
- RPC access to the testnet (localhost:5640)

---

## 🔧 Available Tools

### 1. Send SNRG Tokens

**Script:** `scripts/send-tokens.sh`

```bash
# Send 1M SNRG to a validator
./scripts/send-tokens.sh synv1abc123... 1000000

# Send 5M SNRG for testing
./scripts/send-tokens.sh synv1xyz789... 5000000
```

**Usage:**
```bash
./scripts/send-tokens.sh <recipient_address> <amount>
```

**Recommended Allocations:**
- **Initial validator allocation:** 1,000,000 SNRG
- **Additional testing tokens:** 500,000 - 5,000,000 SNRG
- **Emergency refills:** As needed

### 2. Register Validator

**Script:** `scripts/register-validator.sh`

```bash
# Register a new validator
./scripts/register-validator.sh synv1abc123... "BASE64_PUBLIC_KEY"
```

**Process:**
1. Team member shares `validator-info.txt`
2. Verify the address format (lowercase, starts with `synv1`)
3. Run registration script
4. Send initial SNRG allocation
5. Notify team member

### 3. List All Validators

**Script:** `scripts/list-validators.sh`

```bash
# View all active validators
./scripts/list-validators.sh
```

**Output:**
```
ADDRESS                                       BALANCE         SYNERGY      STATUS     NAME
-------                                       -------         -------      ------     ----
synv11lylxla8qjcrk3ef8gjlyyhew3z4mjsw...     1,000,000       0.45         active     Bootnode 1
synv11csyhf60yd6gp8n4wflz99km29g7fh8g...     1,000,000       0.43         active     Bootnode 2
synv1abc123def456...                          1,000,000       0.12         active     Team Validator
```

---

## 📝 Validator Onboarding Workflow

### Step 1: Receive Registration Request

Team member will send you their `validator-info.txt`:

```
Validator Registration Information
===================================

Validator Address: synv1abc123def456...
Public Key: MIIBIjANBg...
Algorithm: FN-DSA-1024
Node Type: Class 1 Validator
Server IP: 123.45.67.89
Operator: john.doe
Generated: 2025-12-06 14:30:00
```

### Step 2: Validate the Information

```bash
# Check address format (must be lowercase, start with synv1)
echo "synv1abc123..." | grep -qE '^synv1[0-9a-z]{38,42}$' && echo "✅ Valid" || echo "❌ Invalid"

# Verify they're not already registered
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"validator_getInfo","params":["synv1abc123..."],"id":1}' | jq
```

### Step 3: Register the Validator

```bash
# Extract info from their submission
VALIDATOR_ADDR="synv1abc123def456..."
VALIDATOR_PUBKEY="MIIBIjANBg..."  # Full base64 key

# Register
./scripts/register-validator.sh "$VALIDATOR_ADDR" "$VALIDATOR_PUBKEY"
```

### Step 4: Send Initial SNRG Allocation

```bash
# Send 1M SNRG for initial setup
./scripts/send-tokens.sh "$VALIDATOR_ADDR" 1000000
```

### Step 5: Notify Team Member

Send them confirmation:

```
✅ Validator Registration Complete

Your validator has been registered on Synergy Testnet!

Address: synv1abc123...
Initial Balance: 1,000,000 SNRG
Minimum Stake: 50,000 SNRG bonded before activation

You can now start your validator node.
Your Synergy Score will begin calculating once you're online and synced.

Need more tokens? Just ask!
```

---

## 💰 Token Distribution Guidelines

### Faucet Balance

```bash
# Check faucet balance
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"account_getBalance","params":["synw1lfgerdqglc6p74p9u6k8ghfssl59q8jzhuwm07"],"id":1}' | jq

# Faucet Address: synw1lfgerdqglc6p74p9u6k8ghfssl59q8jzhuwm07
# Total Allocation: 2,000,000,000 SNRG (2 Billion)
```

### Recommended Allocations

| Purpose | Amount | Notes |
|---------|--------|-------|
| **Initial Validator** | 1,000,000 SNRG | For first-time setup |
| **Additional Testing** | 500,000 - 5,000,000 SNRG | Upon request |
| **Contract Deployment** | 10,000 - 100,000 SNRG | For smart contract testing |
| **Transaction Testing** | 10,000 - 50,000 SNRG | For basic tx tests |

### Bulk Token Distribution

```bash
# Send to multiple validators
for addr in synv1abc123... synv1def456... synv1ghi789...; do
  echo "Sending 1M SNRG to $addr"
  ./scripts/send-tokens.sh "$addr" 1000000
  sleep 2
done
```

---

## 📊 Monitoring & Maintenance

### Check Network Status

```bash
# View all validators
./scripts/list-validators.sh

# Check specific validator
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"validator_getInfo","params":["synv1abc123..."],"id":1}' | jq

# Check their Synergy Score
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getScore","params":["synv1abc123..."],"id":1}' | jq
```

### Monitor Blockchain Health

```bash
# Check latest block
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getBlockHeight","id":1}' | jq

# Check peer count
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","id":1}' | jq

# Check network consensus
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"consensus_getStatus","id":1}' | jq
```

### View Faucet Transaction History

```bash
# Get faucet transactions
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"account_getTransactions","params":["synw1lfgerdqglc6p74p9u6k8ghfssl59q8jzhuwm07",{"limit":20}],"id":1}' | jq
```

---

## 🔒 Security Best Practices

### Protect Faucet Keys

```bash
# Verify permissions
ls -la config/faucet/identity.json
# Should be: -rw------- (600)

# Set if needed
chmod 600 config/faucet/identity.json
chmod 600 config/treasury/identity.json

# Never commit keys to git
git check-ignore config/faucet/identity.json  # Should return the path
git check-ignore config/treasury/identity.json
```

### Rate Limiting

**Manual Guidelines:**
- Maximum 10M SNRG per validator per day
- Monitor for suspicious activity
- Keep logs of all token distributions

### Audit Log

Create a simple audit log:

```bash
# Log token distributions
cat >> token-distribution-log.txt <<EOF
$(date) - Sent 1,000,000 SNRG to synv1abc123... (john.doe - initial allocation)
EOF

# View recent distributions
tail -20 token-distribution-log.txt
```

---

## ❓ Common Issues & Solutions

### Issue: "Insufficient faucet balance"

```bash
# Check faucet balance
./scripts/send-tokens.sh synv1... 1000000  # Will show current balance

# If needed, transfer from treasury
# (This requires updating the scripts to support treasury transfers)
```

### Issue: "Validator already registered"

```bash
# Check existing validator
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"validator_getInfo","params":["synv1abc123..."],"id":1}' | jq

# If duplicate registration, just send tokens
./scripts/send-tokens.sh synv1abc123... 1000000
```

### Issue: "Invalid address format"

Common mistakes:
- ❌ Mixed case: `sYnV1...` should be `synv1...`
- ❌ Wrong prefix: `synw1...` (wallet) instead of `synv1...` (validator)
- ❌ Has hyphens: `synv1-abc-123` should be `synv1abc123`

Ask team member to regenerate with latest address engine.

---

## 📞 Quick Reference Commands

```bash
# Send tokens
./scripts/send-tokens.sh <address> <amount>

# Register validator
./scripts/register-validator.sh <address> <public_key>

# List all validators
./scripts/list-validators.sh

# Check balance
curl -s -X POST http://localhost:5640/rpc -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"account_getBalance","params":["<address>"],"id":1}' | jq

# Check Synergy Score
curl -s -X POST http://localhost:5640/rpc -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getScore","params":["<address>"],"id":1}' | jq
```

---

## 📋 Onboarding Checklist

For each new validator:

- [ ] Receive `validator-info.txt` from team member
- [ ] Validate address format (lowercase, synv1 prefix)
- [ ] Check validator is not already registered
- [ ] Run `register-validator.sh`
- [ ] Send initial 1M SNRG via `send-tokens.sh`
- [ ] Confirm registration with team member
- [ ] Add to tracking spreadsheet/document
- [ ] Monitor their Synergy Score after 24 hours

---

## 📈 Monitoring Dashboard (Optional)

Create a simple monitoring script:

```bash
#!/bin/bash
# monitor-testnet.sh

echo "=== Synergy Testnet Status ==="
echo ""
echo "Block Height:"
curl -s -X POST http://localhost:5640/rpc -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getBlockHeight","id":1}' | jq -r '.result'

echo ""
echo "Active Validators:"
./scripts/list-validators.sh

echo ""
echo "Faucet Balance:"
curl -s -X POST http://localhost:5640/rpc -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"account_getBalance","params":["synw1lfgerdqglc6p74p9u6k8ghfssl59q8jzhuwm07"],"id":1}' \
  | jq -r '.result.balance'
```

---

**You're all set to manage the Synergy Testnet! 🚀**

Need help? Check the main documentation or reach out to the dev team.
