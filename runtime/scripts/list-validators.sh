#!/bin/bash
# Synergy Testnet - List All Validators
# Shows validator addresses, balances, and Synergy Scores

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

RPC_ENDPOINT="${RPC_ENDPOINT:-https://testnet-core-rpc.synergy-network.io}"

echo -e "${BLUE}===================================${NC}"
echo -e "${BLUE}Synergy Testnet - Active Validators${NC}"
echo -e "${BLUE}===================================${NC}"
echo ""

# Get validator list
VALIDATORS=$(curl -s -X POST "$RPC_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"validator_getAll","id":1}' \
  | jq -r '.result.validators[]')

if [ -z "$VALIDATORS" ]; then
    echo -e "${YELLOW}No validators found${NC}"
    exit 0
fi

# Print header
printf "%-45s %-15s %-12s %-10s %s\n" "ADDRESS" "BALANCE" "SYNERGY" "STATUS" "NAME"
printf "%-45s %-15s %-12s %-10s %s\n" "-------" "-------" "-------" "------" "----"

# Iterate through validators
echo "$VALIDATORS" | while read -r validator; do
    ADDR=$(echo "$validator" | jq -r '.address')

    # Get balance
    BALANCE=$(curl -s -X POST "$RPC_ENDPOINT" \
      -H "Content-Type: application/json" \
      -d "{\"jsonrpc\":\"2.0\",\"method\":\"account_getBalance\",\"params\":[\"$ADDR\"],\"id\":1}" \
      | jq -r '.result.balance // "0"')

    # Get Synergy Score
    SCORE=$(curl -s -X POST "$RPC_ENDPOINT" \
      -H "Content-Type: application/json" \
      -d "{\"jsonrpc\":\"2.0\",\"method\":\"synergy_getScore\",\"params\":[\"$ADDR\"],\"id\":1}" \
      | jq -r '.result.synergyScore // "0.00"')

    STATUS=$(echo "$validator" | jq -r '.status // "active"')
    NAME=$(echo "$validator" | jq -r '.metadata.name // "Unnamed"')

    # Format balance (add commas)
    BALANCE_FMT=$(printf "%'d" "$BALANCE" 2>/dev/null || echo "$BALANCE")

    printf "%-45s %-15s %-12s %-10s %s\n" "$ADDR" "$BALANCE_FMT" "$SCORE" "$STATUS" "$NAME"
done

echo ""
echo -e "${CYAN}Total Validators: $(echo "$VALIDATORS" | wc -l)${NC}"
echo ""
