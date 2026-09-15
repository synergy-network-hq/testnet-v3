#!/bin/bash
# Synergy Testnet - Register New Validator
# Usage: ./register-validator.sh <validator_address> <public_key_base64>

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

RPC_ENDPOINT="${SYNERGY_RPC_ENDPOINT:-https://testnet-core-rpc.synergy-network.io}"

# Check arguments
if [ $# -lt 2 ]; then
    echo -e "${RED}Error: Missing arguments${NC}"
    echo "Usage: $0 <validator_address> <public_key_base64>"
    echo ""
    echo "Example:"
    echo "  $0 synv1abc123... \"MIIBIjANBgk...\""
    exit 1
fi

VALIDATOR_ADDRESS="$1"
PUBLIC_KEY="$2"

# Validate address
if [[ ! "$VALIDATOR_ADDRESS" =~ ^synv1[0-9a-z]{38,42}$ ]]; then
    echo -e "${RED}Error: Invalid validator address format${NC}"
    echo "Must start with synv1 and be lowercase"
    exit 1
fi

echo -e "${BLUE}===================================${NC}"
echo -e "${BLUE}Synergy Testnet - Validator Registration${NC}"
echo -e "${BLUE}===================================${NC}"
echo ""
echo "Validator Address: $VALIDATOR_ADDRESS"
echo "Public Key: ${PUBLIC_KEY:0:64}..."
echo ""

# Check if validator already exists
echo "Checking if validator is already registered..."
EXISTING=$(curl -s -X POST "$RPC_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"validator_getInfo\",\"params\":[\"$VALIDATOR_ADDRESS\"],\"id\":1}" \
  | jq -r '.result.address // "null"')

if [ "$EXISTING" != "null" ]; then
    echo -e "${YELLOW}⚠️  Validator is already registered!${NC}"
    curl -s -X POST "$RPC_ENDPOINT" \
      -H "Content-Type: application/json" \
      -d "{\"jsonrpc\":\"2.0\",\"method\":\"validator_getInfo\",\"params\":[\"$VALIDATOR_ADDRESS\"],\"id\":1}" \
      | jq '.result'
    exit 0
fi

echo "Validator not found - proceeding with registration..."
echo ""

# Register validator
echo "Registering validator..."
RESULT=$(curl -s -X POST "$RPC_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\":\"2.0\",
    \"method\":\"validator_register\",
    \"params\":[{
      \"address\": \"$VALIDATOR_ADDRESS\",
      \"publicKey\": \"$PUBLIC_KEY\",
      \"stake\": \"0\",
      \"metadata\": {
        \"name\": \"Team Validator\",
        \"registeredAt\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
      }
    }],
    \"id\":1
  }")

# Check result
SUCCESS=$(echo "$RESULT" | jq -r '.result.success // false')

if [ "$SUCCESS" == "true" ]; then
    echo -e "${GREEN}✅ Validator registered successfully!${NC}"
    echo ""
    echo "Validator Details:"
    echo "$RESULT" | jq '.result'
    echo ""
    echo -e "${GREEN}Next steps:${NC}"
    echo "1. Send SNRG tokens to the validator:"
    echo "   ./scripts/send-tokens.sh $VALIDATOR_ADDRESS 1000000"
    echo ""
    echo "2. Notify the team member that registration is complete"
else
    ERROR=$(echo "$RESULT" | jq -r '.error.message // "Unknown error"')
    echo -e "${RED}❌ Registration failed${NC}"
    echo "Error: $ERROR"
    exit 1
fi
