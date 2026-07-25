#!/bin/bash
# Add testnet-evm-rpc.synergy-network.io to the SSL certificate

set -e

echo "=========================================="
echo "Add testnet-evm-rpc.synergy-network.io to SSL Certificate"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ This script must be run as root (use sudo)"
    exit 1
fi

# First, let's check what certificate exists
echo "📋 Checking existing certificates..."
echo ""

# Try to find the certificate name
CERT_NAME=""
if [ -d "/etc/letsencrypt/live/synergy-network.io" ]; then
    CERT_NAME="synergy-network.io"
elif [ -d "/etc/letsencrypt/live/synergy-network.io-0001" ]; then
    CERT_NAME="synergy-network.io-0001"
else
    echo "❌ No certificate found. Please obtain a certificate first."
    exit 1
fi

echo "✅ Found certificate: $CERT_NAME"
echo ""

# Get all domains from the existing certificate
echo "📋 Reading existing certificate domains..."
if [ -f "/etc/letsencrypt/live/$CERT_NAME/fullchain.pem" ]; then
    EXISTING_DOMAINS=$(openssl x509 -in /etc/letsencrypt/live/$CERT_NAME/fullchain.pem -text -noout 2>/dev/null | grep -A 1 "Subject Alternative Name" | grep "DNS:" | sed 's/.*DNS:\([^,]*\).*/\1/' | tr '\n' ' ')
    echo "Current domains in certificate:"
    echo "$EXISTING_DOMAINS" | tr ' ' '\n' | grep -v '^$'
    echo ""
fi

# Check if testnet-evm-rpc is already included
if echo "$EXISTING_DOMAINS" | grep -q "testnet-evm-rpc.synergy-network.io"; then
    echo "✅ testnet-evm-rpc.synergy-network.io is already in the certificate!"
    exit 0
fi

echo "📝 Adding testnet-evm-rpc.synergy-network.io to certificate..."
echo ""

# Build the list of all domains to include
# We need to include all existing domains plus the new one
ALL_DOMAINS=(
    "synergy-network.io"
    "testnet-core-rpc.synergy-network.io"
    "testnet-core-ws.synergy-network.io"
    "testnet-evm-rpc.synergy-network.io"
    "testnet-evm-ws.synergy-network.io"
    "testnet-api.synergy-network.io"
    "testnet-explorer.synergy-network.io"
    "testnet-indexer.synergy-network.io"
    "testnet-atlas-api.synergy-network.io"
    "testnet-atlas.synergy-network.io"
    "testnet.synergy-network.io"
    "api.synergy-network.io"
    "ws.synergy-network.io"
    "explorer.synergy-network.io"
)

# Build certbot command to expand the certificate
CERTBOT_CMD="certbot certonly --webroot -w /var/www/letsencrypt --expand"
for domain in "${ALL_DOMAINS[@]}"; do
    CERTBOT_CMD="$CERTBOT_CMD -d $domain"
done
CERTBOT_CMD="$CERTBOT_CMD --email justin@synergy-network.io --agree-tos --non-interactive"

echo "Running certbot to expand certificate..."
echo "Command: $CERTBOT_CMD"
echo ""

eval $CERTBOT_CMD || {
    echo ""
    echo "❌ Certificate expansion failed."
    echo ""
    echo "Alternative: Try getting a wildcard certificate instead:"
    echo "  sudo /opt/synergy/synergy-testnet/scripts/get-ssl-certificate.sh"
    echo ""
    echo "Or manually expand with:"
    echo "  sudo certbot certonly --webroot -w /var/www/letsencrypt --expand \\"
    echo "    -d synergy-network.io \\"
    echo "    -d testnet-core-rpc.synergy-network.io \\"
    echo "    -d testnet-evm-rpc.synergy-network.io \\"
    echo "    [add all other domains]"
    exit 1
}

echo ""
echo "✅ Certificate expanded successfully!"
echo ""

# Check which certificate directory was created/updated
NEW_CERT_NAME=""
if [ -d "/etc/letsencrypt/live/synergy-network.io-0001" ]; then
    NEW_CERT_NAME="synergy-network.io-0001"
elif [ -d "/etc/letsencrypt/live/synergy-network.io-0002" ]; then
    NEW_CERT_NAME="synergy-network.io-0002"
else
    NEW_CERT_NAME="$CERT_NAME"
fi

echo "📝 Certificate location: /etc/letsencrypt/live/$NEW_CERT_NAME/"
echo ""
echo "⚠️  IMPORTANT: Update Nginx configs to use the correct certificate path!"
echo "   If the certificate is now in a new directory (e.g., -0002),"
echo "   update all ssl_certificate paths in nginx configs."
echo ""
echo "Next steps:"
echo "   1. Test nginx: sudo nginx -t"
echo "   2. Reload nginx: sudo systemctl reload nginx"
echo "   3. Verify: openssl s_client -connect testnet-evm-rpc.synergy-network.io:443 -servername testnet-evm-rpc.synergy-network.io < /dev/null 2>/dev/null | openssl x509 -noout -text | grep -A 1 'Subject Alternative Name'"
echo ""
