#!/bin/bash
# Script to obtain SSL certificate for all Synergy Network subdomains
# This will get a wildcard certificate for *.synergy-network.io

set -e

echo "=========================================="
echo "Synergy Network SSL Certificate Setup"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ This script must be run as root (use sudo)"
    exit 1
fi

# List of all subdomains that need to be covered
SUBDOMAINS=(
    "synergy-network.io"
    "www.synergy-network.io"
    "api.synergy-network.io"
    "ws.synergy-network.io"
    "explorer.synergy-network.io"
    "indexer.synergy-network.io"
    "validators.synergy-network.io"
    "status.synergy-network.io"
    "assets.synergy-network.io"
    "docs.synergy-network.io"
    "testnet-core-rpc.synergy-network.io"
    "testnet-core-ws.synergy-network.io"
    "testnet-evm-rpc.synergy-network.io"
    "testnet-evm-ws.synergy-network.io"
    "testnet-api.synergy-network.io"
    "testnet-explorer.synergy-network.io"
    "testnet-indexer.synergy-network.io"
    "testnet-wallet-api.synergy-network.io"
    "testnet-faucet.synergy-network.io"
    "testnet-sxcp-api.synergy-network.io"
    "testnet-sxcp-ws.synergy-network.io"
    "testnet-synq-verify.synergy-network.io"
    "testnet-atlas-api.synergy-network.io"
    "testnet-atlas.synergy-network.io"
    "testnet.synergy-network.io"
)

echo "📋 Subdomains to cover:"
for domain in "${SUBDOMAINS[@]}"; do
    echo "   - $domain"
done
echo ""

# Option 1: Wildcard certificate (recommended)
echo "Option 1: Wildcard Certificate (*.synergy-network.io)"
echo "This will cover ALL subdomains automatically."
echo ""
echo "⚠️  WILDCARD CERTIFICATE REQUIRES DNS-01 CHALLENGE"
echo "   You will need to add a TXT record to your DNS provider."
echo "   Certbot will provide the exact record to add."
echo ""
read -p "Do you want to proceed with wildcard certificate? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🔐 Obtaining wildcard certificate..."
    echo ""
    echo "⚠️  IMPORTANT: You will be prompted to add a DNS TXT record."
    echo "   Certbot will show you the exact record to add."
    echo "   After adding it, press Enter to continue."
    echo ""
    read -p "Press Enter to continue..."
    echo ""
    
    certbot certonly \
        --manual \
        --preferred-challenges dns \
        --server https://acme-v02.api.letsencrypt.org/directory \
        -d "*.synergy-network.io" \
        -d "synergy-network.io" \
        --email justin@synergy-network.io \
        --agree-tos \
        --force-renewal || {
        echo ""
        echo "❌ Certificate generation failed."
        echo "   Make sure to add the TXT record when prompted."
        exit 1
    }
    
    echo ""
    echo "✅ Wildcard certificate obtained!"
    echo ""
    echo "📝 Next steps:"
    echo "   1. The certificate is now at: /etc/letsencrypt/live/synergy-network.io/"
    echo "   2. All nginx configs already point to this certificate"
    echo "   3. Test nginx: sudo nginx -t"
    echo "   4. Reload nginx: sudo systemctl reload nginx"
    exit 0
fi

# Option 2: Multi-SAN certificate (alternative)
echo ""
echo "Option 2: Multi-SAN Certificate (all subdomains listed)"
echo "This uses HTTP-01 challenge (easier, but requires all domains to point here)"
echo ""
read -p "Do you want to proceed with multi-SAN certificate? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🔐 Obtaining multi-SAN certificate..."
    
    # Build certbot command with all domains
    CERTBOT_CMD="certbot certonly --webroot -w /var/www/letsencrypt"
    for domain in "${SUBDOMAINS[@]}"; do
        CERTBOT_CMD="$CERTBOT_CMD -d $domain"
    done
    CERTBOT_CMD="$CERTBOT_CMD --email justin@synergy-network.io --agree-tos --non-interactive"
    
    eval $CERTBOT_CMD || {
        echo ""
        echo "❌ Certificate generation failed."
        echo "   Make sure all domains point to this server and nginx is running."
        exit 1
    }
    
    echo ""
    echo "✅ Multi-SAN certificate obtained!"
    echo ""
    echo "📝 Next steps:"
    echo "   1. The certificate is now at: /etc/letsencrypt/live/synergy-network.io/"
    echo "   2. All nginx configs already point to this certificate"
    echo "   3. Test nginx: sudo nginx -t"
    echo "   4. Reload nginx: sudo systemctl reload nginx"
    exit 0
fi

echo ""
echo "❌ No certificate obtained. Exiting."
exit 1
