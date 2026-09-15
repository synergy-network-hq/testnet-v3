#!/bin/bash
# Simple script to get wildcard SSL certificate using certbot
# This is the easiest method if you have DNS access

set -e

echo "=========================================="
echo "Synergy Network Wildcard SSL Certificate"
echo "=========================================="
echo ""
echo "This will get a wildcard certificate for *.synergy-network.io"
echo "which covers ALL subdomains automatically."
echo ""
echo "⚠️  You will need to add a DNS TXT record when prompted."
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ This script must be run as root (use sudo)"
    exit 1
fi

echo "🔐 Starting certificate generation..."
echo ""
echo "Certbot will prompt you to add a DNS TXT record."
echo "After adding the record to your DNS provider, press Enter."
echo ""

certbot certonly \
    --manual \
    --preferred-challenges dns \
    -d "*.synergy-network.io" \
    -d "synergy-network.io"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Certificate obtained successfully!"
    echo ""
    echo "📝 Next steps:"
    echo "   1. Test nginx: sudo nginx -t"
    echo "   2. Reload nginx: sudo systemctl reload nginx"
    echo "   3. Verify: Check browser console - ERR_CERT_COMMON_NAME_INVALID should be gone"
    echo ""
    echo "Certificate location: /etc/letsencrypt/live/synergy-network.io/"
else
    echo ""
    echo "❌ Certificate generation failed."
    echo "   Make sure you added the DNS TXT record when prompted."
    exit 1
fi
