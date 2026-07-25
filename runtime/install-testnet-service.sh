#!/bin/bash
# Install and enable the testnet bootnode systemd service

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="$SCRIPT_DIR/synergy-testnet-bootnode.service"
SYSTEMD_PATH="/etc/systemd/system/synergy-testnet-bootnode.service"

echo "Installing Synergy Testnet Bootnode systemd service..."

# Check if service file exists
if [ ! -f "$SERVICE_FILE" ]; then
    echo "Error: Service file not found at $SERVICE_FILE"
    exit 1
fi

# Copy service file
sudo cp "$SERVICE_FILE" "$SYSTEMD_PATH"
echo "✓ Service file copied to $SYSTEMD_PATH"

# Reload systemd
sudo systemctl daemon-reload
echo "✓ Systemd daemon reloaded"

# Stop existing bootnode if running via script
if [ -f "$SCRIPT_DIR/data/bootnode1.pid" ]; then
    PID=$(cat "$SCRIPT_DIR/data/bootnode1.pid" 2>/dev/null || echo "")
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        echo "Stopping existing bootnode process (PID: $PID)..."
        kill "$PID" 2>/dev/null || true
        sleep 2
    fi
fi

# Enable and start service
sudo systemctl enable synergy-testnet-bootnode.service
echo "✓ Service enabled to start on boot"

sudo systemctl start synergy-testnet-bootnode.service
echo "✓ Service started"

# Wait a moment and check status
sleep 3
if sudo systemctl is-active --quiet synergy-testnet-bootnode.service; then
    echo ""
    echo "✅ Testnet bootnode service is running!"
    echo ""
    echo "Useful commands:"
    echo "  Check status:  sudo systemctl status synergy-testnet-bootnode.service"
    echo "  View logs:     sudo journalctl -u synergy-testnet-bootnode.service -f"
    echo "  Restart:       sudo systemctl restart synergy-testnet-bootnode.service"
    echo "  Stop:          sudo systemctl stop synergy-testnet-bootnode.service"
else
    echo ""
    echo "⚠️  Service may not have started correctly. Check status:"
    echo "   sudo systemctl status synergy-testnet-bootnode.service"
    exit 1
fi
