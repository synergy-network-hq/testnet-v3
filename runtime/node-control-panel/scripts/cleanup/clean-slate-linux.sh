#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="${HOME}/.synergy-node-control-panel/monitor-workspace"
LEGACY_ROOT="${HOME}/.synergy-node-monitor/monitor-workspace"
SYSTEMD_SERVICE="${HOME}/.config/systemd/user/synergy-testnet-agent.service"

echo "Cleaning Synergy Node Control Panel artifacts on Linux..."

systemctl --user stop synergy-testnet-agent.service >/dev/null 2>&1 || true
systemctl --user disable synergy-testnet-agent.service >/dev/null 2>&1 || true
rm -f "$SYSTEMD_SERVICE"
systemctl --user daemon-reload >/dev/null 2>&1 || true
rm -rf "$WORKSPACE_ROOT" "$LEGACY_ROOT"

echo "Removed local control-panel workspace and systemd user service."
echo "Removed local control-panel artifacts only."
