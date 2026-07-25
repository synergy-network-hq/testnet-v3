#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="${HOME}/.synergy-node-control-panel/monitor-workspace"
LEGACY_ROOT="${HOME}/.synergy-node-monitor/monitor-workspace"
LAUNCH_AGENT="${HOME}/Library/LaunchAgents/io.synergy.testnet.agent.plist"

echo "Cleaning Synergy Node Control Panel artifacts on macOS..."

launchctl unload "$LAUNCH_AGENT" >/dev/null 2>&1 || true
rm -f "$LAUNCH_AGENT"
rm -rf "$WORKSPACE_ROOT" "$LEGACY_ROOT"

echo "Removed local control-panel workspace and launch agent."
echo "Removed local control-panel artifacts only."
