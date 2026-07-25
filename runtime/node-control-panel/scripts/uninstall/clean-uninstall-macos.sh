#!/usr/bin/env bash
set -uo pipefail
shopt -s nullglob

ASSUME_YES=0
if [[ "${1:-}" == "--yes" || "${1:-}" == "-y" ]]; then
  ASSUME_YES=1
fi

log() {
  printf '[clean-uninstall-macos] %s\n' "$*"
}

warn() {
  printf '[clean-uninstall-macos] WARN: %s\n' "$*" >&2
}

prune_empty_dir() {
  local path="$1"
  rmdir "$path" 2>/dev/null || true
}

prune_user_synergy_dirs() {
  prune_empty_dir "$HOME/.synergy/testnet/ceremony/imports"
  prune_empty_dir "$HOME/.synergy/testnet/ceremony"
  prune_empty_dir "$HOME/.synergy/testnet"
  prune_empty_dir "$HOME/.synergy"
}

run_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
    return $?
  fi

  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
    return $?
  fi

  warn "sudo is not available; skipped root command: $*"
  return 1
}

remove_path() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    rm -rf -- "$path" 2>/dev/null || true
    log "Removed $path"
  fi
}

remove_root_path() {
  local path="$1"
  if run_root test -e "$path" 2>/dev/null || run_root test -L "$path" 2>/dev/null; then
    run_root rm -rf -- "$path" 2>/dev/null || true
    log "Removed $path"
  fi
}

confirm_destructive_action() {
  cat <<'EOF'
This will permanently delete:
  - Synergy Node Control Panel.app
  - local validator/node workspaces under ~/.synergy/testnet
  - monitor workspaces under ~/.synergy-node-control-panel
  - legacy control-panel roots
  - local launch agents and validator launch daemons
  - validator/node bundles staged under /Users/Shared/Synergy/testnet

Bootnode and seed-server services/directories are intentionally preserved.
EOF

  if [[ "$ASSUME_YES" -eq 1 ]]; then
    return 0
  fi

  local confirm
  read -r -p "Type REMOVE to continue: " confirm
  if [[ "$confirm" != "REMOVE" ]]; then
    log "Cancelled."
    exit 0
  fi
}

stop_known_processes() {
  local patterns=(
    "Synergy Node Control Panel"
    "synergy-node-control-panel"
    "synergy-testnet-agent"
    "control-service"
    "$HOME/.synergy/testnet/nodes/"
    "/Users/Shared/Synergy/testnet/validator"
  )

  for pattern in "${patterns[@]}"; do
    pkill -f "$pattern" 2>/dev/null || true
  done

  sleep 1
  for pattern in "${patterns[@]}"; do
    pkill -9 -f "$pattern" 2>/dev/null || true
  done
}

remove_user_launch_agents() {
  local plist="$HOME/Library/LaunchAgents/io.synergy.testnet.agent.plist"
  local label="io.synergy.testnet.agent"

  if [[ -f "$plist" || -L "$plist" ]]; then
    launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
    launchctl unload "$plist" 2>/dev/null || true
    rm -f -- "$plist" 2>/dev/null || true
    log "Removed user launch agent $label"
  fi
}

remove_system_launch_daemons() {
  local plist label
  for plist in \
    /Library/LaunchDaemons/io.synergy.testnet.validator*.plist \
    /Library/LaunchDaemons/network.synergy.innernet.plist; do
    [[ -f "$plist" || -L "$plist" ]] || continue
    label="$(basename "$plist" .plist)"
    run_root launchctl bootout "system/$label" 2>/dev/null || true
    run_root launchctl disable "system/$label" 2>/dev/null || true
    run_root rm -f -- "$plist" 2>/dev/null || true
    log "Removed system launch daemon $label"
  done
  run_root rm -f -- /var/log/synergy-innernet.log /var/log/synergy-innernet.err.log 2>/dev/null || true
}

remove_user_files() {
  local paths=(
    "$HOME/.synergy-node-control-panel"
    "$HOME/.synergy-testnet-control-panel"
    "$HOME/.synergy-node-monitor"
    "$HOME/.synergy/node"
    "$HOME/.synergy/testnet/nodes"
    "$HOME/.synergy/testnet/network"
    "$HOME/.synergy/testnet/wallets"
    "$HOME/Applications/Synergy Node Control Panel.app"
    "$HOME/Library/Application Support/Synergy Node Control Panel"
    "$HOME/Library/Application Support/synergy-node-control-panel"
    "$HOME/Library/Application Support/com.synergy.node-monitor"
    "$HOME/Library/Application Support/io.synergy-network.node-control-panel"
    "$HOME/Library/Caches/Synergy Node Control Panel"
    "$HOME/Library/Caches/synergy-node-control-panel"
    "$HOME/Library/Caches/com.synergy.node-monitor"
    "$HOME/Library/Caches/io.synergy-network.node-control-panel"
    "$HOME/Library/Logs/Synergy Node Control Panel"
    "$HOME/Library/Logs/synergy-node-control-panel"
    "$HOME/Library/Logs/com.synergy.node-monitor"
    "$HOME/Library/Logs/io.synergy-network.node-control-panel"
    "$HOME/Library/Saved Application State/io.synergy-network.node-control-panel.savedState"
    "$HOME/Library/Saved Application State/com.synergy.node-monitor.savedState"
    "$HOME/Library/HTTPStorages/io.synergy-network.node-control-panel"
    "$HOME/Library/HTTPStorages/com.synergy.node-monitor"
    "$HOME/Library/WebKit/io.synergy-network.node-control-panel"
    "$HOME/Library/WebKit/com.synergy.node-monitor"
    "$HOME/Library/Cookies/io.synergy-network.node-control-panel.binarycookies"
    "$HOME/Library/Cookies/com.synergy.node-monitor.binarycookies"
    "$HOME/synergy-testnet-agent.log"
  )

  local path
  for path in "${paths[@]}"; do
    remove_path "$path"
  done

  prune_user_synergy_dirs

  for pref in \
    "$HOME/Library/Preferences/io.synergy-network.node-control-panel.plist" \
    "$HOME/Library/Preferences/com.synergy.node-monitor.plist" \
    "$HOME/Library/Preferences/io.synergy-network.node-control-panel.helper"*.plist \
    "$HOME/Library/Preferences/ByHost/io.synergy-network.node-control-panel."*.plist
  do
    remove_path "$pref"
  done
}

remove_system_files() {
  local paths=(
    "/Applications/Synergy Node Control Panel.app"
  )
  local path
  for path in "${paths[@]}"; do
    remove_root_path "$path"
  done

  for validator_dir in /Users/Shared/Synergy/testnet/validator*; do
    remove_root_path "$validator_dir"
  done

  for package_file in /Users/Shared/Synergy/testnet/control-panel/validator-*-setup-package.json; do
    remove_root_path "$package_file"
  done

  run_root rmdir /Users/Shared/Synergy/testnet/control-panel 2>/dev/null || true
  run_root rmdir /Users/Shared/Synergy/testnet 2>/dev/null || true
  run_root rmdir /Users/Shared/Synergy 2>/dev/null || true
}

main() {
  confirm_destructive_action
  stop_known_processes
  remove_user_launch_agents
  remove_system_launch_daemons
  remove_user_files
  remove_system_files

  log "Clean uninstall complete."
}

main "$@"
