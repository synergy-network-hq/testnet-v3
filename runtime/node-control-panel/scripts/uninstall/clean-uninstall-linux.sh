#!/usr/bin/env bash
set -uo pipefail
shopt -s nullglob

ASSUME_YES=0
if [[ "${1:-}" == "--yes" || "${1:-}" == "-y" ]]; then
  ASSUME_YES=1
fi

log() {
  printf '[clean-uninstall-linux] %s\n' "$*"
}

warn() {
  printf '[clean-uninstall-linux] WARN: %s\n' "$*" >&2
}

is_preserved_role() {
  local value="${1:-}"
  value="${value,,}"
  [[ "$value" == bootnode* || "$value" == seed* ]]
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
  - Synergy Node Control Panel application data
  - local validator/node workspaces under ~/.synergy/testnet
  - monitor workspaces under ~/.synergy-node-control-panel
  - legacy control-panel roots
  - local/system testnet agent autostart units
  - validator/node runtimes under /opt/synergy
  - desktop launchers and discovered firewall rules

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
    "/opt/synergy/node-"
    "/opt/synergy/testnet/validator"
  )

  for pattern in "${patterns[@]}"; do
    pkill -f "$pattern" 2>/dev/null || true
  done

  sleep 1
  for pattern in "${patterns[@]}"; do
    pkill -9 -f "$pattern" 2>/dev/null || true
  done
}

stop_user_units() {
  local unit
  for unit_path in "$HOME/.config/systemd/user"/synergy-testnet-agent.service; do
    unit="$(basename "$unit_path")"
    systemctl --user stop "$unit" 2>/dev/null || true
    systemctl --user disable "$unit" 2>/dev/null || true
    rm -f -- "$unit_path" 2>/dev/null || true
    log "Removed user unit $unit"
  done

  systemctl --user daemon-reload 2>/dev/null || true
  systemctl --user reset-failed 2>/dev/null || true
}

stop_system_units() {
  local unit unit_path

  for unit_path in \
    /etc/systemd/system/synergy-testnet-agent.service \
    /usr/lib/systemd/system/synergy-testnet-agent.service \
    /lib/systemd/system/synergy-testnet-agent.service \
    /etc/systemd/system/synergy-testnet-validator*.service \
    /usr/lib/systemd/system/synergy-testnet-validator*.service \
    /lib/systemd/system/synergy-testnet-validator*.service
  do
    unit="$(basename "$unit_path")"
    run_root systemctl stop "$unit" 2>/dev/null || true
    run_root systemctl disable "$unit" 2>/dev/null || true
    run_root rm -f -- "$unit_path" 2>/dev/null || true
    for wants_link in /etc/systemd/system/*.wants/"$unit"; do
      run_root rm -f -- "$wants_link" 2>/dev/null || true
    done
    log "Removed system unit $unit"
  done

  run_root systemctl daemon-reload 2>/dev/null || true
  run_root systemctl reset-failed 2>/dev/null || true
}

remove_linux_packages() {
  local packages=(
    "synergy-node-control-panel"
    "io.synergy-network.node-control-panel"
    "com.synergy.node-control-panel"
    "com.synergy.node-monitor"
  )
  local pkg

  if command -v dpkg-query >/dev/null 2>&1; then
    for pkg in "${packages[@]}"; do
      if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        run_root dpkg -P "$pkg" 2>/dev/null || run_root apt-get purge -y "$pkg" 2>/dev/null || true
        log "Purged package $pkg"
      fi
    done
    run_root apt-get autoremove -y 2>/dev/null || true
  fi

  if command -v rpm >/dev/null 2>&1; then
    for pkg in "${packages[@]}"; do
      if rpm -q "$pkg" >/dev/null 2>&1; then
        run_root rpm -e "$pkg" 2>/dev/null || true
        log "Removed RPM package $pkg"
      fi
    done
  fi

  if command -v dnf >/dev/null 2>&1; then
    for pkg in "${packages[@]}"; do
      run_root dnf remove -y "$pkg" 2>/dev/null || true
    done
  elif command -v yum >/dev/null 2>&1; then
    for pkg in "${packages[@]}"; do
      run_root yum remove -y "$pkg" 2>/dev/null || true
    done
  fi
}

declare -A FIREWALL_PORTS=()

should_collect_ports_from_env() {
  local env_file="$1"
  local machine_id=""
  local node_kind=""
  local key value

  while IFS='=' read -r key value; do
    case "$key" in
      MACHINE_ID)
        machine_id="$value"
        ;;
      NODE_KIND)
        node_kind="$value"
        ;;
    esac
  done < <(grep -E '^(MACHINE_ID|NODE_KIND)=' "$env_file" 2>/dev/null || true)

  if is_preserved_role "$machine_id" || is_preserved_role "$node_kind"; then
    return 1
  fi

  return 0
}

collect_ports_from_node_env() {
  local env_file key value
  local env_files=(
    /opt/synergy/*/node.env
    /opt/synergy/testnet/validator*/node.env
    "$HOME/.synergy-node-control-panel/monitor-workspace/testnet/runtime/installers"/*/node.env
    "$HOME/.synergy-testnet-control-panel/monitor-workspace/testnet/runtime/installers"/*/node.env
    "$HOME/.synergy-node-monitor/monitor-workspace/testnet/runtime/installers"/*/node.env
  )

  FIREWALL_PORTS["47990"]=1

  for env_file in "${env_files[@]}"; do
    [[ -f "$env_file" ]] || continue
    should_collect_ports_from_env "$env_file" || continue
    while IFS='=' read -r key value; do
      case "$key" in
        P2P_PORT|RPC_PORT|WS_PORT|GRPC_PORT|DISCOVERY_PORT)
          if [[ "$value" =~ ^[0-9]+$ ]]; then
            FIREWALL_PORTS["$value"]=1
          fi
          ;;
      esac
    done < <(grep -E '^(P2P_PORT|RPC_PORT|WS_PORT|GRPC_PORT|DISCOVERY_PORT)=' "$env_file" 2>/dev/null || true)
  done
}

remove_firewall_rules() {
  local port touched_firewalld=0

  collect_ports_from_node_env

  if command -v ufw >/dev/null 2>&1; then
    for port in "${!FIREWALL_PORTS[@]}"; do
      run_root ufw --force delete allow "${port}/tcp" >/dev/null 2>&1 || true
    done
  fi

  if command -v firewall-cmd >/dev/null 2>&1; then
    for port in "${!FIREWALL_PORTS[@]}"; do
      if run_root firewall-cmd --permanent --query-port="${port}/tcp" >/dev/null 2>&1; then
        run_root firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || true
        touched_firewalld=1
      fi
    done
    if [[ "$touched_firewalld" -eq 1 ]]; then
      run_root firewall-cmd --reload >/dev/null 2>&1 || true
    fi
  fi

  if command -v iptables >/dev/null 2>&1; then
    for port in "${!FIREWALL_PORTS[@]}"; do
      while run_root iptables -C INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1; do
        run_root iptables -D INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 || break
      done
    done
  fi
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
    "$HOME/.config/synergy-node-control-panel"
    "$HOME/.config/Synergy Node Control Panel"
    "$HOME/.config/com.synergy.node-monitor"
    "$HOME/.config/io.synergy-network.node-control-panel"
    "$HOME/.local/share/synergy-node-control-panel"
    "$HOME/.local/share/Synergy Node Control Panel"
    "$HOME/.local/share/com.synergy.node-monitor"
    "$HOME/.local/share/io.synergy-network.node-control-panel"
    "$HOME/.cache/synergy-node-control-panel"
    "$HOME/.cache/Synergy Node Control Panel"
    "$HOME/.cache/com.synergy.node-monitor"
    "$HOME/.cache/io.synergy-network.node-control-panel"
    "$HOME/Applications/Synergy Node Control Panel.AppImage"
    "$HOME/synergy-testnet-agent.log"
  )

  local path
  for path in "${paths[@]}"; do
    remove_path "$path"
  done

  prune_user_synergy_dirs

  for appimage in "$HOME/Applications"/Synergy*.AppImage "$HOME/Downloads"/Synergy*.AppImage; do
    remove_path "$appimage"
  done

  for desktop in \
    "$HOME/.local/share/applications/com.synergy.node-monitor.desktop" \
    "$HOME/.local/share/applications/synergy-node-control-panel.desktop" \
    "$HOME/.local/share/applications/io.synergy-network.node-control-panel.desktop" \
    "$HOME/.local/share/applications/appimagekit-"*Synergy*.desktop
  do
    remove_path "$desktop"
  done

  for icon in "$HOME/.local/share/icons"/**/appimagekit_*Synergy* "$HOME/.local/share/icons"/**/io.synergy-network.node-control-panel*; do
    remove_path "$icon"
  done
}

remove_system_files() {
  local paths=(
    "/opt/synergy/testnet-agent"
    "/var/log/synergy-testnet-agent.log"
    "/usr/share/applications/com.synergy.node-monitor.desktop"
    "/usr/share/applications/synergy-node-control-panel.desktop"
    "/usr/share/applications/io.synergy-network.node-control-panel.desktop"
  )

  local path
  for path in "${paths[@]}"; do
    remove_root_path "$path"
  done

  for node_dir in /opt/synergy/node-* /opt/synergy/testnet/validator*; do
    remove_root_path "$node_dir"
  done

  for package_file in /opt/synergy/testnet/control-panel/validator-*-setup-package.json; do
    remove_root_path "$package_file"
  done

  run_root rmdir /opt/synergy/testnet/control-panel 2>/dev/null || true
  run_root rmdir /opt/synergy/testnet 2>/dev/null || true
  run_root rmdir /opt/synergy 2>/dev/null || true

  for icon in /usr/share/icons/hicolor/*/apps/io.synergy-network.node-control-panel.* /usr/share/icons/hicolor/*/apps/synergy-node-control-panel.* /usr/share/pixmaps/io.synergy-network.node-control-panel.*; do
    remove_root_path "$icon"
  done
}

main() {
  confirm_destructive_action
  stop_known_processes
  stop_user_units
  stop_system_units
  remove_linux_packages
  remove_firewall_rules
  remove_user_files
  remove_system_files

  log "Clean uninstall complete."
}

main "$@"
