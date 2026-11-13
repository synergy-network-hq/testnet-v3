#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/archive-validator-observability.env"
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
fi

ARCHIVE_PUBLIC_IP="${ARCHIVE_VALIDATOR_PUBLIC_IP:-73.79.66.255}"
ARCHIVE_LOCAL_IP="${ARCHIVE_VALIDATOR_LOCAL_IP:-192.168.11.140}"
ARCHIVE_BIND_ADDRESS="${ARCHIVE_VALIDATOR_BIND_ADDRESS:-0.0.0.0}"
ARCHIVE_SCRAPE_HOST="${ARCHIVE_VALIDATOR_SCRAPE_HOST:-73.79.66.255}"
OBSERVER_PUBLIC_IP="${OBSERVER_PUBLIC_IP:-209.145.50.9}"
METRICS_PORT="${ARCHIVE_VALIDATOR_METRICS_PORT:-6030}"
NODE_EXPORTER_PORT="${ARCHIVE_VALIDATOR_NODE_EXPORTER_PORT:-9100}"
QRPC_PORT="${ARCHIVE_VALIDATOR_QRPC_PORT:-5640}"
ARCHIVE_LABEL="${ARCHIVE_VALIDATOR_LAUNCHD_LABEL:-io.synergynetwork.archive-validator}"
NODE_CONFIG="${ARCHIVE_VALIDATOR_NODE_CONFIG:-/Users/Shared/Synergy/archive-validator/workspace/config/node.toml}"
RESTART_ARCHIVE_SERVICE="true"
INSTALL_NODE_EXPORTER="true"

usage() {
  cat <<EOF
Usage: sudo ./install-archive-observability.sh [options]

macOS Archive Validator observability setup. This does not install the archive
runtime itself; run the packaged setup-archive-validator-m4.sh first.

Options:
  --node-config PATH            Archive validator node.toml to patch.
  --archive-public-ip IP        Public IP Prometheus scrapes. Default: 73.79.66.255.
  --archive-local-ip IP         Mac LAN IP used for local evidence. Default: 192.168.11.140.
  --archive-bind-address IP     Metrics bind address. Default: 0.0.0.0.
  --archive-scrape-host HOST    Host/IP Observer scrapes. Default: 73.79.66.255.
  --observer-public-ip IP       Observer public IP for firewall/NAT notes. Default: 209.145.50.9.
  --metrics-port PORT           Archive metrics port. Default: 6030.
  --node-exporter-port PORT     node_exporter port. Default: 9100.
  --qrpc-port PORT              qRPC TCP probe port. Default: 5640.
  --launchd-label LABEL         Archive launchd label. Default: io.synergynetwork.archive-validator.
  --no-node-exporter            Do not install or configure node_exporter.
  --no-restart                  Patch config but do not restart archive launchd service.
  --help                        Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --node-config) NODE_CONFIG="$2"; shift 2 ;;
    --archive-public-ip) ARCHIVE_PUBLIC_IP="$2"; shift 2 ;;
    --archive-local-ip) ARCHIVE_LOCAL_IP="$2"; shift 2 ;;
    --archive-bind-address) ARCHIVE_BIND_ADDRESS="$2"; shift 2 ;;
    --archive-scrape-host) ARCHIVE_SCRAPE_HOST="$2"; shift 2 ;;
    --observer-public-ip) OBSERVER_PUBLIC_IP="$2"; shift 2 ;;
    --metrics-port) METRICS_PORT="$2"; shift 2 ;;
    --node-exporter-port) NODE_EXPORTER_PORT="$2"; shift 2 ;;
    --qrpc-port) QRPC_PORT="$2"; shift 2 ;;
    --launchd-label) ARCHIVE_LABEL="$2"; shift 2 ;;
    --no-node-exporter) INSTALL_NODE_EXPORTER="false"; shift ;;
    --no-restart) RESTART_ARCHIVE_SERVICE="false"; shift ;;
    --help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

need_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "Run with sudo so launchd plists and archive config can be updated." >&2
    exit 1
  fi
}

need_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "This installer targets the macOS Archive Validator host." >&2
    exit 1
  fi
}

patch_node_config() {
  [[ -f "${NODE_CONFIG}" ]] || {
    echo "Archive node config not found: ${NODE_CONFIG}" >&2
    echo "Run setup-archive-validator-m4.sh first, or pass --node-config /path/to/node.toml." >&2
    exit 1
  }

  local metrics_bind="${ARCHIVE_BIND_ADDRESS}:${METRICS_PORT}"
  local backup="${NODE_CONFIG}.observability.$(date -u +%Y%m%dT%H%M%SZ).bak"
  cp "${NODE_CONFIG}" "${backup}"

  /usr/bin/python3 - "${NODE_CONFIG}" "${metrics_bind}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
metrics_bind = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines()
section_re = re.compile(r"^\s*\[([^\]]+)\]\s*$")

def find_section(section):
    start = None
    end = len(lines)
    for idx, line in enumerate(lines):
        match = section_re.match(line)
        if not match:
            continue
        name = match.group(1).strip()
        if name == section:
            start = idx
            end = len(lines)
            continue
        if start is not None:
            end = idx
            break
    return start, end

def upsert(section, key, value):
    global lines
    start, end = find_section(section)
    if start is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend([f"[{section}]", f"{key} = {value}"])
        return
    key_re = re.compile(rf"^\s*{re.escape(key)}\s*=")
    for idx in range(start + 1, end):
        if key_re.match(lines[idx]):
            lines[idx] = f"{key} = {value}"
            return
    lines.insert(end, f"{key} = {value}")

upsert("telemetry", "enabled", "true")
upsert("telemetry", "metrics_bind", f'"{metrics_bind}"')
upsert("telemetry", "structured_logs", "true")
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

  echo "archive_node_config_patched=true config=${NODE_CONFIG} backup=${backup} metrics_bind=${metrics_bind}"
}

homebrew_bin() {
  if [[ -x /opt/homebrew/bin/brew ]]; then
    printf '%s\n' /opt/homebrew/bin/brew
  elif [[ -x /usr/local/bin/brew ]]; then
    printf '%s\n' /usr/local/bin/brew
  else
    return 1
  fi
}

install_node_exporter() {
  local brew_bin
  brew_bin="$(homebrew_bin)" || {
    echo "Homebrew is required to install node_exporter on macOS. Install Homebrew, then rerun." >&2
    exit 1
  }

  if ! command -v node_exporter >/dev/null 2>&1; then
    sudo -u "${SUDO_USER:-$(stat -f %Su /dev/console)}" "${brew_bin}" install node_exporter
  fi

  local exporter_bin
  exporter_bin="$(command -v node_exporter || true)"
  [[ -n "${exporter_bin}" && -x "${exporter_bin}" ]] || {
    echo "node_exporter binary not found after Homebrew install." >&2
    exit 1
  }

  local plist="/Library/LaunchDaemons/io.prometheus.node-exporter.plist"
  cat > "${plist}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.prometheus.node-exporter</string>
  <key>ProgramArguments</key>
  <array>
    <string>${exporter_bin}</string>
    <string>--web.listen-address=${ARCHIVE_BIND_ADDRESS}:${NODE_EXPORTER_PORT}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/node-exporter.out.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/node-exporter.err.log</string>
</dict>
</plist>
EOF
  chown root:wheel "${plist}"
  chmod 0644 "${plist}"
  plutil -lint "${plist}" >/dev/null
  launchctl bootout system/io.prometheus.node-exporter >/dev/null 2>&1 || true
  launchctl bootstrap system "${plist}"
  launchctl enable system/io.prometheus.node-exporter
  launchctl kickstart -k system/io.prometheus.node-exporter
  echo "node_exporter_configured=true launchd_label=io.prometheus.node-exporter listen=${ARCHIVE_BIND_ADDRESS}:${NODE_EXPORTER_PORT}"
}

restart_archive() {
  if [[ "${RESTART_ARCHIVE_SERVICE}" != "true" ]]; then
    echo "archive_launchd_restart_skipped=true"
    return
  fi
  if launchctl print "system/${ARCHIVE_LABEL}" >/dev/null 2>&1; then
    launchctl kickstart -k "system/${ARCHIVE_LABEL}"
    echo "archive_launchd_restarted=true label=${ARCHIVE_LABEL}"
  else
    echo "archive_launchd_restart_skipped=true reason=label_not_loaded label=${ARCHIVE_LABEL}"
  fi
}

wait_for_http() {
  local url="$1"
  local label="$2"
  local deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    if curl -fsS --max-time 3 "${url}" >/dev/null 2>&1; then
      echo "probe_ok=${label} url=${url}"
      return 0
    fi
    sleep 2
  done
  echo "probe_failed=${label} url=${url}" >&2
  return 1
}

wait_for_tcp_optional() {
  local host="$1"
  local port="$2"
  local label="$3"
  if /usr/bin/python3 - "${host}" "${port}" <<'PY'
import socket
import sys
host = sys.argv[1]
port = int(sys.argv[2])
try:
    with socket.create_connection((host, port), timeout=2.0):
        pass
except OSError:
    raise SystemExit(1)
PY
  then
    echo "tcp_ok=${label} target=${host}:${port}"
  else
    echo "tcp_unavailable=${label} target=${host}:${port}"
  fi
}

main() {
  need_root
  need_macos
  patch_node_config
  if [[ "${INSTALL_NODE_EXPORTER}" == "true" ]]; then
    install_node_exporter
  fi
  restart_archive
  wait_for_http "http://127.0.0.1:${METRICS_PORT}/metrics" "archive_metrics_local"
  if [[ "${INSTALL_NODE_EXPORTER}" == "true" ]]; then
    wait_for_http "http://127.0.0.1:${NODE_EXPORTER_PORT}/metrics" "node_exporter_local"
  fi
  wait_for_tcp_optional "127.0.0.1" "${QRPC_PORT}" "archive_qrpc_local"

  echo "macos_firewall_note=allow_or_forward_public_tcp_ports_${METRICS_PORT}_${NODE_EXPORTER_PORT}_and_optionally_${QRPC_PORT}_from_observer_public_ip_${OBSERVER_PUBLIC_IP}_to_archive_public_ip_${ARCHIVE_PUBLIC_IP}"
  echo "spreadsheet_row_used=true node=\"Archive Validator\" os=macos role=archive_validator local_ip=${ARCHIVE_LOCAL_IP} public_ip=${ARCHIVE_PUBLIC_IP} scrape_host=${ARCHIVE_SCRAPE_HOST} bind_address=${ARCHIVE_BIND_ADDRESS} metrics_port=${METRICS_PORT} node_exporter_port=${NODE_EXPORTER_PORT} qrpc_port=${QRPC_PORT} observer_public_ip=${OBSERVER_PUBLIC_IP} node_config=${NODE_CONFIG}"
}

main "$@"

