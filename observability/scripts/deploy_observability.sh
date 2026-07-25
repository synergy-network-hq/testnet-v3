#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
OBS_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
CONFIG="${OBS_DIR}/live-config-after/observer/prometheus/prometheus.yml"
RULES_DIR="${OBS_DIR}/live-config-after/observer/rules"
MANIFEST="${OBS_DIR}/relayer-telemetry-proxy-contract.json"
VALIDATOR="${SCRIPT_DIR}/validate_observability.rb"

usage() {
  cat <<'EOF'
Usage:
  deploy_observability.sh validate
  deploy_observability.sh plan
  deploy_observability.sh stage DIRECTORY

All commands are local-only. This tool never invokes ssh, systemctl, or a
remote deployment. `stage` writes only the named artifact directory and does
not delete unrelated files there.
EOF
}

die() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

run_contract_validation() {
  command -v ruby >/dev/null 2>&1 || die "ruby is required for YAML and contract validation"
  ruby "$VALIDATOR" --manifest "$MANIFEST" --config "$CONFIG" --rules "$RULES_DIR"
}

run_promtool_validation() {
  if ! command -v promtool >/dev/null 2>&1; then
    printf 'promtool: not installed; skipped external Prometheus parser check\n'
    return 0
  fi

  local temp_dir temp_config
  temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/synergy-observability.XXXXXX")
  temp_config="${temp_dir}/prometheus.yml"
  trap 'rm -rf "${temp_dir}"' RETURN

  ruby -ryaml -e '
    config = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false)
    config["rule_files"] = Dir[ARGV.fetch(1)].sort
    File.write(ARGV.fetch(2), config.to_yaml)
  ' "$CONFIG" "$RULES_DIR/*.yml" "$temp_config"
  promtool check config "$temp_config"
  promtool check rules "$RULES_DIR"/*.yml
}

copy_if_changed() {
  local source=$1 destination=$2
  if [[ -f "$destination" ]] && cmp -s "$source" "$destination"; then
    return 0
  fi
  install -m 0644 "$source" "$destination"
}

stage_bundle() {
  local output=$1
  [[ -n "$output" ]] || die "stage directory must not be empty"
  case "$output" in
    /|/bin|/bin/*|/etc|/etc/*|/opt|/opt/*|/sbin|/sbin/*|/System|/System/*|/usr|/usr/*|/var|/var/log|/var/log/*|/var/db|/var/db/*|/var/root|/var/root/*)
      die "refusing to stage into a system path: $output"
      ;;
  esac

  mkdir -p "$output/prometheus/rules"
  copy_if_changed "$MANIFEST" "$output/relayer-telemetry-proxy-contract.json"
  copy_if_changed "$CONFIG" "$output/prometheus/prometheus.yml"
  for rule in "$RULES_DIR"/*.yml; do
    copy_if_changed "$rule" "$output/prometheus/rules/$(basename "$rule")"
  done
  ruby "$VALIDATOR" --manifest "$MANIFEST" --config "$CONFIG" --rules "$RULES_DIR" --plan \
    >"$output/DEPLOYMENT_PLAN.txt"
  printf 'staged local observability bundle at %s\n' "$output"
}

command=${1:-}
case "$command" in
  validate)
    [[ $# -eq 1 ]] || die "validate takes no arguments"
    run_contract_validation
    run_promtool_validation
    ;;
  plan)
    [[ $# -eq 1 ]] || die "plan takes no arguments"
    run_contract_validation
    ruby "$VALIDATOR" --manifest "$MANIFEST" --config "$CONFIG" --rules "$RULES_DIR" --plan
    ;;
  stage)
    [[ $# -eq 2 ]] || die "usage: deploy_observability.sh stage DIRECTORY"
    run_contract_validation
    stage_bundle "$2"
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
