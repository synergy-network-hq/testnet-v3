#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --aegis-pqvm <canonical-aegis-pqvm-path> --output <verifier-path>" >&2
  exit 2
}

aegis_pqvm=""
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --aegis-pqvm)
      aegis_pqvm="${2:-}"
      shift 2
      ;;
    --output)
      output="${2:-}"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "$aegis_pqvm" && -n "$output" ]] || usage
[[ -f "$aegis_pqvm/Cargo.toml" ]] || {
  echo "canonical Aegis-PQC package is missing: $aegis_pqvm" >&2
  exit 1
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template="$script_dir/../tools/aegis-snapshot-cli/Cargo.toml.in"
source_dir="$script_dir/../tools/aegis-snapshot-cli"
[[ -f "$template" && -f "$source_dir/src/main.rs" ]] || {
  echo "Aegis snapshot CLI source is missing from this control-panel checkout" >&2
  exit 1
}

build_root="$(mktemp -d "${TMPDIR:-/tmp}/synergy-aegis-build.XXXXXX")"
cleanup() {
  rm -rf "$build_root"
}
trap cleanup EXIT

escaped_aegis_path="$(printf '%s' "$aegis_pqvm" | sed 's/[\\&|]/\\&/g')"
sed "s|@@AEGIS_PQVM_PATH@@|$escaped_aegis_path|g" "$template" > "$build_root/Cargo.toml"
mkdir -p "$build_root/src"
cp "$source_dir/src/main.rs" "$build_root/src/main.rs"
cp "$source_dir/Cargo.lock" "$build_root/Cargo.lock"

cargo build --manifest-path "$build_root/Cargo.toml" --release --locked
mkdir -p "$(dirname "$output")"
cp "$build_root/target/release/synergy-aegis-snapshot-cli" "$output"
chmod 0755 "$output"
