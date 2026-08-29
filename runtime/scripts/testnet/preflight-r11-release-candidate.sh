#!/usr/bin/env bash
# Verify a sealed R11 qualification release candidate without deploying it.
set -euo pipefail

usage() {
    printf 'Usage: %s --package DIR\n' "${0##*/}" >&2
    exit 2
}

package=""
while (( $# > 0 )); do
    case "$1" in
        --package) package="${2:-}"; shift 2 ;;
        --help|-h) usage ;;
        *) usage ;;
    esac
done
[[ -n "$package" ]] || usage

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../../.." && pwd)"
exec python3 "$repo_root/scripts/assemble-r11-qualification-release-candidate.py" --verify-package "$package"
