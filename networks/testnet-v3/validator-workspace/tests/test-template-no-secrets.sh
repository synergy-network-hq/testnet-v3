#!/usr/bin/env bash
set -euo pipefail

if find template -type f \( -name '*key.json' -o -name 'node.env' -o -name 'wg*.conf' \) ! -name '*.example' | grep -q .; then
  echo "secret-bearing live file name committed without .example" >&2
  exit 1
fi

if rg -n "BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY|[A-Za-z0-9+/]{120,}={0,2}" template examples docs schemas README.md CHANGELOG.md --glob '!*.example' --glob '!*.md' >/tmp/validator-workspace-secret-scan.txt; then
  cat /tmp/validator-workspace-secret-scan.txt >&2
  echo "possible secret material found outside .example files" >&2
  exit 1
fi

if rg -n "L78Cp95c|NodeMaster1" . --glob '!tests/test-template-no-secrets.sh' >/tmp/validator-workspace-known-secret-scan.txt; then
  cat /tmp/validator-workspace-known-secret-scan.txt >&2
  echo "known live credential string found" >&2
  exit 1
fi

echo "no committed live secrets detected"
