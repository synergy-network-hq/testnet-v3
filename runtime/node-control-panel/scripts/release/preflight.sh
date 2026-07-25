#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

REPO_SLUG="synergy-network-hq/node-control-panel"

echo "== Release preflight =="
echo "Repo: $REPO_SLUG"

if [[ ! -f package.json || ! -f control-service/Cargo.toml || ! -f electron-builder.yml ]]; then
  echo "Release metadata files are missing." >&2
  exit 1
fi

PACKAGE_VERSION="$(node -e 'const fs=require("fs"); const pkg=JSON.parse(fs.readFileSync("package.json","utf8")); process.stdout.write(pkg.version);')"
CARGO_VERSION="$(python3 - <<'PY'
import pathlib
import re

text = pathlib.Path("control-service/Cargo.toml").read_text(encoding="utf-8")
match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
if not match:
    raise SystemExit(1)
print(match.group(1), end="")
PY
)"

if [[ "$PACKAGE_VERSION" != "$CARGO_VERSION" ]]; then
  echo "Version mismatch detected:" >&2
  echo "  package.json: $PACKAGE_VERSION" >&2
  echo "  Cargo.toml:   $CARGO_VERSION" >&2
  exit 1
fi

echo "Version consistency: $PACKAGE_VERSION"

PRODUCT_NAME="$(python3 - <<'PY'
import pathlib
import re

text = pathlib.Path("electron-builder.yml").read_text(encoding="utf-8")
match = re.search(r'^productName:\s*(.+)\s*$', text, re.MULTILINE)
print((match.group(1).strip() if match else ""), end="")
PY
)"
if [[ "$PRODUCT_NAME" != "Synergy Node Control Panel" ]]; then
  echo "Unexpected productName in electron-builder.yml: $PRODUCT_NAME" >&2
  exit 1
fi

OUTPUT_DIR="$(python3 - <<'PY'
import pathlib
import re

text = pathlib.Path("electron-builder.yml").read_text(encoding="utf-8")
match = re.search(r'(?ms)^directories:\s*\n(?:^[ \t].*\n)*?^[ \t]+output:\s*(.+)\s*$', text)
print((match.group(1).strip() if match else ""), end="")
PY
)"
if [[ -z "$OUTPUT_DIR" ]]; then
  echo "electron-builder.yml is missing directories.output" >&2
  exit 1
fi

echo "Electron packaging config: OK"

echo "Frontend build..."
npm run build

echo "Rust compile check..."
cargo check --manifest-path control-service/Cargo.toml --bin control-service --no-default-features

echo "Stage Electron runtime..."
npm run build:control-service
node scripts/electron/prepare-runtime.mjs

echo "Preflight passed."
