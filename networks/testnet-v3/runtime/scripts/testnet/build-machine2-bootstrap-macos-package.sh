#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="${MACHINE2_PACKAGE_OUT_DIR:-$ROOT_DIR/dist}"
PACKAGE_NAME="${MACHINE2_PACKAGE_NAME:-machine2-bootnode2-macos}"
PACKAGE_DIR="$DIST_DIR/$PACKAGE_NAME"
ZIP_PATH="$DIST_DIR/$PACKAGE_NAME.zip"
BOOTNODE_SRC_DIR="$ROOT_DIR/bootstrap-bundles/bootnode2"
HELPER_SCRIPT="$ROOT_DIR/scripts/testnet/restart-machine2-bootstrap-macos.sh"

require_path() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    echo "Missing required path: $path" >&2
    exit 1
  fi
}

require_path "$BOOTNODE_SRC_DIR"
require_path "$HELPER_SCRIPT"

mkdir -p "$DIST_DIR"
rm -rf "$DIST_DIR/machine2-seed2-bootnode2-macos" "$DIST_DIR/machine2-seed2-bootnode2-macos.zip"
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

cp -R "$BOOTNODE_SRC_DIR" "$PACKAGE_DIR/bootnode2"
cp "$HELPER_SCRIPT" "$PACKAGE_DIR/restart-machine2-bootstrap-macos.sh"

cat > "$PACKAGE_DIR/install_machine2_bootstrap.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTNODE_SRC_DIR="$BASE_DIR/bootnode2"
HELPER_SCRIPT="$BASE_DIR/restart-machine2-bootstrap-macos.sh"
BOOTNODE_DST_DIR="${BOOTNODE_DIR:-$HOME/bootnode2}"

require_dir() {
  local path="$1"
  if [[ ! -d "$path" ]]; then
    echo "Missing required directory: $path" >&2
    exit 1
  fi
}

copy_tree() {
  local src="$1"
  local dst="$2"
  mkdir -p "$dst"
  if command -v ditto >/dev/null 2>&1; then
    ditto "$src" "$dst"
    return
  fi

  cp -R "$src"/. "$dst"/
}

require_dir "$BOOTNODE_SRC_DIR"
if [[ ! -f "$HELPER_SCRIPT" ]]; then
  echo "Missing helper script: $HELPER_SCRIPT" >&2
  exit 1
fi

printf '\n==> Installing bootnode2 into %s\n' "$BOOTNODE_DST_DIR"
copy_tree "$BOOTNODE_SRC_DIR" "$BOOTNODE_DST_DIR"

chmod +x "$HELPER_SCRIPT"
printf '\n==> Running bootnode2 restart workflow\n'
BOOTNODE_DIR="$BOOTNODE_DST_DIR" "$HELPER_SCRIPT"
SCRIPT

cat > "$PACKAGE_DIR/README.txt" <<'README'
machine2 macOS bootstrap package
================================

Contents
- bootnode2/
- install_machine2_bootstrap.sh
- restart-machine2-bootstrap-macos.sh

One command after extracting
- cd machine2-bootnode2-macos
- bash ./install_machine2_bootstrap.sh

Default install targets
- ~/bootnode2

Override targets if needed
- BOOTNODE_DIR=/custom/bootnode2 bash ./install_machine2_bootstrap.sh
README

chmod +x "$PACKAGE_DIR/install_machine2_bootstrap.sh" "$PACKAGE_DIR/restart-machine2-bootstrap-macos.sh"

rm -f "$ZIP_PATH"
if command -v zip >/dev/null 2>&1; then
  (
    cd "$DIST_DIR"
    COPYFILE_DISABLE=1 zip -qry "$PACKAGE_NAME.zip" "$PACKAGE_NAME"
  )
else
  (
    cd "$DIST_DIR"
    ditto -c -k --sequesterRsrc --keepParent "$PACKAGE_NAME" "$PACKAGE_NAME.zip"
  )
fi

echo "machine2 package directory: $PACKAGE_DIR"
echo "machine2 package zip: $ZIP_PATH"
