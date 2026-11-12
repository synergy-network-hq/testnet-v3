#!/bin/sh
# Build the canonical checkout for Linux without a source copy or container.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
tools_dir=${SYNERGY_LINUX_TOOLS_DIR:-"$root/target/posy-linux-tools"}
target=x86_64-unknown-linux-gnu

case ${1:-} in
    ''|--preflight) ;;
    *) echo "usage: $0 [--preflight]" >&2; exit 2 ;;
esac

for executable in cargo rustup file shasum; do
    command -v "$executable" >/dev/null || {
        echo "missing build dependency: $executable" >&2
        exit 1
    }
done
test -x "$tools_dir/bin/cargo-zigbuild" && test -x "$tools_dir/bin/python" || {
    echo "missing task-local cargo-zigbuild environment: $tools_dir" >&2
    exit 1
}
rustup target list --installed | grep -qx "$target" || {
    echo "missing Rust target: $target" >&2
    exit 1
}

PATH="$tools_dir/bin:$PATH"
export PATH
CARGO_ZIGBUILD_PYTHON_PATH="$tools_dir/bin/python"
export CARGO_ZIGBUILD_PYTHON_PATH
cargo-zigbuild --version
"$tools_dir/bin/python" -m ziglang version
if test "${1:-}" = --preflight; then
    exit 0
fi

provenance_dir=${SYNERGY_BUILD_PROVENANCE_DIRECTORY:?new build evidence directory required}
test ! -e "$provenance_dir" || { echo "build evidence directory exists" >&2; exit 1; }
mkdir -m 0700 "$provenance_dir"
source_root=$(git rev-parse --show-toplevel)
python3 tools/release/provenance.py inventory --root "$source_root" --output "$provenance_dir/before.json"

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export SOURCE_DATE_EPOCH
CARGO_INCREMENTAL=0 cargo zigbuild --locked --release -p synergy-node -p synergy-keytool -p synergy-genesis --features synergy-node/qualification-timing \
    --target "$target.2.28"
# Compile the ignored native fixture exporter on this canonical source host.
# The qualification Linux host consumes only these exact executables, never source.
cargo zigbuild --locked --release -p synergy-node --tests --features qualification-timing \
    --target "$target.2.28" --message-format=json >"$provenance_dir/exporter-build.jsonl"
fixture_exporter=$(python3 tools/release/provenance.py exporter --cargo-messages "$provenance_dir/exporter-build.jsonl")
printf '%s\n' "$fixture_exporter" >"$provenance_dir/fixture-exporter-path.txt"
binary="${CARGO_TARGET_DIR:-$root/target}/$target/release/synergy-node"
file "$binary" | grep -q 'ELF 64-bit LSB.*x86-64' || {
    echo "release output is not Linux x86-64 ELF: $binary" >&2
    exit 1
}
shasum -a 256 "$binary"

python3 tools/release/provenance.py inventory --root "$source_root" --output "$provenance_dir/after.json"
python3 tools/release/provenance.py assemble \
    --before "$provenance_dir/before.json" --after "$provenance_dir/after.json" \
    --binary "$binary" \
    --keytool "${CARGO_TARGET_DIR:-$root/target}/$target/release/synergy-keytool" \
    --genesis "${CARGO_TARGET_DIR:-$root/target}/$target/release/synergy-genesis" \
    --fixture-exporter "$fixture_exporter" --feature qualification-timing --output "$provenance_dir/build-provenance.json"
