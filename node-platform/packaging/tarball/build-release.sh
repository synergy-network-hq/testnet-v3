#!/bin/sh
set -eu
: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH is required}"
: "${SYNERGY_RELEASE_OUT:?SYNERGY_RELEASE_OUT is required}"
cargo build --locked --release -p synergy-node
install -d "$SYNERGY_RELEASE_OUT"
install -m 0755 target/release/synergy-node "$SYNERGY_RELEASE_OUT/synergy-node"
(cd "$SYNERGY_RELEASE_OUT" && sha256sum synergy-node > SHA256SUMS)
