#!/bin/sh
set -eu
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:?required}
cargo build --locked --release --workspace
