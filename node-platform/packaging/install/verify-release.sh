#!/bin/sh
set -eu
release_dir=${1:?release directory required}
"$(dirname "$0")/../../tools/release/verify.sh" "$release_dir"
