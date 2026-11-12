#!/bin/sh
set -eu
dir=${1:?release directory required}
(cd "$dir" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
