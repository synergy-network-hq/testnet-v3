#!/bin/sh
set -eu
dir=${1:?verified release directory required}
destination=${2:?publication destination required}
"$(dirname "$0")/verify.sh" "$dir"
test ! -e "$destination" || { echo "destination exists" >&2; exit 1; }
mv "$dir" "$destination"
