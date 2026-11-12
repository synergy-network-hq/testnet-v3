#!/bin/sh
set -eu
package=${1:?signed node package required}
"$(dirname "$0")/verify-host.sh"
test -f "$package/SHA256SUMS"
(cd "$package" && sha256sum -c SHA256SUMS)
install -m 0755 "$package/synergy-node" /usr/local/bin/synergy-node
