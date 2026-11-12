#!/bin/sh
set -eu
release_dir=${1:?release directory required}
"$(dirname "$0")/verify-release.sh" "$release_dir"
systemctl stop synergy-node.service
install -m 0755 "$release_dir/synergy-node" /usr/local/bin/synergy-node
systemctl start synergy-node.service
