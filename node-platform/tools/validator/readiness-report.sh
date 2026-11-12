#!/bin/sh
set -eu
socket=${1:-/run/synergy-node/admin.sock}
/usr/bin/synergy-node readiness --admin-socket "$socket" --format json
