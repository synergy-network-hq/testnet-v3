#!/bin/sh
set -eu
address=${1:?NodeAddress required}
/usr/bin/synergy-node validator inspect --node-address "$address" --format json | jq -e '.authority.active == true'
