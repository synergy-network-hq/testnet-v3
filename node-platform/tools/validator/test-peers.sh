#!/bin/sh
set -eu
/usr/bin/synergy-node peers inspect --format json | jq -e '.authenticated >= 3'
