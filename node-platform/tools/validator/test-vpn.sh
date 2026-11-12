#!/bin/sh
set -eu
netbird status --json | jq -e '.status == "Connected"'
