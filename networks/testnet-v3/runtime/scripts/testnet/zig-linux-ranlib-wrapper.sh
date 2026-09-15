#!/usr/bin/env bash
set -euo pipefail

exec zig ranlib "$@"
