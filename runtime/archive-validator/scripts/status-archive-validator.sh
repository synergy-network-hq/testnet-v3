#!/usr/bin/env bash
set -euo pipefail
systemctl status synergy-archive-validator.service synergy-archive-snapshot-api.service synergy-archive-snapshot-worker.service --no-pager
