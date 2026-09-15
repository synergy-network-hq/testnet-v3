#!/usr/bin/env bash
set -euo pipefail
systemctl restart synergy-archive-validator.service synergy-archive-snapshot-api.service synergy-archive-snapshot-worker.service
