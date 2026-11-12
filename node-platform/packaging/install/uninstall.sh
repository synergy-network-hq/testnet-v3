#!/bin/sh
set -eu
systemctl disable --now synergy-node.service 2>/dev/null || true
rm -f /usr/local/bin/synergy-node
printf '%s
' 'State in /var/lib/synergy-node was retained.'
