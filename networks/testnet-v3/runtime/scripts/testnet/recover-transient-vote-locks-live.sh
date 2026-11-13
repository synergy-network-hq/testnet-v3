#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'MESSAGE'
recover-transient-vote-locks-live.sh is retired.

This legacy script edited consensus_vote_locks.json and consensus_proposals
directly under the old workspace layout. That is no longer an approved
validator recovery path.

Use the generic appliance helper instead:

  bash scripts/testnet/validator-appliance-recovery.sh transient-lock-recovery \
    --target <validator> \
    --finalized-height <height> \
    --min-age-secs <seconds> \
    --execute

The replacement uses workbook-backed access and the supported runtime command:

  synergy-node recover-transient-vote-locks --chain-id 1264 --network-id synergy-testnet-v3

When the validator service is active, the helper uses the live qRPC method
synergy_recoverTransientVoteLocks so the running runtime owns the mutation and
records evidence.
MESSAGE

exit 2
