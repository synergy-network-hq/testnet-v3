# Fresh PoSy v3 Genesis consensus decision

Status: `PENDING_FROZEN_AUTHORITY_RELEASE_APPROVAL`

Decision ID: `SNRG-GOV-POSY-P3-GENESIS-20260823-01`

This public decision record binds the separate Testnet-v3 PoSy chain to the
canonical consensus input in
`posy-simplified-parameter-manifest.for-release.json`: Chain ID 1266,
technical network ID `testnet`, `posy/3.0`, block-one activation, one initial
five-validator cluster, strict dynamic quorum, chained three-QC finality, and
a governed ETDAG Genesis binding.

This file is deliberately not signature evidence. The V4 Genesis release
approval signs the exact candidate containing this decision SHA-256 and the
ETDAG parameter, fee, and membership-anchor roots. Until that verification
passes, it is an unsigned release input and cannot authorize a node or wallet
trust value.
