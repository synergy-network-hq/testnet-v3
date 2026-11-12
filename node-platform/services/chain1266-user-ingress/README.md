# Configured-network signed-user ingress

The historical directory name is retained; runtime selection is explicit. This loopback JSON-RPC edge accepts `synergy_submitAegisTransaction` only for the configured chain/network context. It probes upstream chain ID, genesis hash and incarnation before forwarding. The authority still verifies signatures, identity, nonce, balance, fees and execution. A queued response is not finality.

Run `npm test` for local rejection checks. Set `SYNERGY_USER_INGRESS_ENABLED=1`, `SYNERGY_AUTHORITY_RPC`, and optionally `SYNERGY_USER_INGRESS_PORT` (default 8793). Bind remains loopback. Supply `SYNERGY_INGRESS_NETWORK_CONTEXT`, an absolute path to a public JSON object with `chain_id`, `network_id`, `genesis_hash`, and `chain_incarnation`; pin its exact file digest with `SYNERGY_INGRESS_CONTEXT_SHA256`. Deployment must derive this context from authenticated selected genesis/configuration. The upstream RPC cannot choose it.

Not activated or deployed. Opening a public route still requires the approved release lineage, real phone-wallet signature validation, rate limiting, monitoring, and finalized transaction receipts. Do not route unsigned transactions or FN-DSA identity-root signatures through this endpoint.
