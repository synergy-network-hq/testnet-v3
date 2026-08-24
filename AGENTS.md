# Testnet-v3 operational instructions

For every Chain 1266 stall or node incident, read
`CHAIN_1266_STALL_LOG.md` from top to bottom before diagnosing or mutating any
node. Append the incident and every recovery attempt, including unsuccessful
attempts and exact outcomes, using the required format in that log.

Never declare the chain healthy from an active service alone. Require an
advancing, identical finalized tip across all five initial validators, zero new fatal
consensus/signing conflicts, bounded observer/public-tier lag, and live Atlas
data.
