# Raw evidence location

Raw samples are stored under `../runs/<run-id>/raw/` so that every measurement remains coupled to its run manifest, environment snapshots, executable hashes, and `SHA256SUMS` file. The primary publication run is `../runs/publication-m2-20260815-v1/raw/`; two additional independent controlled-load runs are retained beside it.

This directory exists to preserve the requested top-level layout without duplicating or silently merging authoritative rows. `../publication/derivation.json` identifies every raw input and SHA-256 digest used by the consolidated publication outputs.
