# Self-Healing Sync

A self-quarantined validator may use an archive snapshot only after verifying the signed catalog, signed manifest, content root, state root, finalized block hash, and every catch-up QC through `aegis-pqvm`.

Validator recovery and onboarding must use the `validator-pruned` snapshot class. A recovered validator remains duty-disabled while it speed-syncs and shadows at least one complete eligible epoch. Reactivation is allowed only at the next epoch boundary after that full shadow epoch passes.
