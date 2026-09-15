# Rollback Guide

Every migration creates a rollback archive under `/var/backups/synergy/validator`.

Rollback restores:

- previous service unit files
- previous config files
- previous key files
- previous workspace metadata
- previous active service enablement state

Rollback must not delete migrated data or keys. It should restore the old service only when the canonical service fails validation and consensus safety requires returning the host to its prior state.

