# Track H — Testnet-v3 contract address migration

Status: implementation complete; final-candidate gate awaits the corrected
production ceremony snapshot.

## Governing distinction

The ten historical `synq...` values are FN-DSA administrative/custody
identities. They are not deployed SynQ instance addresses. Testnet-v3 has nine
deployed instances at the frozen `sync...` addresses in
`TESTNET_V3_PRODUCTION_CONTRACT_ADDRESSES.json`; SaleClaim is not deployed.

Runtime consumers must use deployed addresses. Identity, custody, provenance,
and historical evidence records preserve the corresponding identity address.

## Implemented migration

`finalize-testnet-v3-genesis` now:

- replaces all nine active `contracts.*.address` values;
- updates `modules.identity.contract_address`,
  `modules.treasury.contract_address`, and `vesting[0].contract_address`;
- moves the TEM-A01 account, allocation, and balance to the deployed
  TeamVesting instance without changing its amount;
- keeps TEM-A01's old assignment as an administrative/custody identity and
  records the deployed instance separately;
- preserves SAL-A01 at its custody identity because SaleClaim is excluded;
- embeds the complete old-to-new ruling in the root-bound
  `contract_address_migration` block.

The ceremony independently applies the same TEM-A01 funding rule before
contract deployment. The exported execution snapshot therefore hashes the
actual finalized balance table rather than the retired identity-assigned table.

## Inventory and gate

The `audit-testnet-v3-address-migration` binary derives its map from the source
genesis and frozen production address record. It recursively inventories the
workspace, classifies every occurrence, and can reject a final candidate that
uses an identity address as a deployed-address consumer.

Initial inventory:

- mappings: 10 (nine deployed, one deferred);
- occurrences: 145;
- active-consumer review items: 3;
- candidate semantic validation: pending the corrected ceremony output.

The three active review items were:

1. a runtime unit test that asserted the retired RewardDistributor address
   (corrected to consume the frozen production record);
2. SAL-A01 in the runtime allocation manifest (preserve as custody);
3. TEM-A01 in the runtime allocation manifest (replace from the finalized
   candidate during the Phase-7/8 freeze).

Machine-readable inventory:
`launch/TRACK_H_ADDRESS_INVENTORY.json`.

Final gate command:

```bash
cd runtime
cargo run --bin audit-testnet-v3-address-migration -- \
  --candidate ../launch/production-genesis-ceremony/genesis.testnet-v3.final-candidate.json \
  --output ../launch/TRACK_H_ADDRESS_INVENTORY.json
```
