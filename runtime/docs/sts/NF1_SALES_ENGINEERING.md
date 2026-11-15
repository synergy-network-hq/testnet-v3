# Activate native NF1 sales on Chain 1266 incarnation 5

PR #19 adds signed listing, cancellation, and purchase operations for transferable NF1 NFTs with no collection royalties or issuer approval. A purchase settles the NFT transfer, buyer debit, seller credit, network fee, and listing consumption in one execution. Spark verifies the sale against the exact signed purchase and finalized receipt.

## Qualify the authority candidate

Use the **Chain 1266 NF1 sale candidate** workflow from the exact PR revision. The unsigned Linux bundle includes the validator, activation tool, bootstrap signer, source commit, dependency lock, and SHA-256 checksums. Check `SOURCE_REVISION` against the reviewed PR revision and run `sha256sum -c SHA256SUMS` in the extracted bundle. Keep the bundle from that revision together. The existing tagged incarnation 4 workflow serves a different release line.

For an independent build, use the revisions in `launch/CHAIN_1266_DEPENDENCIES.lock.json`. Place the locked SynQ checkout beside this repository and check out the pinned `aegis-pqsynq` submodule. On the authority's Linux architecture, run:

```sh
cargo +1.93.0 test --locked --manifest-path runtime/Cargo.toml -p synergy-testnet --lib nf1 -- --test-threads=1
cargo +1.93.0 test --locked --manifest-path runtime/Cargo.toml -p synergy-testnet \
  --lib --features engineering-nf1-sales nft_sale -- --test-threads=1
cargo +1.93.0 build --locked --release --manifest-path runtime/Cargo.toml -p synergy-testnet \
  --features engineering-nf1-sales --bin synergy-validator-node \
  --bin chain1266-nf1-sales-activation --bin chain1266-single-authority-bootstrap
```

Verify the public native RPC route forwards sale reads and signed Aegis submissions to the incarnation 5 authority. This candidate publishes execution state from the authority driver. A gateway proxy can use that state through the authority's RPC. An independently executing reader needs separate qualification at the same activation height before it serves finalized sale reads.

## Prepare and sign

1. Record a checkpoint from the authority's durable finalized head in the active namespace `data/consensus/chain-1266-incarnation-5/single-authority-finality.head.json` under the node root. Record its height, block hash, and state root. The on-disk hashes are 32-byte arrays. Convert them to lowercase hex, and cross-check the checkpoint against the authority's finalized status. Choose an activation height comfortably ahead of the live finalized and signed heights to allow for custody, staging, and startup. Startup requires the exact checkpoint in the installed finality log.
2. Generate the canonical manifest and unsigned desired state with the exact qualified role binary. The operator tool preserves every incumbent desired-state field except the execution fingerprint. Repeat from checkpoint selection if the scheduled height is reached before the first upgraded start.

```sh
"$CANDIDATE/chain1266-nf1-sales-activation" prepare "$ACTIVATION_DIR" \
  "$CHECKPOINT_HEIGHT" "$CHECKPOINT_BLOCK_HASH" "$CHECKPOINT_STATE_ROOT" "$ACTIVATION_HEIGHT" \
  "synergy-validator-node=$CANDIDATE/synergy-validator-node"
```

3. In incumbent Chain 1266 start-authority custody, review the generated manifest and sign using the existing ML-DSA-87 identity with fingerprint `sha256:c39e17970a711cadbbb6e43f49f322b14bb1710a2fb6c90822b081fe7f5ce5b4`. Transfer the public signature and canonical files to staging. Keep the authority key in custody.

```sh
"$CANDIDATE/chain1266-single-authority-bootstrap" sign \
  --custody-dir "$BOOTSTRAP_CUSTODY" \
  --desired-state "$ACTIVATION_DIR/chain1266-desired-state-v2.unsigned.json" \
  --output "$ACTIVATION_DIR/chain1266-start-authorization-v2.json"

"$CANDIDATE/chain1266-nf1-sales-activation" verify \
  "$ACTIVATION_DIR/chain1266-nf1-sales-activation-v1.json" \
  "$ACTIVATION_DIR/chain1266-desired-state-v2.unsigned.json" \
  "$ACTIVATION_DIR/chain1266-start-authorization-v2.json" \
  "synergy-validator-node=$CANDIDATE/synergy-validator-node"
```

## Switch the existing authority and verify continuity

1. Stop the incarnation 5 authority service through the established operator access. Confirm the former process has exited and the service owns the only writer. The packaged unit is `synergy-chain1266-authority.service`. Confirm its installed paths before swapping files. Save consistent copies of the existing binary, three activation/config inputs as applicable, and the durable node state. Keep the signed consensus release ID, Genesis, authority identity, signing journal, and finalized namespace in place.
2. While the authority is stopped, recheck that the durable head and any outstanding signing journal entry are below the activation height. Stage the exact checked validator in `ExecStart`. Place the signed authorization, canonical desired state, and canonical manifest under the installed `config/` directory as `chain1266-start-authorization-v2.json`, `chain1266-desired-state-v2.json`, and `chain1266-nf1-sales-activation-v1.json`. Keep the old service binary stopped throughout the change. Start the authority once. Startup checks the signed policy, binary, durable checkpoint, and existing journal. It records the accepted activation fingerprint beside the finality log so subsequent starts require the same policy. Preserve that marker with the durable namespace. After activation, recover with the signed candidate and its durable data. Starting an earlier binary on the activated namespace would run different execution rules.
3. Verify that the authority extends the same finalized chain and the public route follows. Check incarnation 5, the original Genesis, and the first post-restart finalized parent. Below the activation height, sale RPC must report unavailable and sale admission must reject. At and above activation, `sts_getNftSaleCapabilities` must advertise `sts-nf1-sales-v1` from a matching finalized execution snapshot. Record the finalized activation block hash and state root.
4. Follow the [Spark public sale procedure](https://github.com/synergy-network-hq/synergy-spark/blob/main/scripts/NF1_PUBLIC_SALE.md). Use disposable test wallets. Preserve the exact approved purchase draft and the proof generated from the finalized receipt, which must show ownership moving from seller to buyer, the seller receiving the exact sale price, and the buyer paying the price plus the recorded fee.
