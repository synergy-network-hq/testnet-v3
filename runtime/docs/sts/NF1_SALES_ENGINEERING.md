# Native NF1 sales engineering build

The `engineering-nf1-sales` feature adds three signed STS operations to the Chain 1266 release. A seller lists a transferable NF1 NFT at an exact integer nWei price and an exclusive expiry height. The seller can cancel the listing by ID. A buyer must match the listing ID, NFT, seller, and price. The first version supports collections without royalties or issuer approval.

Native execution applies ownership, buyer payment, seller credit, fee, and listing consumption as one state transition. Rejected purchases leave the NFT and sale payment in place. A payable failure can still charge its network fee. The finalized sale event carries the transaction execution ID and balance deltas so Spark can reconcile them with the signed purchase and finalized receipt.

```sh
cargo +1.93.0 test --locked --manifest-path runtime/Cargo.toml -p synergy-testnet \
  --lib --features engineering-nf1-sales nft_sale
```

The default build preserves the existing STS payloads, historical state encoding, and public RPC surface. The feature is for isolated qualification. A public release needs a consistent activation rule across the authority and observers before they accept the new state transition. Spark and Wallet require the finalized `sts_getNftSaleCapabilities` response before enabling purchase or listing drafts and signing.
