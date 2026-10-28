# sale_claim Requirements — recovered from the deployed presale system

Date: 2026-07-26. Primary sources (actual deployed behavior + data model, per
recovery priority order):

1. `network-websites/synergy-website/docs/token-offering/UNIFIED_PRESALE_INFRASTRUCTURE_SPEC.md`
   (Unified Presale Clearing Architecture — governing specification).
2. `network-websites/synergy-website/contracts/SNRGClaimVoucherSoulbound.sol`
   (canonical Ethereum soulbound voucher; behavioral reference ONLY — no
   Solidity artifact enters the Testnet-v3 package).
3. `network-websites/synergy-website/contracts/`/`SynergyPresaleReceipt.sol`,
   `backend/src/services/presaleVoucherMinter.js`,
   `backend/src/routes/presaleRoutes.js` (purchase recorder, authorized
   minter, reconciliation endpoint).
4. Canonical genesis `contracts.sale_claim` init_params: inventory
   2,240,000,000 SNRG (= SAL-A01 register amount), release modes
   `claim | vesting | refund | settlement`, admin authority DAO-A01.

## Established presale model (verified from sources)

- Canonical receipt chain: Ethereum mainnet; canonical asset: soulbound
  claim-voucher NFT; canonical truth: NFT state + `ReceiptMinted` /
  `ReceiptRedeemed` events.
- Purchases on six rails (ETH/BNB/Polygon/Avalanche/Solana/Bitcoin) with
  per-rail confirmation minimums and hardcoded intake treasury addresses.
- Voucher mint: MINTER_ROLE only; payment-fingerprint replay protection
  `keccak256(paymentChainId || paymentTxHash || buyerAddress || nonce)`;
  duplicate mints revert. Full allocation struct on-chain (buyer, payment
  chain/tx/amount, SNRG allocation nwei, stage, price, USD value, timestamp,
  vesting terms, nonce, redeemed flag).
- Reconciliation: purchaser can reconcile a missed automatic issuance using
  the original payment tx hash; backend validates payment receipt by the
  configured intake address before mint (`presaleRoutes.js`).
- Redemption: one-time; burns the voucher; emits `ReceiptRedeemed` "for the
  distribution pipeline". Voucher is soulbound (no transfer/approval).
- Governance: voucher can carry Keystone voting-power metadata; proposal
  submission still requires the 125,000 SNRG stake per existing governance
  rules (voucher alone insufficient).

## What the Synergy-side `sale_claim` genesis contract therefore is

The distribution-pipeline endpoint: it converts **attested Ethereum
`ReceiptRedeemed` records** into SNRG settlement on Synergy, funded by the
2.24B SNRG SAL-A01 inventory, honoring each voucher's on-chain vesting terms.

### External-chain verification mechanism (not invented)

No native Synergy mechanism verifies Ethereum burns today. The presale system's
existing trust mechanism is authorized-attestor infrastructure (watcher
services + dedicated authorized keys, idempotent, event-driven). Following the
instruction to use the narrowest deterministic interface consistent with the
existing system, `sale_claim` accepts **threshold-signed attestations** of
`ReceiptRedeemed` events from an admin-managed attestor set (DAO-A01 governed;
SXCP attestation can replace attestors later without changing storage
semantics). Replay protection: the Ethereum payment fingerprint AND voucher
tokenId are both recorded; each can settle exactly once.

### Required behaviors (each traced to a source above)

1. Attested redemption registers an entitlement for the redeeming wallet's
   bound Synergy address: amount = voucher `snrgAllocationNwei`; vesting terms
   copied from the voucher struct (vestingStart, cliffSeconds,
   durationSeconds, initialUnlockBps). [spec §8.2, §9]
2. One settlement per voucher tokenId; one per payment fingerprint; duplicate
   attestations revert. [spec §6, §8.1]
3. `claim` mode: pay out the currently-unlocked portion per the voucher's own
   vesting schedule; integer arithmetic; no overclaim/double claim. [§8.2]
4. `refund`/`settlement` modes: admin-authorized dispositions for failed or
   disputed purchases, bounded by the unredeemed entitlement. [init_params]
5. Inventory conservation: total settled + refunded ≤ 2,240,000,000 SNRG.
6. Access control: attestor-set and mode administration only by DAO-A01
   authority; no manual bypass mint path. [spec §10]
7. Deterministic events for every registration, claim, refund, settlement;
   restart persistence; deterministic replay. [spec §11]
8. Voucher-based Keystone voting metadata is recorded but confers no
   proposal-submission authority (125,000 SNRG stake rule governs). [existing
   governance rules]

### Open item for operator confirmation (recorded, not blocking compile)

The attestor-set membership and threshold (which watcher/multisig keys attest
`ReceiptRedeemed` on Testnet-v3) must be supplied by the DAO/custody owner at
deployment-argument time. The contract takes them as constructor arguments;
genesis constructor args must be extended with the approved attestor set
before final binding.

Draft implementation: `genesis-contracts/contracts/SaleClaim.synq`
(compile/tests pending toolchain; the assigned genesis address
`synq1q223wea4q5x74y7xvn24szlfj3da9k6z0ww4` is preserved and must be
reproduced by deterministic deployment).
