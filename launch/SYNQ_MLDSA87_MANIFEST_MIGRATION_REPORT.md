# SynQ ML-DSA-87 manifest migration report

Session 13d, 2026-07-27. All values executed and reproduced, not inferred.

## What changed and why

`required_signature_algorithm` governs the **account-domain** envelope that
authorizes a deploy or a call — the deployer's or caller's signature. It was
`ML-DSA-65`, which is the *validator consensus* algorithm, so the consensus
domain was authorizing contract deployment. It is now `ML-DSA-87`, the governed
account/transaction domain.

The field is emitted from one constant, `compiler::artifacts::SYNQ_TESTNET_SIGNATURE_ALGORITHM`,
into both the manifest (`required_signature_algorithm`) and the ABI
(`security_requirements.signature_algorithm`), so the two cannot disagree.

It is **not**: validator consensus (ML-DSA-65), Synergy identity/address or SXCP
relayer attestation (FN-DSA-1024), P2P node identity (Ed25519), or ETDAG ingress
(ML-KEM-1024).

## Per-contract hashes

Bytecode is unchanged for all eight pre-existing contracts — proof that this is a
declaration change, not a codegen change. ABI and manifest both carry the
algorithm label, so both digests move.

| nonce | contract | bytecode | old manifest | new manifest | old abi | new abi |
|---|---|---|---|---|---|---|
| 0 | Identity | unchanged | `72b94f2be903` | `efe31bd89e54` | `a72b49437691` | `69758689bf86` |
| 1 | ValidatorRegistry | unchanged | `06e684e4d683` | `10b6ecf1385d` | `3d0db97a5463` | `6975c7e4f33a` |
| 2 | Treasury | unchanged | `b7c6ce76a34e` | `59677a0c9411` | `6f705e18ebaf` | `3c8e544c3583` |
| 3 | Governance | unchanged | `0864a02a68d8` | `6093cce183b2` | `171fbc104159` | `a21b107f130b` |
| 4 | Staking | unchanged | `0d27ecaed106` | `099ae13357cd` | `6e807655905f` | `29ea4e6db2aa` |
| 5 | Slashing | unchanged | `1fa8d27fc200` | `32baf35b61e1` | `54a4fdbeee90` | `64a790d0486c` |
| 6 | RewardDistributor | unchanged | `5cd9fa889ce8` | `4e0919c089f7` | `c5920bfb6c0a` | `eaf29c4ca41e` |
| 7 | SynergyOracle | unchanged | `6fbfd50f685e` | `4d75b487e942` | `d463e8bb8764` | `9e894326db9e` |
| 8 | TeamVesting | NEW | `—` | `c340a5ced820` | `—` | `5f7df0c83f56` |

### Full new hashes

**Identity** (nonce 0)

- source   `1dd98c07463662e7ef11747d31ab599ab5e91365bb632cfe953db35222e9b8ff`
- bytecode `4ead4317a26258ea203e9a488d0b046304765ac7e8e788cecb28701da622f8cc`
- abi      `69758689bf865c6339abe56ba2ba253adf6307d94236c1995bbb0e2ff1a218fa`
- manifest `efe31bd89e5427739bb59b99f4b9ffd4d60d3e7c2fa6389b2e6a128c3f809c73`

**ValidatorRegistry** (nonce 1)

- source   `1579f1c3872b82f9313365428a14cd17f3cf416abc9ebdbd73396632a7592581`
- bytecode `abf7805cda0f452b77d9051c037b67342d2526ba707f8376102ddb1de137e012`
- abi      `6975c7e4f33a15a4a1abbdf5d015b6ff375a16a1370e44b92f20c98b3e38a426`
- manifest `10b6ecf1385d7100f4c71f1b9268c117cc760eb3e2b870e4ddec18dd0e57c432`

**Treasury** (nonce 2)

- source   `0e9d3ca2f5ab2005f92e5936031a67e0fb2054d168e0958ef86b853303270ab8`
- bytecode `3f3e0c486d34b37ce5bb2c4d1ee7db009c6627e263d6aa6d83053fc6a94034df`
- abi      `3c8e544c35839762c569795e8bbd5f8c9421b4f06ecb6cb90796a9b8ddcca49c`
- manifest `59677a0c9411952da7237d6ec49bf0ccb2f74e507db59808f818fd72a0fea0ac`

**Governance** (nonce 3)

- source   `e0acfa60aedaf6e0cbca5c262aa5e88be7a320284a1fc9aa6fd4c0d5ec34db8c`
- bytecode `f87903c37d13e16154803c262577fd2ed9b784f76d4873eb9c28c629bb795cbf`
- abi      `a21b107f130b684e9bbba34df39ace485df21ee38f209d2b735c8b151da42349`
- manifest `6093cce183b2c7a204ce7478ca8a4a0d0305b65ee7894805347687634548d3c0`

**Staking** (nonce 4)

- source   `0affdc8b9ecccc085e00b1c340b9b7209a54baa09bcc5fc36128fa0358c2e98a`
- bytecode `14995f99919e2a5e8349175db4012e3671c991075e6be39f8b763105584c103e`
- abi      `29ea4e6db2aa9659d0602990234ad931b28b648f018d0136cb90c3f711131b08`
- manifest `099ae13357cd2591bf7ad3b60d131974f3bb4c03f70623a74d3b4e913a5056b4`

**Slashing** (nonce 5)

- source   `f1e4614ed8fce8fb2851ef0db8de9cdfce317f2eae7e88dde19fd066aa2e47a6`
- bytecode `01e44718048646ec695367bc81bd9556044bc28ea2e813162342ff9ad485db48`
- abi      `64a790d0486c1766306c87855c014af1f67d9ff55d601b26c5ab46044c67452f`
- manifest `32baf35b61e1add55b9b1cf0498b601677e441c85eec906408f0fc0425171297`

**RewardDistributor** (nonce 6)

- source   `4637d427982be8dfa50749f674fda45b79bfee600962a1323b5d39a6709a51fd`
- bytecode `f7006241c97da3e8fa1dc3287bbc2381ee3b1bcdeea77edd8460a31bd3bb8641`
- abi      `eaf29c4ca41e1c786b3ab0785571ea6ec7b0c13988849d881555ba95c63f2825`
- manifest `4e0919c089f7060aef4bd02b5ef4d1e6522e6b168b4b5e1dccb2b5fbabc33e3c`

**SynergyOracle** (nonce 7)

- source   `24bdbfce4d98380004f164aba7672b8ab94d2013ae0a8c68f8326980219a641c`
- bytecode `6cdff83c939df81bef2b0f871c56e9756c723bfd875faea7d991a71bbb44d890`
- abi      `9e894326db9eafda0acbaaf9528f6d7fc46c6b8ec620ca1c78efcfc8a5b5519c`
- manifest `4d75b487e942d3d64d809d6181fc5e5a0b558c23981af8edc1b16dd4c2e09280`

**TeamVesting** (nonce 8)

- source   `7a0bc49290db88fb4efa587499d4a0b407295384be1a1d6946da40c7e3436fe9`
- bytecode `6a4bf755a81615aed240c51f6842aa1bdc6ca8ef16ffa75ce7a510453f1b7f4c`
- abi      `5f7df0c83f56283e9c1f78bfe84f9f8b494f1c300ae9cc412d87164027f00753`
- manifest `c340a5ced8204e5d6dad0e78d0c78bd4a7aaa0ed6f7c2ea9dde053d74ef89383`

## Determinism

Three independent builds into separate output directories
(`/Volumes/xcode/phase8-rebuild-{1,2,3}`) produced **byte-identical**
`.compiled.synq`, `.abi.json` and `.manifest.json` for all nine contracts.
No differing files.

## Test results

- SynQ compiler suite: green (6/6, 6/6, 5/5, 15/15).
- Runtime SynQ tests: **27/27**, including the four previously red
  (`synq_deploy_carrier_verifies_through_pqsynq`, `synq_call_carrier_verifies_through_pqsynq`,
  `synq_deploy_carrier_reaches_receipt_through_node_admission`,
  `real_aegis_transaction_preserves_synq_admission_summary`).
- Full runtime suite: **1105 passed / 0 failed, three consecutive runs**.

Expected-value updates were made only where the reason was proven: the Counter
canonical fixture's ABI and manifest digests moved because both artifacts carry
the algorithm label, while its bytecode hash is unchanged.

## Artifact freeze status

**NOT FROZEN.** The rebuilt artifacts are staged at `/Volumes/xcode/phase8-rebuild-1`
and have deliberately **not** been copied into `genesis-contracts/contracts/`,
because genesis still binds the old hashes and the candidate must not be mutated
incrementally. Freeze happens with the atomic nine-contract rebind, after
constructor arguments are final.

