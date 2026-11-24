# Canonical AIVM Ethereum compatibility

Ethereum execution is an internal capability of AIVM. It uses pinned `revm`
43.0.3 with the explicit Shanghai fork and the existing native `WorldState`,
SNRG accounts, ETDAG order, PoSy candidates, finality and durable stores. There
is no additional VM process, consensus, native currency or independently owned
Ethereum state database. `alloy-trie` 0.9.9 computes derived block-view roots.

Activation requires signed Genesis format 2 with
`network.ethereum_compatibility.profile_id = aivm-ethereum-eip155-shanghai-v1`
and an exact lowercase SHA256 of the initial World's
`aivm/ethereum/v1/policy` bytes. The initial native state root also commits those
bytes. Startup, original admission, candidate execution and RPC recheck that
independently authenticated digest and selected chain. Omission preserves older
Genesis serialization and grants no Ethereum capability. The current profile
keeps its exact policy immutable through epoch changes; an upgrade needs an
explicit authenticated protocol transition rather than editing runtime config.

The policy specifies the engine/fork, native base fee and treasury, block gas,
account/storage/code/memory/patch/receipt bounds and these explicit rules:

- `native_exception_policy = full-gas-no-action-v1`
- `blockhash_policy = native-posy-block-id-v1`
- `randomness_policy = authenticated-epoch-seed-v1`
- `rpc_projection_policy = native-posy-evm-view-v1`
- `retain_base_fee_in_native_treasury = true`
- `reject_sub_native_precision = true`

Current qualification/deployment work targets Canary99999; replacement Testnet9969
formation is deferred until the Canary architecture is complete and stable.
The approved future Testnet chain ID is9969; Mainnet-beta/Mainnet uses469.
A selected 9969 network rejects 1266, 99999, 469 and unprotected signatures.
Fork/fee/treasury/resource values become authority only through the actual
signed Genesis and native formation workflow. The fixture values are test inputs.

## Authorization, ordering and settlement

`eth_sendRawTransaction` accepts bounded legacy EIP155 wire bytes. Canonical
RLP, chain, low-S/range, recovered signer, exact amounts, native funding and
protected account policy are checked. Typed transactions are explicitly refused.
The server encrypts the original bytes using the authenticated native APQE
ML-KEM-1024 roster and submits the separate Ethereum ETDAG admission carrier.
That carrier preserves the public original EIP155 authorization; standard raw
Ethereum submission makes no transaction confidentiality claim and creates no
native user signature. Validators authenticate the external signature, certify
availability, order through the existing native groups, threshold-reveal only
after the existing closure/finality permission, and recheck the exact plaintext.
The existing durable original/progress/completion stores drive restart replay.
Each selected external carrier writes an exact native consumption marker binding
its READY record and transaction hash. The normal authenticated selection and
three-QC retirement verifier recognizes that marker, quiesces its worker budget,
and retains the original bytes only through the existing retention lifecycle.
A duplicate carrier for a settled hash consumes its own native identity without
another fee, nonce or Ethereum receipt. A returned transaction hash requires actual durable native admission; it never
represents a mined receipt.

Execution runs only inside the selected canonical native processing candidate.
Deployment, calls, nonces, balances, code, storage, logs, reverts and receipts
share its atomic World overlay. The same original is authenticated again against
current protected account policy. A conventional address is a representation of
an account in that native SNRG World, not another asset. Existing protected synw
aliases cannot coexist with an independent conventional debit account, and a
recovered conventional key cannot spend a protected account. Protected credits
require the finalized native registry and qualified native Wallet authority.

One native nWei is exactly 10^9 external wei. No conversion rounds. Input dust
is refused before admission. An ordered internal fractional native write,
forbidden protected write, coin-conservation violation or governed execution
resource-bound violation becomes a native exceptional halt: discard all action
writes/output/logs, consume the executable nonce and charge the full signed gas
limit. Its failed receipt includes `synergyNativeException`. Ordinary Solidity
reverts retain their actual consumed gas and revert output. A stale or newly
unfunded original is terminally retired without execution, fee or nonce, and
has no fabricated mined Ethereum receipt. Local resource pressure is retryable;
corrupt state and missing authenticated block history fail closed.

## Finalized JSON-RPC projection

The native RPC implements chain/network identity, finalized height, balances,
nonces, code, storage, calls, gas estimates/price, raw submission, transaction
and receipt lookup, block lookup and bounded logs. `latest`, `safe` and
`finalized` all select verified PoSy-finalized native execution. Only nonce
queries support `pending`, from the native owner's real durable pending set,
including restart reconstruction. Other speculative state/block overrides,
typed transactions, fee history, subscriptions and `eth_getProof` are unsupported.

`native-posy-evm-view-v1` binds each projected block to the actual native block
ID, parent ID, signed consensus timestamp and authenticated epoch seed. Its
transaction and receipt MPT roots derive from the actual ordered EVM raw
transactions and canonical legacy receipt RLP. Gas used, logs and bloom derive
from those same receipts. Beneficiary, gas limit and base fee come from the
committed execution policy. The profile defines zero PoW difficulty/total
difficulty, a zero eight-byte PoW nonce, no ommers and protocol bytes as extraData.
`mixHash`/`prevRandao` carry the authenticated native epoch seed. `size` is the
exact RLP byte length of this derived header/legacy-transaction view. It does not claim
that the native block ID is an Ethereum RLP-header hash. `stateRoot` is the genuine derived account/storage MPT projection of the same
World and resolver; `synergyNativeStateRoot` is the actual native World commitment. Ethereum state
proofs or Ethereum light-client header equivalence are not claimed.

Reads rebind retained data across canonical execution, native finalized state
and PoSy finality. Pruned or corrupt payloads are unavailable, never synthesized.
Logs have bounded height/result/response sizes. Derived views do not grant
execution or finality authority.

## Reproducible qualification

`tests/fixtures/EvmCounter.sol` and its checked fixture use solc 0.8.30 Shanghai
and ethers 6.15.0 with the public EIP155 example test key. The generator accepts
explicit compiler/client module paths. Kernel tests cover real deployment,
calls, storage, events, fee-paying revert, native precision/conservation,
protected-account safety, precompiles, replay and typed resource pressure.
A full30M-gas simulation and a real workload above1M gas are checked within a
512MiB pool with330MiB already reserved; candidate cloning preflights the actual
bounded write set instead of a maximum-patch multiplier. Local pressure never
becomes a successful gas estimate or a consensus rejection.

The ignored node test
`actual_apqe_five_process_ethereum_eip155_solidity_restart_and_rpc` requires an
explicitly pinned native APQE report, a freshly built normal node binary and
independent ethers6.15.0. Its local disposable Canary99999 transactions are
independently re-signed from the checked compiler fixture using the public test
key. This neither renews live Canary authority nor forms the future Testnet9969.
It uses the existing disposable five-process harness,
authenticated encrypted sessions, abrupt admission-process restart, actual
PoSy finality, independently consumed HTTP/ABI/log/block views and independent
MPT reconstruction. Fixture roots, keys and process logs are removed on exit.
This source qualification is distinct from authenticated managed distribution
and acceptance of the actual public Testnet.

Primary specifications: [EIP155](https://eips.ethereum.org/EIPS/eip-155),
[Ethereum JSON-RPC](https://ethereum.org/developers/docs/apis/json-rpc/),
[revm](https://docs.rs/revm/43.0.3/revm/),
[alloy-trie](https://docs.rs/alloy-trie/0.9.9/alloy_trie/).
