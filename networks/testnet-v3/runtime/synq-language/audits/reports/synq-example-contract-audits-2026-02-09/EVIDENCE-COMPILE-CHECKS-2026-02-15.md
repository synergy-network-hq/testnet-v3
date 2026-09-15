# Evidence: SynQ Example Contract Compile Revalidation

Date (UTC): 2026-02-15
Command runner: local CLI (`cargo run -p cli -- compile --path ...`)

## Results

All six canonical example contracts now compile successfully with the official SynQ CLI/compiler path.

1. `docs/examples/1-ERC20-Token.synq` -> PASS (`1-ERC20-Token.compiled.synq`, `1-ERC20-Token.sol`)
2. `docs/examples/2-MultiSig-Wallet.synq` -> PASS (`2-MultiSig-Wallet.compiled.synq`, `2-MultiSig-Wallet.sol`)
3. `docs/examples/3-DAO-Voting.synq` -> PASS (`3-DAO-Voting.compiled.synq`, `3-DAO-Voting.sol`)
4. `docs/examples/4-NFT-Contract.synq` -> PASS (`4-NFT-Contract.compiled.synq`, `4-NFT-Contract.sol`)
5. `docs/examples/5-Escrow-Contract.synq` -> PASS (`5-Escrow-Contract.compiled.synq`, `5-Escrow-Contract.sol`)
6. `docs/examples/6-Staking-Contract.synq` -> PASS (`6-Staking-Contract.compiled.synq`, `6-Staking-Contract.sol`)

## Scope Note

This revalidation closes the parser/compile blocker recorded in the 2026-02-09 evidence file.
It does **not** close the security findings from the six contract audits; those remain open until remediations are implemented and re-audited.
