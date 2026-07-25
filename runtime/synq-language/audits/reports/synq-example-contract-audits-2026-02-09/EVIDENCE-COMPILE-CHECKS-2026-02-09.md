# Evidence: SynQ Example Contract Compile Checks

Date (UTC): 2026-02-09T23:17:57Z
Commit: `71aab8af592d6a1523679354a0a67db7106655d7`

Commands executed:

1. `cargo run -p cli -- compile --path docs/examples/1-ERC20-Token.synq`
   - Result: Fail
   - Error: `expected contract_part` at `docs/examples/1-ERC20-Token.synq:8`
2. `cargo run -p cli -- compile --path docs/examples/2-MultiSig-Wallet.synq`
   - Result: Fail
   - Error: `expected contract_part` at `docs/examples/2-MultiSig-Wallet.synq:8`
3. `cargo run -p cli -- compile --path docs/examples/3-DAO-Voting.synq`
   - Result: Fail
   - Error: `expected contract_part` at `docs/examples/3-DAO-Voting.synq:8`
4. `cargo run -p cli -- compile --path docs/examples/4-NFT-Contract.synq`
   - Result: Fail
   - Error: `expected contract_part` at `docs/examples/4-NFT-Contract.synq:8`
5. `cargo run -p cli -- compile --path docs/examples/5-Escrow-Contract.synq`
   - Result: Fail
   - Error: `expected contract_part` at `docs/examples/5-Escrow-Contract.synq:8`
6. `cargo run -p cli -- compile --path docs/examples/6-Staking-Contract.synq`
   - Result: Fail
   - Error: `expected contract_part` at `docs/examples/6-Staking-Contract.synq:8`

Grammar reference supporting this incompatibility:

- `state_variable_declaration = { annotation* ~ IDENT ~ ":" ~ type_decl ~ ("public")? ~ ";" }` at `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/compiler/src/synq.pest:28`

Observed mismatch:

- Examples use Solidity-like declarations (`Type public name;`) instead of grammar-supported declarations (`name: Type public;`).
