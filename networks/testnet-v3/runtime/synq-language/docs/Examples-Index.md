# SynQ Example Contracts Index

This directory contains comprehensive SynQ smart-contract examples intended for reference and testing.

> **Security Status (2026-02-15):** These examples now compile with the official SynQ CLI, but they are **not certified production contracts** yet. See audited findings and remediation backlog under `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/audits/reports/synq-example-contract-audits-2026-02-09/`.

## Example Contracts

### 1. ERC20 Token Contract (`1-ERC20-Token.synq`)

A complete ERC20-like token implementation with post-quantum security features.

**Features Demonstrated:**

- ✅ Standard ERC20 functions (transfer, approve, transferFrom)
- ✅ Token minting with PQC signature verification
- ✅ Token burning
- ✅ Pause/unpause functionality with PQC governance
- ✅ Batch transfers
- ✅ Governance key management
- ✅ Gas annotations and optimization
- ✅ `require_pqc` blocks for secure operations

**Key Functions:**

- `transfer()`, `transferFrom()`, `approve()`
- `mint()` - Requires ML-DSA signature
- `burn()`, `burnFrom()`
- `pause()`, `unpause()` - PQC-governed
- `batchTransfer()` - Gas-optimized batch operations
- `updateGovernanceKey()` - PQC-secured key rotation

---

### 2. Multi-Signature Wallet (`2-MultiSig-Wallet.synq`)

A post-quantum multi-signature wallet requiring multiple PQC signatures for transactions.

**Features Demonstrated:**

- ✅ Multi-owner management
- ✅ Transaction submission and confirmation
- ✅ PQC signature verification for confirmations
- ✅ Owner addition/removal with multi-sig approval
- ✅ Required signatures configuration
- ✅ Batch signature verification

**Key Functions:**

- `submitTransaction()` - Create new transaction
- `confirmTransaction()` - Confirm with PQC signature
- `addOwner()`, `removeOwner()`, `replaceOwner()` - Multi-sig governance
- `changeRequiredSignatures()` - Update threshold
- `executeTransaction()` - Auto-execute when threshold met

---

### 3. DAO Voting Contract (`3-DAO-Voting.synq`)

A complete DAO implementation with PQC-secured governance and voting.

**Features Demonstrated:**

- ✅ Proposal creation and management
- ✅ Token-weighted voting
- ✅ PQC signature voting (for off-chain voting)
- ✅ Quorum enforcement
- ✅ Proposal execution with PQC verification
- ✅ Governance parameter updates

**Key Functions:**

- `propose()` - Create governance proposal
- `castVote()` - Standard on-chain voting
- `castVoteWithSignature()` - Off-chain voting with PQC
- `executeProposal()` - Execute with PQC governance signature
- `updateGovernanceKey()`, `updateQuorum()` - Governance updates

---

### 4. NFT Contract (`4-NFT-Contract.synq`)

A complete ERC721-like NFT contract with PQC-secured minting.

**Features Demonstrated:**

- ✅ Standard NFT functions (transfer, approve, etc.)
- ✅ PQC signature verification for minting
- ✅ Batch minting
- ✅ Royalty management
- ✅ Token metadata management
- ✅ Public and private minting modes

**Key Functions:**

- `mint()` - Mint with PQC signature
- `publicMint()` - Public minting (when enabled)
- `batchMint()` - Gas-optimized batch minting
- `transferFrom()`, `safeTransferFrom()` - Standard transfers
- `setRoyalty()` - Configure royalties
- `burn()` - Destroy NFT

---

### 5. Escrow Contract (`5-Escrow-Contract.synq`)

A secure escrow system with PQC signature verification for releases.

**Features Demonstrated:**

- ✅ Escrow creation with lock periods
- ✅ PQC signature verification for release
- ✅ Dispute resolution with arbitrator
- ✅ Automatic expiration handling
- ✅ Refund functionality

**Key Functions:**

- `createEscrow()` - Create new escrow
- `releaseEscrow()` - Release with PQC signature
- `refundEscrow()` - Refund after expiration
- `raiseDispute()` - Initiate dispute
- `resolveDispute()` - Arbitrator resolution with PQC
- `checkExpiration()` - Handle expired escrows

---

### 6. Staking Contract (`6-Staking-Contract.synq`)

A complete staking system with PQC-secured rewards and emergency withdrawals.

**Features Demonstrated:**

- ✅ Token staking with lock periods
- ✅ Reward calculation and distribution
- ✅ PQC signature for emergency withdrawals
- ✅ Reward compounding
- ✅ Governance for reward rate updates

**Key Functions:**

- `stake()` - Stake tokens with lock period
- `unstake()` - Unstake after lock expires
- `claimRewards()` - Claim earned rewards
- `compound()` - Re-stake rewards
- `emergencyWithdraw()` - Emergency withdrawal with PQC
- `updateRewardRate()` - Governance-controlled rate updates

---

## Common Patterns Across Examples

### PQC Signature Verification

All examples use `require_pqc` blocks for secure operations:

```synq
require_pqc {
    let isValid = verifyMLDSASignature(
        publicKey,
        message,
        signature
    );
    require(isValid, "Invalid signature");
} or revert("PQC verification failed");
```

### Gas Annotations

All examples include gas cost annotations:

```synq
@gas_cost(base: 100000, mldsa_verify: 35000)
function secureOperation(...) {
    // ...
}
```

### Event Emission

All state changes emit events for off-chain tracking:

```synq
emit Transfer(from, to, amount);
```

### Access Control

All examples implement proper access control:

```synq
require(msg.sender == owner, "Not authorized");
require(isOwner(msg.sender), "Not an owner");
```

---

## Usage Instructions

1. **Review the Contract**: Read through the contract to understand its structure
2. **Compile**: Use the SynQ compiler API (CLI tools planned for future)
3. **Deploy**: Use deployment tools (planned for future)
4. **Test**: Interact with the contract using the provided functions

> **Note:** The `qsc` CLI tool mentioned in some examples is planned for future implementation. Currently, compilation is done programmatically via the Rust compiler API.

## Gas Considerations

- PQC operations (ML-DSA verify) cost ~35,000 gas
- Batch operations are planned for future implementation and will be more gas-efficient
- Use `@gas_cost` annotations to specify costs (currently parsed but not yet enforced at compile-time)
- Gas usage monitoring tools are planned for future implementation

## Security Best Practices

All examples follow these security principles:

1. ✅ Always verify PQC signatures before critical operations
2. ✅ Use `require_pqc` blocks for multi-step verifications
3. ✅ Implement proper access control
4. ✅ Validate all inputs
5. ✅ Use events for important state changes
6. ✅ Handle edge cases (zero addresses, empty arrays, etc.)

---

## Next Steps

- Modify examples to fit your use case
- Combine patterns from multiple examples
- Add additional features as needed
- Test thoroughly before deployment

For more information, see the [SynQ User Manual](./SynQ-User-Manual.md).
