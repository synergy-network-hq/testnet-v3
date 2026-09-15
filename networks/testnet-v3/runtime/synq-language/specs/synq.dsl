# SynQ Language Specification v1.0

---

## 1. Introduction

SynQ is a smart contract language designed for the post-quantum era. It integrates NIST-standardized quantum-safe algorithms as first-class types: **ML-DSA** (Module-Lattice-Based Digital Signature Algorithm), **FN-DSA** (FFT over NTRU-Lattice-Based Digital Signature Algorithm), **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism), **SLH-DSA** (Stateless Hash-Based Digital Signature Algorithm), **HQC** (Hamming Quasi-Cyclic), and **Classic McEliece**. The language emphasizes cryptographic clarity, safety by design, and explicit resource accounting.

---

## 2. Type System

### 2.1 Primitive Types

**Integer Types:**
- `UInt8`, `UInt16`, `UInt32`, `UInt64`, `UInt128`, `UInt256` - Unsigned integers
- `Int8`, `Int16`, `Int32`, `Int64`, `Int128`, `Int256` - Signed integers

**Other Primitive Types:**
- `Bool` - Boolean (true/false)
- `Bytes` - Variable-length byte array
- `String` - UTF-8 string
- `Address` - 20-byte address type

### 2.2 Post-Quantum Cryptographic Types

#### 2.2.1 ML-DSA (Module-Lattice-Based Digital Signature Algorithm)

```synq
// Security levels: 44 (Level 2), 65 (Level 3), 87 (Level 5)
type MLDSAKeyPair44
type MLDSAPublicKey44
type MLDSASecretKey44
type MLDSASignature44

type MLDSAKeyPair65
type MLDSAPublicKey65
type MLDSASecretKey65
type MLDSASignature65

type MLDSAKeyPair87
type MLDSAPublicKey87
type MLDSASecretKey87
type MLDSASignature87

// Type aliases for convenience
type MLDSAKeyPair = MLDSAKeyPair65  // Default: Level 3
type MLDSAPublicKey = MLDSAPublicKey65
type MLDSASecretKey = MLDSASecretKey65
type MLDSASignature = MLDSASignature65
```

#### 2.2.2 FN-DSA (FFT over NTRU-Lattice-Based Digital Signature Algorithm)

```synq
// Security levels: 512 (Level 1), 1024 (Level 5)
// Variants: standard and padded
type FNDSAKeyPair512
type FNDSAPublicKey512
type FNDSASecretKey512
type FNDSASignature512
type FNDSASignedMessage512

type FNDSAKeyPair1024
type FNDSAPublicKey1024
type FNDSASecretKey1024
type FNDSASignature1024
type FNDSASignedMessage1024

// Padded variants
type FNDSAPaddedKeyPair512
type FNDSAPaddedKeyPair1024

// Type aliases
type FNDSAKeyPair = FNDSAKeyPair1024  // Default: Level 5
type FNDSAPublicKey = FNDSAPublicKey1024
type FNDSASecretKey = FNDSASecretKey1024
type FNDSASignature = FNDSASignature1024
```

#### 2.2.3 ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)

```synq
// Security levels: 512 (Level 1), 768 (Level 3), 1024 (Level 5)
type MLKEMKeyPair512
type MLKEMPublicKey512
type MLKEMSecretKey512
type MLKEMCiphertext512
type MLKEMSharedSecret512

type MLKEMKeyPair768
type MLKEMPublicKey768
type MLKEMSecretKey768
type MLKEMCiphertext768
type MLKEMSharedSecret768

type MLKEMKeyPair1024
type MLKEMPublicKey1024
type MLKEMSecretKey1024
type MLKEMCiphertext1024
type MLKEMSharedSecret1024

// Type aliases
type MLKEMKeyPair = MLKEMKeyPair768  // Default: Level 3
type MLKEMPublicKey = MLKEMPublicKey768
type MLKEMSecretKey = MLKEMSecretKey768
type MLKEMCiphertext = MLKEMCiphertext768
type MLKEMSharedSecret = MLKEMSharedSecret768
```

#### 2.2.4 SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)

```synq
// Security levels: 128 (Level 1), 192 (Level 3), 256 (Level 5)
// Variants: SHA2/SHAKE hash functions, fast/simple parameter sets
type SLHDSAKeyPair128f  // SHA2-128f-simple
type SLHDSAKeyPair128s  // SHA2-128s-simple
type SLHDSAKeyPair192f  // SHA2-192f-simple
type SLHDSAKeyPair192s  // SHA2-192s-simple
type SLHDSAKeyPair256f  // SHA2-256f-simple
type SLHDSAKeyPair256s  // SHA2-256s-simple

type SLHDSAKeyPairShake128f  // SHAKE-128f-simple
type SLHDSAKeyPairShake128s  // SHAKE-128s-simple
type SLHDSAKeyPairShake192f  // SHAKE-192f-simple
type SLHDSAKeyPairShake192s  // SHAKE-192s-simple
type SLHDSAKeyPairShake256f  // SHAKE-256f-simple
type SLHDSAKeyPairShake256s  // SHAKE-256s-simple

// Corresponding PublicKey, SecretKey, Signature types for each variant
// Example:
type SLHDSAPublicKey256f
type SLHDSASecretKey256f
type SLHDSASignature256f

// Type aliases (default: SHA2-256f-simple, Level 5)
type SLHDSAKeyPair = SLHDSAKeyPair256f
type SLHDSAPublicKey = SLHDSAPublicKey256f
type SLHDSASecretKey = SLHDSASecretKey256f
type SLHDSASignature = SLHDSASignature256f
```

#### 2.2.5 HQC (Hamming Quasi-Cyclic)

```synq
// Security levels: 128 (Level 1), 192 (Level 3), 256 (Level 5)
type HQCKeyPair128
type HQCPublicKey128
type HQCSecretKey128
type HQCCiphertext128
type HQCSharedSecret128

type HQCKeyPair192
type HQCPublicKey192
type HQCSecretKey192
type HQCCiphertext192
type HQCSharedSecret192

type HQCKeyPair256
type HQCPublicKey256
type HQCSecretKey256
type HQCCiphertext256
type HQCSharedSecret256

// Type aliases
type HQCKeyPair = HQCKeyPair192  // Default: Level 3
type HQCPublicKey = HQCPublicKey192
type HQCSecretKey = HQCSecretKey192
type HQCCiphertext = HQCCiphertext192
type HQCSharedSecret = HQCSharedSecret192
```

#### 2.2.6 Classic McEliece

```synq
// Security levels: Various parameter sets
type ClassicMcElieceKeyPair348864
type ClassicMcElieceKeyPair348864f
type ClassicMcElieceKeyPair460896
type ClassicMcElieceKeyPair460896f
type ClassicMcElieceKeyPair6688128
type ClassicMcElieceKeyPair6688128f
type ClassicMcElieceKeyPair6960119
type ClassicMcElieceKeyPair6960119f
type ClassicMcElieceKeyPair8192128
type ClassicMcElieceKeyPair8192128f

// Corresponding PublicKey, SecretKey, Ciphertext types
// 'f' variants are faster implementations
```

### 2.3 Composite Types

```synq
// Composite authentication structure
type PQAuth = {
    mldsa_key: MLDSAKeyPair65,
    fndsa_key: FNDSAKeyPair1024,
    backup_key: MLDSAKeyPair44
}

// Multi-algorithm key set
type MultiPQAuth = {
    primary: MLDSAKeyPair65,
    secondary: FNDSAKeyPair1024,
    kem_key: MLKEMKeyPair768,
    hash_based: SLHDSAKeyPair256f
}

// Key encapsulation result
type KEMResult = {
    ciphertext: MLKEMCiphertext768,
    shared_secret: MLKEMSharedSecret768
}
```

### 2.4 Collections and Mappings

```synq
// Arrays
type ProposalArray = Proposal[]
type AddressArray = Address[]

// Mappings
type ProposalMapping = mapping(UInt256 => Proposal)
type KeyMapping = mapping(Address => MLDSAPublicKey65)

// Structs
struct Proposal {
    id: UInt256,
    proposer: Address,
    description: Bytes,
    executed: Bool,
    votesFor: UInt256,
    votesAgainst: UInt256
}
```

---

## 3. Built-in Functions

### 3.1 ML-DSA Signature Operations

```synq
// Key generation (off-chain, but type-checked)
builtin mldsa_keygen44() -> (MLDSAKeyPair44, MLDSAPublicKey44, MLDSASecretKey44)
builtin mldsa_keygen65() -> (MLDSAKeyPair65, MLDSAPublicKey65, MLDSASecretKey65)
builtin mldsa_keygen87() -> (MLDSAKeyPair87, MLDSAPublicKey87, MLDSASecretKey87)

// Signature verification (on-chain)
builtin verify_mldsa44(
    msg: Bytes,
    sig: MLDSASignature44,
    pubkey: MLDSAPublicKey44
) -> Bool

builtin verify_mldsa65(
    msg: Bytes,
    sig: MLDSASignature65,
    pubkey: MLDSAPublicKey65
) -> Bool

builtin verify_mldsa87(
    msg: Bytes,
    sig: MLDSASignature87,
    pubkey: MLDSAPublicKey87
) -> Bool

// Convenience alias
builtin verify_mldsa(
    msg: Bytes,
    sig: MLDSASignature,
    pubkey: MLDSAPublicKey
) -> Bool
```

### 3.2 FN-DSA Signature Operations

```synq
// Key generation
builtin fndsa_keygen512() -> (FNDSAKeyPair512, FNDSAPublicKey512, FNDSASecretKey512)
builtin fndsa_keygen1024() -> (FNDSAKeyPair1024, FNDSAPublicKey1024, FNDSASecretKey1024)

// Signature verification
builtin verify_fndsa512(
    msg: Bytes,
    sig: FNDSASignature512,
    pubkey: FNDSAPublicKey512
) -> Bool

builtin verify_fndsa1024(
    msg: Bytes,
    sig: FNDSASignature1024,
    pubkey: FNDSAPublicKey1024
) -> Bool

// Signed message verification (includes message)
builtin verify_fndsa_signed512(
    signed_msg: FNDSASignedMessage512,
    pubkey: FNDSAPublicKey512
) -> Bool

builtin verify_fndsa_signed1024(
    signed_msg: FNDSASignedMessage1024,
    pubkey: FNDSAPublicKey1024
) -> Bool
```

### 3.3 ML-KEM Key Encapsulation

```synq
// Key generation
builtin mlkem_keygen512() -> (MLKEMKeyPair512, MLKEMPublicKey512, MLKEMSecretKey512)
builtin mlkem_keygen768() -> (MLKEMKeyPair768, MLKEMPublicKey768, MLKEMSecretKey768)
builtin mlkem_keygen1024() -> (MLKEMKeyPair1024, MLKEMPublicKey1024, MLKEMSecretKey1024)

// Encapsulation (typically off-chain, but type-checked)
builtin mlkem_encapsulate512(pubkey: MLKEMPublicKey512) -> (MLKEMCiphertext512, MLKEMSharedSecret512)
builtin mlkem_encapsulate768(pubkey: MLKEMPublicKey768) -> (MLKEMCiphertext768, MLKEMSharedSecret768)
builtin mlkem_encapsulate1024(pubkey: MLKEMPublicKey1024) -> (MLKEMCiphertext1024, MLKEMSharedSecret1024)

// Decapsulation (on-chain)
builtin mlkem_decapsulate512(
    ciphertext: MLKEMCiphertext512,
    seckey: MLKEMSecretKey512
) -> MLKEMSharedSecret512

builtin mlkem_decapsulate768(
    ciphertext: MLKEMCiphertext768,
    seckey: MLKEMSecretKey768
) -> MLKEMSharedSecret768

builtin mlkem_decapsulate1024(
    ciphertext: MLKEMCiphertext1024,
    seckey: MLKEMSecretKey1024
) -> MLKEMSharedSecret1024
```

### 3.4 SLH-DSA Signature Operations

```synq
// Key generation (example for SHA2-256f-simple)
builtin slhdsa_keygen256f() -> (SLHDSAKeyPair256f, SLHDSAPublicKey256f, SLHDSASecretKey256f)

// Signature verification
builtin verify_slhdsa256f(
    msg: Bytes,
    sig: SLHDSASignature256f,
    pubkey: SLHDSAPublicKey256f
) -> Bool

// Similar functions for all variants (128f, 128s, 192f, 192s, 256f, 256s, Shake variants)
```

### 3.5 HQC Key Encapsulation

```synq
// Key generation
builtin hqc_keygen128() -> (HQCKeyPair128, HQCPublicKey128, HQCSecretKey128)
builtin hqc_keygen192() -> (HQCKeyPair192, HQCPublicKey192, HQCSecretKey192)
builtin hqc_keygen256() -> (HQCKeyPair256, HQCPublicKey256, HQCSecretKey256)

// Encapsulation
builtin hqc_encapsulate128(pubkey: HQCPublicKey128) -> (HQCCiphertext128, HQCSharedSecret128)
builtin hqc_encapsulate192(pubkey: HQCPublicKey192) -> (HQCCiphertext192, HQCSharedSecret192)
builtin hqc_encapsulate256(pubkey: HQCPublicKey256) -> (HQCCiphertext256, HQCSharedSecret256)

// Decapsulation
builtin hqc_decapsulate128(
    ciphertext: HQCCiphertext128,
    seckey: HQCSecretKey128
) -> HQCSharedSecret128

builtin hqc_decapsulate192(
    ciphertext: HQCCiphertext192,
    seckey: HQCSecretKey192
) -> HQCSharedSecret192

builtin hqc_decapsulate256(
    ciphertext: HQCCiphertext256,
    seckey: HQCSecretKey256
) -> HQCSharedSecret256
```

### 3.6 Classic McEliece Operations

```synq
// Key generation (example for 348864)
builtin classicmceliece_keygen348864() -> (ClassicMcElieceKeyPair348864, ...)

// Encapsulation/Decapsulation operations
// (Implementation-specific, see VM specification)
```

### 3.7 Composite Authentication

```synq
// Multi-signature verification
builtin verify_composite_auth(
    message: Bytes,
    mldsa_sig: MLDSASignature65,
    fndsa_sig: FNDSASignature1024,
    auth: PQAuth
) -> Bool

// Multi-algorithm verification
builtin verify_multi_pq_auth(
    message: Bytes,
    signatures: Bytes,  // Encoded multiple signatures
    auth: MultiPQAuth
) -> Bool
```

### 3.8 Batch Verification (Future)

```synq
// Batch verification for efficiency (planned)
builtin batch_verify_mldsa65(
    messages: Bytes[],
    signatures: MLDSASignature65[],
    pubkeys: MLDSAPublicKey65[]
) -> Bool[]

builtin batch_verify_fndsa1024(
    messages: Bytes[],
    signatures: FNDSASignature1024[],
    pubkeys: FNDSAPublicKey1024[]
) -> Bool[]
```

---

## 4. Language Keywords & Decorators

### 4.1 Contract Structure

```synq
contract ContractName {
    // State variables
    Address public owner;
    MLDSAPublicKey65 public governanceKey;
    
    // Events
    event ProposalCreated(UInt256 indexed id, Address indexed proposer);
    
    // Constructor
    @deploy
    constructor(MLDSAPublicKey65 _governanceKey) {
        owner = msg.sender;
        governanceKey = _governanceKey;
    }
    
    // Functions
    @public
    @view
    function getOwner() -> Address {
        return owner;
    }
}
```

### 4.2 Decorators

```synq
@deploy             // Marks constructor function
@public             // Marks public entrypoint (callable externally)
@view               // Marks read-only view function (no state changes)
@payable            // Function can receive native tokens
@extensible         // Marks experimental/upgradeable modules
@gas_cost(base: 45000, mldsa_verify: 35000)  // Explicit gas cost annotation
@optimize_gas       // Hint to compiler for gas optimization
@gas_limit(100000)  // Maximum gas limit for function execution
@precompile("mldsa_verify")  // Marks precompiled contract call
```

### 4.3 Modifiers

```synq
modifier authenticated_pqc(
    auth: PQAuth,
    msg: Bytes,
    mldsa_sig: MLDSASignature65,
    fndsa_sig: FNDSASignature1024
) {
    require(
        verify_composite_auth(msg, mldsa_sig, fndsa_sig, auth),
        "Bad composite signature"
    );
    _;
}

modifier time_locked_pqc(
    unlock_time: UInt256,
    auth: PQAuth,
    time_sig: MLDSASignature65
) {
    require(block.timestamp >= unlock_time, "Time lock not expired");
    Bytes time_msg = encode_time(unlock_time);
    require(
        verify_mldsa65(time_msg, time_sig, auth.mldsa_key.public),
        "Invalid time lock signature"
    );
    _;
}

modifier only_owner() {
    require(msg.sender == owner, "Not owner");
    _;
}
```

### 4.4 PQC Require Block

```synq
// Enforces PQC verification with custom error message
require_pqc {
    verify_mldsa65(admin_key, proposal_data, admin_signature);
} or revert("Invalid admin signature");

// Multiple verifications
require_pqc {
    verify_mldsa65(msg, sig1, key1);
    verify_fndsa1024(msg, sig2, key2);
} or revert("Multi-sig verification failed");
```

### 4.5 Gas Budget Block

```synq
// Explicit gas limit for operation
with_gas_limit(100000) {
    cast_vote(proposal_id, support, signature);
}

// Nested gas budgets
with_gas_limit(50000) {
    verify_mldsa65(msg, sig, key);
    with_gas_limit(30000) {
        update_state();
    }
}
```

---

## 5. Imports & Modules

```synq
// Standard library imports
use std::math
use std::crypto

// PQC module imports
use pqc::mldsa
use pqc::fndsa
use pqc::mlkem
use pqc::slhdsa
use pqc::hqc
use pqc::classicmceliece

// Contract imports
use "./Proposal.synq"
use "./Voting.synq" as VotingModule
```

---

## 6. Message Signing Conventions

### 6.1 Domain Separation

All ABI-encoded messages must be prefixed with a context label to prevent replay attacks and ensure domain separation:

```synq
// Examples of proper message prefixes
Bytes vote_msg = encode("VOTE:", proposal_id, support);
Bytes proposal_msg = encode("PROPOSAL:", proposal_id, description);
Bytes transfer_msg = encode("TRANSFER:", from, to, amount);
Bytes key_rotation_msg = encode("KEY_ROTATION:", old_key, new_key);
```

### 6.2 Message Encoding

```synq
// Standard ABI encoding function
builtin encode(...) -> Bytes

// Example usage
Bytes message = encode(
    "VOTE:",
    proposal_id,
    support,
    block.timestamp,
    msg.sender
);
```

---

## 7. Addressing

SynQ supports advanced address formats compatible with Synergy's Bech32m encoding:
- `sYnQ` - SynQ contract addresses
- `sYnU` - User addresses
- `sYnX` - Cross-chain addresses

The VM accommodates multiple address schemes with cross-chain validation support.

---

## 8. Control Flow

### 8.1 Conditionals

```synq
if (condition) {
    // code
} else {
    // code
}

// Ternary operator
UInt256 result = condition ? value1 : value2;
```

### 8.2 Loops

```synq
// For loop
for (UInt256 i = 0; i < array.length; i++) {
    // process array[i]
}

// While loop
while (condition) {
    // code
}

// Do-while loop
do {
    // code
} while (condition);
```

### 8.3 Error Handling

```synq
// Require statement
require(condition, "Error message");

// Revert with message
revert("Custom error message");

// Assert (for invariants)
assert(condition, "Invariant violated");
```

---

## 9. Events and Logging

```synq
// Event declaration
event ProposalCreated(
    UInt256 indexed id,
    Address indexed proposer,
    Bytes description
);

// Emitting events
emit ProposalCreated(proposal_id, msg.sender, description);
```

---

## 10. Gas Model Integration

### 10.1 Gas Cost Annotations

```synq
@gas_cost(
    base: 45000,
    mldsa_verify: 35000,
    storage_write: 20000
)
function submit_proposal(
    Bytes description,
    MLDSASignature65 sig
) -> UInt256 {
    // Function implementation
}
```

### 10.2 Gas Estimation

```synq
// Built-in gas estimation
builtin estimate_gas(function_call) -> UInt256

// Example
UInt256 estimated = estimate_gas(
    submit_proposal(description, signature)
);
```

---

## 11. Security Best Practices

### 11.1 Signature Verification

- Always verify signatures before executing critical operations
- Use composite authentication for high-value transactions
- Implement time-locked operations for key rotation

### 11.2 Key Management

- Never store secret keys on-chain
- Use public keys for on-chain verification
- Implement key rotation mechanisms with proper authentication

### 11.3 Message Prefixing

- Always prefix messages with context labels
- Include nonces or timestamps to prevent replay attacks
- Use domain separation for different operation types

---

## 12. Example: Complete DAO Contract

```synq
contract PQCVerifiedDAO {
    Address public owner;
    MLDSAPublicKey65 public governanceKey;
    mapping(UInt256 => Proposal) public proposals;
    UInt256 public nextProposalId;
    
    event ProposalCreated(UInt256 indexed id, Address indexed proposer);
    event Voted(UInt256 indexed proposalId, Address indexed voter, Bool support);
    event ProposalExecuted(UInt256 indexed id);
    
    @deploy
    constructor(MLDSAPublicKey65 _governanceKey) {
        owner = msg.sender;
        governanceKey = _governanceKey;
        nextProposalId = 1;
    }
    
    @public
    @gas_cost(base: 30000, storage_write: 20000)
    function createProposal(Bytes _description) -> UInt256 {
        UInt256 proposalId = nextProposalId;
        proposals[proposalId] = Proposal({
            id: proposalId,
            proposer: msg.sender,
            description: _description,
            executed: false,
            votesFor: 0,
            votesAgainst: 0
        });
        nextProposalId += 1;
        emit ProposalCreated(proposalId, msg.sender);
        return proposalId;
    }
    
    @public
    @gas_cost(base: 20000)
    function vote(UInt256 _proposalId, Bool _support) {
        require(proposals[_proposalId].id != 0, "Proposal does not exist");
        if (_support) {
            proposals[_proposalId].votesFor += 1;
        } else {
            proposals[_proposalId].votesAgainst += 1;
        }
        emit Voted(_proposalId, msg.sender, _support);
    }
    
    @public
    @gas_cost(base: 45000, mldsa_verify: 35000)
    function executeProposal(
        UInt256 _proposalId,
        Bytes _messageToSign,
        MLDSASignature65 _signature
    ) {
        require(proposals[_proposalId].id != 0, "Proposal does not exist");
        require(!proposals[_proposalId].executed, "Proposal already executed");
        
        require_pqc {
            verify_mldsa65(_messageToSign, _signature, governanceKey);
        } or revert("Invalid PQC governance signature");
        
        require(
            proposals[_proposalId].votesFor > proposals[_proposalId].votesAgainst,
            "Proposal not approved by majority"
        );
        
        proposals[_proposalId].executed = true;
        emit ProposalExecuted(_proposalId);
    }
}
```

---

## 13. Future Extensions

### 13.1 Planned Features

- Support for new PQC algorithms via `@extensible` modules
- Precompiled runtime targets for performance optimization
- Hardware-backed validation (Ledger, TPM, HSM)
- zkPQC support (e.g., zk-ML-DSA circuits)
- Batch verification optimizations
- Signature aggregation
- Cross-chain PQC validation

### 13.2 Experimental Features

- Quantum-resistant hash functions
- Lattice-based zero-knowledge proofs
- Multi-party computation support
- Threshold signatures

---

## 14. Version Information

**Current Version:** v1.0  
**Last Updated:** 2024  
**Compatibility:** SynQ VM v1.0+

---

End of Specification v1.0
