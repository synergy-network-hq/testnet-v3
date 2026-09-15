# QuantumVM Bytecode Format and Instruction Set Specification

## 1. Introduction

QuantumVM is a virtual machine designed to execute SynQ smart contracts. This document specifies the bytecode format and the instruction set (opcodes) that QuantumVM understands. The design prioritizes efficiency, security, and native support for post-quantum cryptographic operations.

## 2. Bytecode Format

QuantumVM bytecode is a sequence of instructions, each consisting of an opcode followed by zero or more operands. The bytecode is designed to be compact and easily parsable.

### 2.1. Instruction Structure

Each instruction in QuantumVM bytecode follows a simple structure:

`[Opcode (1 byte)] [Operand 1 (variable size)] [Operand 2 (variable size)] ...`

*   **Opcode:** A single byte representing the operation to be performed.
*   **Operands:** Data required by the opcode, such as values, addresses, or jump targets. The size and type of operands depend on the specific opcode.

### 2.2. Data Representation

*   **Integers:** Represented using variable-length encoding (e.g., LEB128) for efficiency, allowing smaller numbers to take less space.
*   **Addresses:** Fixed-size (e.g., 20 bytes for a typical blockchain address).
*   **Bytes/Arrays:** Preceded by a length indicator.

## 3. Instruction Set (Opcodes)

QuantumVM is a stack-based machine. Most operations consume operands from the stack and push results back onto it. The instruction set includes standard arithmetic, logical, control flow, and memory operations, along with specialized opcodes for post-quantum cryptography.

### 3.1. Stack Manipulation

| Opcode | Name    | Description                                   | Stack Effect |
|--------|---------|-----------------------------------------------|--------------|
| `0x00` | `PUSH`  | Push a value onto the stack.                  | `-> value`   |
| `0x01` | `POP`   | Pop a value from the stack.                   | `value ->`   |
| `0x02` | `DUP`   | Duplicate the top value on the stack.         | `value -> value, value` |
| `0x03` | `SWAP`  | Swap the top two values on the stack.         | `a, b -> b, a` |

### 3.2. Arithmetic Operations

| Opcode | Name    | Description                                   | Stack Effect |
|--------|---------|-----------------------------------------------|--------------|
| `0x10` | `ADD`   | Add two numbers.                              | `a, b -> a+b`|
| `0x11` | `SUB`   | Subtract two numbers.                         | `a, b -> a-b`|
| `0x12` | `MUL`   | Multiply two numbers.                         | `a, b -> a*b`|
| `0x13` | `DIV`   | Divide two numbers.                           | `a, b -> a/b`|

### 3.3. Comparison Operations

| Opcode | Name    | Description                                   | Stack Effect |
|--------|---------|-----------------------------------------------|--------------|
| `0x20` | `EQ`    | Check if two values are equal.                | `a, b -> bool`|
| `0x21` | `LT`    | Check if value A is less than value B.        | `a, b -> bool`|
| `0x22` | `GT`    | Check if value A is greater than value B.     | `a, b -> bool`|

### 3.4. Control Flow

| Opcode | Name    | Description                                   | Stack Effect |
|--------|---------|-----------------------------------------------|--------------|
| `0x30` | `JUMP`  | Unconditional jump to an instruction address. | `address ->` |
| `0x31` | `JUMPI` | Conditional jump if top of stack is true.     | `address, bool ->` |
| `0x32` | `RETURN`| Halt execution and return value.              | `value ->`   |

### 3.5. Memory and Storage Operations

| Opcode | Name    | Description                                   | Stack Effect |
|--------|---------|-----------------------------------------------|--------------|
| `0x40` | `MLOAD` | Load value from memory.                       | `address -> value` |
| `0x41` | `MSTORE`| Store value to memory.                        | `value, address ->` |
| `0x42` | `SLOAD` | Load value from contract storage.             | `key -> value` |
| `0x43` | `SSTORE`| Store value to contract storage.              | `value, key ->` |

### 3.6. Post-Quantum Cryptography Operations

These opcodes are specifically designed to handle post-quantum cryptographic primitives. They will incur higher gas costs due to their computational intensity.

| Opcode | Name                 | Description                                                                                             | Stack Effect |
|--------|----------------------|---------------------------------------------------------------------------------------------------------|--------------|
| `0xA0` | `DILITHIUM_VERIFY`   | Verifies a Dilithium signature. Expects public key, message, and signature on stack. Pushes boolean result. | `pubkey, msg, sig -> bool` |
| `0xA1` | `FALCON_VERIFY`      | Verifies a Falcon signature. Expects public key, message, and signature on stack. Pushes boolean result.    | `pubkey, msg, sig -> bool` |
| `0xA2` | `KYBER_ENCAPSULATE`  | Encapsulates a shared secret using a Kyber public key. Pushes ciphertext and shared secret.               | `pubkey -> ciphertext, shared_secret` |
| `0xA3` | `KYBER_DECAPSULATE`  | Decapsulates a shared secret using a Kyber private key and ciphertext. Pushes shared secret.              | `privkey, ciphertext -> shared_secret` |

### 3.7. Environmental Information

| Opcode | Name    | Description                                   | Stack Effect |
|--------|---------|-----------------------------------------------|--------------|
| `0xB0` | `ADDRESS`| Get current contract address.                 | `-> address` |
| `0xB1` | `CALLER`| Get address of the caller.                    | `-> address` |
| `0xB2` | `GAS`   | Get remaining gas.                            | `-> uint256` |

## 4. Gas Model Considerations for PQC Opcodes

The gas cost for `DILITHIUM_VERIFY`, `FALCON_VERIFY`, `KYBER_ENCAPSULATE`, and `KYBER_DECAPSULATE` will be significantly higher and dynamically calculated based on the specific parameters (e.g., security level, key/signature size) of the PQC algorithm being used. This ensures that the computational burden of these operations is accurately reflected in transaction fees, preventing network abuse and incentivizing efficient contract design. The exact gas costs will be determined through empirical benchmarking of the underlying cryptographic libraries.

## 5. Future Extensions

This instruction set can be extended to include more PQC algorithms (e.g., SPHINCS+ for stateless signatures) or other cryptographic primitives as they become standardized and relevant to smart contract applications.




## 6. Example Usage

This section provides a simple example of QuantumVM bytecode and how it would be executed by the interpreter. This example demonstrates basic stack manipulation and arithmetic operations.

### 6.1. Example Bytecode: `PUSH 1, PUSH 2, ADD`

This bytecode sequence pushes the value `1` onto the stack, then pushes the value `2` onto the stack, and finally performs an addition operation, leaving the result (`3`) on the stack.

```
0x00 // PUSH
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 // Value 1 (32 bytes)
0x00 // PUSH
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 // Value 2 (32 bytes)
0x10 // ADD
```

### 6.2. Execution Flow

1.  **`PUSH 1`**: The `PUSH` opcode reads the next 32 bytes (representing the value `1`) from the bytecode and pushes it onto the stack.
2.  **`PUSH 2`**: Similarly, the value `2` is pushed onto the stack.
3.  **`ADD`**: The `ADD` opcode pops the top two values (`2` and `1`) from the stack, adds them, and pushes the result (`3`) back onto the stack.

After execution, the stack will contain a single element: `[0x00...0x03]` (representing the value 3).

