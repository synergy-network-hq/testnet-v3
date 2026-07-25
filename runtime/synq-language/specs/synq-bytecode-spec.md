# SynQ Bytecode Spec

Spec version: 0.1

All multi-byte integers are unsigned big-endian unless stated otherwise.

## Header

| Offset | Size | Field | Value |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `SYNQ` (`0x53 0x59 0x4e 0x51`) |
| 4 | 2 | bytecode_version | `0x0001` |
| 6 | 2 | target_aivm_version | `0x0001` |
| 8 | 32 | abi_hash | SHA-256 of canonical ABI bytes |
| 40 | 32 | manifest_hash | SHA-256 of canonical manifest bytes |
| 72 | 32 | code_hash | SHA-256 of instruction section bytes |
| 104 | 4 | section_count | number of following sections |

Header length is 108 bytes.

## Section Record

| Size | Field |
|---:|---|
| 2 | section_type |
| 4 | section_length |
| N | section_bytes |

Section types:

| ID | Name |
|---:|---|
| 1 | constants |
| 2 | functions |
| 3 | instructions |
| 4 | exports |
| 5 | imports |
| 6 | metadata |

## Instruction Encoding

Instruction stream is a sequence of:

| Size | Field |
|---:|---|
| 1 | opcode |
| N | operands, fixed by opcode |

Initial opcode table:

| Opcode | Mnemonic | Operand layout |
|---:|---|---|
| 0x00 | `NOP` | none |
| 0x01 | `PUSH_U64` | `u64 value` |
| 0x02 | `PUSH_BYTES` | `u32 len`, `len bytes` |
| 0x10 | `LOAD_STATE` | `u16 key_index` |
| 0x11 | `STORE_STATE` | `u16 key_index` |
| 0x12 | `LOAD_LOCAL` | `u16 local_index` |
| 0x13 | `STORE_LOCAL` | `u16 local_index` |
| 0x20 | `ADD_U64` | none |
| 0x21 | `SUB_U64` | none |
| 0x22 | `MUL_U64` | none |
| 0x23 | `DIV_U64` | none |
| 0x30 | `EQ` | none |
| 0x31 | `LT` | none |
| 0x32 | `GT` | none |
| 0x40 | `JMP` | `u32 instruction_offset` |
| 0x41 | `JMP_IF` | `u32 instruction_offset` |
| 0x50 | `CALL` | `u32 function_index` |
| 0x51 | `RET` | none |
| 0x60 | `EMIT` | `u16 event_index` |
| 0x70 | `TRAP` | `u16 trap_code` |
| 0x80 | `HOST_CALL` | `u16 import_index` |

## Validation

AIVM MUST reject:

- wrong magic
- unsupported bytecode version
- unsupported target AIVM version
- malformed section length
- duplicate singleton sections
- jump target outside instruction section
- instruction operands extending past section end
- ABI, manifest, or code hash mismatch
