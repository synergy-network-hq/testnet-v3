# SynQ ABI Spec

Spec version: 0.1

## Canonical Form

The ABI artifact is canonical JSON encoded as UTF-8 with:

- sorted object keys
- no insignificant whitespace
- decimal strings for `u128` values
- no floating point values
- arrays in declared order

The ABI hash is `SHA-256(canonical_abi_json_bytes)`.

## Top-Level Fields

| Field | Type |
|---|---|
| `abi_version` | string, fixed `0.1` |
| `contract` | string |
| `methods` | array of method objects |
| `events` | array of event objects |
| `errors` | array of error objects |
| `state_schema` | array of state field objects |
| `security_requirements` | object |

## Method Object

| Field | Type |
|---|---|
| `name` | string |
| `selector` | lowercase `0x` hex, 4 bytes |
| `visibility` | `public` or `private` |
| `mutability` | `view` or `write` |
| `params` | ordered ABI type list |
| `returns` | ordered ABI type list |

Selector rule: first 4 bytes of `SHA-256(name + "(" + comma_types + ")")`.

## Type Encoding

Call data layout:

| Size | Field |
|---:|---|
| 4 | method selector |
| N | encoded parameters |

Primitive values are encoded big-endian. Dynamic values are encoded as `u32 len`
followed by raw bytes. Arrays are `u32 count` followed by item encodings.

| Type | Encoding |
|---|---|
| `bool` | `u8`, `0` false or `1` true |
| `u8`/`u16`/`u32`/`u64`/`u128` | fixed-width big-endian |
| `i32`/`i64` | two's-complement big-endian |
| `bytes` | `u32 len`, bytes |
| `bytes32` | 32 bytes |
| `address` | canonical 41-byte SynQ address bytes |
| `string` | `u32 utf8_len`, UTF-8 bytes |
| `array<T>` | `u32 count`, item encodings |

Return data uses the same encoding without a method selector.
