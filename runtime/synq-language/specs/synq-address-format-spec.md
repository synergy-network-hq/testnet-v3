# SynQ Address Format Spec

Spec version: 0.1

## Internal Address Bytes

| Size | Field |
|---:|---|
| 1 | address version, `0x01` |
| 2 | network ID, `0x04f0` for chain 1264 |
| 2 | algorithm ID |
| 32 | public key hash |
| 4 | checksum |

Total internal length: 41 bytes.

`public_key_hash = SHA-256(public_key_bytes)`.

`checksum = first_4_bytes(SHA-256(address_version || network_id ||
algorithm_id || public_key_hash))`.

## Human Encoding

Human-facing testnet addresses use Bech32m with HRP `tsynq`.

Mainnet-candidate HRP is reserved as `synq`.

Implementations MUST store and compare internal bytes. Human strings are display
and input encoding only.

## Test Vector Seed

For public key bytes `0x010203`, algorithm `ML-DSA-65` (`0x0102`), and network
`1264` (`0x04f0`):

- public key hash:
  `039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81`
- checksum input length: 37 bytes

The final Bech32m string is pending implementation and MUST be added before
live TESTNET deploy/call support is marked complete.
