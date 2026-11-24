//! Ethereum wire decoding at the canonical AIVM boundary.
//!
//! Decoding is not authorization, execution, or finality. The caller must verify
//! the recovered signer against authoritative account policy and submit through
//! the governed ETDAG/PoSy path. Typed envelopes remain explicitly unsupported.
//! Wire rules: https://eips.ethereum.org/EIPS/eip-155 and Ethereum RLP.
use sha3::{Digest, Keccak256};

pub const MAX_LEGACY_TRANSACTION_BYTES: usize = 1_048_576;
pub const WEI_PER_NWEI: u64 = 1_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthereumDecodeError {
    SizeLimit,
    UnsupportedEnvelope,
    InvalidRlp,
    NonCanonicalInteger,
    IntegerOverflow,
    InvalidRecipient,
    InvalidSignature,
    UnprotectedSignature,
    WrongChain,
    SubNativePrecision,
    InvalidGasLimit,
    InvalidNonce,
    FeeCapTooLow,
}

impl std::fmt::Display for EthereumDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for EthereumDecodeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLegacyTransaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price_wei: [u8; 32],
    pub recipient: Option<[u8; 20]>,
    pub value_wei: [u8; 32],
    pub data: Vec<u8>,
    pub v: u128,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub signing_hash: [u8; 32],
    pub transaction_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLegacyTerms {
    pub value_nwei: u128,
    pub gas_price_nwei: u64,
    pub maximum_fee_nwei: u128,
    pub maximum_debit_nwei: u128,
}

impl DecodedLegacyTransaction {
    /// Exact conversion only: no rounding, extra asset, or fractional native
    /// account balance is introduced by an Ethereum representation.
    pub fn native_terms(&self) -> Result<NativeLegacyTerms, EthereumDecodeError> {
        let value_nwei = wei_to_nwei(self.value_wei)?;
        let gas_price_nwei = u64::try_from(wei_to_nwei(self.gas_price_wei)?)
            .map_err(|_| EthereumDecodeError::IntegerOverflow)?;
        let maximum_fee_nwei = u128::from(gas_price_nwei) * u128::from(self.gas_limit);
        let maximum_debit_nwei = value_nwei
            .checked_add(maximum_fee_nwei)
            .ok_or(EthereumDecodeError::IntegerOverflow)?;
        Ok(NativeLegacyTerms {
            value_nwei,
            gas_price_nwei,
            maximum_fee_nwei,
            maximum_debit_nwei,
        })
    }

    /// The execution owner supplies the selected fork's actual intrinsic gas
    /// and governed limits. No fork or fee policy is guessed by the decoder.
    pub fn validate_execution_limits(
        &self,
        expected_nonce: u64,
        intrinsic_gas: u64,
        maximum_gas: u64,
        base_fee_nwei: u64,
    ) -> Result<NativeLegacyTerms, EthereumDecodeError> {
        if self.nonce != expected_nonce || self.nonce == u64::MAX {
            return Err(EthereumDecodeError::InvalidNonce);
        }
        if intrinsic_gas == 0 || self.gas_limit < intrinsic_gas || self.gas_limit > maximum_gas {
            return Err(EthereumDecodeError::InvalidGasLimit);
        }
        let terms = self.native_terms()?;
        if terms.gas_price_nwei < base_fee_nwei {
            return Err(EthereumDecodeError::FeeCapTooLow);
        }
        Ok(terms)
    }
}

/// Decode only replay-protected legacy transactions for the explicitly selected
/// chain. The unprotected v=27/28 form is deliberately rejected.
pub fn decode_eip155(
    raw: &[u8],
    expected_chain_id: u64,
) -> Result<DecodedLegacyTransaction, EthereumDecodeError> {
    if raw.is_empty() || raw.len() > MAX_LEGACY_TRANSACTION_BYTES {
        return Err(EthereumDecodeError::SizeLimit);
    }
    if raw[0] < 0xc0 {
        return Err(EthereumDecodeError::UnsupportedEnvelope);
    }
    let (list, used, is_list) = item(raw)?;
    if !is_list || used != raw.len() {
        return Err(EthereumDecodeError::InvalidRlp);
    }
    let mut remaining = list;
    let mut fields = [&[][..]; 9];
    let mut signing_fields_end = 0;
    for (index, field) in fields.iter_mut().enumerate() {
        let (payload, consumed, nested) = item(remaining)?;
        if nested {
            return Err(EthereumDecodeError::InvalidRlp);
        }
        *field = payload;
        remaining = &remaining[consumed..];
        if index == 5 {
            signing_fields_end = list.len() - remaining.len();
        }
    }
    if !remaining.is_empty() {
        return Err(EthereumDecodeError::InvalidRlp);
    }
    let nonce = number(fields[0], 8)? as u64;
    let gas_price_wei = word(fields[1])?;
    let gas_limit = number(fields[2], 8)? as u64;
    let recipient = match fields[3].len() {
        0 => None,
        20 => Some(fields[3].try_into().unwrap()),
        _ => return Err(EthereumDecodeError::InvalidRecipient),
    };
    let value_wei = word(fields[4])?;
    let v = number(fields[6], 16)?;
    if v == 27 || v == 28 {
        return Err(EthereumDecodeError::UnprotectedSignature);
    }
    if v < 35 {
        return Err(EthereumDecodeError::InvalidSignature);
    }
    let chain = (v - 35) / 2;
    if expected_chain_id == 0 || chain != u128::from(expected_chain_id) {
        return Err(EthereumDecodeError::WrongChain);
    }
    let r = word(fields[7])?;
    let s = word(fields[8])?;
    if r == [0; 32] || s == [0; 32] {
        return Err(EthereumDecodeError::InvalidSignature);
    }
    let mut signing_payload = list[..signing_fields_end].to_vec();
    encode_bytes(
        minimal_bytes(&expected_chain_id.to_be_bytes()),
        &mut signing_payload,
    );
    signing_payload.extend_from_slice(&[0x80, 0x80]);
    let mut signing_preimage = Vec::new();
    encode_length(signing_payload.len(), 0xc0, &mut signing_preimage);
    signing_preimage.extend_from_slice(&signing_payload);
    Ok(DecodedLegacyTransaction {
        chain_id: expected_chain_id,
        nonce,
        gas_limit,
        gas_price_wei,
        recipient,
        value_wei,
        data: fields[5].to_vec(),
        v,
        r,
        s,
        signing_hash: Keccak256::digest(signing_preimage).into(),
        transaction_hash: Keccak256::digest(raw).into(),
    })
}

/// Convert Ethereum's 18-decimal representation into the 9-decimal ledger.
/// Long division accepts the full wire uint256 while rejecting a native u128
/// overflow and every non-zero remainder.
pub fn wei_to_nwei(wei: [u8; 32]) -> Result<u128, EthereumDecodeError> {
    let mut quotient = [0u8; 32];
    let mut remainder = 0u64;
    for (index, byte) in wei.into_iter().enumerate() {
        let current = remainder * 256 + u64::from(byte);
        quotient[index] = (current / WEI_PER_NWEI) as u8;
        remainder = current % WEI_PER_NWEI;
    }
    if remainder != 0 {
        return Err(EthereumDecodeError::SubNativePrecision);
    }
    if quotient[..16].iter().any(|&byte| byte != 0) {
        return Err(EthereumDecodeError::IntegerOverflow);
    }
    Ok(u128::from_be_bytes(quotient[16..].try_into().unwrap()))
}

/// Native uint128 balances always fit the Ethereum uint256 presentation.
pub fn nwei_to_wei(nwei: u128) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[16..].copy_from_slice(&nwei.to_be_bytes());
    let mut carry = 0u64;
    for byte in result.iter_mut().rev() {
        let product = u64::from(*byte) * WEI_PER_NWEI + carry;
        *byte = product as u8;
        carry = product >> 8;
    }
    debug_assert_eq!(carry, 0);
    result
}

fn number(bytes: &[u8], limit: usize) -> Result<u128, EthereumDecodeError> {
    canonical_integer(bytes, limit)?;
    Ok(bytes
        .iter()
        .fold(0, |value, byte| (value << 8) | u128::from(*byte)))
}
fn word(bytes: &[u8]) -> Result<[u8; 32], EthereumDecodeError> {
    canonical_integer(bytes, 32)?;
    let mut value = [0; 32];
    value[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(value)
}
fn canonical_integer(bytes: &[u8], limit: usize) -> Result<(), EthereumDecodeError> {
    if bytes.first() == Some(&0) {
        return Err(EthereumDecodeError::NonCanonicalInteger);
    }
    if bytes.len() > limit {
        return Err(EthereumDecodeError::IntegerOverflow);
    }
    Ok(())
}
fn minimal_bytes(bytes: &[u8]) -> &[u8] {
    &bytes[bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len())..]
}
fn encode_length(length: usize, offset: u8, output: &mut Vec<u8>) {
    if length < 56 {
        output.push(offset + length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let bytes = minimal_bytes(&bytes);
        output.push(offset + 55 + bytes.len() as u8);
        output.extend_from_slice(bytes);
    }
}
fn encode_bytes(bytes: &[u8], output: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        output.push(bytes[0]);
    } else {
        encode_length(bytes.len(), 0x80, output);
        output.extend_from_slice(bytes);
    }
}
fn item(raw: &[u8]) -> Result<(&[u8], usize, bool), EthereumDecodeError> {
    let prefix = *raw.first().ok_or(EthereumDecodeError::InvalidRlp)?;
    if prefix < 0x80 {
        return Ok((&raw[..1], 1, false));
    }
    let is_list = prefix >= 0xc0;
    let base = if is_list { 0xc0 } else { 0x80 };
    let short = prefix - base;
    let (start, length) = if short <= 55 {
        (1, usize::from(short))
    } else {
        let width = usize::from(short - 55);
        let bytes = raw
            .get(1..1 + width)
            .ok_or(EthereumDecodeError::InvalidRlp)?;
        if bytes[0] == 0 || width > std::mem::size_of::<usize>() {
            return Err(EthereumDecodeError::InvalidRlp);
        }
        let mut length = 0usize;
        for byte in bytes {
            length = length
                .checked_mul(256)
                .and_then(|v| v.checked_add(usize::from(*byte)))
                .ok_or(EthereumDecodeError::InvalidRlp)?;
        }
        if length < 56 {
            return Err(EthereumDecodeError::InvalidRlp);
        }
        (1 + width, length)
    };
    let end = start
        .checked_add(length)
        .ok_or(EthereumDecodeError::InvalidRlp)?;
    let payload = raw.get(start..end).ok_or(EthereumDecodeError::InvalidRlp)?;
    if !is_list && length == 1 && payload[0] < 0x80 {
        return Err(EthereumDecodeError::InvalidRlp);
    }
    Ok((payload, end, is_list))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    const EIP155_VECTOR: &str = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    #[test]
    fn published_eip155_vector_and_exact_native_accounting() {
        let tx = decode_eip155(&hex(EIP155_VECTOR), 1).unwrap();
        assert_eq!(
            tx.signing_hash.as_slice(),
            hex("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")
        );
        assert_eq!(tx.recipient, Some([0x35; 20]));
        let terms = tx
            .validate_execution_limits(9, 21_000, 30_000_000, 1)
            .unwrap();
        assert_eq!(terms.value_nwei, 1_000_000_000);
        assert_eq!(terms.gas_price_nwei, 20);
        assert_eq!(terms.maximum_fee_nwei, 420_000);
        assert_eq!(terms.maximum_debit_nwei, 1_000_420_000);
        assert_eq!(
            decode_eip155(&hex(EIP155_VECTOR), 1266),
            Err(EthereumDecodeError::WrongChain)
        );
    }
    #[test]
    fn rejects_replayable_and_unsupported_envelopes() {
        let mut raw = hex(EIP155_VECTOR);
        let index = raw.iter().position(|b| *b == 0x25).unwrap();
        for v in [27, 28] {
            raw[index] = v;
            assert_eq!(
                decode_eip155(&raw, 1),
                Err(EthereumDecodeError::UnprotectedSignature)
            );
        }
        for envelope in [0, 1, 2, 3, 4, 0x80] {
            assert_eq!(
                decode_eip155(&[envelope], 1),
                Err(EthereumDecodeError::UnsupportedEnvelope)
            );
        }
    }
    #[test]
    fn rejects_noncanonical_rlp_lengths_integers_truncation_and_trailing_data() {
        for raw in [
            vec![0x81, 1],
            vec![0xb8, 1, 0x80],
            vec![0xf8, 1, 0x80],
            vec![0xb9, 0, 56],
        ] {
            assert!(item(&raw).is_err());
        }
        let raw = hex(EIP155_VECTOR);
        for length in 0..raw.len() {
            assert!(decode_eip155(&raw[..length], 1).is_err());
        }
        let mut extra = raw.clone();
        extra.push(0);
        assert!(decode_eip155(&extra, 1).is_err());
        let mut zero_nonce = raw;
        zero_nonce[2] = 0;
        assert_eq!(
            decode_eip155(&zero_nonce, 1),
            Err(EthereumDecodeError::NonCanonicalInteger)
        );
        assert_eq!(
            decode_eip155(&vec![0xff; MAX_LEGACY_TRANSACTION_BYTES + 1], 1),
            Err(EthereumDecodeError::SizeLimit)
        );
    }
    #[test]
    fn denomination_roundtrip_has_no_rounding_or_uint128_overflow() {
        for amount in [
            0,
            1,
            999_999_999,
            1_000_000_000,
            u64::MAX as u128,
            u128::MAX,
        ] {
            assert_eq!(wei_to_nwei(nwei_to_wei(amount)), Ok(amount));
        }
        let mut fractional = nwei_to_wei(1);
        fractional[31] += 1;
        assert_eq!(
            wei_to_nwei(fractional),
            Err(EthereumDecodeError::SubNativePrecision)
        );
        let mut overflow = [0; 32];
        overflow[0] = 1;
        // A multiple of 1e9 greater than the native balance bound.
        let mut larger_native = [0; 32];
        larger_native[12..16].copy_from_slice(&(WEI_PER_NWEI as u32).to_be_bytes());
        assert_eq!(
            wei_to_nwei(larger_native),
            Err(EthereumDecodeError::IntegerOverflow)
        );
        assert!(wei_to_nwei(overflow).is_err());
    }
    #[test]
    fn nonce_fee_and_gas_are_checked_without_mutating_state() {
        let mut tx = decode_eip155(&hex(EIP155_VECTOR), 1).unwrap();
        assert_eq!(
            tx.validate_execution_limits(8, 21_000, 30_000_000, 1),
            Err(EthereumDecodeError::InvalidNonce)
        );
        assert_eq!(
            tx.validate_execution_limits(9, 21_001, 30_000_000, 1),
            Err(EthereumDecodeError::InvalidGasLimit)
        );
        assert_eq!(
            tx.validate_execution_limits(9, 21_000, 20_000, 1),
            Err(EthereumDecodeError::InvalidGasLimit)
        );
        assert_eq!(
            tx.validate_execution_limits(9, 21_000, 30_000_000, 21),
            Err(EthereumDecodeError::FeeCapTooLow)
        );
        tx.value_wei = nwei_to_wei(u128::MAX);
        assert_eq!(tx.native_terms(), Err(EthereumDecodeError::IntegerOverflow));
    }

    #[test]
    fn replacement_chain_9969_rejects_legacy_canary_and_mainnet_domains() {
        for chain in [9969u64, 1266, 99999, 469] {
            let fields: [&[u8]; 6] = [&[], &[1], &[0x52, 0x08], &[0x35; 20], &[], &[]];
            let mut payload = Vec::new();
            for field in fields {
                encode_bytes(field, &mut payload);
            }
            let v = (u128::from(chain) * 2 + 35).to_be_bytes();
            encode_bytes(minimal_bytes(&v), &mut payload);
            encode_bytes(&[1], &mut payload);
            encode_bytes(&[1], &mut payload);
            let mut raw = Vec::new();
            encode_length(payload.len(), 0xc0, &mut raw);
            raw.extend_from_slice(&payload);
            let result = decode_eip155(&raw, 9969);
            if chain == 9969 {
                assert_eq!(result.unwrap().chain_id, 9969);
            } else {
                assert_eq!(result, Err(EthereumDecodeError::WrongChain));
            }
        }
    }
}
