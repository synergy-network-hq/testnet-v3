//! Ethereum interoperability verification through the existing APQE primitives.
//!
//! Recovery establishes an external signer only. It does not establish native
//! D/P authorization, protected-account spending rights, or finalized execution.
use synergy_address_engine::apqe::{HashAlgorithm, Primitives};

const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthereumAuthorizationError {
    InvalidChain,
    UnprotectedSignature,
    WrongChain,
    InvalidScalar,
    NoncanonicalSignature,
    InvalidSignature,
    Provider,
}
impl std::fmt::Display for EthereumAuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ethereum signer rejected: {self:?}")
    }
}
impl std::error::Error for EthereumAuthorizationError {}

/// An externally recovered signer, deliberately distinct from native protected
/// spending authorization. The caller must check finalized account policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEthereumSigner {
    chain_id: u64,
    account_id: [u8; 20],
    public_key: [u8; 65],
}
impl VerifiedEthereumSigner {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    pub fn account_id(&self) -> &[u8; 20] {
        &self.account_id
    }
    pub fn public_key(&self) -> &[u8; 65] {
        &self.public_key
    }
}

/// Strict replay-protected legacy transaction policy. Unprotected v=27/28,
/// bare recovery bits and chain zero are rejected. Widen before arithmetic so
/// every governed u64 chain ID can be represented without overflow.
pub fn eip155_recovery_parity(
    expected_chain_id: u64,
    v: u128,
) -> Result<u8, EthereumAuthorizationError> {
    if expected_chain_id == 0 {
        return Err(EthereumAuthorizationError::InvalidChain);
    }
    if v < 35 {
        return Err(EthereumAuthorizationError::UnprotectedSignature);
    }
    let adjusted = v - 35;
    if adjusted / 2 != u128::from(expected_chain_id) {
        return Err(EthereumAuthorizationError::WrongChain);
    }
    Ok((adjusted % 2) as u8)
}

/// Recover a canonical EIP-155 signer over the decoder's exact nine-field
/// signing prehash. The decoder must compute the prehash from the raw signed
/// transaction, not accept a client-supplied hash or claimed sender.
pub fn verify_eip155_signature(
    expected_chain_id: u64,
    signing_hash: &[u8; 32],
    v: u128,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<VerifiedEthereumSigner, EthereumAuthorizationError> {
    let parity = eip155_recovery_parity(expected_chain_id, v)?;
    if *r == [0; 32] || *r >= ORDER || *s == [0; 32] || *s >= ORDER {
        return Err(EthereumAuthorizationError::InvalidScalar);
    }
    // EIP-2 applies to transaction signatures, even when the provider's
    // ecrecover primitive also supports historical high-S signatures.
    if *s > HALF_ORDER {
        return Err(EthereumAuthorizationError::NoncanonicalSignature);
    }
    let mut signature = [0; 65];
    signature[..32].copy_from_slice(r);
    signature[32..64].copy_from_slice(s);
    signature[64] = parity;
    let public_key = Primitives
        .secp256k1_recover_prehash(signing_hash, &signature)
        .map_err(|_| EthereumAuthorizationError::InvalidSignature)?;
    let digest = Primitives
        .hash(HashAlgorithm::Keccak256, &public_key[1..])
        .map_err(|_| EthereumAuthorizationError::Provider)?;
    if digest.len() != 32 {
        return Err(EthereumAuthorizationError::Provider);
    }
    let mut account_id = [0; 20];
    account_id.copy_from_slice(&digest[12..]);
    Ok(VerifiedEthereumSigner {
        chain_id: expected_chain_id,
        account_id,
        public_key,
    })
}

/// Ethereum's contract ecrecover precompile accepts historical high-S values,
/// unlike transaction admission. Normalize the equivalent point/parity before
/// using the same APQE interoperability provider; this grants no native rights.
pub fn recover_ethereum_precompile(
    signature: &[u8; 64], parity: u8, digest: &[u8; 32],
) -> Result<[u8; 32], EthereumAuthorizationError> {
    let r: [u8;32] = signature[..32].try_into().unwrap();
    let s: [u8;32] = signature[32..].try_into().unwrap();
    if parity>1 || r==[0;32] || r>=ORDER || s==[0;32] || s>=ORDER {
        return Err(EthereumAuthorizationError::InvalidScalar);
    }
    let mut normalized=[0;65]; normalized[..64].copy_from_slice(signature);normalized[64]=parity;
    if s>HALF_ORDER {
        let mut borrow=0i16;
        for index in (0..32).rev() {
            let value=ORDER[index] as i16-s[index] as i16-borrow;
            normalized[32+index]=value.rem_euclid(256) as u8;borrow=i16::from(value<0);
        }
        normalized[64]^=1;
    }
    let point=Primitives.secp256k1_recover_prehash(digest,&normalized).map_err(|_|EthereumAuthorizationError::InvalidSignature)?;
    let hash=Primitives.hash(HashAlgorithm::Keccak256,&point[1..]).map_err(|_|EthereumAuthorizationError::Provider)?;
    if hash.len()!=32 {return Err(EthereumAuthorizationError::Provider);}
    let mut output=[0;32];output[12..].copy_from_slice(&hash[12..]);Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        std::array::from_fn(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap())
    }
    fn vector() -> ([u8; 32], [u8; 32], [u8; 32]) {
        // Independent published EIP-155 transaction example, chain 1.
        (
            hex("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"),
            hex("28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276"),
            hex("67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"),
        )
    }
    #[test]
    fn published_eip155_signature_recovers_original_external_account() {
        let (hash, r, s) = vector();
        let recovered = verify_eip155_signature(1, &hash, 37, &r, &s).unwrap();
        assert_eq!(recovered.chain_id(), 1);
        assert_eq!(
            *recovered.account_id(),
            hex("9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f")
        );
    }
    #[test]
    fn rejects_other_chain_and_unprotected_signatures_before_recovery() {
        let (hash, r, s) = vector();
        assert_eq!(
            verify_eip155_signature(1266, &hash, 37, &r, &s),
            Err(EthereumAuthorizationError::WrongChain)
        );
        for other_chain in [1266_u64, 99999, 469] {
            for parity in 0..2 {
                let v = u128::from(other_chain) * 2 + 35 + parity;
                assert_eq!(
                    verify_eip155_signature(9969, &hash, v, &r, &s),
                    Err(EthereumAuthorizationError::WrongChain)
                );
            }
        }
        for v in [0, 1, 27, 28, 34] {
            assert_eq!(
                verify_eip155_signature(1, &hash, v, &r, &s),
                Err(EthereumAuthorizationError::UnprotectedSignature)
            );
        }
        assert_eq!(
            eip155_recovery_parity(0, 35),
            Err(EthereumAuthorizationError::InvalidChain)
        );
        assert_eq!(
            eip155_recovery_parity(1, u128::MAX),
            Err(EthereumAuthorizationError::WrongChain)
        );
        for parity in 0..2 {
            assert_eq!(
                eip155_recovery_parity(u64::MAX, u128::from(u64::MAX) * 2 + 35 + parity),
                Ok(parity as u8)
            );
        }
    }
    #[test]
    fn rejects_high_s_malleation_and_out_of_range_scalars() {
        let (hash, r, s) = vector();
        assert_eq!(
            verify_eip155_signature(1, &hash, 37, &r, &ORDER),
            Err(EthereumAuthorizationError::InvalidScalar)
        );
        let mut high_s = HALF_ORDER;
        high_s[31] += 1;
        assert_eq!(
            verify_eip155_signature(1, &hash, 37, &r, &high_s),
            Err(EthereumAuthorizationError::NoncanonicalSignature)
        );
        assert_eq!(
            verify_eip155_signature(1, &hash, 37, &ORDER, &s),
            Err(EthereumAuthorizationError::InvalidScalar)
        );
        assert_eq!(
            verify_eip155_signature(1, &hash, 37, &[0; 32], &s),
            Err(EthereumAuthorizationError::InvalidScalar)
        );
        assert_eq!(
            verify_eip155_signature(1, &hash, 37, &r, &[0; 32]),
            Err(EthereumAuthorizationError::InvalidScalar)
        );
    }
    #[test]
    fn contract_ecrecover_preserves_historical_high_s_without_weakening_transaction_admission() {
        let (digest,r,s)=vector();let mut signature=[0;64];signature[..32].copy_from_slice(&r);signature[32..].copy_from_slice(&s);
        let low=recover_ethereum_precompile(&signature,0,&digest).unwrap();
        let mut borrow=0i16;for i in (0..32).rev(){let value=ORDER[i] as i16-s[i] as i16-borrow;signature[32+i]=value.rem_euclid(256) as u8;borrow=i16::from(value<0);}
        assert_eq!(recover_ethereum_precompile(&signature,1,&digest).unwrap(),low);
        assert!(matches!(verify_eip155_signature(1,&digest,38,&r,&signature[32..].try_into().unwrap()),Err(EthereumAuthorizationError::NoncanonicalSignature)));
        assert!(recover_ethereum_precompile(&signature,2,&digest).is_err());
    }
}
