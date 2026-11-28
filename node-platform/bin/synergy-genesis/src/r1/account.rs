//! Complete initial financial policy and external controller possession proofs.
//! The account PoP domain/profile/context are explicit engineering selections.
use super::policy::{CompletePolicy, IndexedProof, PolicyError};
use synergy_address_engine::apqe::{
    crypto_engine::CryptoEngine,
    native_identity_derivation_r1::{validate_received_identity, BirthBody},
    native_identity_presentation_r1::NativeIdentityPresentation,
    network_birth_r1::ProfileRef,
    provider::SignOptions,
    r1_framing::{self as c, NetworkRef, Value},
};
use synergy_protocol_types::c14n02::{Decoder, Encoder};
use synergy_state::r1::R1GenesisAccountPolicy;
pub const ACCOUNT_POP_CONTEXT: &[u8] = b"SYNERGY.ACCOUNT.POP.R1";
const MAX: usize = 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRecord {
    pub identity: String,
    pub birth_nonce: [u8; 32],
    pub policy: CompletePolicy,
    pub policy_epoch: u64,
    pub transaction_nonce: u64,
    pub enrollment_nonce: [u8; 32],
    pub possession_proofs: Vec<IndexedProof>,
}
impl AccountRecord {
    pub fn decode_from(d: &mut Decoder<'_>, n: NetworkRef) -> Result<Self, PolicyError> {
        let cv = |_| PolicyError::Encoding;
        let namespace = d.ascii(6).map_err(cv)?.to_owned();
        let raw = d.fixed::<48>().map_err(cv)?;
        let identity = NativeIdentityPresentation::from_raw(&namespace, raw)
            .map_err(|_| PolicyError::Identity)?
            .to_text();
        let record = Self {
            identity,
            birth_nonce: d.fixed().map_err(cv)?,
            policy: CompletePolicy::decode_from(d)?,
            policy_epoch: d.u64().map_err(cv)?,
            transaction_nonce: d.u64().map_err(cv)?,
            enrollment_nonce: d.fixed().map_err(cv)?,
            possession_proofs: super::policy::decode_proofs(d, 32)?,
        };
        record.validate_birth(n)?;
        Ok(record)
    }
    pub fn validate_birth(&self, n: NetworkRef) -> Result<NativeIdentityPresentation, PolicyError> {
        if self.birth_nonce == [0; 32]
            || self.enrollment_nonce == [0; 32]
            || self.policy_epoch != 1
            || self.transaction_nonce != 0
            || !matches!(
                self.policy.namespace.as_str(),
                "synw" | "syns" | "syna" | "synm" | "synu"
            )
        {
            return Err(PolicyError::Policy);
        }
        if matches!(self.policy.namespace.as_str(), "synm" | "synu")
            && self.policy.ordinary.threshold < 2
        {
            return Err(PolicyError::Policy);
        }
        let presentation = self.policy.with_apqe(|p| {
            validate_received_identity(
                &self.identity,
                n,
                &BirthBody::Account {
                    nonce32: &self.birth_nonce,
                    policy: p,
                },
                MAX,
            )
            .map_err(|_| PolicyError::Identity)
        })?;
        Ok(presentation)
    }
    pub fn possession_frame(&self, n: NetworkRef, index: u32) -> Result<Vec<u8>, PolicyError> {
        let id = self.validate_birth(n)?;
        let key = &self
            .policy
            .controllers
            .get(index as usize)
            .ok_or(PolicyError::Proof)?
            .key;
        let k = key.as_apqe()?;
        c::frame(
            "IDENTITY.ACCOUNT.POSSESSION",
            ProfileRef {
                name: "APQE-ACCOUNT-POSSESSION",
                revision: 1,
            },
            Some(n),
            Value::Array(vec![
                c::text(id.namespace()),
                c::bytes(id.raw48()),
                Value::Array(vec![
                    c::text(k.role),
                    c::text(k.algorithm),
                    Value::Unsigned(k.key_generation),
                    c::bytes(k.full_public_key),
                ]),
                c::bytes(&self.policy.commitment(n)?),
                c::bytes(&self.enrollment_nonce),
            ]),
            MAX,
        )
        .map_err(|_| PolicyError::Encoding)
    }
    pub fn verify(
        &self,
        n: NetworkRef,
        engine: &CryptoEngine,
    ) -> Result<R1GenesisAccountPolicy, PolicyError> {
        self.validate_birth(n)?;
        if self.possession_proofs.len() != self.policy.controllers.len() {
            return Err(PolicyError::Proof);
        }
        for (index, (controller, proof)) in self
            .policy
            .controllers
            .iter()
            .zip(&self.possession_proofs)
            .enumerate()
        {
            if proof.index as usize != index {
                return Err(PolicyError::Proof);
            }
            let expected = match controller.key.algorithm {
                synergy_address_engine::types::Algorithm::MlDsa65 => 3309,
                synergy_address_engine::types::Algorithm::MlDsa87 => 4627,
                _ => return Err(PolicyError::Key),
            };
            if proof.signature.len() != expected
                || !engine
                    .verify(
                        controller.key.algorithm,
                        &controller.key.public_key,
                        &self.possession_frame(n, proof.index)?,
                        &proof.signature,
                        SignOptions::Pure {
                            context: ACCOUNT_POP_CONTEXT,
                        },
                    )
                    .map_err(|_| PolicyError::Provider)?
            {
                return Err(PolicyError::Proof);
            }
        }
        Ok(R1GenesisAccountPolicy {
            identity: self.identity.clone(),
            birth_nonce32: self.birth_nonce,
            nonce: self.transaction_nonce,
            policy_epoch: self.policy_epoch,
            full_policy_frame: self.policy.frame(n)?,
            policy_commitment: self.policy.commitment(n)?,
        })
    }
    pub fn encode_into(&self, e: &mut Encoder, n: NetworkRef) -> Result<(), PolicyError> {
        let id = self.validate_birth(n)?;
        let cv = |_| PolicyError::Encoding;
        e.ascii(id.namespace(), 6).map_err(cv)?;
        e.fixed(id.raw48()).map_err(cv)?;
        e.fixed(&self.birth_nonce).map_err(cv)?;
        self.policy.encode_into(e)?;
        e.u64(self.policy_epoch).map_err(cv)?;
        e.u64(self.transaction_nonce).map_err(cv)?;
        e.fixed(&self.enrollment_nonce).map_err(cv)?;
        super::policy::encode_proofs(e, &self.possession_proofs, 32)
    }
}
