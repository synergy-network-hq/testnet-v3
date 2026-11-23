//! Prepare the published Wallet release bytes for an independent owner signer.
//!
//! The report's key and chain context identify the requested authorization.
//! Sign the entire transcript file with pure ML-DSA-65 and an empty FIPS
//! context. Use the reported SHA-256 to identify the file.
//! Managed native preflight authenticates the assembled attachment.
use serde::Deserialize;
use std::path::Path;
use synergy_aegis::{
    AegisProtectedPrimitives, KeyId, NativeVerificationQualification, SignatureAlgorithm,
    SignedNativeVerificationQualification, SigningContext,
};
use synergy_etdag::EtdagParameters;
use synergy_genesis::authority::{
    SignedWalletDispatchRelease, WalletDispatchReleaseIssuerAuthorization,
    WalletDispatchReleasePayload, WALLET_RELEASE_ISSUER_DOMAIN,
};
use synergy_genesis::builder::UnsignedGenesis;
use synergy_posy::SimplifiedEpochContext;

pub(super) const USAGE: &str = "synergy-genesis wallet-release-transcript REQUEST_JSON OUTPUT\nsynergy-genesis wallet-release-attach-signature REQUEST_JSON DETACHED_ML_DSA_65_SIGNATURE OUTPUT";
const MAX_REQUEST: u64 = super::MAX_GENESIS_BYTES + 32 * 1024;
const SIGNATURE_BYTES: usize = 3309;

#[cfg(test)]
mod tests;

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Dispatch {
        payload: WalletDispatchReleasePayload,
        predecessor: Box<SimplifiedEpochContext>,
        parameters: EtdagParameters,
    },
    IssuerDelegation {
        origin: Box<UnsignedGenesis>,
        authorization: WalletDispatchReleaseIssuerAuthorization,
    },
    NativeVerificationQualification {
        payload: WalletDispatchReleasePayload,
        qualification: NativeVerificationQualification,
    },
}

impl Request {
    fn signing_input(&self) -> Result<(KeyId, SigningContext, Vec<u8>), String> {
        let (key, context, bytes) = match self {
            Self::Dispatch {
                payload,
                predecessor,
                parameters,
            } => {
                parameters
                    .validate()
                    .map_err(|error| format!("protected parameters: {error:?}"))?;
                payload.check_predecessor(predecessor, parameters)?;
                (
                    &payload.signer_key_id,
                    payload.signing_context(predecessor)?,
                    payload.signing_bytes()?,
                )
            }
            Self::IssuerDelegation {
                origin,
                authorization,
            } => {
                if !authorization.signature.is_empty()
                    || authorization.genesis_hash != origin.genesis_hash()?
                {
                    return Err("unsigned issuer delegation must match its Genesis preimage".into());
                }
                (
                    &origin.authority_trust_key_id,
                    SigningContext {
                        domain: WALLET_RELEASE_ISSUER_DOMAIN.into(),
                        chain_id: origin.network.chain_id,
                        epoch: None,
                        height: None,
                    },
                    authorization.signing_bytes()?,
                )
            }
            Self::NativeVerificationQualification {
                payload,
                qualification,
            } => {
                if qualification.release_context != payload.release_context()?
                    || qualification.release_attestation_sha256
                        != synergy_posy::parse_hash_bytes(
                            &payload.policy.release_attestation_sha256,
                        )
                        .map_err(|e| e.to_string())?
                    || !payload
                        .policy
                        .enrollment_proof_provider_artifacts
                        .iter()
                        .any(|pin| {
                            synergy_posy::parse_hash_bytes(pin)
                                .is_ok_and(|pin| pin == qualification.artifact_sha256)
                        })
                {
                    return Err(
                        "native verification qualification differs from exact Wallet release"
                            .into(),
                    );
                }
                let bytes = qualification.signing_bytes().map_err(|e| e.to_string())?;
                let separator = bytes
                    .iter()
                    .position(|&byte| byte == 0)
                    .ok_or("native qualification transcript lacks domain")?;
                let domain = std::str::from_utf8(&bytes[..separator]).map_err(|e| e.to_string())?;
                (
                    &payload.signer_key_id,
                    SigningContext {
                        domain: domain.into(),
                        chain_id: payload.policy.chain_id,
                        epoch: None,
                        height: Some(payload.policy.activation_finalized_height),
                    },
                    bytes,
                )
            }
        };
        context.validate().map_err(|e| e.to_string())?;
        Ok((KeyId::new(key).map_err(|e| e.to_string())?, context, bytes))
    }

    fn attach_signature(self, signature: Vec<u8>) -> Result<Vec<u8>, String> {
        if signature.len() != SIGNATURE_BYTES || signature.iter().all(|&byte| byte == 0) {
            return Err("expected one detached 3309-byte ML-DSA-65 signature".into());
        }
        match self {
            Self::Dispatch { payload, .. } => serde_json::to_vec(&SignedWalletDispatchRelease {
                payload,
                signature_algorithm: SignatureAlgorithm::MlDsa65,
                signature,
            }),
            Self::IssuerDelegation { authorization, .. } => {
                serde_json::to_vec(&WalletDispatchReleaseIssuerAuthorization {
                    signature,
                    ..authorization
                })
            }
            Self::NativeVerificationQualification { qualification, .. } => {
                serde_json::to_vec(&SignedNativeVerificationQualification {
                    qualification,
                    signature,
                })
            }
        }
        .map_err(|e| e.to_string())
    }
}

pub(super) fn run(request: &str, signature: Option<&str>, output: &str) -> Result<(), String> {
    if [Some(request), signature, Some(output)]
        .into_iter()
        .flatten()
        .any(|path| !Path::new(path).is_absolute())
    {
        return Err(
            "Wallet release signing inputs and output require explicit absolute paths".into(),
        );
    }
    let request: Request = super::decode(request, MAX_REQUEST)?;
    let (key, context, preimage) = request.signing_input()?;
    let bytes = match signature {
        Some(path) => {
            request.attach_signature(super::read_bounded(path, SIGNATURE_BYTES as u64)?)?
        }
        None => preimage,
    };
    let sha256: String = AegisProtectedPrimitives
        .sha256(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    super::write_new(output, &bytes)?;
    println!(
        "{}",
        serde_json::json!({
            "key_id": key.as_str(), "signing_context": context, "output_sha256": sha256,
            "signature_algorithm": SignatureAlgorithm::MlDsa65, "signature_mode": "pure_empty_fips_context",
            "artifact": if signature.is_none() { "signing_transcript" } else { "unverified_signed_attachment" },
        })
    );
    Ok(())
}
