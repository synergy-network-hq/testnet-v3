//! Author the exact Wallet issuer delegation using the original formation key.
use super::*;
use std::path::PathBuf;
use synergy_address_engine::apqe::{
    enrollment_registry::EnrollmentRegistryReleaseIssuer,
    provider::{SignedNativeVerificationQualification, VerifiedNativeVerificationQualification},
};
use synergy_etdag::EtdagParameters;
use synergy_genesis::authority::{
    VerifiedWalletDispatchRelease, WalletDispatchReleaseIssuerAuthorization,
    WalletDispatchReleaseIssuerTrust, WalletDispatchReleaseTrust, WALLET_RELEASE_ISSUER_DOMAIN,
};
use synergy_posy::{FrozenValidatorRegistry, SimplifiedEpochContext};

const ACTION: &str = "wallet_release_delegate_issuer";
const RESERVATIONS: &str = "wallet-release-issuer-delegations";
const AUTHORIZATION_FILE: &str = "wallet-dispatch-release-issuer-authorization.json";
const QUALIFICATION_FILE: &str = "wallet-dispatch-ml-dsa-87-qualification.json";
const APPROVED_REQUEST: &str = "approved-request.sha256";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewParameters {
    formation_sha256: String,
    formation_review_sha256: String,
    genesis_sha256: String,
    authority_sha256: String,
    authority_root_sha256: String,
    attachment_sha256: String,
    issuer_sha256: String,
    issuer_key_id: String,
    qualification_sha256: String,
    managed_release_manifest_sha256: String,
    off_chain_approval_sha256: String,
    release_attestation_sha256: String,
    predecessor: SimplifiedEpochContext,
    parameters: EtdagParameters,
}

pub(crate) struct Inputs<'a> {
    pub(crate) context: &'a Path,
    pub(crate) formation_sha256: &'a str,
    pub(crate) formation: &'a Path,
    pub(crate) reviewed: &'a Path,
    pub(crate) request: &'a Path,
    pub(crate) request_sha256: &'a str,
    pub(crate) provider_report_sha256: &'a str,
}

fn parse_digest(value: &str) -> Result<[u8; 32], String> {
    if !pin(value) || !value.bytes().any(|byte| byte != b'0') {
        return Err("Nonzero canonical Wallet release approval digest required".into());
    }
    synergy_posy::parse_hash_bytes(value).map_err(|error| error.to_string())
}

fn pinned_artifact(
    directory: &Path,
    name: &str,
    limit: u64,
    approved: &str,
) -> Result<SecretBytes, String> {
    parse_digest(approved)?;
    let raw = read(&directory.join(name), limit, false)?;
    if digest(raw.as_bytes()) != approved {
        return Err(format!("Reviewed Wallet release artifact changed: {name}"));
    }
    Ok(raw)
}

fn require_scope(
    prepared: &Prepared,
    signed: &SignedFormation,
    selection: &ReviewParameters,
    input: &Inputs<'_>,
) -> Result<(), String> {
    if selection.formation_sha256 != input.formation_sha256
        || selection.formation_review_sha256 != prepared.review_pin
        || selection.genesis_sha256 != digest(signed.genesis_bytes.as_bytes())
        || selection.authority_sha256 != digest(signed.authority_bytes.as_bytes())
        || selection.authority_root_sha256 != prepared.review.authority_root_sha256
        || selection.predecessor.chain_id != signed.genesis.unsigned.network.chain_id
        || selection.predecessor.network_id != signed.genesis.unsigned.network.network_id
        || selection.predecessor.epoch < signed.authority.payload.epoch
        || !synergy_genesis::validate_autonomous_origin(
            &signed.genesis.unsigned,
            &signed.authority.payload,
        )?
    {
        return Err("Wallet delegation differs from the reviewed signed formation".into());
    }
    synergy_genesis::verify_binding_with_verifier(
        &signed.genesis,
        &prepared.public,
        &signed.authority,
        &crate::provider::verifier(policy(), Some(prepared.signer.clone()))?,
    )?;
    if selection.predecessor.epoch == signed.authority.payload.epoch {
        let a = &signed.authority.payload;
        let registry = FrozenValidatorRegistry::new(
            a.epoch,
            a.validators
                .iter()
                .map(|validator| validator.record.clone())
                .collect(),
        )
        .map_err(|error| error.to_string())?;
        let first_epoch = SimplifiedEpochContext::from_frozen_registry(
            a.chain_id,
            a.network_id.clone(),
            a.epoch,
            a.epoch_start_height,
            a.epoch_end_height,
            a.finalized_epoch_seed_root.clone(),
            a.consensus_parameter_root.clone(),
            &registry,
        )
        .map_err(|error| error.to_string())?;
        let original = a
            .protected
            .as_ref()
            .ok_or("Signed origin omits protected processing parameters")?;
        if selection.predecessor != first_epoch || selection.parameters != original.parameters {
            return Err("E1 release predecessor differs from the signed origin".into());
        }
    }
    Ok(())
}

fn present(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("Cannot inspect Wallet issuer delegation state".into()),
    }
}

fn reserve(formation: &Path, attachment_sha256: &str) -> Result<(PathBuf, bool), String> {
    let parent = formation.join(RESERVATIONS);
    if !present(&parent)? {
        // Concurrent first requests may race to create the shared private parent.
        if let Err(error) = begin(&parent) {
            if !present(&parent)? {
                return Err(error);
            }
        }
    }
    private_dir(&parent)?;
    sync(formation)?;
    let slot = parent.join(attachment_sha256);
    if present(&slot)? {
        private_dir(&slot)?;
        return Ok((slot, false));
    }
    begin(&slot)?;
    Ok((slot, true))
}

struct VerifiedDossier {
    prepared: Prepared,
    signed: SignedFormation,
    selection: ReviewParameters,
    attachment: SecretBytes,
    issuer: SecretBytes,
    issuer_id: KeyId,
    verifier_artifact: [u8; 32],
}

fn verify_dossier(
    input: &Inputs<'_>,
    engine: crate::provider::Engine,
) -> Result<VerifiedDossier, String> {
    private_dir(input.reviewed)?;
    if input.reviewed.starts_with(input.formation) || input.formation.starts_with(input.reviewed) {
        return Err("Review inputs must be separate from formation custody".into());
    }
    let (request, _) =
        exact_request::<ReviewParameters>(input.request, input.request_sha256, ACTION)?;
    let selection = request.parameters;
    let parsed_attestation = parse_digest(&selection.release_attestation_sha256)?;
    parse_digest(&selection.off_chain_approval_sha256)?;
    let report_digest = parse_digest(input.provider_report_sha256)?;
    let prepared = load(
        input.context,
        input.formation_sha256,
        input.formation,
        engine.clone(),
    )?;
    let signed = prepared
        .read_signed_formation(input.formation)?
        .ok_or("Original formation must be signed before Wallet delegation")?;
    require_scope(&prepared, &signed, &selection, input)?;
    let attachment = pinned_artifact(
        input.reviewed,
        "wallet-dispatch-release.json",
        32 * 1024,
        &selection.attachment_sha256,
    )?;
    let issuer = pinned_artifact(
        input.reviewed,
        "wallet-dispatch-release-issuer.pub",
        1952,
        &selection.issuer_sha256,
    )?;
    let qualification = pinned_artifact(
        input.reviewed,
        QUALIFICATION_FILE,
        24 * 1024,
        &selection.qualification_sha256,
    )?;
    let managed = pinned_artifact(
        input.reviewed,
        "wallet-dispatch-managed-artifacts.json",
        8 * 1024,
        &selection.managed_release_manifest_sha256,
    )?;
    let issuer_id = KeyId::new(&selection.issuer_key_id).map_err(|error| error.to_string())?;
    if issuer_id.as_str() == prepared.review.key_id
        || issuer.as_bytes() == prepared.public.as_slice()
    {
        return Err("Wallet release requires separate issuer and origin authority keys".into());
    }
    let verifier_artifact = engine
        .lock()
        .map_err(|_| "APQE provider unavailable")?
        .provider_provenance(Algorithm::MlDsa65)
        .map_err(|error| error.to_string())?
        .artifact_sha256;
    let dossier = VerifiedDossier {
        prepared,
        signed,
        selection,
        attachment,
        issuer,
        issuer_id,
        verifier_artifact,
    };
    {
        let guard = engine.lock().map_err(|_| "APQE provider unavailable")?;
        let release = VerifiedWalletDispatchRelease::verify(
            dossier.attachment.as_bytes(),
            &dossier.trust(),
            &dossier.selection.predecessor,
            &dossier.selection.parameters,
            &guard,
        )?;
        VerifiedNativeVerificationQualification::verify(
            qualification.as_bytes(),
            release.enrollment(),
            &EnrollmentRegistryReleaseIssuer {
                public_key: dossier.issuer.as_bytes(),
                verifier_artifact_sha256: verifier_artifact,
            },
            &guard,
            report_digest,
            parsed_attestation,
        )
        .map_err(|error| format!("Wallet release qualification: {error}"))?;
    }
    let index: Value = decode(&managed)?;
    let native: SignedNativeVerificationQualification = decode(&qualification)?;
    let genesis = &dossier.signed.genesis;
    if index["version"] != 1
        || index["chain_id"] != genesis.unsigned.network.chain_id
        || index["network_id"] != genesis.unsigned.network.network_id
        || index["genesis_hash"] != genesis.genesis_hash
        || !index["platforms"].as_array().is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry["target"] == native.qualification.target
                    && entry["apqe_report_sha256"] == input.provider_report_sha256
            })
        })
    {
        return Err(
            "Reviewed Wallet release artifact index differs from this qualified target".into(),
        );
    }
    Ok(dossier)
}

impl VerifiedDossier {
    fn trust(&self) -> WalletDispatchReleaseTrust<'_> {
        WalletDispatchReleaseTrust {
            genesis_hash: &self.signed.genesis.genesis_hash,
            release_signer_key_id: &self.issuer_id,
            release_signer_public_key: self.issuer.as_bytes(),
            release_verifier_artifact_sha256: self.verifier_artifact,
            managed_release_manifest_sha256: &self.selection.managed_release_manifest_sha256,
            off_chain_approval_sha256: &self.selection.off_chain_approval_sha256,
            release_attestation_sha256: &self.selection.release_attestation_sha256,
        }
    }

    fn verify_authorization(&self, contents: &[u8]) -> Result<(), String> {
        WalletDispatchReleaseIssuerAuthorization::verify(
            contents,
            self.attachment.as_bytes(),
            &self.trust(),
            &WalletDispatchReleaseIssuerTrust {
                origin: &self.signed.genesis,
                authority_public_key: &self.prepared.public,
                attachment_sha256: &self.selection.attachment_sha256,
                issuer_sha256: &self.selection.issuer_sha256,
            },
            &crate::provider::verifier(policy(), Some(self.prepared.signer.clone()))?,
        )
        .map(drop)
    }

    fn retained_authorization(
        &self,
        slot: &Path,
        request_sha256: &str,
    ) -> Result<Option<SecretBytes>, String> {
        let request_pin = slot.join(APPROVED_REQUEST);
        let authorization = slot.join(AUTHORIZATION_FILE);
        if !present(&request_pin)? {
            if present(&authorization)? {
                return Err("Retained Wallet authorization has no approved request binding".into());
            }
            return Ok(None);
        }
        if read(&request_pin, 64, true)?.as_bytes() != request_sha256.as_bytes() {
            return Err(
                "Wallet release issuer slot belongs to a different approved request".into(),
            );
        }
        if !present(&authorization)? {
            return Ok(None);
        }
        let retained = read(&authorization, 24 * 1024, true)?;
        self.verify_authorization(retained.as_bytes())?;
        Ok(Some(retained))
    }

    fn authorization_reply(
        &self,
        request_sha256: &str,
        authorization: &[u8],
    ) -> Result<Value, String> {
        Ok(json!({
            "schema":"nodenetwork-wallet-release-issuer-delegation-v1",
            "request_sha256":request_sha256, "genesis_hash":self.signed.genesis.genesis_hash,
            "attachment_sha256":self.selection.attachment_sha256, "issuer_sha256":self.selection.issuer_sha256,
            "authorization_sha256":digest(authorization),
            "authorization_json":std::str::from_utf8(authorization).map_err(|error| error.to_string())?,
        }))
    }
}

pub(crate) fn inspect(input: Inputs<'_>, engine: crate::provider::Engine) -> Result<Value, String> {
    let dossier = verify_dossier(&input, engine)?;
    let selection = &dossier.selection;
    let parent = input.formation.join(RESERVATIONS);
    if present(&parent)? {
        private_dir(&parent)?;
    }
    let slot = parent.join(&selection.attachment_sha256);
    let (state, delegation) = if present(&slot)? {
        private_dir(&slot)?;
        match dossier.retained_authorization(&slot, input.request_sha256)? {
            Some(raw) => (
                "signed",
                Some(dossier.authorization_reply(input.request_sha256, raw.as_bytes())?),
            ),
            None => ("interrupted", None),
        }
    } else {
        ("ready", None)
    };
    let genesis = &dossier.signed.genesis;
    Ok(json!({
        "schema":"nodenetwork-wallet-release-issuer-inspection-v1",
        "state":state,
        "request_sha256":input.request_sha256,
        "formation_sha256":selection.formation_sha256,
        "formation_review_sha256":selection.formation_review_sha256,
        "chain_id":genesis.unsigned.network.chain_id.to_string(),
        "network_id":genesis.unsigned.network.network_id,
        "genesis_hash":genesis.genesis_hash,
        "genesis_sha256":selection.genesis_sha256,
        "authority_sha256":selection.authority_sha256,
        "authority_root_sha256":selection.authority_root_sha256,
        "attachment_sha256":selection.attachment_sha256,
        "issuer_sha256":selection.issuer_sha256,
        "issuer_key_id":selection.issuer_key_id,
        "apqe_report_sha256":input.provider_report_sha256,
        "qualification_sha256":selection.qualification_sha256,
        "managed_release_manifest_sha256":selection.managed_release_manifest_sha256,
        "off_chain_approval_sha256":selection.off_chain_approval_sha256,
        "release_attestation_sha256":selection.release_attestation_sha256,
        "predecessor_context_root":selection.predecessor.root().map_err(|error|error.to_string())?,
        "predecessor_epoch":selection.predecessor.epoch,
        "predecessor_end_height":selection.predecessor.epoch_end_height,
        "delegation":delegation,
    }))
}

pub(crate) fn delegate(
    input: Inputs<'_>,
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    let dossier = verify_dossier(&input, engine)?;
    let selection = &dossier.selection;
    let signed = &dossier.signed;
    let prepared = &dossier.prepared;
    let key = prepared.read_custody(input.formation)?;
    let (slot, fresh) = reserve(input.formation, &selection.attachment_sha256)?;
    let authorization = if fresh {
        write(
            &slot.join(APPROVED_REQUEST),
            input.request_sha256.as_bytes(),
        )?;
        sync(&slot)?;
        let mut authorization = WalletDispatchReleaseIssuerAuthorization {
            version: 1,
            genesis_hash: signed.genesis.genesis_hash.clone(),
            attachment_sha256: selection.attachment_sha256.clone(),
            issuer_sha256: selection.issuer_sha256.clone(),
            issuer_key_id: selection.issuer_key_id.clone(),
            signature: Vec::new(),
        };
        let root_id = KeyId::new(&prepared.review.key_id).map_err(|error| error.to_string())?;
        authorization.signature = prepared
            .signer(&key)?
            .sign(
                &root_id,
                &SigningContext {
                    domain: WALLET_RELEASE_ISSUER_DOMAIN.into(),
                    chain_id: signed.genesis.unsigned.network.chain_id,
                    epoch: None,
                    height: None,
                },
                &authorization.signing_bytes()?,
            )
            .map_err(|error| error.to_string())?
            .bytes;
        let raw = serde_json::to_vec(&authorization).map_err(|error| error.to_string())?;
        dossier.verify_authorization(&raw)?;
        write(&slot.join(AUTHORIZATION_FILE), &raw)?;
        raw
    } else {
        let retained = dossier
            .retained_authorization(&slot, input.request_sha256)?
            .ok_or("Interrupted Wallet issuer delegation requires reconciliation")?;
        retained.as_bytes().to_vec()
    };
    sync(&slot)?;
    dossier.authorization_reply(input.request_sha256, &authorization)
}

#[cfg(test)]
pub(super) mod tests;
