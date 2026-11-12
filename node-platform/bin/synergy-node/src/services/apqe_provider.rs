//! Authenticated, explicitly selected APQE provider loading. No environment lookup.
use std::sync::{Arc, Mutex};
use synergy_address_engine::apqe::crypto_engine::CryptoEngine;
use synergy_aegis::{AegisPolicy, KeyId, PqvmSigner, PqvmVerifier};
use synergy_config::NodeConfiguration;

pub(crate) fn load(configuration: &NodeConfiguration) -> Result<Arc<Mutex<CryptoEngine>>, String> {
    let selected = configuration.aegis_provider.as_ref().ok_or("explicit authenticated aegis_provider configuration is required; embedded crypto is unavailable in this production caller")?;
    load_selected(selected)
}
pub(crate) fn load_selected(
    selected: &synergy_config::ApqeProviderConfiguration,
) -> Result<Arc<Mutex<CryptoEngine>>, String> {
    synergy_aegis::load_authenticated_native_engine(
        &selected.report_path,
        &selected.authenticated_report_sha256,
    )
}
pub(crate) fn verifier(
    configuration: &NodeConfiguration,
    policy: AegisPolicy,
) -> Result<PqvmVerifier, String> {
    #[cfg(test)]
    if configuration.aegis_provider.is_none() {
        return PqvmVerifier::new(policy).map_err(|e| e.to_string());
    }
    PqvmVerifier::with_apqe(policy, load(configuration)?).map_err(|e| e.to_string())
}
pub(crate) fn signer(
    configuration: &NodeConfiguration,
    policy: AegisPolicy,
    key_id: KeyId,
    public: &[u8],
    secret: Vec<u8>,
) -> Result<PqvmSigner, String> {
    #[cfg(test)]
    if configuration.aegis_provider.is_none() {
        return PqvmSigner::from_secret_key_bytes(policy, key_id, secret)
            .map_err(|e| e.to_string());
    }
    let engine = match load(configuration) {
        Ok(engine) => engine,
        Err(error) => {
            drop(synergy_address_engine::apqe::SecretBytes::from_bytes(
                secret,
            ));
            return Err(error);
        }
    };
    PqvmSigner::with_apqe(policy, key_id, public, secret, engine).map_err(|e| e.to_string())
}

pub(crate) fn identity_verifier(
    configuration: &NodeConfiguration,
) -> Result<Option<synergy_aegis::ApqeIdentityVerifier>, String> {
    #[cfg(test)]
    if configuration.aegis_provider.is_none() {
        return Ok(None);
    }
    synergy_aegis::ApqeIdentityVerifier::new(load(configuration)?).map(Some)
}

/// Open custody inputs by descriptor and enforce private ownership before reading.
fn custody_file(path: &std::path::Path, maximum: u64, private: bool) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let before =
        std::fs::symlink_metadata(path).map_err(|e| format!("inspect custody input: {e}"))?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.len() == 0
        || before.len() > maximum
    {
        return Err("custody input must be bounded regular non-symlink file".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .map_err(|e| format!("open custody input: {e}"))?;
    let opened = file
        .metadata()
        .map_err(|e| format!("inspect opened custody input: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || (private
                && (opened.permissions().mode() & 0o077 != 0
                    || opened.uid() != unsafe { libc::geteuid() }))
        {
            return Err("custody input changed or has unsafe ownership/permissions".into());
        }
    }
    if !opened.is_file() || opened.len() != before.len() {
        return Err("custody input changed shape".into());
    }
    let mut bytes = Vec::new();
    if let Err(error) = file.take(maximum + 1).read_to_end(&mut bytes) {
        drop(synergy_address_engine::apqe::SecretBytes::from_bytes(bytes));
        return Err(format!("read custody input: {error}"));
    }
    if bytes.len() as u64 != opened.len() {
        drop(synergy_address_engine::apqe::SecretBytes::from_bytes(bytes));
        return Err("custody input changed length".into());
    }
    Ok(bytes)
}

pub(super) struct CustodyInputs {
    pub request: synergy_address_engine::validator_provisioning::EnrollmentRequest,
    pub envelope: synergy_address_engine::encrypt::EncryptedEnvelope,
    pub network: synergy_address_engine::validator_provisioning::NetworkBinding,
    passphrase: synergy_address_engine::apqe::SecretBytes,
}
impl CustodyInputs {
    pub fn passphrase(&self) -> Result<&str, String> {
        std::str::from_utf8(self.passphrase.as_bytes())
            .map_err(|_| "custody unlock input is not UTF8".into())
    }
}
pub(super) fn custody_inputs(
    configuration: &NodeConfiguration,
    authority: &super::authority::VerifiedAuthority,
) -> Result<CustodyInputs, String> {
    let selected = configuration
        .apqe_transport
        .as_ref()
        .ok_or("explicit canary custody configuration required")?;
    let (_, network) =
        crate::commands::selected_network::verify_with_custody_binding(configuration)?;
    if configuration.chain_id != authority.epoch.chain_id
        || configuration.network_id != authority.epoch.network_id
    {
        return Err("custody configuration differs from authenticated authority".into());
    }
    let request =
        serde_json::from_slice(&custody_file(&selected.enrollment_path, 128 * 1024, false)?)
            .map_err(|_| "invalid validator enrollment")?;
    let envelope = serde_json::from_slice(&custody_file(&selected.custody_path, 256 * 1024, true)?)
        .map_err(|_| "invalid encrypted validator custody")?;
    let passphrase = synergy_address_engine::apqe::SecretBytes::from_bytes(custody_file(
        &selected.custody_unlock_path,
        4096,
        true,
    )?);
    Ok(CustodyInputs {
        request,
        envelope,
        network,
        passphrase,
    })
}

struct OpaqueConsensusSigner {
    key_id: KeyId,
    chain_id: u64,
    epoch: u64,
    policy: AegisPolicy,
    engine: Arc<Mutex<CryptoEngine>>,
    handle: synergy_address_engine::validator_provisioning::ConsensusCustodyHandle,
}
impl synergy_aegis::AegisSigner for OpaqueConsensusSigner {
    fn sign(
        &self,
        key_id: &KeyId,
        context: &synergy_aegis::SigningContext,
        message: &[u8],
    ) -> Result<synergy_aegis::Signature, synergy_aegis::SigningError> {
        use synergy_aegis::{Signature, SignatureAlgorithm, SigningError};
        context.validate()?;
        if key_id != &self.key_id
            || context.chain_id != self.chain_id
            || context.epoch != Some(self.epoch)
        {
            return Err(SigningError::InvalidContext);
        }
        self.policy
            .authorize(SignatureAlgorithm::MlDsa65, message.len(), 0)
            .map_err(SigningError::Policy)?;
        let engine = self
            .engine
            .try_lock()
            .map_err(|_| SigningError::Provider("custody provider busy or poisoned".into()))?;
        let bytes = self
            .handle
            .sign_canonical(&engine, message)
            .map_err(|e| SigningError::Provider(e.to_string()))?;
        self.policy
            .authorize(SignatureAlgorithm::MlDsa65, message.len(), bytes.len())
            .map_err(SigningError::Policy)?;
        Ok(Signature {
            algorithm: SignatureAlgorithm::MlDsa65,
            key_id: key_id.clone(),
            bytes,
        })
    }
}
pub(super) fn consensus_signer(
    configuration: &NodeConfiguration,
    authority: &super::authority::VerifiedAuthority,
    validator: &str,
    policy: AegisPolicy,
) -> Result<Arc<dyn synergy_aegis::AegisSigner>, String> {
    let inputs = custody_inputs(configuration, authority)?;
    if inputs.request.payload.identity.address != validator {
        return Err("validator custody belongs to another node".into());
    }
    let (key_id, public) = authority.consensus_binding(validator)?;
    let engine = load(configuration)?;
    let handle = {
        let guard = engine
            .try_lock()
            .map_err(|_| "custody provider busy or poisoned")?;
        synergy_address_engine::validator_provisioning::unlock_consensus_custody(
            &guard,
            &inputs.request,
            &inputs.network,
            &inputs.envelope,
            inputs.passphrase()?,
            synergy_address_engine::validator_provisioning::CustodyRole::ConsensusMlDsa65,
            public,
        )
        .map_err(|e| e.to_string())?
    };
    Ok(Arc::new(OpaqueConsensusSigner {
        key_id: KeyId::new(key_id.to_owned()).map_err(|e| e.to_string())?,
        chain_id: configuration.chain_id,
        epoch: authority.epoch.epoch,
        policy,
        engine,
        handle,
    }))
}

struct OpaqueIngressKem {
    engine: Arc<Mutex<CryptoEngine>>,
    handle: synergy_address_engine::validator_provisioning::IngressCustodyHandle,
}
impl synergy_aegis::AegisKem for OpaqueIngressKem {
    fn algorithm(&self) -> &'static str {
        "ML-KEM-1024"
    }
    fn encapsulate(
        &self,
        public_key: &[u8],
    ) -> Result<synergy_aegis::KemEncapsulation, synergy_aegis::KemError> {
        if public_key != self.handle.public_key() {
            return Err(synergy_aegis::KemError::InvalidPublicKey);
        }
        let engine = self
            .engine
            .try_lock()
            .map_err(|_| synergy_aegis::KemError::ProviderUnavailable)?;
        let value = engine
            .kem_encapsulate(
                synergy_address_engine::types::Algorithm::MlKem1024,
                public_key,
            )
            .map_err(|_| synergy_aegis::KemError::ProviderUnavailable)?;
        Ok(synergy_aegis::KemEncapsulation {
            ciphertext: value.ciphertext,
            shared_secret: value.shared_secret.as_bytes().to_vec(),
        })
    }
    fn decapsulate(
        &self,
        ciphertext: &[u8],
        secret_key: &[u8],
    ) -> Result<Vec<u8>, synergy_aegis::KemError> {
        // The canonical capsule API retains a secret parameter for legacy owners;
        // opaque custody permits only an empty sentinel, never a substituted key.
        if !secret_key.is_empty() {
            return Err(synergy_aegis::KemError::InvalidSecretKey);
        }
        let engine = self
            .engine
            .try_lock()
            .map_err(|_| synergy_aegis::KemError::ProviderUnavailable)?;
        self.handle
            .decapsulate(&engine, ciphertext)
            .map(|v| v.as_bytes().to_vec())
            .map_err(|_| synergy_aegis::KemError::ProviderUnavailable)
    }
}
pub(super) fn ingress_kem(
    configuration: &NodeConfiguration,
    authority: &super::authority::VerifiedAuthority,
    validator: &str,
) -> Result<Arc<dyn synergy_aegis::AegisKem>, String> {
    let inputs = custody_inputs(configuration, authority)?;
    if inputs.request.payload.identity.address != validator {
        return Err("ingress custody belongs to another validator".into());
    }
    authority.consensus_binding(validator)?; // active frozen membership is mandatory
    let registry = authority.protected_ingress_registry()?;
    registry
        .validate_protected_profile()
        .map_err(|e| format!("invalid ingress registry: {e:?}"))?;
    let public = synergy_address_engine::snts07::decode_lower_hex(
        "ingress public",
        &inputs.request.payload.ingress_key.public_key,
        1568,
    )?;
    let matching: Vec<_> = registry
        .records
        .iter()
        .filter(|record| record.validator_id == validator && record.public_key.public_key == public)
        .collect();
    if matching.len() != 1 {
        return Err("custody ingress key lacks unique governed validator binding".into());
    }
    let engine = load(configuration)?;
    let handle = {
        let guard = engine
            .try_lock()
            .map_err(|_| "ingress provider busy or poisoned")?;
        synergy_address_engine::validator_provisioning::unlock_ingress_custody(
            &guard,
            &inputs.request,
            &inputs.network,
            &inputs.envelope,
            inputs.passphrase()?,
            &public,
        )
        .map_err(|e| e.to_string())?
    };
    Ok(Arc::new(OpaqueIngressKem { engine, handle }))
}
