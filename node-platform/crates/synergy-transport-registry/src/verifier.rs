//! Signed provider-snapshot verification.
//!
//! This boundary verifies transport artifacts only. It requires active
//! identities supplied by the membership owner, but cannot authorize, activate,
//! jail, or otherwise alter PoSy membership.

use crate::{OverlayScope, RegistryError, TransportRoute, VerifiedTransportRegistry};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use synergy_address_engine::apqe::crypto_engine::CryptoEngine;
use synergy_aegis::{
    AegisPolicy, AegisVerifier, KeyId, PqvmVerifier, Signature, SignatureAlgorithm, SigningContext,
};

pub const SNAPSHOT_VERSION: u32 = 2;
pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotTransport {
    pub validator_address: String,
    pub dial_address: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransportSnapshot {
    pub version: u32,
    pub network: String,
    pub registry_id: String,
    pub chain_id: u64,
    pub network_id: String,
    pub release_id: String,
    pub protocol_version: String,
    pub provider_plan_sha256: String,
    pub configuration_version: u64,
    pub transports: Vec<SnapshotTransport>,
    pub signature: String,
}
/// Expected tuple from the authenticated selected network, never the candidate snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotContext {
    pub network: String,
    pub registry_id: String,
    pub chain_id: u64,
    pub network_id: String,
    pub release_id: String,
    pub protocol_version: String,
}
#[derive(Clone)]
pub struct SnapshotTrust {
    verifying_key: Vec<u8>,
    verifier: PqvmVerifier,
    provider_plan_sha256: String,
    context: SnapshotContext,
}
#[derive(Debug, Clone)]
pub struct VerifiedSnapshot {
    registry_id: String,
    generation: u64,
    registry: VerifiedTransportRegistry,
}
impl VerifiedSnapshot {
    pub fn registry_id(&self) -> &str {
        &self.registry_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn registry(&self) -> &VerifiedTransportRegistry {
        &self.registry
    }
    #[cfg(test)]
    pub(crate) fn from_routes_for_test(generation: u64, routes: Vec<TransportRoute>) -> Self {
        Self {
            registry_id: "fixture-transport-v1".into(),
            generation,
            registry: VerifiedTransportRegistry::from_verified_snapshot(generation, routes)
                .unwrap(),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotInstall {
    pub generation: u64,
    pub changed: bool,
}
#[derive(Debug, Default, Clone)]
pub struct SnapshotAcceptance {
    current: Option<VerifiedSnapshot>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    InvalidDocument(String),
    InvalidSignature,
    Provider(String),
    Registry(RegistryError),
    Coverage(RegistryError),
    RegistryChanged,
    Rollback { received: u64, current: u64 },
    Equivocation { generation: u64 },
}
impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDocument(s) => write!(f, "invalid transport snapshot: {s}"),
            Self::Provider(message) => {
                write!(f, "native APQE registry provider unavailable: {message}")
            }
            Self::InvalidSignature => f.write_str("invalid validator transport snapshot signature"),
            Self::Registry(e) => write!(f, "invalid transport routes: {e:?}"),
            Self::Coverage(e) => write!(f, "incomplete transport coverage: {e:?}"),
            Self::RegistryChanged => f.write_str("transport registry id changed"),
            Self::Rollback { received, current } => {
                write!(f, "transport snapshot rollback: {received} < {current}")
            }
            Self::Equivocation { generation } => write!(
                f,
                "transport snapshot equivocation at generation {generation}"
            ),
        }
    }
}
impl std::error::Error for SnapshotError {}

impl SnapshotTrust {
    /// Constructs a pinned public trust root from the governed release
    /// configuration; a snapshot cannot select its own verifier.
    pub fn from_encoded(
        public_key: &str,
        provider_plan_sha256: String,
        context: SnapshotContext,
    ) -> Result<Self, SnapshotError> {
        let _ = (public_key, provider_plan_sha256, context);
        Err(SnapshotError::InvalidDocument("explicit authenticated APQE transport-registry provider required; classical trust is forbidden".into()))
    }

    pub fn from_encoded_with_provider(
        public_key: &str,
        provider_plan_sha256: String,
        context: SnapshotContext,
        engine: Arc<Mutex<CryptoEngine>>,
    ) -> Result<Self, SnapshotError> {
        let encoded = public_key.strip_prefix("ml-dsa-87:").ok_or_else(|| {
            SnapshotError::InvalidDocument(
                "native registry trust requires ML-DSA-87; classical algorithms are forbidden"
                    .into(),
            )
        })?;
        let verifying_key = general_purpose::STANDARD.decode(encoded).map_err(|_| {
            SnapshotError::InvalidDocument("invalid registry public key base64".into())
        })?;
        if verifying_key.len() != 2592 {
            return Err(SnapshotError::InvalidDocument(
                "ML-DSA-87 registry public key must be 2592 bytes".into(),
            ));
        }
        let verifier = PqvmVerifier::with_apqe(
            AegisPolicy {
                allowed_algorithms: vec![SignatureAlgorithm::MlDsa87],
                maximum_message_bytes: MAX_SNAPSHOT_BYTES,
                maximum_signature_bytes: 4627,
            },
            engine,
        )
        .map_err(|e| SnapshotError::InvalidDocument(e.to_string()))?;
        if context.chain_id == 0
            || [
                &context.network,
                &context.registry_id,
                &context.network_id,
                &context.release_id,
                &context.protocol_version,
            ]
            .iter()
            .any(|v| v.trim().is_empty() || v.len() > 256 || v.contains(char::is_control))
        {
            return Err(SnapshotError::InvalidDocument(
                "invalid selected transport context".into(),
            ));
        }
        if !lower_hex_64(&provider_plan_sha256) {
            return Err(SnapshotError::InvalidDocument(
                "provider-plan hash must be lowercase SHA-256".into(),
            ));
        }
        Ok(Self {
            verifying_key,
            verifier,
            provider_plan_sha256,
            context,
        })
    }
    pub fn verifying_key(&self) -> &[u8] {
        &self.verifying_key
    }
}

/// Parses a bounded JSON artifact and verifies its cryptographic and semantic
/// bindings before returning transport-only route data.
pub fn verify_snapshot_bytes(
    bytes: &[u8],
    trust: &SnapshotTrust,
) -> Result<VerifiedSnapshot, SnapshotError> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotError::InvalidDocument(
            "snapshot exceeds size limit".into(),
        ));
    }
    let snapshot = serde_json::from_slice(bytes)
        .map_err(|e| SnapshotError::InvalidDocument(format!("invalid JSON: {e}")))?;
    verify_snapshot(&snapshot, trust)
}
pub fn verify_snapshot(
    snapshot: &SignedTransportSnapshot,
    trust: &SnapshotTrust,
) -> Result<VerifiedSnapshot, SnapshotError> {
    if snapshot.version != SNAPSHOT_VERSION {
        return invalid("unsupported snapshot version");
    };
    if snapshot.network != trust.context.network {
        return invalid("unexpected network");
    };
    if snapshot.registry_id != trust.context.registry_id {
        return invalid("unexpected registry id");
    };
    if snapshot.chain_id != trust.context.chain_id
        || snapshot.network_id != trust.context.network_id
        || snapshot.release_id != trust.context.release_id
        || snapshot.protocol_version != trust.context.protocol_version
    {
        return invalid("unexpected chain network release or protocol tuple");
    };
    if snapshot.provider_plan_sha256 != trust.provider_plan_sha256 {
        return invalid("provider-plan binding mismatch");
    };
    if snapshot.configuration_version == 0 {
        return invalid("generation must be greater than zero");
    };
    if snapshot.transports.is_empty() {
        return invalid("snapshot has no transports");
    }
    let mut identities = BTreeSet::new();
    let mut dials = BTreeSet::new();
    let mut routes = Vec::with_capacity(snapshot.transports.len());
    for route in &snapshot.transports {
        if !identities.insert(route.validator_address.clone()) {
            return invalid("duplicate validator identity");
        };
        if !dials.insert(route.dial_address.clone()) {
            return invalid("duplicate validator dial address");
        };
        routes.push(TransportRoute {
            identity: route.validator_address.clone(),
            dial_address: route.dial_address.clone(),
            scope: OverlayScope::Validator,
        });
    }
    let signature = decode_signature(&snapshot.signature)?;
    trust
        .verifier
        .verify(
            &SigningContext {
                domain: "SYNERGY-TRANSPORT-REGISTRY-ATTESTATION-V1".into(),
                chain_id: trust.context.chain_id,
                epoch: None,
                height: None,
            },
            &signed_payload(snapshot)?,
            &Signature {
                algorithm: SignatureAlgorithm::MlDsa87,
                key_id: KeyId::new("transport-registry-attestation")
                    .map_err(|e| SnapshotError::InvalidDocument(e.to_string()))?,
                bytes: signature,
            },
            &trust.verifying_key,
        )
        .map_err(|error| match error {
            synergy_aegis::VerificationError::Provider(message) => SnapshotError::Provider(message),
            _ => SnapshotError::InvalidSignature,
        })?;
    let registry =
        VerifiedTransportRegistry::from_verified_snapshot(snapshot.configuration_version, routes)
            .map_err(SnapshotError::Registry)?;
    Ok(VerifiedSnapshot {
        registry_id: snapshot.registry_id.clone(),
        generation: snapshot.configuration_version,
        registry,
    })
}
impl SnapshotAcceptance {
    pub fn install(
        &mut self,
        snapshot: VerifiedSnapshot,
        active: &[String],
    ) -> Result<SnapshotInstall, SnapshotError> {
        snapshot
            .registry
            .require_coverage(active)
            .map_err(SnapshotError::Coverage)?;
        match self.current.as_ref() {
            None => {
                let generation = snapshot.generation;
                self.current = Some(snapshot);
                Ok(SnapshotInstall {
                    generation,
                    changed: true,
                })
            }
            Some(current) if current.registry_id != snapshot.registry_id => {
                Err(SnapshotError::RegistryChanged)
            }
            Some(current) if snapshot.generation < current.generation => {
                Err(SnapshotError::Rollback {
                    received: snapshot.generation,
                    current: current.generation,
                })
            }
            Some(current) if snapshot.generation == current.generation => {
                if current.registry.same_routes(&snapshot.registry) {
                    Ok(SnapshotInstall {
                        generation: snapshot.generation,
                        changed: false,
                    })
                } else {
                    Err(SnapshotError::Equivocation {
                        generation: snapshot.generation,
                    })
                }
            }
            Some(_) => {
                let generation = snapshot.generation;
                self.current = Some(snapshot);
                Ok(SnapshotInstall {
                    generation,
                    changed: true,
                })
            }
        }
    }
    pub fn current(&self) -> Option<&VerifiedSnapshot> {
        self.current.as_ref()
    }
}
fn invalid(message: &str) -> Result<VerifiedSnapshot, SnapshotError> {
    Err(SnapshotError::InvalidDocument(message.into()))
}
fn decode_signature(value: &str) -> Result<Vec<u8>, SnapshotError> {
    let encoded = value.strip_prefix("ml-dsa-87:").ok_or_else(|| {
        SnapshotError::InvalidDocument(
            "native registry signature requires ML-DSA-87; classical algorithms are forbidden"
                .into(),
        )
    })?;
    let bytes = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| SnapshotError::InvalidDocument("signature is not base64".into()))?;
    if bytes.len() != 4627 {
        return Err(SnapshotError::InvalidDocument(
            "ML-DSA-87 registry signature must be 4627 bytes".into(),
        ));
    }
    Ok(bytes)
}
fn signed_payload(snapshot: &SignedTransportSnapshot) -> Result<Vec<u8>, SnapshotError> {
    serde_json::to_vec(&json!({"version":snapshot.version,"network":snapshot.network,"registry_id":snapshot.registry_id,"chain_id":snapshot.chain_id,"network_id":snapshot.network_id,"release_id":snapshot.release_id,"protocol_version":snapshot.protocol_version,"provider_plan_sha256":snapshot.provider_plan_sha256,"configuration_version":snapshot.configuration_version,"transports":snapshot.transports})).map_err(|e|SnapshotError::InvalidDocument(format!("cannot serialize signed payload: {e}")))
}
fn lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    pub const EXPECTED_NETWORK: &str = "synergy-testnet-v3-validator-transport-v1";
    pub const EXPECTED_REGISTRY_ID: &str = "synergy-testnet-v3-block-zero-transport-v1";
    pub const EXPECTED_CHAIN_ID: u64 = 1266;
    pub const EXPECTED_NETWORK_ID: &str = "testnet";
    pub const EXPECTED_RELEASE_ID: &str = "testnet-v3";
    pub const EXPECTED_PROTOCOL_VERSION: &str = "posy/3.0";

    use super::*;
    use synergy_address_engine::{
        apqe::{provider::SignOptions, SecretBytes},
        types::Algorithm,
    };
    struct SigningKey {
        engine: Arc<Mutex<CryptoEngine>>,
        public: Vec<u8>,
        secret: SecretBytes,
    }
    impl SigningKey {
        fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.engine
                .lock()
                .unwrap()
                .sign(
                    Algorithm::MlDsa87,
                    self.secret.as_bytes(),
                    message,
                    SignOptions::default(),
                )
                .unwrap()
        }
        fn trust(&self, context: SnapshotContext) -> SnapshotTrust {
            SnapshotTrust::from_encoded_with_provider(
                &format!(
                    "ml-dsa-87:{}",
                    general_purpose::STANDARD.encode(&self.public)
                ),
                "a".repeat(64),
                context,
                self.engine.clone(),
            )
            .unwrap()
        }
    }
    #[test]
    fn classical_registry_trust_and_signatures_are_unconditionally_rejected() {
        for algorithm in ["ed25519:", "ecdsa:", "rsa:", "secp256k1:"] {
            assert!(SnapshotTrust::from_encoded(
                &format!("{algorithm}{}", general_purpose::STANDARD.encode([0; 32])),
                "a".repeat(64),
                fixture_context()
            )
            .is_err());
            assert!(decode_signature(&format!(
                "{algorithm}{}",
                general_purpose::STANDARD.encode([0; 64])
            ))
            .is_err());
        }
    }
    fn fixture_context() -> SnapshotContext {
        SnapshotContext {
            network: EXPECTED_NETWORK.into(),
            registry_id: EXPECTED_REGISTRY_ID.into(),
            chain_id: EXPECTED_CHAIN_ID,
            network_id: EXPECTED_NETWORK_ID.into(),
            release_id: EXPECTED_RELEASE_ID.into(),
            protocol_version: EXPECTED_PROTOCOL_VERSION.into(),
        }
    }
    fn key() -> (SigningKey, SnapshotTrust) {
        let engine = synergy_aegis::load_authenticated_native_engine(
            std::path::Path::new(
                &std::env::var("APQE_TRUSTED_NATIVE_REPORT").expect("explicit native report"),
            ),
            &std::env::var("APQE_AUTHENTICATED_REPORT_SHA256")
                .expect("authenticated report digest"),
        )
        .unwrap();
        let pair = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa87)
            .unwrap();
        let key = SigningKey {
            engine,
            public: pair.public_key,
            secret: pair.private_key,
        };
        let trust = key.trust(fixture_context());
        (key, trust)
    }

    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn signed_snapshot_is_bound_to_the_selected_network_on_every_chain() {
        let (key, _) = key();
        for chain_id in [1266, 9001, 9002] {
            let mut context = fixture_context();
            context.chain_id = chain_id;
            context.network_id = format!("network-{chain_id}");
            let trust = key.trust(context.clone());
            let mut candidate = snapshot(&key, 1, "10.69.10.2:5622");
            candidate.chain_id = chain_id;
            candidate.network_id = context.network_id;
            candidate.signature = format!(
                "ml-dsa-87:{}",
                general_purpose::STANDARD.encode(key.sign(&signed_payload(&candidate).unwrap()))
            );
            assert!(verify_snapshot(&candidate, &trust).is_ok());
            let mut other = candidate.clone();
            other.chain_id += 1;
            assert!(verify_snapshot(&other, &trust).is_err());
            other = candidate.clone();
            other.network_id.push_str("-different-incarnation");
            assert!(verify_snapshot(&other, &trust).is_err());
            other = candidate;
            other.signature = format!("ml-dsa-87:{}", general_purpose::STANDARD.encode([0u8; 64]));
            assert!(verify_snapshot(&other, &trust).is_err());
        }
    }
    fn snapshot(key: &SigningKey, generation: u64, dial: &str) -> SignedTransportSnapshot {
        let mut value = SignedTransportSnapshot {
            version: SNAPSHOT_VERSION,
            network: EXPECTED_NETWORK.into(),
            registry_id: EXPECTED_REGISTRY_ID.into(),
            chain_id: EXPECTED_CHAIN_ID,
            network_id: EXPECTED_NETWORK_ID.into(),
            release_id: EXPECTED_RELEASE_ID.into(),
            protocol_version: EXPECTED_PROTOCOL_VERSION.into(),
            provider_plan_sha256: "a".repeat(64),
            configuration_version: generation,
            transports: vec![SnapshotTransport {
                validator_address: "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn".into(),
                dial_address: dial.into(),
            }],
            signature: String::new(),
        };
        value.signature = format!(
            "ml-dsa-87:{}",
            general_purpose::STANDARD.encode(key.sign(&signed_payload(&value).unwrap()))
        );
        value
    }
    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn signed_private_overlay_allocations_accept_only_the_authorized_endpoint() {
        let (key, trust) = key();
        for dial in [
            "10.69.106.160:5622",
            "10.69.11.219:5622",
            "10.69.56.215:5622",
            "10.69.184.171:5622",
            "10.69.140.27:5622",
            "172.20.1.2:5622",
        ] {
            let signed = snapshot(&key, 1, dial);
            assert!(verify_snapshot(&signed, &trust).is_ok());
            let mut tampered = signed;
            tampered.transports[0].dial_address = "192.168.1.2:5622".into();
            assert_eq!(
                verify_snapshot(&tampered, &trust).unwrap_err(),
                SnapshotError::InvalidSignature
            );
        }
        for dial in ["8.8.8.8:5622", "127.0.0.1:5622", "10.69.11.219:5623"] {
            assert!(matches!(
                verify_snapshot(&snapshot(&key, 1, dial), &trust),
                Err(SnapshotError::Registry(_))
            ));
        }
    }
    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn signed_identity_complete_snapshot_is_admitted() {
        let (key, trust) = key();
        let value = verify_snapshot(&snapshot(&key, 7, "10.69.10.7:5622"), &trust).unwrap();
        let mut acceptance = SnapshotAcceptance::default();
        assert_eq!(
            acceptance.install(value, &["synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn".into()]),
            Ok(SnapshotInstall {
                generation: 7,
                changed: true
            })
        );
    }
    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn tampering_provider_binding_or_signature_fails_closed() {
        let (key, trust) = key();
        let mut bad = snapshot(&key, 1, "10.69.10.1:5622");
        bad.provider_plan_sha256 = "b".repeat(64);
        assert!(matches!(
            verify_snapshot(&bad, &trust),
            Err(SnapshotError::InvalidDocument(_))
        ));
        let mut bad = snapshot(&key, 1, "10.69.10.1:5622");
        bad.transports[0].dial_address = "10.69.10.2:5622".into();
        assert!(matches!(
            verify_snapshot(&bad, &trust),
            Err(SnapshotError::InvalidSignature)
        ));
    }
    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn incomplete_active_coverage_rollback_and_equivocation_are_rejected() {
        let (key, trust) = key();
        let mut acceptance = SnapshotAcceptance::default();
        let first = verify_snapshot(&snapshot(&key, 8, "10.69.10.8:5622"), &trust).unwrap();
        acceptance
            .install(first, &["synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn".into()])
            .unwrap();
        let old = verify_snapshot(&snapshot(&key, 7, "10.69.10.7:5622"), &trust).unwrap();
        assert!(matches!(
            acceptance.install(old, &["synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn".into()]),
            Err(SnapshotError::Rollback { .. })
        ));
        let same_generation =
            verify_snapshot(&snapshot(&key, 8, "10.69.10.9:5622"), &trust).unwrap();
        assert!(matches!(
            acceptance.install(
                same_generation,
                &["synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn".into()]
            ),
            Err(SnapshotError::Equivocation { .. })
        ));
        let new = verify_snapshot(&snapshot(&key, 9, "10.69.10.9:5622"), &trust).unwrap();
        assert!(matches!(
            acceptance.install(
                new,
                &[
                    "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn".into(),
                    "synv21lrh6jcxaejkj4zv994j7qwn2rk6u3zat22n".into()
                ]
            ),
            Err(SnapshotError::Coverage(_))
        ));
    }
}
