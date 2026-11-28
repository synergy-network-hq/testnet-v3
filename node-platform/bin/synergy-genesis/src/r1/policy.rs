//! Complete owned transport models mapped into canonical APQE policy/birth types.
//! No second policy codec. The engineering-selected PoP/role-binding domains are
//! separate from birth identity and contain no final Genesis commitment.
use std::collections::BTreeSet;
use synergy_address_engine::{
    apqe::{
        crypto_engine::CryptoEngine,
        native_identity_derivation_r1::{
            self as identity, AccessRule, BirthBody, BirthPolicy, Controller,
        },
        native_identity_presentation_r1::NativeIdentityPresentation,
        network_birth_r1::{BootstrapKeyRecord, ProfileRef},
        preparation::require_nonproduction_fixture,
        provider::SignOptions,
        r1_framing::{self as c, NetworkRef, Value},
        HashAlgorithm, Primitives,
    },
    types::Algorithm,
};
use synergy_protocol_types::{NodeClass, NodeRole};

pub const POP_CONTEXT: &[u8] = b"SYNERGY.NODE.POP.R1";
pub const ROLE_BINDING_CONTEXT: &[u8] = b"SYNERGY.NODE.ROLE-BINDING.R1";
const BUDGET: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    pub role: String,
    pub algorithm: Algorithm,
    pub generation: u64,
    pub public_key: Vec<u8>,
}
impl KeyRecord {
    pub fn as_apqe(&self) -> Result<BootstrapKeyRecord<'_>, PolicyError> {
        let length = match self.algorithm {
            Algorithm::MlDsa65 => 1952,
            Algorithm::MlDsa87 => 2592,
            _ => return Err(PolicyError::Key),
        };
        if self.role.is_empty()
            || self.role.len() > 64
            || !self.role.is_ascii()
            || self.role.contains('\0')
            || self.generation == 0
            || self.public_key.len() != length
        {
            return Err(PolicyError::Key);
        }
        Ok(BootstrapKeyRecord {
            role: &self.role,
            algorithm: self.algorithm.display_name(),
            key_generation: self.generation,
            full_public_key: &self.public_key,
        })
    }
    fn value(&self) -> Result<Value, PolicyError> {
        let key = self.as_apqe()?;
        Ok(Value::Array(vec![
            c::text(key.role),
            c::text(key.algorithm),
            Value::Unsigned(key.key_generation),
            c::bytes(key.full_public_key),
        ]))
    }
    fn signature_size(&self) -> usize {
        match self.algorithm {
            Algorithm::MlDsa65 => 3309,
            Algorithm::MlDsa87 => 4627,
            _ => 0,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyController {
    pub key: KeyRecord,
    pub declared_independence_domain: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRule {
    pub threshold: u32,
    pub controller_indices: Vec<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletePolicy {
    pub namespace: String,
    pub controllers: Vec<PolicyController>,
    pub ordinary: PolicyRule,
    pub recovery: Option<PolicyRule>,
}
impl CompletePolicy {
    pub fn with_apqe<T>(
        &self,
        operation: impl FnOnce(&BirthPolicy<'_>) -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        if self.controllers.len() > 32 {
            return Err(PolicyError::Bound);
        }
        let controllers = self
            .controllers
            .iter()
            .map(|controller| {
                Ok(Controller {
                    key: controller.key.as_apqe()?,
                    asserted_independence_domain: &controller.declared_independence_domain,
                })
            })
            .collect::<Result<Vec<_>, PolicyError>>()?;
        let policy = BirthPolicy {
            namespace: &self.namespace,
            controllers: &controllers,
            ordinary: AccessRule {
                threshold: self.ordinary.threshold,
                controller_indices: &self.ordinary.controller_indices,
            },
            recovery: self.recovery.as_ref().map(|r| AccessRule {
                threshold: r.threshold,
                controller_indices: &r.controller_indices,
            }),
        };
        operation(&policy)
    }
    pub fn frame(&self, network: NetworkRef) -> Result<Vec<u8>, PolicyError> {
        self.with_apqe(|policy| {
            identity::candidate_policy_frame(network, policy, BUDGET)
                .map_err(|_| PolicyError::Policy)
        })
    }
    pub fn commitment(&self, network: NetworkRef) -> Result<[u8; 64], PolicyError> {
        self.with_apqe(|policy| {
            identity::candidate_policy_commitment(network, policy, BUDGET)
                .map_err(|_| PolicyError::Policy)
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RoleKeyKind {
    Consensus,
    TransportPublic,
    TransportPrivate,
    TransportService,
}
impl RoleKeyKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Consensus => "consensus",
            Self::TransportPublic => "transport/public",
            Self::TransportPrivate => "transport/private",
            Self::TransportService => "transport/service",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleKey {
    pub kind: RoleKeyKind,
    pub key: KeyRecord,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedProof {
    pub index: u32,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRecord {
    pub identity: String,
    pub class: NodeClass,
    pub primary_role: NodeRole,
    pub birth_nonce: [u8; 32],
    pub birth_root: KeyRecord,
    pub birth_policy: CompletePolicy,
    pub current_policy: CompletePolicy,
    pub policy_epoch: u64,
    pub enrollment_nonce: [u8; 32],
    pub role_keys: Vec<RoleKey>,
    pub possession_proofs: Vec<IndexedProof>,
    pub ordinary_controller_approvals: Vec<IndexedProof>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    Ceremony,
    Bound,
    Key,
    Policy,
    Identity,
    Role,
    Encoding,
    Proof,
    Provider,
}
impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "R1 Genesis node rejected: {self:?}")
    }
}
impl std::error::Error for PolicyError {}

pub fn role_class(role: NodeRole) -> NodeClass {
    match role {
        NodeRole::Validator | NodeRole::Sentry | NodeRole::Archive | NodeRole::ConsensusAudit => {
            NodeClass::ConsensusAndChainIntegrity
        }
        NodeRole::CrossChain | NodeRole::Witness | NodeRole::Oracle | NodeRole::UmaCoordinator => {
            NodeClass::Interoperability
        }
        NodeRole::SynqExecution
        | NodeRole::NetworkAnalytics
        | NodeRole::AegisCryptography
        | NodeRole::DataAvailability => NodeClass::ExecutionDataAndCryptography,
        NodeRole::AiCompute
        | NodeRole::AiCoordination
        | NodeRole::AiData
        | NodeRole::AiAssurance => NodeClass::AiAndIntelligence,
        _ => NodeClass::ServiceAndAccess,
    }
}
impl NodeRecord {
    pub fn validate_birth(
        &self,
        network: NetworkRef,
    ) -> Result<NativeIdentityPresentation, PolicyError> {
        require_nonproduction_fixture(network.chain_id).map_err(|_| PolicyError::Ceremony)?;
        let namespace = format!("synv{}", self.class.digit());
        if self.class != role_class(self.primary_role)
            || self.birth_policy.namespace != namespace
            || self.current_policy.namespace != namespace
            || self.policy_epoch != 1
            || self.birth_nonce == [0; 32]
            || self.enrollment_nonce == [0; 32]
            || self.birth_root.algorithm != Algorithm::MlDsa87
            || self.birth_root.role != "node_birth_root"
            || self.birth_policy.frame(network)? != self.current_policy.frame(network)?
        {
            return Err(PolicyError::Policy);
        }
        let root = self.birth_root.as_apqe()?;
        let candidate = self.birth_policy.with_apqe(|policy| {
            identity::derive_candidate(
                network,
                &BirthBody::Node {
                    namespace: &namespace,
                    node_class: self.class.digit(),
                    nonce32: &self.birth_nonce,
                    birth_root: root,
                    policy,
                },
                BUDGET,
            )
            .map_err(|_| PolicyError::Identity)
        })?;
        if candidate.presentation.to_text() != self.identity {
            return Err(PolicyError::Identity);
        }
        if self.role_keys.len() > 4 {
            return Err(PolicyError::Bound);
        }
        let required: &[RoleKeyKind] = match self.primary_role {
            NodeRole::Validator => &[RoleKeyKind::Consensus, RoleKeyKind::TransportPrivate],
            NodeRole::Sentry => &[RoleKeyKind::TransportPublic, RoleKeyKind::TransportPrivate],
            _ => &[RoleKeyKind::TransportService],
        };
        let kinds = self
            .role_keys
            .iter()
            .map(|r| r.kind)
            .collect::<BTreeSet<_>>();
        if kinds.len() != self.role_keys.len() || kinds != required.iter().copied().collect() {
            return Err(PolicyError::Role);
        }
        let mut encoded = Vec::new();
        let mut keys = BTreeSet::new();
        for role in &self.role_keys {
            if role.key.algorithm != Algorithm::MlDsa65
                || role.key.role != role.kind.label()
                || role.key.public_key == self.birth_root.public_key
                || !keys.insert(&role.key.public_key)
            {
                return Err(PolicyError::Key);
            }
            encoded.push(
                role.key
                    .value()?
                    .encode(BUDGET)
                    .map_err(|_| PolicyError::Encoding)?,
            );
        }
        if encoded.windows(2).any(|w| w[0] >= w[1]) {
            return Err(PolicyError::Encoding);
        }
        Ok(candidate.presentation)
    }
    /// Canonical distinct complete key records used for indexed PoPs. Birth-root
    /// and the same exact policy-controller record are one key, never two votes.
    pub fn possession_keys(&self) -> Result<Vec<&KeyRecord>, PolicyError> {
        let mut keys = vec![&self.birth_root];
        keys.extend(self.current_policy.controllers.iter().map(|c| &c.key));
        keys.extend(self.role_keys.iter().map(|r| &r.key));
        let mut encoded = keys
            .into_iter()
            .map(|k| {
                Ok((
                    k.value()?
                        .encode(BUDGET)
                        .map_err(|_| PolicyError::Encoding)?,
                    k,
                ))
            })
            .collect::<Result<Vec<_>, PolicyError>>()?;
        encoded.sort_by(|a, b| a.0.cmp(&b.0));
        encoded.dedup_by(|a, b| a.0 == b.0);
        let mut full_keys = BTreeSet::new();
        for (_, key) in &encoded {
            if !full_keys.insert(&key.public_key) {
                return Err(PolicyError::Key);
            }
        }
        Ok(encoded.into_iter().map(|(_, key)| key).collect())
    }
    pub fn role_key_set_commitment(&self, network: NetworkRef) -> Result<[u8; 64], PolicyError> {
        require_nonproduction_fixture(network.chain_id).map_err(|_| PolicyError::Ceremony)?;
        let values = self
            .role_keys
            .iter()
            .map(|r| r.key.value())
            .collect::<Result<Vec<_>, _>>()?;
        let frame = c::frame(
            "IDENTITY.NODE.ROLE-KEY-SET",
            ProfileRef {
                name: "APQE-NODE-ROLE-BINDING",
                revision: 1,
            },
            Some(network),
            Value::Array(values),
            BUDGET,
        )
        .map_err(|_| PolicyError::Encoding)?;
        Primitives
            .hash(HashAlgorithm::Sha3512, &frame)
            .map_err(|_| PolicyError::Provider)?
            .try_into()
            .map_err(|_| PolicyError::Encoding)
    }
    pub fn possession_frame(
        &self,
        network: NetworkRef,
        index: u32,
    ) -> Result<Vec<u8>, PolicyError> {
        let identity = self.validate_birth(network)?;
        let keys = self.possession_keys()?;
        let key = keys.get(index as usize).ok_or(PolicyError::Proof)?;
        c::frame(
            "IDENTITY.NODE.POSSESSION",
            ProfileRef {
                name: "APQE-NODE-POSSESSION",
                revision: 1,
            },
            Some(network),
            Value::Array(vec![
                c::text(identity.namespace()),
                c::bytes(identity.raw48()),
                key.value()?,
                c::bytes(&self.current_policy.commitment(network)?),
                c::bytes(&self.enrollment_nonce),
            ]),
            BUDGET,
        )
        .map_err(|_| PolicyError::Encoding)
    }
    pub fn role_binding_frame(&self, network: NetworkRef) -> Result<Vec<u8>, PolicyError> {
        let identity = self.validate_birth(network)?;
        c::frame(
            "IDENTITY.NODE.ROLE-BINDING",
            ProfileRef {
                name: "APQE-NODE-ROLE-BINDING",
                revision: 1,
            },
            Some(network),
            Value::Array(vec![
                c::text(identity.namespace()),
                c::bytes(identity.raw48()),
                c::bytes(&self.current_policy.commitment(network)?),
                c::bytes(&self.role_key_set_commitment(network)?),
                c::bytes(&self.enrollment_nonce),
                Value::Unsigned(self.policy_epoch),
            ]),
            BUDGET,
        )
        .map_err(|_| PolicyError::Encoding)
    }
}
/// Cryptographic possession/controller agreement only. Physical independence,
/// PoSy admission, host/overlay privileges and runtime activation are separate.
pub struct VerifiedNodeRecord {
    record: NodeRecord,
}
impl VerifiedNodeRecord {
    pub fn record(&self) -> &NodeRecord {
        &self.record
    }
}
pub fn verify_node(
    record: NodeRecord,
    network: NetworkRef,
    engine: &CryptoEngine,
) -> Result<VerifiedNodeRecord, PolicyError> {
    record.validate_birth(network)?;
    let keys = record.possession_keys()?;
    if record.possession_proofs.len() != keys.len() {
        return Err(PolicyError::Proof);
    }
    for (index, proof) in record.possession_proofs.iter().enumerate() {
        if proof.index as usize != index {
            return Err(PolicyError::Proof);
        }
        let key = keys[index];
        let frame = record.possession_frame(network, proof.index)?;
        if proof.signature.len() != key.signature_size()
            || engine
                .verify(
                    key.algorithm,
                    &key.public_key,
                    &frame,
                    &proof.signature,
                    SignOptions::Pure {
                        context: POP_CONTEXT,
                    },
                )
                .map_err(|_| PolicyError::Provider)?
                != true
        {
            return Err(PolicyError::Proof);
        }
    }
    let rule = &record.current_policy.ordinary;
    if record.ordinary_controller_approvals.len() < rule.threshold as usize
        || record
            .ordinary_controller_approvals
            .windows(2)
            .any(|p| p[0].index >= p[1].index)
    {
        return Err(PolicyError::Proof);
    }
    let frame = record.role_binding_frame(network)?;
    for proof in &record.ordinary_controller_approvals {
        if !rule.controller_indices.contains(&proof.index) {
            return Err(PolicyError::Proof);
        }
        let key = &record
            .current_policy
            .controllers
            .get(proof.index as usize)
            .ok_or(PolicyError::Proof)?
            .key;
        if proof.signature.len() != key.signature_size()
            || engine
                .verify(
                    key.algorithm,
                    &key.public_key,
                    &frame,
                    &proof.signature,
                    SignOptions::Pure {
                        context: ROLE_BINDING_CONTEXT,
                    },
                )
                .map_err(|_| PolicyError::Provider)?
                != true
        {
            return Err(PolicyError::Proof);
        }
    }
    Ok(VerifiedNodeRecord { record })
}

// The Genesis envelope uses the selected C14N-02 schema. APQE still owns the
// distinct policy/birth commitment codec; these complete fields reconstruct it.
use synergy_protocol_types::c14n02::{Decoder, Encoder};
fn enc<T>(value: Result<T, synergy_protocol_types::c14n02::Error>) -> Result<T, PolicyError> {
    value.map_err(|_| PolicyError::Encoding)
}
impl KeyRecord {
    pub fn encode_into(&self, e: &mut Encoder) -> Result<(), PolicyError> {
        self.as_apqe()?;
        enc(e.ascii(&self.role, 64))?;
        enc(e.u16(match self.algorithm {
            Algorithm::MlDsa65 => 65,
            Algorithm::MlDsa87 => 87,
            _ => return Err(PolicyError::Key),
        }))?;
        enc(e.u64(self.generation))?;
        enc(e.bytes(&self.public_key, 2592))
    }
    pub fn decode_from(d: &mut Decoder<'_>) -> Result<Self, PolicyError> {
        let role = enc(d.ascii(64))?.to_owned();
        let algorithm = match enc(d.u16())? {
            65 => Algorithm::MlDsa65,
            87 => Algorithm::MlDsa87,
            _ => return Err(PolicyError::Key),
        };
        let generation = enc(d.u64())?;
        let public_key = enc(d.bytes(2592))?.to_vec();
        let result = Self {
            role,
            algorithm,
            generation,
            public_key,
        };
        result.as_apqe()?;
        Ok(result)
    }
}
impl PolicyRule {
    fn encode_into(&self, e: &mut Encoder) -> Result<(), PolicyError> {
        enc(e.u32(self.threshold))?;
        enc(e.vector(&self.controller_indices, 32, |e, i| e.u32(*i)))
    }
    fn decode_from(d: &mut Decoder<'_>) -> Result<Self, PolicyError> {
        Ok(Self {
            threshold: enc(d.u32())?,
            controller_indices: enc(d.vector(32, 4, |d| d.u32()))?,
        })
    }
}
impl CompletePolicy {
    pub fn encode_into(&self, e: &mut Encoder) -> Result<(), PolicyError> {
        enc(e.ascii(&self.namespace, 6))?;
        if self.controllers.len() > 32 {
            return Err(PolicyError::Bound);
        }
        enc(e.u32(self.controllers.len() as u32))?;
        for controller in &self.controllers {
            controller.key.encode_into(e)?;
            enc(e.ascii(&controller.declared_independence_domain, 128))?;
        }
        self.ordinary.encode_into(e)?;
        enc(e.boolean(self.recovery.is_some()))?;
        if let Some(r) = &self.recovery {
            r.encode_into(e)?;
        }
        Ok(())
    }
    pub fn decode_from(d: &mut Decoder<'_>) -> Result<Self, PolicyError> {
        let namespace = enc(d.ascii(6))?.to_owned();
        let count = enc(d.u32())? as usize;
        if count == 0 || count > 32 {
            return Err(PolicyError::Bound);
        }
        let mut controllers = Vec::with_capacity(count);
        for _ in 0..count {
            controllers.push(PolicyController {
                key: KeyRecord::decode_from(d)?,
                declared_independence_domain: enc(d.ascii(128))?.to_owned(),
            });
        }
        let ordinary = PolicyRule::decode_from(d)?;
        let recovery = if enc(d.boolean())? {
            Some(PolicyRule::decode_from(d)?)
        } else {
            None
        };
        Ok(Self {
            namespace,
            controllers,
            ordinary,
            recovery,
        })
    }
}
fn role_number(role: NodeRole) -> u16 {
    match role {
        NodeRole::Validator => 1,
        NodeRole::Sentry => 2,
        NodeRole::Archive => 3,
        NodeRole::ConsensusAudit => 4,
        NodeRole::CrossChain => 5,
        NodeRole::Witness => 6,
        NodeRole::Oracle => 7,
        NodeRole::UmaCoordinator => 8,
        NodeRole::SynqExecution => 9,
        NodeRole::NetworkAnalytics => 10,
        NodeRole::AegisCryptography => 11,
        NodeRole::DataAvailability => 12,
        NodeRole::AiCompute => 13,
        NodeRole::AiCoordination => 14,
        NodeRole::AiData => 15,
        NodeRole::AiAssurance => 16,
        NodeRole::RpcGateway => 17,
        NodeRole::Indexer => 18,
        NodeRole::ObserverLight => 19,
        NodeRole::Bootseed => 20,
    }
}
fn role_from_number(value: u16) -> Result<NodeRole, PolicyError> {
    Ok(match value {
        1 => NodeRole::Validator,
        2 => NodeRole::Sentry,
        3 => NodeRole::Archive,
        4 => NodeRole::ConsensusAudit,
        5 => NodeRole::CrossChain,
        6 => NodeRole::Witness,
        7 => NodeRole::Oracle,
        8 => NodeRole::UmaCoordinator,
        9 => NodeRole::SynqExecution,
        10 => NodeRole::NetworkAnalytics,
        11 => NodeRole::AegisCryptography,
        12 => NodeRole::DataAvailability,
        13 => NodeRole::AiCompute,
        14 => NodeRole::AiCoordination,
        15 => NodeRole::AiData,
        16 => NodeRole::AiAssurance,
        17 => NodeRole::RpcGateway,
        18 => NodeRole::Indexer,
        19 => NodeRole::ObserverLight,
        20 => NodeRole::Bootseed,
        _ => return Err(PolicyError::Role),
    })
}
pub(super) fn encode_proofs(
    e: &mut Encoder,
    proofs: &[IndexedProof],
    bound: usize,
) -> Result<(), PolicyError> {
    if proofs.len() > bound {
        return Err(PolicyError::Bound);
    }
    enc(e.u32(proofs.len() as u32))?;
    for p in proofs {
        enc(e.u32(p.index))?;
        enc(e.bytes(&p.signature, 4627))?;
    }
    Ok(())
}
pub(super) fn decode_proofs(
    d: &mut Decoder<'_>,
    bound: usize,
) -> Result<Vec<IndexedProof>, PolicyError> {
    let count = enc(d.u32())? as usize;
    if count > bound {
        return Err(PolicyError::Bound);
    }
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        result.push(IndexedProof {
            index: enc(d.u32())?,
            signature: enc(d.bytes(4627))?.to_vec(),
        });
    }
    Ok(result)
}
impl NodeRecord {
    pub fn encode_into(&self, e: &mut Encoder, network: NetworkRef) -> Result<(), PolicyError> {
        let identity = self.validate_birth(network)?;
        enc(e.fixed(identity.raw48()))?;
        enc(e.u8(self.class.digit()))?;
        enc(e.u16(role_number(self.primary_role)))?;
        enc(e.fixed(&self.birth_nonce))?;
        self.birth_root.encode_into(e)?;
        self.birth_policy.encode_into(e)?;
        self.current_policy.encode_into(e)?;
        enc(e.u64(self.policy_epoch))?;
        enc(e.fixed(&self.enrollment_nonce))?;
        enc(e.u32(self.role_keys.len() as u32))?;
        for role in &self.role_keys {
            enc(e.u16(match role.kind {
                RoleKeyKind::Consensus => 1,
                RoleKeyKind::TransportPublic => 2,
                RoleKeyKind::TransportPrivate => 3,
                RoleKeyKind::TransportService => 4,
            }))?;
            role.key.encode_into(e)?;
        }
        encode_proofs(e, &self.possession_proofs, 64)?;
        encode_proofs(e, &self.ordinary_controller_approvals, 32)
    }
    pub fn decode_from(d: &mut Decoder<'_>, network: NetworkRef) -> Result<Self, PolicyError> {
        let raw48 = enc(d.fixed::<48>())?;
        let class = NodeClass::try_from(enc(d.u8())?).map_err(|_| PolicyError::Role)?;
        let identity =
            NativeIdentityPresentation::from_raw(&format!("synv{}", class.digit()), raw48)
                .map_err(|_| PolicyError::Identity)?
                .to_text();
        let primary_role = role_from_number(enc(d.u16())?)?;
        let birth_nonce = enc(d.fixed())?;
        let birth_root = KeyRecord::decode_from(d)?;
        let birth_policy = CompletePolicy::decode_from(d)?;
        let current_policy = CompletePolicy::decode_from(d)?;
        let policy_epoch = enc(d.u64())?;
        let enrollment_nonce = enc(d.fixed())?;
        let count = enc(d.u32())? as usize;
        if count > 4 {
            return Err(PolicyError::Bound);
        }
        let mut role_keys = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = match enc(d.u16())? {
                1 => RoleKeyKind::Consensus,
                2 => RoleKeyKind::TransportPublic,
                3 => RoleKeyKind::TransportPrivate,
                4 => RoleKeyKind::TransportService,
                _ => return Err(PolicyError::Role),
            };
            role_keys.push(RoleKey {
                kind,
                key: KeyRecord::decode_from(d)?,
            });
        }
        let possession_proofs = decode_proofs(d, 64)?;
        let ordinary_controller_approvals = decode_proofs(d, 32)?;
        let result = Self {
            identity,
            class,
            primary_role,
            birth_nonce,
            birth_root,
            birth_policy,
            current_policy,
            policy_epoch,
            enrollment_nonce,
            role_keys,
            possession_proofs,
            ordinary_controller_approvals,
        };
        result.validate_birth(network)?;
        Ok(result)
    }
}
