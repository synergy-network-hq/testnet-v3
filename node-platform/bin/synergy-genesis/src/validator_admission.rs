//! Admission provenance: a typed record is earned only by an old-authority
//! certified block and its exact canonical World. Bare caller keys earn nothing.
use crate::authority::{AuthorityValidator, ProtectedEpochPolicy, VerifiedWalletDispatchRelease};
use crate::membership::VerifiedMembershipRetirement;
use serde::{Deserialize, Serialize};
use synergy_governance::{
    AutomaticValidatorAdmissionPolicy, FinalizedValidatorAdmissionRecord,
    VALIDATOR_ADMISSION_PREFIX,
};
use synergy_posy::{
    ConsensusSignatureVerifier, EpochTransitionAuthorization, FinalitySyncWitness,
    FinalizedBlockRecord, FrozenValidatorRegistry, SimplifiedEpochContext, ThreeQcFinality,
    ValidatorRecord, ValidatorStatus,
};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipAdmissionEvidence {
    #[serde(with = "synergy_protocol_types::bounded_document")]
    pub closing_block_commitment: Vec<u8>,
    #[serde(with = "synergy_protocol_types::bounded_document")]
    pub closing_world: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct NativeMembershipAdmissionSet {
    records: Vec<FinalizedValidatorAdmissionRecord>,
    policy: AutomaticValidatorAdmissionPolicy,
    previous_context_root: String,
}
impl NativeMembershipAdmissionSet {
    /// This proves the record against the OLD registry before exposing any new
    /// verification key. The caller must still require the derived exact next
    /// subject/registry, and commit its cursor and keys atomically afterwards.
    fn verify(
        previous: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        current: &ProtectedEpochPolicy,
        genesis_hash: &str,
        finalized: &FinalizedBlockRecord,
        witness: &FinalitySyncWitness,
        evidence: &MembershipAdmissionEvidence,
        retirement: Option<&VerifiedMembershipRetirement>,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> Result<VerifiedMembershipAdmissions, String> {
        let verified = VerifiedValidatorAdmissionWorld::verify(
            previous, registry, finalized, witness, evidence, verifier,
        )?;
        let world = verified.world();
        Self::from_finalized_world(
            previous,
            registry,
            current,
            genesis_hash,
            finalized.height,
            world,
            retirement,
        )
        .map(|set| VerifiedMembershipAdmissions { set })
    }
    /// Native owner only: its caller supplies an already authenticated finalized
    /// World. This does not turn local scheduling or caller records into proofs.
    pub fn from_finalized_world(
        previous: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        current: &ProtectedEpochPolicy,
        genesis_hash: &str,
        finalized_height: u64,
        world: &synergy_state::WorldState,
        retirement: Option<&VerifiedMembershipRetirement>,
    ) -> Result<Self, String> {
        let policy = retirement
            .and_then(|r| r.spec().automatic_admission_policy.as_ref())
            .or(current.automatic_validator_admission.as_ref())
            .ok_or("automatic validator admission has no governed policy")?
            .clone();
        policy.validate()?;
        let target = previous
            .epoch
            .checked_add(1)
            .ok_or("admission epoch overflow")?;
        let prefix = format!("{VALIDATOR_ADMISSION_PREFIX}epoch-{target:020}/");
        let root = previous.root().map_err(|e| e.to_string())?;
        let mut records = vec![];
        let mut ids = std::collections::BTreeSet::new();
        let mut keys = std::collections::BTreeSet::new();
        let mut public_keys = std::collections::BTreeSet::new();
        let mut kem_ids = std::collections::BTreeSet::new();
        let mut kem_keys = std::collections::BTreeSet::new();
        for (key, bytes) in world
            .protocol
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
        {
            if records.len() >= policy.maximum_admissions_per_epoch as usize
                || bytes.len() > 48 * 1024
            {
                return Err("admission set exceeds governed bound".into());
            }
            let r: FinalizedValidatorAdmissionRecord =
                serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
            if serde_json::to_vec(&r).map_err(|e| e.to_string())? != *bytes
                || r.schema_version != 1
                || r.chain_id != previous.chain_id
                || r.network_id != previous.network_id
                || r.genesis_hash != genesis_hash
                || r.frozen_epoch != previous.epoch
                || r.frozen_epoch_context_root != root
                || r.effective_epoch != target
                || r.record_key() != *key
                || r.bond_nwei != policy.minimum_bond_nwei
                || r.escrow_account != format!("validator-bond:{}", r.validator_id)
                || !previous.contains_height(r.installed_height)
                || r.installed_height > finalized_height
                || r.installed_height
                    .checked_add(policy.minimum_shadow_finalized_blocks)
                    != Some(r.eligible_finalized_height)
                || r.eligible_finalized_height > previous.epoch_end_height.saturating_sub(2)
                || r.sync_finalized_height >= r.installed_height
                || !previous.contains_height(r.sync_finalized_height)
                || !synergy_posy::is_hash(&r.sync_finalized_block_id)
                || !synergy_posy::is_hash(&r.identity_root_sha3_256)
                || !synergy_posy::is_hash(&r.request_sha256)
                || r.consensus_public_key.len() != 1952
                || r.transport_public_key.len() != 1952
                || r.ingress_kem_public_key.len() != 1568
                || r.consensus_public_key == r.transport_public_key
                || r.consensus_key_id.is_empty()
                || r.ingress_kem_key_id.is_empty()
                || registry.active_validator(&r.validator_id).is_ok()
                || !ids.insert(r.validator_id.clone())
                || synergy_protocol_types::NodeAddress::parse(&r.validator_id).is_err()
                || !public_keys.insert(r.consensus_public_key.clone())
                || !public_keys.insert(r.transport_public_key.clone())
                || !kem_ids.insert(r.ingress_kem_key_id.clone())
                || !kem_keys.insert(r.ingress_kem_public_key.clone())
                || !keys.insert(r.consensus_key_id.clone())
                || registry
                    .active()
                    .any(|v| v.consensus_key_id == r.consensus_key_id)
                || current.ingress_kem_registry.records.iter().any(|k| {
                    k.key_id == r.ingress_kem_key_id
                        || k.public_key.public_key == r.ingress_kem_public_key
                })
                || !world.accounts.get(&r.escrow_account).is_some_and(|a| {
                    a.balance_nwei == policy.bond_nwei().unwrap_or(0)
                        && a.nonce == 0
                        && a.code_hash.is_none()
                })
                || world.protocol.get(&r.bond_key())
                    != Some(&serde_json::to_vec(&r.bond_record()).map_err(|e| e.to_string())?)
            {
                return Err(
                    "validator admission is not the exact finalized eligible bonded record".into(),
                );
            }
            records.push(r);
        }
        if records.is_empty() {
            return Err("certified admission evidence contains no newly eligible validator".into());
        }
        Ok(Self {
            records,
            policy,
            previous_context_root: root,
        })
    }
    pub fn records(&self) -> &[FinalizedValidatorAdmissionRecord] {
        &self.records
    }
    fn admitted_validators(&self) -> Vec<AuthorityValidator> {
        self.records
            .iter()
            .map(|r| AuthorityValidator {
                record: ValidatorRecord {
                    validator_id: r.validator_id.clone(),
                    consensus_key_id: r.consensus_key_id.clone(),
                    frozen_voting_weight: self.policy.initial_frozen_voting_weight,
                    status: ValidatorStatus::Active,
                },
                algorithm: synergy_aegis::SignatureAlgorithm::MlDsa65,
                public_key: r.consensus_public_key.clone(),
            })
            .collect()
    }
    pub fn prepare_successor(
        &self,
        previous: &SimplifiedEpochContext,
        current: &ProtectedEpochPolicy,
        registry: &FrozenValidatorRegistry,
        retirement: Option<&VerifiedMembershipRetirement>,
        wallet: Option<&VerifiedWalletDispatchRelease>,
    ) -> Result<
        (
            EpochTransitionAuthorization,
            ProtectedEpochPolicy,
            FrozenValidatorRegistry,
        ),
        String,
    > {
        if previous.root().map_err(|e| e.to_string())? != self.previous_context_root {
            return Err("admission set belongs to another frozen epoch".into());
        }
        let (mut policy, mut active) = if let Some(retire) = retirement {
            let (_, p, r) =
                retire.prepare_successor_with_wallet(previous, current, registry, wallet)?;
            (p, r.active().cloned().collect::<Vec<_>>())
        } else {
            let mut next =
                current.successor_clock(previous.epoch_start_height, previous.epoch_end_height)?;
            if let Some(release) = wallet {
                let (_, p) = release.prepare_successor(previous, current, registry)?;
                next.wallet_dispatch = p.wallet_dispatch;
            }
            (next, registry.active().cloned().collect())
        };
        active.extend(self.admitted_validators().into_iter().map(|v| v.record));
        let next_registry =
            FrozenValidatorRegistry::new(previous.epoch + 1, active).map_err(|e| e.to_string())?;
        policy.automatic_validator_admission = Some(self.policy.clone());
        policy.membership_authorization_root = Some(
            synergy_posy::canonical_hash(
                "SYNERGY_POSY_FINALIZED_ADMISSION_SET_V1",
                &(&policy.membership_authorization_root, &self.records),
            )
            .map_err(|e| e.to_string())?,
        );
        let start = previous
            .epoch_end_height
            .checked_add(1)
            .ok_or("admission height overflow")?;
        for r in &self.records {
            policy
                .ingress_kem_registry
                .records
                .push(synergy_etdag::crypto::IngressKemKeyRecord {
                    key_id: r.ingress_kem_key_id.clone(),
                    validator_id: r.validator_id.clone(),
                    public_key: synergy_etdag::crypto::IngressKemPublicKey {
                        algorithm: synergy_etdag::crypto::ML_KEM_1024_ALGORITHM.into(),
                        public_key: r.ingress_kem_public_key.clone(),
                    },
                    activation_height: start,
                    retirement_height: None,
                });
        }
        policy.assigned_cluster_membership_root =
            next_registry.active_set_root().map_err(|e| e.to_string())?;
        crate::membership::rebind_processing_membership(&mut policy, previous, &next_registry)?;
        let auth = EpochTransitionAuthorization::for_governed_successor(
            previous,
            &next_registry,
            policy.commitment()?,
        )
        .map_err(|e| e.to_string())?;
        let next = SimplifiedEpochContext::from_frozen_registry(
            previous.chain_id,
            previous.network_id.clone(),
            auth.next_epoch,
            auth.next_epoch_start_height,
            auth.next_epoch_end_height,
            previous.finalized_epoch_seed_root.clone(),
            auth.next_consensus_parameter_root.clone(),
            &next_registry,
        )
        .map_err(|e| e.to_string())?;
        policy.validate(&next_registry, &next)?;
        Ok((auth, policy, next_registry))
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedMembershipAdmissions {
    set: NativeMembershipAdmissionSet,
}
impl VerifiedMembershipAdmissions {
    pub fn verify(
        previous: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        current: &ProtectedEpochPolicy,
        genesis: &str,
        finalized: &FinalizedBlockRecord,
        witness: &FinalitySyncWitness,
        evidence: &MembershipAdmissionEvidence,
        retirement: Option<&VerifiedMembershipRetirement>,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> Result<Self, String> {
        if finalized.height.checked_add(2) != Some(previous.epoch_end_height) {
            return Err("membership activation requires the exact certified epoch closure".into());
        }
        NativeMembershipAdmissionSet::verify(
            previous, registry, current, genesis, finalized, witness, evidence, retirement,
            verifier,
        )
    }
    pub fn records(&self) -> &[FinalizedValidatorAdmissionRecord] {
        self.set.records()
    }
    pub fn native_projection(&self) -> &NativeMembershipAdmissionSet {
        &self.set
    }
    pub fn admitted_validators(&self) -> Vec<AuthorityValidator> {
        self.set.admitted_validators()
    }
    pub fn prepare_successor(
        &self,
        previous: &SimplifiedEpochContext,
        current: &ProtectedEpochPolicy,
        registry: &FrozenValidatorRegistry,
        retirement: Option<&VerifiedMembershipRetirement>,
        wallet: Option<&VerifiedWalletDispatchRelease>,
    ) -> Result<
        (
            EpochTransitionAuthorization,
            ProtectedEpochPolicy,
            FrozenValidatorRegistry,
        ),
        String,
    > {
        self.set
            .prepare_successor(previous, current, registry, retirement, wallet)
    }
}

/// Earns synchronization routing only. This cannot add a consensus verification
/// key or create a successor; the epoch-closing verifier remains mandatory.
#[derive(Clone, Debug)]
pub struct VerifiedShadowValidatorAdmissions {
    set: NativeMembershipAdmissionSet,
}
impl VerifiedShadowValidatorAdmissions {
    pub fn verify(
        previous: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        current: &ProtectedEpochPolicy,
        genesis: &str,
        finalized: &FinalizedBlockRecord,
        witness: &FinalitySyncWitness,
        evidence: &MembershipAdmissionEvidence,
        retirement: Option<&VerifiedMembershipRetirement>,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> Result<Self, String> {
        NativeMembershipAdmissionSet::verify(
            previous, registry, current, genesis, finalized, witness, evidence, retirement,
            verifier,
        )
        .map(|v| Self { set: v.set })
    }
    pub fn records(&self) -> &[FinalizedValidatorAdmissionRecord] {
        self.set.records()
    }
    pub fn native_projection(&self) -> &NativeMembershipAdmissionSet {
        &self.set
    }
}

/// Original-committee finality and exact canonical native World, usable by
/// closed node authoring and snapshot bootstrap without trusting raw JSON.
#[derive(Clone, Debug)]
pub struct VerifiedValidatorAdmissionWorld {
    world: synergy_state::WorldState,
    finalized: FinalizedBlockRecord,
}
impl VerifiedValidatorAdmissionWorld {
    pub fn verify(
        previous: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        finalized: &FinalizedBlockRecord,
        witness: &FinalitySyncWitness,
        evidence: &MembershipAdmissionEvidence,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> Result<Self, String> {
        previous
            .validate_against(registry)
            .map_err(|e| e.to_string())?;
        if evidence.closing_world.is_empty()
            || evidence.closing_world.len() > 1024 * 1024
            || evidence.closing_block_commitment.is_empty()
            || evidence.closing_block_commitment.len() > 1024 * 1024
            || witness.timeout_certificates.len() > 128
            || !previous.contains_height(finalized.height)
            || finalized
                .height
                .checked_add(2)
                .is_none_or(|h| h > previous.epoch_end_height)
        {
            return Err("bounded exact epoch-closing admission evidence required".into());
        }
        witness
            .verified_timeout_closure(previous, registry, verifier)
            .map_err(|e| e.to_string())?;
        let mut finality = ThreeQcFinality::default();
        for qc in &witness.quorum_certificates {
            qc.verify(previous, registry, verifier)
                .map_err(|e| e.to_string())?;
            finality.accept(qc.clone()).map_err(|e| e.to_string())?;
        }
        if finality.last_finalized() != Some(finalized) {
            return Err("admission evidence lacks old-authority three-QC finality".into());
        }
        let block_id = synergy_block::hash_block_bytes(&evidence.closing_block_commitment);
        let (height, _parent, protected, state_root, _, _): (
            u64,
            String,
            String,
            String,
            serde::de::IgnoredAny,
            serde::de::IgnoredAny,
        ) = serde_json::from_slice(&evidence.closing_block_commitment)
            .map_err(|e| e.to_string())?;
        if block_id != finalized.block_id
            || height != finalized.height
            || protected != finalized.protected_execution_root
        {
            return Err("admission block differs from certified closure".into());
        }
        let world: synergy_state::WorldState =
            serde_json::from_slice(&evidence.closing_world).map_err(|e| e.to_string())?;
        if synergy_state::state_root(&world).map_err(|e| format!("{e:?}"))? != state_root
            || serde_json::to_vec(&world).map_err(|e| e.to_string())? != evidence.closing_world
        {
            return Err("admission World differs from certified block state".into());
        }
        Ok(Self {
            world,
            finalized: finalized.clone(),
        })
    }
    pub fn world(&self) -> &synergy_state::WorldState {
        &self.world
    }
    pub fn finalized(&self) -> &FinalizedBlockRecord {
        &self.finalized
    }
}

/// One verifier for the exact new-node identity and independent role-key proof.
/// Financial authorization and certified-source policy are checked separately.
pub fn verify_validator_admission_possession(
    request: &synergy_governance::ValidatorAdmissionRequest,
    chain_id: u64,
    genesis: &str,
    epoch: u64,
    context_root: &str,
    owner: &str,
    verifier: &synergy_aegis::ApqeIdentityVerifier,
) -> Result<(), synergy_aegis::VerificationError> {
    use synergy_aegis::VerificationError;
    let spec = &request.spec;
    spec.validate_shape()
        .map_err(|_| VerificationError::InvalidContext)?;
    if spec.chain_id != chain_id
        || spec.genesis_hash != genesis
        || spec.frozen_epoch != epoch
        || spec.frozen_epoch_context_root != context_root
        || spec.owner_wallet != owner
    {
        return Err(VerificationError::InvalidContext);
    }
    let hex = spec
        .identity_root_public_key
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if synergy_address::generate_validator_address(&hex, 1)
        .map_err(|_| VerificationError::InvalidPublicKey)?
        != spec.validator_id
    {
        return Err(VerificationError::InvalidPublicKey);
    }
    let message = spec
        .signing_bytes()
        .map_err(|_| VerificationError::InvalidContext)?;
    for (algorithm, key, signature) in [
        (
            "FN-DSA-1024",
            &spec.identity_root_public_key,
            &request.identity_root_signature,
        ),
        (
            "ML-DSA-65",
            &spec.consensus_public_key,
            &request.consensus_possession_signature,
        ),
        (
            "ML-DSA-65",
            &spec.transport_public_key,
            &request.transport_possession_signature,
        ),
    ] {
        verifier.verify_raw_classified(algorithm, key, &message, signature)?;
    }
    Ok(())
}

/// Compact transport of unchanged PoSy objects. Signature bytes use canonical
/// base64, avoiding nested decimal arrays; the verified QC bytes/IDs are intact.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorAdmissionSyncEvidence {
    pub version: u8,
    pub finalized: FinalizedBlockRecord,
    pub witness: FinalitySyncWitness,
}
fn map_sync_signatures(value: &mut serde_json::Value, compact: bool) -> Result<(), String> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if key == "signature" {
                    if compact {
                        let bytes: Vec<u8> = serde_json::from_value(value.clone())
                            .map_err(|_| "invalid PoSy signature bytes")?;
                        *value = serde_json::Value::String(
                            synergy_protocol_types::canonical_bytes::encode(&bytes)?,
                        );
                    } else {
                        let bytes = synergy_protocol_types::canonical_bytes::decode(
                            value
                                .as_str()
                                .ok_or("canonical PoSy signature encoding required")?,
                        )?;
                        *value = serde_json::to_value(bytes).map_err(|e| e.to_string())?;
                    }
                } else {
                    map_sync_signatures(value, compact)?;
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                map_sync_signatures(value, compact)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub fn encode_validator_admission_sync(
    finalized: &FinalizedBlockRecord,
    witness: &FinalitySyncWitness,
) -> Result<Vec<u8>, String> {
    if witness.timeout_certificates.len() > 128 {
        return Err("bounded sync timeout work required".into());
    }
    let doc = ValidatorAdmissionSyncEvidence {
        version: 1,
        finalized: finalized.clone(),
        witness: witness.clone(),
    };
    let mut value = serde_json::to_value(doc).map_err(|e| e.to_string())?;
    map_sync_signatures(&mut value, true)?;
    let bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("native sync proof exceeds original document bound".into());
    }
    Ok(bytes)
}
pub fn decode_validator_admission_sync(
    bytes: &[u8],
) -> Result<ValidatorAdmissionSyncEvidence, String> {
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err("bounded native sync proof required".into());
    }
    let mut value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "invalid compact native sync proof")?;
    if serde_json::to_vec(&value).map_err(|e| e.to_string())? != bytes {
        return Err("noncanonical compact native sync proof".into());
    }
    map_sync_signatures(&mut value, false)?;
    let doc: ValidatorAdmissionSyncEvidence =
        serde_json::from_value(value).map_err(|_| "invalid closed native sync proof")?;
    if doc.version != 1 || encode_validator_admission_sync(&doc.finalized, &doc.witness)? != bytes {
        return Err("invalid exact native sync proof".into());
    }
    Ok(doc)
}
