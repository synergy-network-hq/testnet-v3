//! Closed public schemas for the original finalized Wallet World preimage.
use super::*;
use synergy_genesis::authority::ProtectedWalletDispatchPolicy;

pub(in crate::services) struct PublicWalletRecords {
    network: Network,
    wire: UnactivatedWireProfile,
    activation: u64,
    height: u64,
    permits_primary_companion: bool,
    allowed_providers: Vec<[u8; 32]>,
}

impl PublicWalletRecords {
    pub(in crate::services) fn new(
        policy: &ProtectedWalletDispatchPolicy,
        genesis: &str,
        finalized: &FinalizedBlockRecord,
    ) -> Result<Self, String> {
        processing_execution::native::require_compiled_wallet_contract(policy)?;
        policy.check_finalized_source(genesis, finalized)?;
        let parse = |hash: &str| synergy_posy::parse_hash_bytes(hash).map_err(display);
        let wire = inspection::candidate_wire_profile()?;
        let permits_primary_companion = inspection::hex_bytes(
            &wire
                .dual_enrollment_profile_fingerprint()
                .map_err(display)?,
        ) == policy.enrollment_wire_profile_fingerprint;
        let allowed_providers = policy
            .enrollment_provider_manifests
            .iter()
            .map(|pin| parse(pin))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            network: Network {
                native_chain: *ChainId::from_u64(policy.chain_id).as_be_bytes(),
                genesis: parse(genesis)?,
                ownership_chain: parse(&policy.ownership_chain_id)?,
            },
            wire,
            activation: policy.activation_finalized_height,
            height: finalized.height,
            permits_primary_companion,
            allowed_providers,
        })
    }

    pub(super) fn matches(&self, network: &Network, included: u64) -> bool {
        self.network == *network && (self.activation..=self.height).contains(&included)
    }
}

#[cfg(test)]
impl PublicWalletRecords {
    pub(in crate::services) fn fixture_commit(&self, commitment: [u8; 32]) -> (String, Vec<u8>) {
        let record = CommitRecord {
            network: self.network,
            commitment,
            included_height: self.height,
            consensus_time: 1,
            consumed: false,
        };
        (
            commit_key(EnrollmentCommitment::from_bytes(commitment)),
            encode(&record).unwrap(),
        )
    }
}

pub(in crate::services) fn validate_public_wallet_record(
    scope: &PublicWalletRecords,
    world: &WorldState,
    key: &str,
    bytes: &[u8],
) -> Result<bool, String> {
    if key.starts_with(COMMIT_PREFIX) {
        let record: CommitRecord = decode(bytes, MAX_STORED_COMMIT_BYTES)?;
        if !scope.matches(&record.network, record.included_height)
            || record.consensus_time == 0
            || record.commitment == [0; 32]
            || key != commit_key(EnrollmentCommitment::from_bytes(record.commitment))
            || encode(&record)? != bytes
        {
            return Err("invalid public protected commitment record".into());
        }
        return Ok(true);
    }
    if key.starts_with(ACCOUNT_PREFIX) {
        let record: PolicyRecord = decode(bytes, MAX_STORED_POLICY_BYTES)?;
        let account = AccountIdentifier::from_bytes(record.account);
        if !scope.matches(&record.network, record.registered_height)
            || record.replacement_policy.is_some()
            || record.native_recovery_since.is_some()
            || key != account_key(account)
            || encode(&record)? != bytes
        {
            return Err("unqualified public protected policy record".into());
        }
        let enrollment =
            policy_variant::InitialEnrollment::decode(&record.enrollment, &scope.wire)?;
        let (policy, canonical) = match &enrollment {
            policy_variant::InitialEnrollment::WithRecovery(initial) => (
                policy_variant::PolicyTerms::from(initial.policy()),
                CanonicalPublicPolicy::decode(initial.canonical_policy(), &scope.wire).map_err(display)?.hash().map_err(display)?,
            ),
            policy_variant::InitialEnrollment::PrimaryCompanion(initial) if scope.permits_primary_companion => (
                policy_variant::PolicyTerms::from(initial.policy()),
                synergy_address_engine::apqe::enrollment::CanonicalPrimaryCompanionPublicPolicy::decode(
                    initial.canonical_policy(), &scope.wire,
                ).map_err(display)?.hash().map_err(display)?,
            ),
            _ => return Err("release has no two-role protected enrollment disclosure".into()),
        };
        if policy.genesis.as_bytes() != &scope.network.genesis
            || policy.account != account
            || policy.policy_epoch != record.policy_epoch
            || canonical != record.policy_hash
            || !scope
                .allowed_providers
                .contains(&policy.provider_manifest_hash)
        {
            return Err("unqualified public protected policy record".into());
        }
        return Ok(true);
    }
    if let Some(id)=key.strip_prefix(synergy_etdag::admission::FEE_FREE_SYNID_SETTLEMENT_PREFIX) {
        use synergy_etdag::admission::*;
        let record:FeeFreeSynIdSettlement=decode(bytes,8192)?;
        if encode(&record)?!=bytes||record.version!=1||record.genesis!=scope.network.genesis
            ||record.account==[0;20]||record.fee_nwei!=0||record.gas_used==0||record.admission_digest.len()!=64
            ||record.source_finalized_height==0||record.source_finalized_height>=record.included_height
            ||record.deciding_finalized_height<record.source_finalized_height||record.deciding_finalized_height>=record.included_height
            ||record.included_height>scope.height||record.included_height<scope.activation
            ||record.envelope_id.0!=id||record.envelope_id.is_zero()||record.envelope_id.validate().is_err()
            ||synergy_naming::normalize_wallet_syn_id(&record.syn_id)?!=record.syn_id {return Err("invalid public fee-free SynID record".into());}
    } else if key.starts_with(synergy_etdag::admission::FEE_FREE_ENROLLMENT_SETTLEMENT_PREFIX) {
        use synergy_etdag::admission::*;
        let record:FeeFreeEnrollmentSettlement=decode(bytes,8192)?;
        if encode(&record)?!=bytes || record.version!=1 || record.genesis!=scope.network.genesis
            || record.account==[0;20] || record.commitment==[0;32] || record.session_id==[0;32]
            || record.fee_nwei!=0 || record.gas_used==0 || record.admission_digest.len()!=64
            || record.source_finalized_height==0 || record.source_finalized_height>=record.included_height
            || record.deciding_finalized_height<record.source_finalized_height
            || record.deciding_finalized_height>=record.included_height
            || record.included_height>scope.height || record.included_height<scope.activation
            || record.source_consensus_timestamp_unix==0
            || record.inclusion_consensus_timestamp_unix<record.source_consensus_timestamp_unix
            || fee_free_enrollment_settlement_key(&record.session_id,record.action).map_err(debug)?!=key
            || record.envelope_id.is_zero() || record.envelope_id.validate().is_err()
            || !matches!((record.action,&record.outcome),
                (FEE_FREE_ENROLL_COMMIT,FeeFreeEnrollmentOutcome::CommitApplied|FeeFreeEnrollmentOutcome::CommitAlreadyPresent|FeeFreeEnrollmentOutcome::Expired)
                |(FEE_FREE_ENROLL_REVEAL,FeeFreeEnrollmentOutcome::RevealApplied|FeeFreeEnrollmentOutcome::RevealRejectedCommitUsed|FeeFreeEnrollmentOutcome::Expired))
        {return Err("invalid public fee-free enrollment settlement".into());}
    } else if sponsor_settlement::owns_key(key) {
        sponsor_settlement::validate_public_record(scope, key, bytes)?;
    } else if settlement::owns_key(key) {
        settlement::validate_public_record(scope, key, bytes)?;
    } else if processing_disposition::owns_key(key) {
        processing_disposition::validate_public_record(scope, key, bytes)?;
    } else if !processing_execution::retirement::validate_public_record(
        world,
        key,
        bytes,
        scope.height,
    )? {
        return Ok(false);
    }
    Ok(true)
}
