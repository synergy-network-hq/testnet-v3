//! Canonical policy lookup for either initial enrollment variant.
use super::*;
use synergy_address_engine::apqe::enrollment::{
    AccountPublicPolicy, CanonicalPrimaryCompanionEnrollment,
    CanonicalPrimaryCompanionPublicPolicy, RoleRecord,
    native_recovery::CanonicalNativeRecoveryPublicPolicy,
};

pub(super) enum InitialEnrollment<'a> {
    WithRecovery(CanonicalEnrollment<'a>),
    PrimaryCompanion(CanonicalPrimaryCompanionEnrollment<'a>),
}

impl<'a> InitialEnrollment<'a> {
    pub(super) fn decode(
        bytes: &'a [u8],
        wire: &'a UnactivatedWireProfile,
    ) -> Result<Self, String> {
        match bytes.get(..3) {
            Some([0xaa, 0, 1]) => CanonicalEnrollment::decode(bytes, wire)
                .map(Self::WithRecovery)
                .map_err(display),
            Some([0xaa, 0, 2]) => CanonicalPrimaryCompanionEnrollment::decode(bytes, wire)
                .map(Self::PrimaryCompanion)
                .map_err(display),
            _ => Err("unknown protected enrollment shape".into()),
        }
    }

    pub(super) fn primary_companion(&self) -> bool {
        matches!(self, Self::PrimaryCompanion(_))
    }

    fn terms(&self) -> (PolicyTerms<'_>, &'a [u8]) {
        match self {
            Self::WithRecovery(enrollment) => (
                PolicyTerms::from(enrollment.policy()),
                enrollment.canonical_policy(),
            ),
            Self::PrimaryCompanion(enrollment) => (
                PolicyTerms::from(enrollment.policy()),
                enrollment.canonical_policy(),
            ),
        }
    }
}

pub(super) enum CurrentPolicy<'a> {
    WithRecovery(CanonicalPublicPolicy<'a>),
    PrimaryCompanion(CanonicalPrimaryCompanionPublicPolicy<'a>),
    NativeOnlyRecovery(CanonicalNativeRecoveryPublicPolicy<'a>),
}

#[derive(Clone, Copy)]
pub(super) struct PolicyTerms<'a> {
    pub(super) genesis: NativeGenesisHash,
    pub(super) account: AccountIdentifier,
    pub(super) policy_epoch: u64,
    pub(super) roles: &'a [RoleRecord<'a>],
    pub(super) evm_public_key: &'a [u8; 65],
    pub(super) provider_manifest_hash: [u8; 32],
}

impl<'a, const N: usize> From<&'a AccountPublicPolicy<'a, N>> for PolicyTerms<'a> {
    fn from(policy: &'a AccountPublicPolicy<'a, N>) -> Self {
        Self {
            genesis: policy.genesis,
            account: policy.account,
            policy_epoch: policy.policy_epoch,
            roles: &policy.roles,
            evm_public_key: &policy.evm_public_key,
            provider_manifest_hash: policy.provider_manifest_hash,
        }
    }
}

impl<'a> CurrentPolicy<'a> {
    pub(super) fn encoded(&self) -> &'a [u8] {
        match self {
            Self::WithRecovery(policy) => policy.encoded(),
            Self::PrimaryCompanion(policy) => policy.encoded(),
            Self::NativeOnlyRecovery(policy) => policy.encoded(),
        }
    }

    pub(super) fn terms(&self) -> PolicyTerms<'_> {
        match self {
            Self::WithRecovery(policy) => PolicyTerms::from(policy.policy()),
            Self::PrimaryCompanion(policy) => PolicyTerms::from(policy.policy()),
            Self::NativeOnlyRecovery(policy) => PolicyTerms::from(policy.policy()),
        }
    }

    pub(super) fn with_recovery(&self) -> Result<&CanonicalPublicPolicy<'a>, String> {
        match self {
            Self::WithRecovery(policy) => Ok(policy),
            Self::PrimaryCompanion(_) => Err("protected account recovery is unset".into()),
            Self::NativeOnlyRecovery(_) => {
                Err("protected account permits native recovery only".into())
            }
        }
    }

    fn hash(&self) -> Result<[u8; 32], String> {
        match self {
            Self::WithRecovery(policy) => policy.hash(),
            Self::PrimaryCompanion(policy) => policy.hash(),
            Self::NativeOnlyRecovery(policy) => policy.hash(),
        }
        .map_err(display)
    }

    pub(super) fn native(
        &self,
        coordinate: NativeAccountCoordinate,
        epoch: u64,
        policy_hash: [u8; 32],
    ) -> Result<NativePolicy, String> {
        let enrolled = |role, record: RoleRecord<'_>| {
            Ok::<_, String>(EnrolledRole {
                role,
                participant_id: record.participant_id,
                public_key: PublicKey::from_bytes(record.auth_public_key).map_err(debug)?,
            })
        };
        match self {
            Self::WithRecovery(policy) => {
                let [d, p, r] = policy.policy().roles;
                NativePolicy::from_authenticated_enrollment(
                    coordinate,
                    epoch,
                    policy_hash,
                    [
                        enrolled(Role::D, d)?,
                        enrolled(Role::P, p)?,
                        enrolled(Role::R, r)?,
                    ],
                )
                .map_err(display)
            }
            Self::PrimaryCompanion(policy) => {
                let [d, p] = policy.policy().roles;
                NativePolicy::from_authenticated_primary_companion(
                    coordinate,
                    epoch,
                    policy_hash,
                    [enrolled(Role::D, d)?, enrolled(Role::P, p)?],
                )
                .map_err(display)
            }
            Self::NativeOnlyRecovery(policy) => {
                policy.native_policy(coordinate.chain_id).map_err(display)
            }
        }
    }
}

impl CandidateProtectedAccounts<'_> {
    pub(super) fn current_policy<'p>(
        &'p self,
        record: &'p PolicyRecord,
    ) -> Result<CurrentPolicy<'p>, String> {
        let initial = InitialEnrollment::decode(&record.enrollment, self.wire)?;
        let (original, encoded) = initial.terms();
        let bytes = match &record.replacement_policy {
            Some(policy) if record.policy_epoch > original.policy_epoch => policy,
            None if record.policy_epoch == original.policy_epoch => encoded,
            _ => return Err("protected policy epoch has no matching policy source".into()),
        };
        let policy = match bytes.get(..3) {
            // A two-role origin cannot claim recovery through a substituted
            // policy. No qualified original-share attachment proof is admitted.
            Some([0xab, 0, 1])
                if !initial.primary_companion() && record.native_recovery_since.is_none() =>
            {
                CurrentPolicy::WithRecovery(
                    CanonicalPublicPolicy::decode(bytes, self.wire).map_err(display)?,
                )
            }
            Some([0xaa, 0, 2])
                if initial.primary_companion() && record.native_recovery_since.is_none() =>
            {
                CurrentPolicy::PrimaryCompanion(
                    CanonicalPrimaryCompanionPublicPolicy::decode(bytes, self.wire)
                        .map_err(display)?,
                )
            }
            Some([0xac, 0, 3])
                if initial.primary_companion()
                    && record
                        .native_recovery_since
                        .is_some_and(|height| height > record.registered_height) =>
            {
                let policy = CanonicalNativeRecoveryPublicPolicy::decode(bytes, self.wire)
                    .map_err(display)?;
                if policy.policy().provider_manifest_hash != original.provider_manifest_hash {
                    return Err(
                        "native-only recovery changes the original threshold provider".into(),
                    );
                }
                CurrentPolicy::NativeOnlyRecovery(policy)
            }
            _ => return Err("invalid protected policy profile transition".into()),
        };
        let current = policy.terms();
        if original.genesis != self.chain.native_genesis()
            || original.account.as_bytes() != &record.account
            || current.genesis != original.genesis
            || current.account != original.account
            || current.evm_public_key != original.evm_public_key
            || current.policy_epoch != record.policy_epoch
            || policy.hash()? != record.policy_hash
        {
            return Err("protected account policy does not match its canonical state".into());
        }
        Ok(policy)
    }
}
