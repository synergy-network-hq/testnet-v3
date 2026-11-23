//! The live processing scheduler consumes protected intake and completion
//! records from the same native journal verifier used for restart replay.
use super::*;
use crate::services::processing_pipeline::NativeProcessingPipeline;
use std::collections::BTreeSet;
use synergy_posy::FinalizedBlockRecord;

const ACTION_REGISTRY: &str = "aee5e1e0cdc826fc00061d29696adfa291a878cd8689e8d247e49a2cef697bce";
const WIRE_SCHEMA: &str = "a80223355b314d20388c51beb6bb6b9b44d509b8d6282694fcf48bfac3dc3324";
const ACTION_VECTORS: &str = "4dfd6d62c1745785362ff494ae39f637f6f244aa52df5e3da239b251f387372f";

static QUICK_SETUP_CONTRACT: std::sync::LazyLock<[String; 3]> = std::sync::LazyLock::new(|| {
    use crate::services::apqe_transport::sha256;
    [
        sha256(include_bytes!("protected_quick_setup_registry.json")),
        sha256(include_bytes!("protected_quick_setup_wire.cddl")),
        sha256(include_bytes!("protected_quick_setup_vectors.json")),
    ]
});

pub(in crate::services::protected_accounts) fn require_dispatch_policy(
    authority: &VerifiedAuthority,
    genesis: &str,
    record: &FinalizedBlockRecord,
    expected: &ProtectedWalletDispatchPolicy,
) -> Result<(), String> {
    if !authority.processing_profile_enabled()
        || authority.wallet_dispatch_policy() != Some(expected)
    {
        return Err("authenticated authority does not select this Wallet action contract".into());
    }
    require_compiled_wallet_contract(expected)?;
    expected.check_finalized_source(genesis, record)
}

pub(in crate::services) fn require_compiled_wallet_contract(
    expected: &ProtectedWalletDispatchPolicy,
) -> Result<(), String> {
    let wire = super::super::inspection::candidate_wire_profile()?;
    let compiled = if expected.enrollment_wire_profile_fingerprint
        == super::super::inspection::hex_bytes(&wire.profile_fingerprint().map_err(debug)?)
    {
        [ACTION_REGISTRY, WIRE_SCHEMA, ACTION_VECTORS]
    } else if expected.enrollment_wire_profile_fingerprint
        == super::super::inspection::hex_bytes(&wire.dual_enrollment_profile_fingerprint().map_err(debug)?)
    {
        QUICK_SETUP_CONTRACT.each_ref().map(String::as_str)
    } else {
        return Err("authenticated authority selects an unsupported enrollment wire profile".into());
    };
    if [
        expected.action_registry_sha256.as_str(),
        expected.wire_schema_sha256.as_str(),
        expected.action_vectors_sha256.as_str(),
    ] != compiled
        || synergy_address::address_kind(&expected.fee_collector)
            != synergy_address::AddressKind::FeeCollector
    {
        return Err("authenticated authority does not select this Wallet action contract".into());
    }
    Ok(())
}

/// Prepared with native-owned storage and the original signed sources. The
/// constructor does not expose any journal or source insertion from RPC.
pub(in crate::services) struct NativeProtectedJournal<'a> {
    pending: &'a PendingProcessingStore<CandidateAdmission>,
    recovery: &'a ProtectedJournalRecovery<'a>,
    finalized: Pw13FinalizedSource<'a>,
    registry: &'a CandidateProtectedAccounts<'a>,
    policy: JournalPolicy<'a>,
}

enum JournalPolicy<'a> {
    Governed(&'a ProtectedWalletDispatchPolicy),
    #[cfg(test)]
    Fixture,
}

impl<'a> NativeProtectedJournal<'a> {
    pub(super) fn new(
        authority: &VerifiedAuthority,
        finalized: &'a NativeProcessingContext<'a>,
        registry: &'a CandidateProtectedAccounts<'a>,
        pending: &'a PendingProcessingStore<CandidateAdmission>,
        recovery: &'a ProtectedJournalRecovery<'a>,
    ) -> Result<Self, String> {
        let finalized = finalized.verified_finalized_source()?;
        let policy = finalized
            .authority
            .wallet_dispatch_policy()
            .ok_or("finalized Wallet dispatch policy is absent")?;
        require_dispatch_policy(authority, finalized.genesis_hash, finalized.record, policy)?;
        let activated = registry.activated_enrollment(policy)?;
        activated
            .require_activation(registry.native_finalized_snapshot(&finalized)?.context())
            .map_err(debug)?;
        for source in recovery.sources {
            if !std::ptr::eq(source.intake.registry, registry)
                || !matches!(source.intake.terms.metering, ProtectedMetering::Governed(original) if original == policy)
            {
                return Err(
                    "protected recovery does not retain the original governed Wallet policy".into(),
                );
            }
        }
        if registry.network.ownership_chain
            != synergy_posy::parse_hash_bytes(&policy.ownership_chain_id).map_err(debug)?
        {
            return Err(
                "protected account ownership domain differs from the authorized Wallet policy"
                    .into(),
            );
        }
        Ok(Self {
            pending,
            recovery,
            finalized,
            registry,
            policy: JournalPolicy::Governed(policy),
        })
    }

    #[cfg(test)]
    pub(in crate::services::protected_accounts) fn qualification(
        authority: &VerifiedAuthority,
        finalized: &'a NativeProcessingContext<'a>,
        registry: &'a CandidateProtectedAccounts<'a>,
        pending: &'a PendingProcessingStore<CandidateAdmission>,
        recovery: &'a ProtectedJournalRecovery<'a>,
    ) -> Result<Self, String> {
        if authority.wallet_dispatch_policy().is_some()
            || finalized
                .verified_finalized_source()?
                .authority
                .wallet_dispatch_policy()
                .is_some()
        {
            return Err("a qualification fixture requires the unactivated Wallet policy".into());
        }
        Ok(Self {
            pending,
            recovery,
            finalized: finalized.verified_finalized_source()?,
            registry,
            policy: JournalPolicy::Fixture,
        })
    }

    pub(in crate::services) fn prepare<'b>(
        &'b self,
        authority: &VerifiedAuthority,
        ordinary: &'b NativeProcessingPipeline<'b>,
        context: &synergy_execution::ProcessingCandidateContext<'b>,
        parent: &'b BudgetedWorld,
    ) -> Result<NativeProtectedDispatch<'b>, synergy_execution::ProcessingCandidateError> {
        use synergy_execution::ProcessingCandidateError::Invalid;
        match self.policy {
            JournalPolicy::Governed(policy) => {
                require_dispatch_policy(
                    authority,
                    self.finalized.genesis_hash,
                    self.finalized.record,
                    policy,
                )
                .map_err(Invalid)?;
            }
            #[cfg(test)]
            JournalPolicy::Fixture => {}
        }
        let finalized = self
            .registry
            .native_finalized_snapshot(&self.finalized)
            .map_err(Invalid)?;
        if context.height <= finalized.position.height
            || context.consensus_timestamp_unix < finalized.position.consensus_time
            || context.network.chain_id != authority.epoch.chain_id
            || context.network.network_id != authority.epoch.network_id
            || !std::ptr::eq(context.finalized_authorization_state, self.finalized.world)
        {
            return Err(Invalid(
                "Wallet dispatch has a different finalized execution source".into(),
            ));
        }
        let parameters = authority.protected_parameters().map_err(Invalid)?;
        if (context.maximum_gas, context.maximum_bytes)
            != (parameters.max_protected_gas, parameters.max_protected_bytes)
        {
            return Err(Invalid(
                "protected execution limits differ from authenticated authority".into(),
            ));
        }
        let registry = ParentProcessingRegistry::read(
            parent.as_ref(),
            context.namespace_root,
            parent.budget(),
        )?;
        let mut permit = parent
            .budget()
            .reserve(registry.records().len() * 256 + 16 * 1024)?;
        let mut owned = BTreeSet::new();
        for original in self.pending.pending_identities() {
            permit.grow(512)?;
            if ordinary.has_completion(&original.envelope_id) {
                return Err(Invalid(
                    "native Wallet carrier conflicts with ordinary completion".into(),
                ));
            }
            owned.insert(original.envelope_id.clone());
        }
        let mut dispositions = BTreeMap::new();
        for record in registry.records() {
            if owned.contains(&record.item.envelope_id) {
                if let Some(disposition) = self
                    .recovery
                    .disposition(self.pending, record, &finalized)
                    .map_err(Invalid)?
                {
                    dispositions.insert(record.item.envelope_id.clone(), disposition);
                }
            }
        }
        Ok(NativeProtectedDispatch {
            ordinary,
            originals: DispatchOriginals::Journal(self),
            parent,
            finalized,
            inclusion: Position {
                height: context.height,
                consensus_time: context.consensus_timestamp_unix,
            },
            parameters,
            owned,
            dispositions,
            _permit: permit,
        })
    }
}

pub(in crate::services) struct NativeProtectedDispatch<'a> {
    ordinary: &'a NativeProcessingPipeline<'a>,
    originals: DispatchOriginals<'a>,
    parent: &'a BudgetedWorld,
    finalized: FinalizedSnapshot<'a>,
    inclusion: Position,
    parameters: EtdagParameters,
    owned: BTreeSet<EtdagDigest>,
    dispositions: BTreeMap<EtdagDigest, Disposition>,
    _permit: WorldResourcePermit,
}

enum DispatchOriginals<'a> {
    Journal(&'a NativeProtectedJournal<'a>),
    Live {
        completions: BTreeMap<EtdagDigest, &'a NativeProtectedCompletion>,
        terms: ProtectedRecoveryTerms<'a>,
    },
}

impl NativeProtectedDispatch<'_> {
    fn slot(&self) -> CandidateSlot<'_> {
        CandidateSlot {
            inclusion: self.inclusion,
            finalized_parent: &self.finalized,
        }
    }

    fn with_action<T>(
        &self,
        record: &ProcessingReadyRecord,
        action: impl FnOnce(PreparedProtectedAction<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        match &self.originals {
            DispatchOriginals::Journal(owner) => owner.recovery.with_action(
                owner.pending,
                record,
                self.parent,
                &self.parameters,
                action,
            ),
            DispatchOriginals::Live { completions, terms } => completions
                .get(&record.item.envelope_id)
                .ok_or("protected Wallet READY lacks verified retained proof")?
                .with_action(self.parent, self.finalized.registry, *terms, action),
        }
    }

    pub(in crate::services) fn can_publish(
        &self,
        record: &ProcessingReadyRecord,
    ) -> Result<bool, String> {
        match &self.originals {
            DispatchOriginals::Live { completions, .. } => {
                let completion = completions
                    .get(&record.item.envelope_id)
                    .ok_or("Wallet publication lacks retained original")?;
                if completion.record != *record {
                    return Err("Wallet publication rewrites the durable original record".into());
                }
                if completion.original_position.height > self.finalized.position.height
                    || completion
                        .authorization
                        .terms()
                        .disposition(record, &self.finalized)?
                        .is_some()
                {
                    return Ok(false);
                }
                // Untrusted opened content cannot stop ordinary proposal
                // assembly. Any record actually published is checked again
                // by the required replay path using the same exact trial.
                Ok(self
                    .with_action(record, |action| {
                        action.verify_publication(self.parent, record, self.slot())
                    })
                    .is_ok())
            }
            DispatchOriginals::Journal(_) => Ok(false),
        }
    }
}

/// Build native dispatch from finalized proof and the originals persisted by
/// the live ETDAG worker before publication to the execution owner.
pub(in crate::services) fn with_live_wallet_dispatch<T>(
    authority: &VerifiedAuthority,
    ordinary: &NativeProcessingPipeline<'_>,
    context: &synergy_execution::ProcessingCandidateContext<'_>,
    parent: &BudgetedWorld,
    source: &NativeProcessingContext<'_>,
    captured: &[Arc<NativeProtectedCompletion>],
    execute: impl FnOnce(
        &NativeProtectedDispatch<'_>,
    ) -> Result<T, synergy_execution::ProcessingCandidateError>,
) -> Result<T, synergy_execution::ProcessingCandidateError> {
    use synergy_execution::ProcessingCandidateError::Invalid;

    with_native_wallet_registry(source, |registry, terms| {
        let native = source.verified_finalized_source()?;
        let finalized = registry.native_finalized_snapshot(&native)?;
        #[cfg(test)]
        let ProtectedMetering::Governed(policy) = terms.metering
        else {
            return Err("live Wallet dispatch requires authenticated metering".into());
        };
        #[cfg(not(test))]
        let ProtectedMetering::Governed(policy) = terms.metering;
        require_dispatch_policy(authority, native.genesis_hash, native.record, policy)?;
        let parameters = authority.protected_parameters()?;
        if context.height <= finalized.position.height
            || context.consensus_timestamp_unix < finalized.position.consensus_time
            || context.network.chain_id != authority.epoch.chain_id
            || context.network.network_id != authority.epoch.network_id
            || (context.maximum_gas, context.maximum_bytes)
                != (parameters.max_protected_gas, parameters.max_protected_bytes)
            || !std::ptr::eq(context.finalized_authorization_state, native.world)
        {
            return Err("live Wallet dispatch has a different finalized candidate source".into());
        }
        let mut permit = parent.budget().reserve(16 * 1024).map_err(debug)?;
        let mut completions = BTreeMap::new();
        for original in captured {
            permit.grow(1024).map_err(debug)?;
            let id = &original.record.item.envelope_id;
            if original.policy != *policy
                || ordinary.has_completion(id)
                || completions.insert(id.clone(), original.as_ref()).is_some()
            {
                return Err("conflicting protected Wallet completion or release".into());
            }
        }
        let owned = completions.keys().cloned().collect::<BTreeSet<_>>();
        let mut dispositions = BTreeMap::new();
        let records = ParentProcessingRegistry::read(
            parent.as_ref(),
            context.namespace_root,
            parent.budget(),
        )
        .map_err(debug)?;
        for record in records.records() {
            if let Some(original) = completions.get(&record.item.envelope_id) {
                if let Some(disposition) = original
                    .authorization
                    .terms()
                    .disposition(record, &finalized)?
                {
                    dispositions.insert(record.item.envelope_id.clone(), disposition);
                }
            }
        }
        let dispatch = NativeProtectedDispatch {
            ordinary,
            originals: DispatchOriginals::Live { completions, terms },
            parent,
            finalized,
            inclusion: Position {
                height: context.height,
                consensus_time: context.consensus_timestamp_unix,
            },
            parameters,
            owned,
            dispositions,
            _permit: permit,
        };
        Ok(execute(&dispatch))
    })
    .map_err(Invalid)?
}

impl ProcessingReadinessVerifier for NativeProtectedDispatch<'_> {
    fn first_unconsumed_position(
        &self,
        record: &ProcessingReadyRecord,
        parent: &WorldState,
    ) -> Result<Option<u32>, String> {
        self.ordinary.first_unconsumed_position(record, parent)
    }

    fn verify_ordered_group(
        &self,
        group: &synergy_etdag::execution::ProcessingOrderGroup,
        parent: &WorldState,
    ) -> Result<(), String> {
        self.ordinary.verify_ordered_group(group, parent)
    }

    fn verify_publication(
        &self,
        record: &ProcessingReadyRecord,
        parent: &WorldState,
    ) -> Result<(), String> {
        if !self.owns(record) {
            return self.ordinary.verify_publication(record, parent);
        }
        if !std::ptr::eq(parent, self.parent.as_ref()) {
            return Err("protected publication belongs to a different parent".into());
        }
        self.with_action(record, |action| {
            action.verify_publication(self.parent, record, self.slot())
        })
    }

    fn identity_is_current(
        &self,
        record: &ProcessingReadyRecord,
        parent: &WorldState,
    ) -> Result<bool, String> {
        if !self.owns(record) {
            return self.ordinary.identity_is_current(record, parent);
        }
        if !std::ptr::eq(parent, self.parent.as_ref()) {
            return Err("protected eligibility belongs to a different parent".into());
        }
        Ok(parent
            .accounts
            .get(&record.sender_wallet)
            .is_some_and(|account| {
                account.code_hash.is_none() && account.nonce <= record.sender_nonce
            }))
    }

    fn retires_without_nonce(&self, record: &ProcessingReadyRecord) -> bool {
        self.dispositions.contains_key(&record.item.envelope_id)
    }
}

impl ProcessingNativeWalletActions for NativeProtectedDispatch<'_> {
    fn owns(&self, record: &ProcessingReadyRecord) -> bool {
        self.owned.contains(&record.item.envelope_id)
    }

    fn execute(
        &self,
        record: &ProcessingReadyRecord,
        parent: &BudgetedWorld,
        candidate: &mut BudgetedWorld,
    ) -> Result<(), BlockExecutionError> {
        let expect_parent = std::ptr::eq(parent, self.parent);
        let mut run = || -> Result<(), String> {
            if !expect_parent || !self.owns(record) {
                return Err(
                    "protected execution has a different candidate parent or original".into(),
                );
            }
            let disposition = self.dispositions.get(&record.item.envelope_id).copied();
            self.with_action(record, |action| {
                action.verify_selection(parent, record)?;
                action
                    .execute_selected(candidate, self.slot(), disposition)
                    .map(drop)
            })
        };
        run().map_err(|message| BlockExecutionError::Dispatcher {
            transaction_index: record.item.order_position as usize,
            message,
        })
    }
}
