use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use synergy_posy::{
    canonical_hash, is_hash, FrozenValidatorRegistry, MembershipAuthority, ScheduledDeactivation,
    ScheduledExpulsion, ScheduledJailing, SlashingDecision, ValidatorId, ValidatorRegistration,
    ValidatorStatus,
};

use crate::{
    schedule_expulsion, schedule_jailing, schedule_removal, schedule_slashing,
    stage_shadow_registration, ActivationRequest, ActiveMembershipWitness, ValidatorApplication,
    ValidatorLifecycle, ValidatorLifecycleState, ValidatorManagementStore,
};

const MANAGEMENT_SCHEMA_VERSION: u16 = 1;
const MAX_APPLIED_COMMANDS: usize = 1024;
const MAX_SLASHING_DECISIONS_PER_VALIDATOR: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedValidatorRecord {
    pub lifecycle: ValidatorLifecycle,
    pub application: Option<ValidatorApplication>,
    pub shadow_registration: Option<ValidatorRegistration>,
    pub activation: Option<ActivationRequest>,
    pub scheduled_jailing: Option<ScheduledJailing>,
    pub scheduled_deactivation: Option<ScheduledDeactivation>,
    pub scheduled_expulsion: Option<ScheduledExpulsion>,
    pub slashing_decisions: Vec<SlashingDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorManagementReceipt {
    pub sequence: u64,
    pub validator_id: ValidatorId,
    pub state: ValidatorLifecycleState,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorManagementResult {
    pub receipt: ValidatorManagementReceipt,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ValidatorManagementCommand {
    Onboard {
        current_epoch: u64,
        application: ValidatorApplication,
        required_shadow_blocks: u64,
    },
    Authorize {
        validator_id: ValidatorId,
    },
    BeginSynchronization {
        validator_id: ValidatorId,
    },
    EnterShadow {
        validator_id: ValidatorId,
        authority: MembershipAuthority,
        frozen_voting_weight: u128,
    },
    RecordShadowProgress {
        validator_id: ValidatorId,
        verified_blocks: u64,
    },
    MarkReady {
        validator_id: ValidatorId,
    },
    ScheduleActivation {
        validator_id: ValidatorId,
        authority: MembershipAuthority,
    },
    ConfirmFrozenAuthority {
        validator_id: ValidatorId,
    },
    ScheduleJailing {
        validator_id: ValidatorId,
        evidence_root: String,
        current_epoch: u64,
        effective_epoch: u64,
        release_epoch: Option<u64>,
        authorization_root: String,
    },
    ScheduleDeactivation {
        validator_id: ValidatorId,
        current_epoch: u64,
        effective_epoch: u64,
        authorization_root: String,
    },
    ScheduleExpulsion {
        validator_id: ValidatorId,
        evidence_root: String,
        current_epoch: u64,
        effective_epoch: u64,
        authorization_root: String,
    },
    ScheduleSlashing {
        validator_id: ValidatorId,
        evidence_root: String,
        penalty_units: u128,
        current_epoch: u64,
        effective_epoch: u64,
        authorization_root: String,
    },
}

impl ValidatorManagementCommand {
    fn validator_id(&self) -> &str {
        match self {
            Self::Onboard { application, .. } => &application.validator_id,
            Self::Authorize { validator_id }
            | Self::BeginSynchronization { validator_id }
            | Self::EnterShadow { validator_id, .. }
            | Self::RecordShadowProgress { validator_id, .. }
            | Self::MarkReady { validator_id }
            | Self::ScheduleActivation { validator_id, .. }
            | Self::ConfirmFrozenAuthority { validator_id }
            | Self::ScheduleJailing { validator_id, .. }
            | Self::ScheduleDeactivation { validator_id, .. }
            | Self::ScheduleExpulsion { validator_id, .. }
            | Self::ScheduleSlashing { validator_id, .. } => validator_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AppliedCommand {
    fingerprint: String,
    receipt: ValidatorManagementReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ValidatorManagementSnapshot {
    schema_version: u16,
    sequence: u64,
    records: BTreeMap<ValidatorId, ManagedValidatorRecord>,
    applied_commands: BTreeMap<String, AppliedCommand>,
}

impl Default for ValidatorManagementSnapshot {
    fn default() -> Self {
        Self {
            schema_version: MANAGEMENT_SCHEMA_VERSION,
            sequence: 0,
            records: BTreeMap::new(),
            applied_commands: BTreeMap::new(),
        }
    }
}

/// Canonical operational owner for validator lifecycle changes. Decisions are
/// staged for future epochs; only frozen PoSy membership can make them active.
pub struct PersistentValidatorManagement<S> {
    store: S,
    snapshot: ValidatorManagementSnapshot,
    encoded: Vec<u8>,
}

impl<S: ValidatorManagementStore> PersistentValidatorManagement<S> {
    pub fn load(mut store: S) -> Result<Self, String> {
        match store.load()? {
            Some(encoded) => {
                let snapshot: ValidatorManagementSnapshot = serde_json::from_slice(&encoded)
                    .map_err(|error| format!("decode validator management state: {error}"))?;
                validate_snapshot(&snapshot)?;
                Ok(Self {
                    store,
                    snapshot,
                    encoded,
                })
            }
            None => {
                let snapshot = ValidatorManagementSnapshot::default();
                let encoded = encode_snapshot(&snapshot)?;
                store.compare_and_swap(None, &encoded)?;
                Ok(Self {
                    store,
                    snapshot,
                    encoded,
                })
            }
        }
    }

    pub fn record(&self, validator_id: &str) -> Option<&ManagedValidatorRecord> {
        self.snapshot.records.get(validator_id)
    }

    pub fn execute(
        &mut self,
        idempotency_key: &str,
        command: ValidatorManagementCommand,
        frozen_registry: Option<&FrozenValidatorRegistry>,
    ) -> Result<ValidatorManagementResult, String> {
        if idempotency_key.trim().is_empty() || idempotency_key.len() > 256 {
            return Err("validator command requires a bounded idempotency key".into());
        }
        let fingerprint = canonical_hash("Synergy/ValidatorManagement/v1/command", &command)
            .map_err(|error| error.to_string())?;
        if let Some(applied) = self.snapshot.applied_commands.get(idempotency_key) {
            if applied.fingerprint != fingerprint {
                return Err("validator idempotency key was reused for a different command".into());
            }
            return Ok(ValidatorManagementResult {
                receipt: applied.receipt.clone(),
                replayed: true,
            });
        }

        let mut next = self.snapshot.clone();
        let validator_id = command.validator_id().to_string();
        let detail = apply_command(&mut next, command, frozen_registry)?;
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or_else(|| "validator management sequence overflow".to_string())?;
        let state = next
            .records
            .get(&validator_id)
            .ok_or_else(|| "validator management record disappeared".to_string())?
            .lifecycle
            .state;
        let receipt = ValidatorManagementReceipt {
            sequence: next.sequence,
            validator_id,
            state,
            detail,
        };
        next.applied_commands.insert(
            idempotency_key.to_string(),
            AppliedCommand {
                fingerprint,
                receipt: receipt.clone(),
            },
        );
        prune_applied_commands(&mut next.applied_commands);
        self.persist(next)?;
        Ok(ValidatorManagementResult {
            receipt,
            replayed: false,
        })
    }

    /// Reconciles persisted operational records after loading a new frozen
    /// epoch. A scheduled decision cannot take effect by itself.
    pub fn reconcile_frozen_authority(
        &mut self,
        registry: &FrozenValidatorRegistry,
    ) -> Result<(), String> {
        let mut next = self.snapshot.clone();
        let mut changed = false;
        for validator in registry.active() {
            if !next.records.contains_key(&validator.validator_id) {
                next.records.insert(
                    validator.validator_id.clone(),
                    ManagedValidatorRecord {
                        lifecycle: ValidatorLifecycle {
                            validator_id: validator.validator_id.clone(),
                            state: ValidatorLifecycleState::Active,
                            target_epoch: registry.epoch(),
                            required_shadow_blocks: 1,
                            shadow_progress_blocks: 1,
                        },
                        application: None,
                        shadow_registration: None,
                        activation: None,
                        scheduled_jailing: None,
                        scheduled_deactivation: None,
                        scheduled_expulsion: None,
                        slashing_decisions: Vec::new(),
                    },
                );
                changed = true;
            }
        }

        for record in next.records.values_mut() {
            let status = registry
                .validator(&record.lifecycle.validator_id)
                .ok()
                .map(|validator| validator.status);
            if record.lifecycle.state == ValidatorLifecycleState::ActivationScheduled
                && record.lifecycle.target_epoch == registry.epoch()
                && status == Some(ValidatorStatus::Active)
            {
                let frozen = registry
                    .active_validator(&record.lifecycle.validator_id)
                    .map_err(|error| error.to_string())?;
                require_staged_binding(record, frozen)?;
                record.lifecycle.transition(
                    ValidatorLifecycleState::Active,
                    Some(&FrozenRegistryWitness(registry)),
                )?;
                changed = true;
            } else if record
                .scheduled_jailing
                .as_ref()
                .is_some_and(|decision| decision.effective_epoch <= registry.epoch())
                && status == Some(ValidatorStatus::Jailed)
                && record.lifecycle.state != ValidatorLifecycleState::Jailed
            {
                record.lifecycle.state = ValidatorLifecycleState::Jailed;
                changed = true;
            } else if record
                .scheduled_expulsion
                .as_ref()
                .is_some_and(|decision| decision.effective_epoch <= registry.epoch())
                && status == Some(ValidatorStatus::Removed)
                && record.lifecycle.state != ValidatorLifecycleState::Expelled
            {
                record.lifecycle.state = ValidatorLifecycleState::Expelled;
                changed = true;
            } else if record
                .scheduled_deactivation
                .as_ref()
                .is_some_and(|decision| decision.effective_epoch <= registry.epoch())
                && status == Some(ValidatorStatus::Removed)
                && record.lifecycle.state != ValidatorLifecycleState::Removed
            {
                record.lifecycle.state = ValidatorLifecycleState::Removed;
                changed = true;
            }
        }
        if changed {
            self.persist(next)?;
        }
        Ok(())
    }

    fn persist(&mut self, next: ValidatorManagementSnapshot) -> Result<(), String> {
        let replacement = encode_snapshot(&next)?;
        self.store
            .compare_and_swap(Some(&self.encoded), &replacement)?;
        self.snapshot = next;
        self.encoded = replacement;
        Ok(())
    }
}

fn apply_command(
    snapshot: &mut ValidatorManagementSnapshot,
    command: ValidatorManagementCommand,
    frozen_registry: Option<&FrozenValidatorRegistry>,
) -> Result<String, String> {
    match command {
        ValidatorManagementCommand::Onboard {
            current_epoch,
            application,
            required_shadow_blocks,
        } => {
            application.validate(current_epoch)?;
            let expected_epoch = current_epoch
                .checked_add(1)
                .ok_or_else(|| "validator target epoch overflow".to_string())?;
            if application.target_epoch != expected_epoch {
                return Err("validator onboarding must target the next frozen epoch".into());
            }
            if snapshot.records.contains_key(&application.validator_id) {
                return Err("validator lifecycle already exists".into());
            }
            let lifecycle = ValidatorLifecycle::new(
                application.validator_id.clone(),
                application.target_epoch,
                required_shadow_blocks,
            )?;
            snapshot.records.insert(
                application.validator_id.clone(),
                ManagedValidatorRecord {
                    lifecycle,
                    application: Some(application),
                    shadow_registration: None,
                    activation: None,
                    scheduled_jailing: None,
                    scheduled_deactivation: None,
                    scheduled_expulsion: None,
                    slashing_decisions: Vec::new(),
                },
            );
            Ok("validator application durably registered".into())
        }
        ValidatorManagementCommand::Authorize { validator_id } => {
            transition(
                snapshot,
                &validator_id,
                ValidatorLifecycleState::Authorized,
                None,
            )?;
            Ok("validator application authorized".into())
        }
        ValidatorManagementCommand::BeginSynchronization { validator_id } => {
            transition(
                snapshot,
                &validator_id,
                ValidatorLifecycleState::Synchronizing,
                None,
            )?;
            Ok("validator synchronization started".into())
        }
        ValidatorManagementCommand::EnterShadow {
            validator_id,
            authority,
            frozen_voting_weight,
        } => {
            let record = required_record(snapshot, &validator_id)?;
            let application = record
                .application
                .clone()
                .ok_or_else(|| "validator application is unavailable".to_string())?;
            record.shadow_registration = Some(stage_shadow_registration(
                application,
                &authority,
                frozen_voting_weight,
            )?);
            record
                .lifecycle
                .transition(ValidatorLifecycleState::Shadowing, None::<&NoActiveWitness>)?;
            Ok("validator shadow registration staged".into())
        }
        ValidatorManagementCommand::RecordShadowProgress {
            validator_id,
            verified_blocks,
        } => {
            required_record(snapshot, &validator_id)?
                .lifecycle
                .record_shadow_progress(verified_blocks)?;
            Ok("verified shadow progress recorded".into())
        }
        ValidatorManagementCommand::MarkReady { validator_id } => {
            transition(
                snapshot,
                &validator_id,
                ValidatorLifecycleState::Ready,
                None,
            )?;
            Ok("validator shadowing requirements satisfied".into())
        }
        ValidatorManagementCommand::ScheduleActivation {
            validator_id,
            authority,
        } => {
            let request = ActivationRequest {
                validator_id: validator_id.clone(),
                target_epoch: authority.target_epoch,
                membership_authority_id: authority.id().map_err(|error| error.to_string())?,
            };
            request.validate(&authority)?;
            let record = required_record(snapshot, &validator_id)?;
            record.activation = Some(request);
            record.lifecycle.transition(
                ValidatorLifecycleState::ActivationScheduled,
                None::<&NoActiveWitness>,
            )?;
            Ok("validator activation staged for the authorized epoch".into())
        }
        ValidatorManagementCommand::ConfirmFrozenAuthority { validator_id } => {
            let registry = frozen_registry
                .ok_or_else(|| "frozen PoSy registry is required for activation".to_string())?;
            let record = required_record(snapshot, &validator_id)?;
            if record.lifecycle.target_epoch != registry.epoch() {
                return Err("frozen PoSy registry epoch does not match activation target".into());
            }
            let frozen = registry
                .active_validator(&validator_id)
                .map_err(|error| error.to_string())?;
            if record
                .application
                .as_ref()
                .is_some_and(|application| application.consensus_key_id != frozen.consensus_key_id)
                || record
                    .shadow_registration
                    .as_ref()
                    .is_some_and(|registration| {
                        registration.validator.validator_id != frozen.validator_id
                            || registration.validator.consensus_key_id != frozen.consensus_key_id
                            || registration.validator.frozen_voting_weight
                                != frozen.frozen_voting_weight
                    })
            {
                return Err(
                    "frozen PoSy authority differs from the staged validator binding".into(),
                );
            }
            record.lifecycle.transition(
                ValidatorLifecycleState::Active,
                Some(&FrozenRegistryWitness(registry)),
            )?;
            Ok("frozen PoSy registry confirmed active authority".into())
        }
        ValidatorManagementCommand::ScheduleJailing {
            validator_id,
            evidence_root,
            current_epoch,
            effective_epoch,
            release_epoch,
            authorization_root,
        } => {
            let decision = schedule_jailing(
                validator_id.clone(),
                evidence_root,
                current_epoch,
                effective_epoch,
                release_epoch,
                authorization_root,
            )?;
            require_current_or_jailed(snapshot, &validator_id)?.scheduled_jailing = Some(decision);
            Ok("validator jailing staged for a future epoch".into())
        }
        ValidatorManagementCommand::ScheduleDeactivation {
            validator_id,
            current_epoch,
            effective_epoch,
            authorization_root,
        } => {
            let decision = schedule_removal(
                validator_id.clone(),
                current_epoch,
                effective_epoch,
                authorization_root,
            )?;
            require_current_or_jailed(snapshot, &validator_id)?.scheduled_deactivation =
                Some(decision);
            Ok("validator deactivation staged for a future epoch".into())
        }
        ValidatorManagementCommand::ScheduleExpulsion {
            validator_id,
            evidence_root,
            current_epoch,
            effective_epoch,
            authorization_root,
        } => {
            let decision = schedule_expulsion(
                validator_id.clone(),
                evidence_root,
                current_epoch,
                effective_epoch,
                authorization_root,
            )?;
            require_current_or_jailed(snapshot, &validator_id)?.scheduled_expulsion =
                Some(decision);
            Ok("validator expulsion staged for a future epoch".into())
        }
        ValidatorManagementCommand::ScheduleSlashing {
            validator_id,
            evidence_root,
            penalty_units,
            current_epoch,
            effective_epoch,
            authorization_root,
        } => {
            let decision = schedule_slashing(
                validator_id.clone(),
                evidence_root,
                penalty_units,
                current_epoch,
                effective_epoch,
                authorization_root,
            )?;
            let record = require_current_or_jailed(snapshot, &validator_id)?;
            if record.slashing_decisions.len() >= MAX_SLASHING_DECISIONS_PER_VALIDATOR {
                return Err("validator slashing decision journal is full".into());
            }
            record.slashing_decisions.push(decision);
            Ok("validator slashing decision durably recorded".into())
        }
    }
}

fn require_staged_binding(
    record: &ManagedValidatorRecord,
    frozen: &synergy_posy::ValidatorRecord,
) -> Result<(), String> {
    if record
        .application
        .as_ref()
        .is_some_and(|application| application.consensus_key_id != frozen.consensus_key_id)
        || record
            .shadow_registration
            .as_ref()
            .is_some_and(|registration| {
                registration.validator.validator_id != frozen.validator_id
                    || registration.validator.consensus_key_id != frozen.consensus_key_id
                    || registration.validator.frozen_voting_weight != frozen.frozen_voting_weight
            })
    {
        return Err("frozen PoSy authority differs from the staged validator binding".into());
    }
    Ok(())
}

fn required_record<'a>(
    snapshot: &'a mut ValidatorManagementSnapshot,
    validator_id: &str,
) -> Result<&'a mut ManagedValidatorRecord, String> {
    snapshot
        .records
        .get_mut(validator_id)
        .ok_or_else(|| format!("validator {validator_id} is not managed"))
}

fn require_current_or_jailed<'a>(
    snapshot: &'a mut ValidatorManagementSnapshot,
    validator_id: &str,
) -> Result<&'a mut ManagedValidatorRecord, String> {
    let record = required_record(snapshot, validator_id)?;
    if !matches!(
        record.lifecycle.state,
        ValidatorLifecycleState::Active | ValidatorLifecycleState::Jailed
    ) {
        return Err(
            "validator lifecycle decision requires frozen active or jailed membership".into(),
        );
    }
    Ok(record)
}

fn transition(
    snapshot: &mut ValidatorManagementSnapshot,
    validator_id: &str,
    state: ValidatorLifecycleState,
    witness: Option<&FrozenRegistryWitness<'_>>,
) -> Result<(), String> {
    required_record(snapshot, validator_id)?
        .lifecycle
        .transition(state, witness)
}

struct NoActiveWitness;

impl ActiveMembershipWitness for NoActiveWitness {
    fn confirms_active(&self, _validator_id: &str, _epoch: u64) -> Result<bool, String> {
        Ok(false)
    }
}

struct FrozenRegistryWitness<'a>(&'a FrozenValidatorRegistry);

impl ActiveMembershipWitness for FrozenRegistryWitness<'_> {
    fn confirms_active(&self, validator_id: &str, epoch: u64) -> Result<bool, String> {
        Ok(self.0.epoch() == epoch && self.0.active_validator(validator_id).is_ok())
    }
}

fn validate_snapshot(snapshot: &ValidatorManagementSnapshot) -> Result<(), String> {
    if snapshot.schema_version != MANAGEMENT_SCHEMA_VERSION {
        return Err("unsupported validator management schema".into());
    }
    for (validator_id, record) in &snapshot.records {
        if validator_id.trim().is_empty()
            || record.lifecycle.validator_id != *validator_id
            || record.lifecycle.target_epoch == 0
            || record.lifecycle.required_shadow_blocks == 0
            || record.slashing_decisions.len() > MAX_SLASHING_DECISIONS_PER_VALIDATOR
        {
            return Err("persisted validator management record is invalid".into());
        }
        if let Some(application) = &record.application {
            application.validate(application.target_epoch.saturating_sub(1))?;
            if application.validator_id != *validator_id
                || application.target_epoch != record.lifecycle.target_epoch
                || !is_hash(&application.authorization_root)
            {
                return Err("persisted validator application binding is invalid".into());
            }
        }
        if let Some(registration) = &record.shadow_registration {
            registration
                .validator
                .validate()
                .map_err(|error| error.to_string())?;
            if registration.validator.validator_id != *validator_id
                || registration.validator.status != ValidatorStatus::Shadow
                || registration.target_epoch != record.lifecycle.target_epoch
                || registration.membership_authority_id.trim().is_empty()
            {
                return Err("persisted shadow registration binding is invalid".into());
            }
        }
        if let Some(activation) = &record.activation {
            if activation.validator_id != *validator_id
                || activation.target_epoch != record.lifecycle.target_epoch
                || activation.membership_authority_id.trim().is_empty()
            {
                return Err("persisted validator activation binding is invalid".into());
            }
        }
        if let Some(decision) = &record.scheduled_jailing {
            if decision.validator_id != *validator_id {
                return Err("persisted validator jailing binding is invalid".into());
            }
            decision
                .validate(decision.effective_epoch.saturating_sub(1))
                .map_err(|error| error.to_string())?;
        }
        if let Some(decision) = &record.scheduled_deactivation {
            if decision.validator_id != *validator_id {
                return Err("persisted validator deactivation binding is invalid".into());
            }
            decision
                .validate(decision.effective_epoch.saturating_sub(1))
                .map_err(|error| error.to_string())?;
        }
        if let Some(decision) = &record.scheduled_expulsion {
            if decision.validator_id != *validator_id {
                return Err("persisted validator expulsion binding is invalid".into());
            }
            decision
                .validate(decision.effective_epoch.saturating_sub(1))
                .map_err(|error| error.to_string())?;
        }
        for decision in &record.slashing_decisions {
            if decision.validator_id != *validator_id {
                return Err("persisted validator slashing binding is invalid".into());
            }
            decision
                .validate(decision.effective_epoch.saturating_sub(1))
                .map_err(|error| error.to_string())?;
        }
    }
    if snapshot.applied_commands.len() > MAX_APPLIED_COMMANDS {
        return Err("persisted validator idempotency journal exceeds its bound".into());
    }
    for (key, applied) in &snapshot.applied_commands {
        if key.trim().is_empty()
            || key.len() > 256
            || !is_hash(&applied.fingerprint)
            || applied.receipt.sequence == 0
            || applied.receipt.sequence > snapshot.sequence
            || applied.receipt.validator_id.trim().is_empty()
            || applied.receipt.detail.len() > 1024
        {
            return Err("persisted validator idempotency record is invalid".into());
        }
    }
    Ok(())
}

fn encode_snapshot(snapshot: &ValidatorManagementSnapshot) -> Result<Vec<u8>, String> {
    validate_snapshot(snapshot)?;
    serde_json::to_vec(snapshot)
        .map_err(|error| format!("encode validator management state: {error}"))
}

fn prune_applied_commands(commands: &mut BTreeMap<String, AppliedCommand>) {
    while commands.len() > MAX_APPLIED_COMMANDS {
        let oldest = commands
            .iter()
            .min_by_key(|(_, applied)| applied.receipt.sequence)
            .map(|(key, _)| key.clone());
        let Some(oldest) = oldest else {
            break;
        };
        commands.remove(&oldest);
    }
}
