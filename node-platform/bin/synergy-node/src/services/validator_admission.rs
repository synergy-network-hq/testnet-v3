//! Permissionless, consensus-owned admission. An ordinary authenticated native
//! transaction pays its normal fee and atomically bonds the approved stake.
use super::authority::VerifiedAuthority;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use synergy_governance::*;
use synergy_state::{AccountChange, ProtocolChange, StateDiff, WorldState};
use synergy_transaction::SignedTransaction;
pub(super) fn validate_public_record(
    world: &WorldState,
    key: &str,
    bytes: &[u8],
) -> Result<bool, String> {
    let hash = |s: &str| synergy_posy::is_hash(s) && s.bytes().any(|b| b != b'0');
    let bond = if key.starts_with(VALIDATOR_ADMISSION_PREFIX) {
        if bytes.is_empty() || bytes.len() > 48 * 1024 {
            return Err("public admission descriptor exceeds bound".into());
        }
        let r: FinalizedValidatorAdmissionRecord =
            serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if serde_json::to_vec(&r).map_err(|e| e.to_string())? != bytes
            || r.record_key() != key
            || r.schema_version != 1
            || r.chain_id == 0
            || !hash(&r.genesis_hash)
            || !hash(&r.frozen_epoch_context_root)
            || !hash(&r.request_sha256)
            || !hash(&r.identity_root_sha3_256)
            || !hash(&r.sync_finalized_block_id)
            || r.frozen_epoch.checked_add(1) != Some(r.effective_epoch)
            || r.installed_height == 0
            || r.sync_finalized_height >= r.installed_height
            || r.installed_height
                .checked_add(3)
                .is_none_or(|h| r.eligible_finalized_height < h)
            || synergy_protocol_types::NodeAddress::parse(&r.validator_id).is_err()
            || !synergy_address::is_spendable_user_address(&r.owner_wallet)
            || r.consensus_public_key.len() != 1952
            || r.transport_public_key.len() != 1952
            || r.ingress_kem_public_key.len() != 1568
            || r.consensus_public_key == r.transport_public_key
            || r.consensus_key_id.is_empty()
            || r.consensus_key_id.len() > 128
            || r.transport_key_id.is_empty()
            || r.transport_key_id.len() > 128
            || r.ingress_kem_key_id.is_empty()
            || r.ingress_kem_key_id.len() > 128
            || world.protocol.get(&r.bond_key())
                != Some(&serde_json::to_vec(&r.bond_record()).map_err(|e| e.to_string())?)
        {
            return Err("invalid closed public admission descriptor".into());
        }
        r.bond_record()
    } else if key.starts_with(VALIDATOR_BOND_PREFIX) {
        if bytes.is_empty() || bytes.len() > 2048 {
            return Err("public validator bond exceeds bound".into());
        }
        let r: ValidatorBondRecord = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if serde_json::to_vec(&r).map_err(|e| e.to_string())? != bytes
            || key != format!("{VALIDATOR_BOND_PREFIX}{}", r.validator_id)
        {
            return Err("invalid closed public validator bond".into());
        }
        r
    } else {
        return Ok(false);
    };
    let amount = bond
        .bond_nwei
        .parse::<u128>()
        .map_err(|_| "invalid public validator bond amount")?;
    if bond.schema_version != 1
        || bond.chain_id == 0
        || !hash(&bond.genesis_hash)
        || !hash(&bond.request_sha256)
        || bond.installed_height == 0
        || bond.effective_epoch == 0
        || amount.to_string() != bond.bond_nwei
        || amount < synergy_protocol_types::VALIDATOR_MINIMUM_BOND_NWEI
        || !synergy_address::is_spendable_user_address(&bond.owner_wallet)
        || synergy_protocol_types::NodeAddress::parse(&bond.validator_id).is_err()
        || bond.escrow_account != format!("validator-bond:{}", bond.validator_id)
        || !world
            .accounts
            .get(&bond.escrow_account)
            .is_some_and(|a| a.balance_nwei == amount && a.nonce == 0 && a.code_hash.is_none())
    {
        return Err("public validator bond differs from exact native escrow".into());
    }
    Ok(true)
}
pub(super) fn refresh_finalized(
    authority: &VerifiedAuthority,
    height: u64,
    world: &WorldState,
) -> Result<(), String> {
    if !authority.epoch.contains_height(height) || authority.automatic_admission_policy()?.is_none()
    {
        return Ok(());
    }
    let target = authority
        .epoch
        .epoch
        .checked_add(1)
        .ok_or("admission epoch overflow")?;
    let prefix = format!("{VALIDATOR_ADMISSION_PREFIX}epoch-{target:020}/");
    if !world
        .protocol
        .range(prefix.clone()..)
        .next()
        .is_some_and(|(k, _)| k.starts_with(&prefix))
    {
        return Ok(());
    }
    let retirement = authority.pending_membership_retirement()?;
    let policy = authority
        .protected_policy()
        .ok_or("native admission policy missing")?;
    let verified =
        synergy_genesis::validator_admission::NativeMembershipAdmissionSet::from_finalized_world(
            &authority.epoch,
            &authority.registry,
            policy,
            super::membership_retirement::genesis(authority)?,
            height,
            world,
            retirement.as_deref(),
        )?;
    let mut cache = authority
        .validator_admissions
        .lock()
        .map_err(|_| "admission cache poisoned")?;
    if cache.as_ref().is_some_and(|old| {
        old.records()
            .iter()
            .any(|record| !verified.records().contains(record))
    }) {
        return Err("finalized admission set rewrote or removed an earlier earned record".into());
    }
    *cache = Some(Arc::new(verified));
    Ok(())
}
struct TypedVerifier<'a> {
    authority: &'a VerifiedAuthority,
    local: &'a AtomicBool,
}
impl synergy_posy::ConsensusSignatureVerifier for TypedVerifier<'_> {
    fn verify_consensus_signature(
        &self,
        _domain: &str,
        message: &[u8],
        validator: &synergy_posy::ValidatorRecord,
        key_id: &str,
        _height: u64,
        signature: &[u8],
    ) -> synergy_posy::PosyResult<()> {
        let (id, key) = self
            .authority
            .consensus_binding(&validator.validator_id)
            .map_err(synergy_posy::PosyError::invalid)?;
        if id != key_id || validator.consensus_key_id != key_id {
            return Err(synergy_posy::PosyError::invalid("sync signer key differs"));
        }
        self.authority
            .native_identity_verifier()
            .ok_or_else(|| {
                self.local.store(true, Ordering::Relaxed);
                synergy_posy::PosyError::invalid("native source verifier unavailable")
            })?
            .verify_raw_classified("ML-DSA-65", key, message, signature)
            .map_err(|e| {
                if matches!(e, synergy_aegis::VerificationError::Provider(_)) {
                    self.local.store(true, Ordering::Relaxed);
                }
                synergy_posy::PosyError::invalid(format!("sync signature rejected: {e}"))
            })
    }
}
fn verify_sync(
    authority: &VerifiedAuthority,
    bytes: &[u8],
    local: &AtomicBool,
) -> Result<synergy_posy::FinalizedBlockRecord, String> {
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err("bounded native sync evidence required".into());
    }
    let source = synergy_genesis::validator_admission::decode_validator_admission_sync(bytes)?;
    let verifier = TypedVerifier { authority, local };
    source
        .witness
        .verified_timeout_closure(&authority.epoch, &authority.registry, &verifier)
        .map_err(|e| e.to_string())?;
    let mut finality = synergy_posy::ThreeQcFinality::default();
    for qc in &source.witness.quorum_certificates {
        qc.verify(&authority.epoch, &authority.registry, &verifier)
            .map_err(|e| e.to_string())?;
        finality.accept(qc.clone()).map_err(|e| e.to_string())?;
    }
    if finality.last_finalized() != Some(&source.finalized) {
        return Err("validator sync lacks original frozen three-QC finality".into());
    }
    Ok(source.finalized)
}

pub(super) fn prepare(
    authority: &Arc<VerifiedAuthority>,
    world: &WorldState,
    transaction: &SignedTransaction,
    input: &[u8],
    height: u64,
    local: &AtomicBool,
) -> Result<(StateDiff, u64), String> {
    if transaction.unsigned.receiver != transaction.unsigned.sender
        || transaction.unsigned.amount_nwei != 0
    {
        return Err("validator registration requires zero-value owner self target".into());
    }
    prepare_for_owner(
        authority,
        world,
        &transaction.unsigned.sender,
        transaction.unsigned.nonce,
        input,
        height,
        local,
    )
}
pub(super) fn prepare_for_owner(
    authority: &VerifiedAuthority,
    world: &WorldState,
    owner: &str,
    nonce: u64,
    input: &[u8],
    height: u64,
    local: &AtomicBool,
) -> Result<(StateDiff, u64), String> {
    if input.is_empty() || input.len() > 128 * 1024 {
        return Err("bounded exact validator admission required".into());
    }
    let request: ValidatorAdmissionRequest =
        serde_json::from_slice(input).map_err(|_| "invalid closed validator admission")?;
    if serde_json::to_vec(&request).map_err(|e| e.to_string())? != input {
        return Err("canonical validator admission bytes required".into());
    }
    let spec = &request.spec;
    spec.validate_shape()?;
    let dial = spec
        .dial_address
        .parse::<std::net::SocketAddr>()
        .map_err(|_| "literal private validator endpoint required")?;
    let private = match dial.ip() {
        std::net::IpAddr::V4(ip) => {
            ip.is_private()
                || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
                || (cfg!(test) && ip.is_loopback())
        }
        std::net::IpAddr::V6(ip) => ip.is_unique_local() || (cfg!(test) && ip.is_loopback()),
    };
    if !private || dial.port() == 0 || !synergy_posy::is_hash(&spec.enrollment_sha256) {
        return Err(
            "private validator endpoint and exact public enrollment digest required".into(),
        );
    }
    let policy = authority
        .automatic_admission_policy()?
        .ok_or("automatic validator admission policy is not finalized")?;
    policy.validate()?;
    let close = authority
        .epoch
        .epoch_end_height
        .checked_sub(2)
        .ok_or("validator admission epoch underflow")?;
    let eligible = height
        .checked_add(policy.minimum_shadow_finalized_blocks)
        .ok_or("validator shadow height overflow")?;
    if spec.chain_id != authority.epoch.chain_id
        || spec.network_id != authority.epoch.network_id
        || spec.genesis_hash != super::membership_retirement::genesis(authority)?
        || spec.frozen_epoch != authority.epoch.epoch
        || spec.frozen_epoch_context_root != authority.epoch.root().map_err(|e| e.to_string())?
        || spec.owner_wallet != owner
        || eligible > close
        || !authority.epoch.contains_height(height)
        || world.protocol.contains_key(&spec.bond_key())
        || world.protocol.contains_key(&spec.record_key())
        || authority.has_historical_validator(&spec.validator_id)
        || authority
            .has_historical_consensus_key(&spec.consensus_key_id, &spec.consensus_public_key)
        || world.accounts.contains_key(&spec.escrow_account())
    {
        return Err(
            "validator admission scope, ownership, frozen epoch, identity or eligibility rejected"
                .into(),
        );
    }
    let prefix = format!(
        "{VALIDATOR_ADMISSION_PREFIX}epoch-{:020}/",
        spec.effective_epoch
    );
    let mut count = 0;
    for (_, bytes) in world
        .protocol
        .range(prefix.clone()..)
        .take_while(|(k, _)| k.starts_with(&prefix))
    {
        count += 1;
        if count >= policy.maximum_admissions_per_epoch as usize {
            return Err("governed validator admission capacity exhausted".into());
        }
        let prior: FinalizedValidatorAdmissionRecord =
            serde_json::from_slice(bytes).map_err(|_| {
                local.store(true, Ordering::Relaxed);
                "corrupt pending validator admission"
            })?;
        if prior.consensus_key_id == spec.consensus_key_id
            || prior.consensus_public_key == spec.consensus_public_key
            || prior.transport_public_key == spec.transport_public_key
            || prior.ingress_kem_key_id == spec.ingress_kem_key_id
            || prior.ingress_kem_public_key == spec.ingress_kem_public_key
        {
            return Err("validator admission reuses an already claimed key".into());
        }
    }
    if authority
        .protected_ingress_registry()?
        .records
        .iter()
        .any(|r| {
            r.key_id == spec.ingress_kem_key_id
                || r.public_key.public_key == spec.ingress_kem_public_key
        })
    {
        return Err("validator admission reuses current ingress KEM".into());
    }
    let verifier = authority.native_identity_verifier().ok_or_else(|| {
        local.store(true, Ordering::Relaxed);
        "native admission provider unavailable"
    })?;
    synergy_genesis::validator_admission::verify_validator_admission_possession(
        &request,
        authority.epoch.chain_id,
        super::membership_retirement::genesis(authority)?,
        authority.epoch.epoch,
        &authority.epoch.root().map_err(|e| e.to_string())?,
        owner,
        verifier,
    )
    .map_err(|e| {
        if matches!(e, synergy_aegis::VerificationError::Provider(_)) {
            local.store(true, Ordering::Relaxed);
        }
        format!("validator possession rejected: {e}")
    })?;
    let source = verify_sync(authority, &request.sync_finality_document, local)?;
    if source.height != spec.sync_finalized_height
        || source.block_id != spec.sync_finalized_block_id
        || source.height >= height
        || !authority.epoch.contains_height(source.height)
    {
        return Err("validator sync evidence differs from its signed original source".into());
    }
    let bond = policy.bond_nwei()?;
    if !world
        .accounts
        .get(&spec.owner_wallet)
        .is_some_and(|a| a.nonce == nonce && a.balance_nwei >= bond && a.code_hash.is_none())
    {
        return Err("validator bond is not funded by the authenticated owner".into());
    }
    let request_sha256 = super::apqe_transport::sha256(input);
    let record = FinalizedValidatorAdmissionRecord {
        schema_version: 1,
        chain_id: spec.chain_id,
        network_id: spec.network_id.clone(),
        genesis_hash: spec.genesis_hash.clone(),
        frozen_epoch: spec.frozen_epoch,
        frozen_epoch_context_root: spec.frozen_epoch_context_root.clone(),
        effective_epoch: spec.effective_epoch,
        owner_wallet: spec.owner_wallet.clone(),
        validator_id: spec.validator_id.clone(),
        identity_root_sha3_256: synergy_crypto::sha3_256_segments(
            &synergy_crypto::AegisSha3_256,
            &[&spec.identity_root_public_key],
        )?
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect(),
        consensus_key_id: spec.consensus_key_id.clone(),
        consensus_public_key: spec.consensus_public_key.clone(),
        transport_key_id: spec.transport_key_id.clone(),
        transport_public_key: spec.transport_public_key.clone(),
        ingress_kem_key_id: spec.ingress_kem_key_id.clone(),
        ingress_kem_public_key: spec.ingress_kem_public_key.clone(),
        installed_height: height,
        eligible_finalized_height: eligible,
        sync_finalized_height: spec.sync_finalized_height,
        sync_finalized_block_id: spec.sync_finalized_block_id.clone(),
        bond_nwei: bond.to_string(),
        escrow_account: spec.escrow_account(),
        request_sha256,
        dial_address: spec.dial_address.clone(),
        enrollment_sha256: spec.enrollment_sha256.clone(),
    };
    let gas = 75000u64
        .checked_add(input.len() as u64)
        .ok_or("validator admission gas overflow")?;
    let mut diff = StateDiff {
        changes: vec![
            AccountChange {
                account: spec.owner_wallet.clone(),
                debit_nwei: bond,
                credit_nwei: 0,
                expected_nonce: Some(nonce),
                code_hash: None,
            },
            AccountChange {
                account: spec.escrow_account(),
                debit_nwei: 0,
                credit_nwei: bond,
                expected_nonce: None,
                code_hash: None,
            },
        ],
        protocol_changes: vec![
            ProtocolChange {
                key: spec.record_key(),
                expected_value: None,
                value: Some(serde_json::to_vec(&record).map_err(|e| e.to_string())?),
            },
            ProtocolChange {
                key: spec.bond_key(),
                expected_value: None,
                value: Some(serde_json::to_vec(&record.bond_record()).map_err(|e| e.to_string())?),
            },
        ],
    };
    // Activated public keys live in certified epoch history. Retain the small
    // bond ledger, and retire an earlier batch's redundant pending descriptors
    // atomically with the next valid admission, keeping the World proof bounded.
    let mut old_count = 0;
    for (key, bytes) in world
        .protocol
        .range(VALIDATOR_ADMISSION_PREFIX.to_owned()..)
        .take_while(|(k, _)| k.starts_with(VALIDATOR_ADMISSION_PREFIX))
    {
        let old: FinalizedValidatorAdmissionRecord =
            serde_json::from_slice(bytes).map_err(|_| {
                local.store(true, Ordering::Relaxed);
                "corrupt earlier validator descriptor"
            })?;
        if old.effective_epoch <= authority.epoch.epoch {
            old_count += 1;
            if old_count > 4
                || !authority.has_historical_validator(&old.validator_id)
                || !authority
                    .has_historical_consensus_key(&old.consensus_key_id, &old.consensus_public_key)
                || serde_json::to_vec(&old).map_err(|e| e.to_string())? != *bytes
            {
                local.store(true, Ordering::Relaxed);
                return Err("earlier admission differs from certified membership history".into());
            }
            diff.protocol_changes.push(ProtocolChange {
                key: key.clone(),
                expected_value: Some(bytes.clone()),
                value: None,
            });
        }
    }
    Ok((diff, gas))
}
