//! One closed paid D/P action for the caller's own validator bond.
use super::*;
use crate::services::{authority::VerifiedAuthority, protected_action_wire};
use synergy_governance::{
    ValidatorAdmissionRequest, ValidatorBondOutcome, ValidatorBondSettlement,
    PROTECTED_VALIDATOR_BOND_ACTION, VALIDATOR_BOND_SETTLEMENT_PREFIX,
};
impl CandidateProtectedAccounts<'_> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn execute_validator_bond(
        &self,
        authority: &VerifiedAuthority,
        provider: &PqProvider<Mldsa87>,
        source: &FinalizedSnapshot<'_>,
        world: &mut BudgetedWorld,
        opened: crate::services::processing_pipeline::RevealedProcessingPayload<'_>,
        admission: &transfer_admission::VerifiedTransferAdmission,
        fees: &synergy_execution::FeeSchedule,
        gas: u64,
        inclusion: Position,
    ) -> Result<ValidatorBondSettlement, String> {
        let content = protected_action_wire::decode_validator_bond_content(opened.plaintext())?;
        let intent = CanonicalNativeIntent::decode(content.intent, 128 * 1024).map_err(display)?;
        let body = intent.body();
        let digest = intent.digest().map_err(display)?;
        if body.action_type != PROTECTED_VALIDATOR_BOND_ACTION || body.intent_id == [0; 32] {
            return Err("closed validator bond action required".into());
        }
        let policy_record = self.read_policy(source.world, body.account)?;
        let policy = self.current_policy(&policy_record)?;
        let build = |index: usize, role: Role| -> Result<RoleSignature, String> {
            let supplied = &content.proofs[index];
            let enrolled = policy.terms().roles[index];
            if supplied.participant_id != enrolled.participant_id
                || supplied.key_version != enrolled.key_version
                || &supplied.digest != digest.as_bytes()
            {
                return Err(
                    "bond proof differs from exact enrolled participant and reviewed intent".into(),
                );
            }
            Ok(RoleSignature {
                role,
                signature: Signature::from_bytes(supplied.signature).map_err(debug)?,
            })
        };
        let proofs = [build(0, Role::D)?, build(1, Role::P)?];
        let owner = body.account.to_native(&Primitives).map_err(display)?;
        let (request, _) = self.verify_spend(
            provider,
            source,
            world.as_ref(),
            content.intent,
            128 * 1024,
            |body| {
                if body.action_type != PROTECTED_VALIDATOR_BOND_ACTION {
                    return Err("closed validator bond action required".into());
                }
                let request: ValidatorAdmissionRequest =
                    serde_json::from_slice(body.action_payload)
                        .map_err(|_| "invalid closed validator request")?;
                if serde_json::to_vec(&request).map_err(display)? != body.action_payload
                    || request.spec.owner_wallet != owner
                {
                    return Err("validator bond does not bind this exact protected owner".into());
                }
                Ok(request)
            },
            &proofs,
        )?;
        admission.verify_opened(
            source,
            &intent,
            opened.envelope(),
            opened.context(),
            fees,
            gas,
        )?;
        fees.validate().map_err(display)?;
        let quoted_fee = u128::from(gas)
            .checked_mul(u128::from(fees.base_fee_per_gas_nwei))
            .ok_or("validator fee overflow")?;
        let mut encoded_fee = [0; 32];
        encoded_fee[16..].copy_from_slice(&quoted_fee.to_be_bytes());
        if gas == 0
            || gas > body.gas_limit
            || encoded_fee > body.maximum_total_fee
            || fees.collector == owner
        {
            return Err("validator bond exceeds reviewed paid resource authorization".into());
        }
        let available = world
            .accounts
            .get(&owner)
            .ok_or("protected bond owner ledger missing")?
            .balance_nwei;
        let fee = if available >= quoted_fee {
            quoted_fee
        } else {
            0
        };
        let charged_gas = if fee == quoted_fee { gas } else { 0 };
        let local = std::sync::atomic::AtomicBool::new(false);
        let staged = crate::services::validator_admission::prepare_for_owner(
            authority,
            world,
            &owner,
            body.transaction_nonce,
            body.action_payload,
            inclusion.height,
            &local,
        );
        if local.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("native validator admission provider unavailable".into());
        }
        let (mut diff, bond, outcome) = match staged {
            Ok((diff, required))
                if fee == quoted_fee
                    && required <= gas
                    && diff
                        .changes
                        .iter()
                        .find(|a| a.account == owner)
                        .is_some_and(|a| {
                            a.debit_nwei
                                .checked_add(fee)
                                .is_some_and(|total| total <= available)
                        }) =>
            {
                let bond = diff
                    .changes
                    .iter()
                    .find(|a| a.account == owner)
                    .unwrap()
                    .debit_nwei;
                (diff, bond, ValidatorBondOutcome::Registered)
            }
            _ => (
                StateDiff {
                    changes: vec![AccountChange {
                        account: owner.clone(),
                        debit_nwei: 0,
                        credit_nwei: 0,
                        expected_nonce: Some(body.transaction_nonce),
                        code_hash: None,
                    }],
                    protocol_changes: vec![],
                },
                0,
                ValidatorBondOutcome::Rejected,
            ),
        };
        diff.changes
            .iter_mut()
            .find(|a| a.account == owner)
            .ok_or("bond transition lost owner nonce")?
            .debit_nwei += fee;
        if fee > 0 {
            diff.changes.push(AccountChange {
                account: fees.collector.clone(),
                debit_nwei: 0,
                credit_nwei: fee,
                expected_nonce: None,
                code_hash: None,
            });
        }
        let receipt = ValidatorBondSettlement {
            version: 1,
            genesis: *body.genesis.as_bytes(),
            account: *body.account.as_bytes(),
            intent_id: body.intent_id,
            validator_id: request.spec.validator_id,
            request_sha256: crate::services::apqe_transport::sha256(body.action_payload),
            native_intent_digest: digest.as_bytes().to_vec(),
            envelope_id: opened.envelope().envelope_id.0.clone(),
            policy_epoch: body.policy_epoch,
            nonce_before: body.transaction_nonce,
            nonce_after: body
                .transaction_nonce
                .checked_add(1)
                .ok_or("bond nonce overflow")?,
            source_finalized_height: source.position.height,
            included_height: inclusion.height,
            bond_nwei: bond.to_string(),
            gas_used: charged_gas,
            fee_nwei: fee.to_string(),
            outcome,
        };
        if world.protocol.contains_key(&receipt.record_key()) {
            return Err("validator bond settlement already exists".into());
        }
        diff.protocol_changes.push(ProtocolChange {
            key: receipt.record_key(),
            expected_value: None,
            value: Some(serde_json::to_vec(&receipt).map_err(display)?),
        });
        world.try_apply(&diff).map_err(debug)?;
        Ok(receipt)
    }
}
pub(super) fn validate_public(
    world: &WorldState,
    key: &str,
    bytes: &[u8],
    height: u64,
    genesis: [u8; 32],
) -> Result<bool, String> {
    if !key.starts_with(VALIDATOR_BOND_SETTLEMENT_PREFIX) {
        return Ok(false);
    }
    if bytes.is_empty() || bytes.len() > 8192 {
        return Err("validator bond settlement exceeds public bound".into());
    }
    let r: ValidatorBondSettlement = serde_json::from_slice(bytes).map_err(display)?;
    let bond = r.bond_nwei.parse::<u128>().map_err(display)?;
    let fee = r.fee_nwei.parse::<u128>().map_err(display)?;
    if serde_json::to_vec(&r).map_err(display)? != bytes
        || r.version != 1
        || r.record_key() != key
        || r.genesis == [0; 32]
        || r.genesis != genesis
        || r.intent_id == [0; 32]
        || r.native_intent_digest.len() != 64
        || !synergy_posy::is_hash(&r.request_sha256)
        || !(r.envelope_id.len() == 128
            && r.envelope_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        || r.nonce_before.checked_add(1) != Some(r.nonce_after)
        || r.source_finalized_height == 0
        || r.included_height <= r.source_finalized_height
        || r.included_height > height
        || bond.to_string() != r.bond_nwei
        || fee.to_string() != r.fee_nwei
        || (r.gas_used == 0) != (fee == 0)
    {
        return Err("invalid closed public validator bond settlement".into());
    }
    match r.outcome {
        ValidatorBondOutcome::Rejected if bond != 0 => {
            return Err("rejected validator bond debited stake".into())
        }
        ValidatorBondOutcome::Registered => {
            let record: synergy_governance::ValidatorBondRecord = serde_json::from_slice(
                world
                    .protocol
                    .get(&format!(
                        "{}{}",
                        synergy_governance::VALIDATOR_BOND_PREFIX,
                        r.validator_id
                    ))
                    .ok_or("bond settlement lacks canonical escrow record")?,
            )
            .map_err(display)?;
            if record.request_sha256 != r.request_sha256
                || record.bond_nwei != r.bond_nwei
                || record.owner_wallet
                    != AccountIdentifier::from_bytes(r.account)
                        .to_native(&Primitives)
                        .map_err(display)?
            {
                return Err("validator settlement differs from native bonded admission".into());
            }
        }
        _ => {}
    }
    Ok(true)
}

#[cfg(test)]
pub(crate) fn qualify_real_dp_bond(
    authority: &VerifiedAuthority,
    base: &WorldState,
    source_record: &FinalizedBlockRecord,
    make_request: impl FnOnce(&str) -> ValidatorAdmissionRequest,
) {
    use k256::ecdsa::SigningKey;
    use synergy_address_engine::apqe::{enrollment::*, identity::WalletUuid, provider::Profile};
    let provider = unsafe {
        PqProvider::<Mldsa87>::open_verified(
            std::env::var_os("CORE_APQE_MLDSA87_LIBRARY").unwrap(),
            synergy_posy::parse_hash_bytes(&std::env::var("CORE_APQE_MLDSA87_SHA256").unwrap())
                .unwrap(),
            Profile::Validation,
        )
    }
    .unwrap();
    let (d, ds) = provider.generate_keypair().unwrap();
    let (p, ps) = provider.generate_keypair().unwrap();
    let ec = SigningKey::from_slice(&[11; 32]).unwrap();
    let public = ec.verifying_key().to_encoded_point(false);
    let point = synergy_address_engine::apqe::address::ValidatedSec1PublicPoint::parse(
        &Primitives,
        public.as_bytes(),
    )
    .unwrap();
    let account =
        synergy_address_engine::apqe::address::derive_account_identifier(&Primitives, &point)
            .unwrap();
    let address = account.to_native(&Primitives).unwrap();
    let request = make_request(&address);
    let request_json = serde_json::to_vec(&request).unwrap();
    let genesis = NativeGenesisHash::from_bytes(
        synergy_posy::parse_hash_bytes(authority.authenticated_genesis_hash().unwrap()).unwrap(),
    );
    let chain = ChainId::from_u64(authority.epoch.chain_id);
    let wire = inspection::candidate_wire_profile().unwrap();
    let manifest = [34; 32];
    let data = PrimaryCompanionEnrollmentData {
        genesis,
        account,
        evm_public_key: *point.as_sec1_bytes(),
        public_policy: PrimaryCompanionPublicPolicy {
            genesis,
            account,
            policy_epoch: 0,
            roles: [
                RoleRecord {
                    role_id: 0,
                    participant_id: [1; 32],
                    key_version: 1,
                    auth_algorithm: 1,
                    auth_public_key: d.as_bytes(),
                },
                RoleRecord {
                    role_id: 1,
                    participant_id: [2; 32],
                    key_version: 1,
                    auth_algorithm: 1,
                    auth_public_key: p.as_bytes(),
                },
            ],
            evm_public_key: *point.as_sec1_bytes(),
            provider_manifest_hash: manifest,
            ordinary_change_delay: 7200,
            recovery_delay: 0,
            status: 0,
        },
        dkg_transcript_commitment: &[51; 32],
        nonce: [68; 32],
        issued_at: 100,
        expires_at: 200,
        wallet_uuid: WalletUuid::from_bytes([85; 16]),
    };
    let enrollment = data.encode(&wire).unwrap();
    let enrolled = CanonicalPrimaryCompanionEnrollment::decode(&enrollment, &wire).unwrap();
    let mut registry = CandidateProtectedAccounts::new(
        chain,
        ExternalChainPolicy::new(chain, genesis).unwrap(),
        &wire,
        UnactivatedCommitmentProfile::candidate_concat_v1(),
        vec![manifest],
    )
    .unwrap();
    registry.verifier = EnrollmentVerifier::Candidate(
        CandidateEnrollmentVerifier::new_with_primary_companion(
            genesis,
            chain,
            &wire,
            UnactivatedCommitmentProfile::candidate_concat_v1(),
            vec![manifest],
        )
        .unwrap(),
    );
    // A previously enrolled/funded account is a caller-authenticated state fixture;
    // initial D/P enrollment/AccountBinding itself has a separate real-native test.
    let mut raw = base.clone();
    let amount = synergy_protocol_types::VALIDATOR_MINIMUM_BOND_NWEI * 2;
    let payer = &request.spec.owner_wallet;
    raw.accounts.insert(
        payer.clone(),
        synergy_state::AccountState {
            balance_nwei: amount,
            nonce: 0,
            code_hash: None,
        },
    );
    raw.protocol.insert(
        account_key(account),
        encode(&PolicyRecord {
            network: registry.network,
            account: *account.as_bytes(),
            policy_epoch: 0,
            policy_hash: enrolled.policy_hash().unwrap(),
            enrollment: enrollment.clone(),
            registered_height: 1,
            replacement_policy: None,
            native_recovery_since: None,
        })
        .unwrap(),
    );
    let source_height = source_record.height;
    let time = authority.consensus_timestamp_unix(source_height).unwrap();
    let finalized = FinalizedState {
        finalized_height: source_height,
        finalized_block_id: source_record.block_id.clone(),
        state_root: state_root(&raw).unwrap(),
    };
    let snapshot = registry
        .finalized_snapshot(&raw, &finalized, source_record, time)
        .unwrap();
    let mut max_fee = [0; 32];
    max_fee[16..].copy_from_slice(&10_000_000u128.to_be_bytes());
    let body = NativeIntentBody {
        genesis,
        account,
        policy_epoch: 0,
        transaction_nonce: 0,
        action_type: PROTECTED_VALIDATOR_BOND_ACTION,
        action_payload: &request_json,
        gas_limit: 250000,
        maximum_total_fee: max_fee,
        valid_until_finalized_height: authority.epoch.epoch_end_height,
        intent_id: [79; 32],
    };
    let encoded = body.encode(128 * 1024).unwrap();
    let native = CanonicalNativeIntent::decode(&encoded, 128 * 1024).unwrap();
    let digest = native.digest().unwrap();
    let inner = [&ds, &ps].map(|secret| {
        provider
            .sign(
                digest.as_bytes(),
                secret,
                SignOptions::Pure {
                    context: NATIVE_TX_CONTEXT,
                },
            )
            .unwrap()
    });
    fn bytes(value: &[u8], out: &mut Vec<u8>) {
        match value.len() {
            0..=23 => out.push(0x40 | value.len() as u8),
            24..=255 => out.extend([0x58, value.len() as u8]),
            256..=65535 => {
                out.push(0x59);
                out.extend((value.len() as u16).to_be_bytes());
            }
            _ => {
                out.push(0x5a);
                out.extend((value.len() as u32).to_be_bytes());
            }
        }
        out.extend(value);
    }
    let mut content = vec![0x84, 0x19, 0x70, 0x0b];
    bytes(&encoded, &mut content);
    content.push(0x82);
    for i in 0..2 {
        content.extend([0x87, 1, 1, 1, i as u8]);
        bytes(&[i as u8 + 1; 32], &mut content);
        bytes(digest.as_bytes(), &mut content);
        bytes(inner[i].as_bytes(), &mut content);
    }
    content.push(0xf6);
    assert!(
        content.len() < 131072,
        "closed700b content exceeded unchanged plaintext class: {}",
        content.len()
    );
    let limits = synergy_etdag::EtdagParameters::default();
    let fees = synergy_execution::FeeSchedule {
        base_fee_per_gas_nwei: 40,
        collector: "synf1pnchsrnyral0u9r65xusjrexuctfh465h06l".into(),
    };
    let report =
        std::path::PathBuf::from(std::env::var_os("APQE_ENGINEERING_NATIVE_REPORT").unwrap());
    let report_pin = std::env::var("APQE_ENGINEERING_NATIVE_REPORT_SHA256").unwrap();
    let (opened, admission) = etdag_candidate::open_candidate_envelope(
        &content,
        &report,
        &report_pin,
        authority.epoch.chain_id,
        source_record,
        &address,
        0,
        etdag_candidate::CandidateEnvelopeProfile::Transfer,
        None,
        |env, ctx, _| {
            let resources = synergy_etdag::admission::Pw13TransferResources {
                genesis: *genesis.as_bytes(),
                account: *account.as_bytes(),
                policy_epoch: 0,
                policy_hash: enrolled.policy_hash().unwrap(),
                gas_limit: 250000,
                maximum_total_fee: max_fee,
                valid_until_finalized_height: authority.epoch.epoch_end_height,
                native_intent_digest: digest.as_bytes().to_vec(),
                envelope_id: env.envelope_id.clone(),
            };
            let outer_digest = resources.signing_digest().unwrap();
            let proofs = std::array::from_fn(|i| synergy_etdag::admission::Pw13AdmissionProof {
                participant_id: [i as u8 + 1; 32],
                key_version: 1,
                signature: provider
                    .sign(
                        &outer_digest,
                        if i == 0 { &ds } else { &ps },
                        SignOptions::Pure {
                            context: synergy_etdag::admission::PW13_ADMISSION_CONTEXT,
                        },
                    )
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            });
            registry
                .verify_transfer_admission(
                    &provider,
                    &snapshot,
                    ctx,
                    env,
                    &synergy_etdag::admission::Pw13TransferAdmission { resources, proofs },
                    &limits,
                    &fees,
                    250000,
                )
                .map(|v| (v, None))
        },
    )
    .unwrap();
    let height = opened.envelope().aad.authorization_height;
    let budget = synergy_state::world_resources::WorldResourceBudget::new(64 * 1024 * 1024);
    let mut world = BudgetedWorld::try_clone_world(&raw, &budget).unwrap();
    let receipt = registry
        .execute_validator_bond(
            authority,
            &provider,
            &snapshot,
            &mut world,
            opened.payload(),
            &admission,
            &fees,
            250000,
            Position {
                height,
                consensus_time: authority.consensus_timestamp_unix(height).unwrap(),
            },
        )
        .unwrap();
    assert_eq!(receipt.outcome, ValidatorBondOutcome::Registered);
    assert_eq!(receipt.fee_nwei, "10000000");
    assert_eq!(
        receipt.bond_nwei,
        synergy_protocol_types::VALIDATOR_MINIMUM_BOND_NWEI.to_string()
    );
    assert_eq!(world.accounts[&address].nonce, 1);
    assert_eq!(
        raw.accounts[&address].balance_nwei - world.accounts[&address].balance_nwei,
        synergy_protocol_types::VALIDATOR_MINIMUM_BOND_NWEI + 10_000_000
    );
    assert_eq!(
        world.accounts[&request.spec.escrow_account()].balance_nwei,
        synergy_protocol_types::VALIDATOR_MINIMUM_BOND_NWEI
    );
    for available in [10_000_000u128, 1] {
        let mut changed = raw.clone();
        changed.accounts.get_mut(&address).unwrap().balance_nwei = available;
        let mut rejected = BudgetedWorld::try_clone_world(&changed, &budget).unwrap();
        let before = changed
            .accounts
            .values()
            .map(|a| a.balance_nwei)
            .sum::<u128>();
        let terminal = registry
            .execute_validator_bond(
                authority,
                &provider,
                &snapshot,
                &mut rejected,
                opened.payload(),
                &admission,
                &fees,
                250000,
                Position {
                    height,
                    consensus_time: authority.consensus_timestamp_unix(height).unwrap(),
                },
            )
            .unwrap();
        assert_eq!(terminal.outcome, ValidatorBondOutcome::Rejected);
        assert_eq!(terminal.bond_nwei, "0");
        assert_eq!(
            terminal.fee_nwei,
            if available >= 10_000_000 {
                "10000000"
            } else {
                "0"
            }
        );
        assert_eq!(rejected.accounts[&address].nonce, 1);
        assert_eq!(
            rejected
                .accounts
                .values()
                .map(|a| a.balance_nwei)
                .sum::<u128>(),
            before
        );
        assert!(!rejected
            .accounts
            .contains_key(&request.spec.escrow_account()));
        assert!(validate_public(
            &rejected,
            &terminal.record_key(),
            &rejected.protocol[&terminal.record_key()],
            height,
            *genesis.as_bytes()
        )
        .unwrap());
    }
    assert!(registry
        .execute_validator_bond(
            authority,
            &provider,
            &snapshot,
            &mut world,
            opened.payload(),
            &admission,
            &fees,
            250000,
            Position {
                height: height + 1,
                consensus_time: authority.consensus_timestamp_unix(height + 1).unwrap()
            }
        )
        .is_err());
    assert!(validate_public(
        &world,
        &receipt.record_key(),
        &world.protocol[&receipt.record_key()],
        height,
        *genesis.as_bytes()
    )
    .unwrap());
    eprintln!("Real native D/P700b closed bond+fee+nonce/accounting/replay: request{}B nativeintent{}B content{}B",request_json.len(),encoded.len(),content.len());
}
