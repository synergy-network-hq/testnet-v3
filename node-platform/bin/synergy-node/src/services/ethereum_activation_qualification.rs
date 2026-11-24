//! Actual-provider governance/native-settlement component acceptance.
//! History inputs here are caller-context fixtures, not claimed PoSy finality.
use super::*;
use crate::services::ethereum_activation as activation;
use std::collections::{BTreeMap, BTreeSet};
use synergy_aivm::ethereum_execution::{execute_legacy_evm, EvmBlockContext, EVM_POLICY_KEY};
use synergy_governance::*;
use synergy_state::world_resources::WorldResourceBudget;
use synergy_transaction::SignedTransaction;

fn authorization_root(
    proposal: &GovernanceProposal,
    constitution: &Constitution,
    votes: &[GovernanceVote],
) -> String {
    let approvals = votes
        .iter()
        .map(|vote| vote.authority_id.clone())
        .collect::<BTreeSet<_>>();
    let bytes = serde_json::to_vec(&(
        &proposal.proposal_root,
        &constitution.constitution_root,
        &approvals,
    ))
    .unwrap();
    let digest = synergy_crypto::sha3_256_segments(
        &synergy_crypto::AegisSha3_256,
        &[b"SYNERGY_GOVERNANCE_AUTHORIZATION_V1", &bytes],
    )
    .unwrap();
    lower_hex(&digest.0)
}
fn proposal(
    spec: &activation::EthereumActivationSpec,
    authority: &authority::VerifiedAuthority,
    ids: &[String],
    signers: &[Arc<dyn AegisSigner>],
    count: usize,
) -> GovernanceExecution {
    proposal_window(spec, authority, ids, signers, count, 30)
}
fn proposal_window(
    spec: &activation::EthereumActivationSpec,
    authority: &authority::VerifiedAuthority,
    ids: &[String],
    signers: &[Arc<dyn AegisSigner>],
    count: usize,
    expires_at_height: u64,
) -> GovernanceExecution {
    let mut constitution = Constitution {
        version: 1,
        constitution_root: String::new(),
        rules: BTreeMap::from([(
            activation::ACTION.into(),
            GovernanceRule {
                action_kind: activation::ACTION.into(),
                eligible_authorities: ids.iter().cloned().collect(),
                approval_threshold: 1,
                minimum_delay_blocks: 0,
                emergency_permitted: false,
            },
        )]),
    };
    constitution.constitution_root = constitution.canonical_root().unwrap();
    let mutation = GovernedStateMutation {
        action_kind: activation::ACTION.into(),
        target: activation::TARGET.into(),
        expected_value: None,
        value: serde_json::to_vec(spec).unwrap(),
    };
    let mut proposal = GovernanceProposal {
        proposal_id: "qualified-canary-evm-amendment".into(),
        proposal_root: String::new(),
        proposer: ids[0].clone(),
        constitution_version: 1,
        created_at_height: 1,
        expires_at_height,
        actions: vec![GovernanceAction {
            kind: activation::ACTION.into(),
            target: activation::TARGET.into(),
            payload_root: mutation.payload_root().unwrap(),
        }],
        state: ProposalState::Authorized,
    };
    proposal.proposal_root = proposal.canonical_root().unwrap();
    let votes = (0..count)
        .map(|index| {
            let key_id = KeyId::new(format!("consensus-{index}")).unwrap();
            let mut vote = GovernanceVote {
                proposal_root: proposal.proposal_root.clone(),
                authority_id: ids[index].clone(),
                key_id: key_id.as_str().into(),
                choice: VoteChoice::Approve,
                signature: vec![1],
            };
            vote.signature = signers[index]
                .sign(
                    &key_id,
                    &SigningContext {
                        domain: "SYNERGY-GOVERNANCE-VOTE-V1".into(),
                        chain_id: authority.epoch.chain_id,
                        epoch: Some(authority.epoch.epoch),
                        height: None,
                    },
                    &vote.signing_bytes().unwrap(),
                )
                .unwrap()
                .bytes;
            vote
        })
        .collect::<Vec<_>>();
    let root = authorization_root(&proposal, &constitution, &votes);
    let authorization = GovernanceAuthorization::assemble(
        &proposal,
        &constitution,
        &votes,
        authority,
        root.clone(),
    )
    .unwrap();
    let point = GovernedActivation::new(
        &proposal,
        &authorization,
        ActivationPoint::FinalizedHeight {
            height: spec.install_height,
        },
    )
    .unwrap();
    GovernanceExecution {
        proposal,
        constitution,
        votes,
        authorization_root: root,
        activation: point,
        mutation,
    }
}

#[test]
#[ignore = "requires explicitly pinned real native APQE provider"]
fn real_apqe_governance_evm_scope_native_settlement_history_and_restart() {
    let provider = trusted_apqe_provider();
    let network = secure_fixture_network();
    let (mut transaction, mut initial, mut account_secret) =
        funded_transaction_fixture_for_network_provider_chain(
            &network,
            10_000_000_000,
            Some(&provider),
            99999,
        );
    let counter = super::ethereum_qualification::fixture();
    let sender: [u8; 20] = hex_decode(counter["sender"].as_str().unwrap().trim_start_matches("0x"))
        .try_into()
        .unwrap();
    initial.accounts.insert(
        synergy_aivm::ethereum_execution::conventional_evm_account_key(sender),
        synergy_state::AccountState {
            balance_nwei: 10_000_000_000_000,
            nonce: 0,
            code_hash: None,
        },
    );
    let prepared = prepare_socket_fixture_with_protocol(
        initial,
        None,
        true,
        None,
        Some(&provider),
        true,
        None,
        99999,
        None,
        true,
    );
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(prepared.root.clone());
    let configuration = &prepared.configurations[0];
    let genesis_bytes = fs::read(configuration.genesis_path.as_ref().unwrap()).unwrap();
    let authority = authority::load(configuration).unwrap().unwrap();
    assert!(authority.ethereum_genesis().is_none());
    let signers = prepared
        .configurations
        .iter()
        .take(4)
        .map(|config| posy::qualification_protocol_signer(config, &authority).unwrap())
        .collect::<Vec<_>>();
    let budget = WorldResourceBudget::new(512 * 1024 * 1024);
    let initial = authority.initial_world_state_budgeted(&budget).unwrap();
    let policy_bytes =
        serde_json::to_vec(&super::ethereum_qualification::fixture_policy()).unwrap();
    let spec = activation::EthereumActivationSpec {
        schema_version: 1,
        profile_id: synergy_genesis::network::ETHEREUM_COMPATIBILITY_PROFILE_V1.into(),
        chain_id: 99999,
        network_id: authority.epoch.network_id.clone(),
        genesis_hash: activation::genesis_hash(&authority).unwrap().into(),
        frozen_epoch: 1,
        frozen_epoch_context_root: authority.epoch.root().unwrap(),
        install_height: 10,
        activation_height: 286,
        policy_sha256: lower_hex(&synergy_aegis::AegisProtectedPrimitives.sha256(&policy_bytes)),
        policy_bytes,
    };
    let execution = proposal(&spec, &authority, &prepared.ids, &signers, 4);
    // Native admin signing-owner component test. Injecting its trusted finalized
    // boundary below is a caller-context fixture, not claimed PoSy finality.
    // Keys come from the actual sealed native fixture custody loaded above.
    let draft=EthereumActivationDraft{spec:spec.clone(),proposal:execution.proposal.clone(),constitution:execution.constitution.clone()};
    let ingress=crate::services::ingress::AuthenticatedIngress::with_world_budget(Arc::clone(&budget));
    ingress.submit_finality(synergy_posy::FinalizedBlockRecord{height:1,block_id:"31".repeat(32),
        finality_certificate_id:"32".repeat(32),protected_execution_root:"33".repeat(32)},vec![1]).unwrap();
    ingress.publish_processing_finalized_world(1,Arc::new(synergy_state::world_resources::BudgetedWorld::try_clone_world(&initial,&budget).unwrap())).unwrap();
    let review_root=draft.review_root().unwrap();
    let mut actual_votes=Vec::new();
    for index in 0..4 {
        let root=prepared.root.join(format!("native-governance-{index}"));
        let create=||crate::services::governance_admin::GovernanceApprovalOwner::new(prepared.ids[index].clone(),
            KeyId::new(format!("consensus-{index}")).unwrap(),Arc::clone(&signers[index]),&root).unwrap();
        let mut owner=create();
        if index==0 {
            let policy=include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/../../../networks/synergy-posy-canary-20261117/ethereum-compatibility-policy.candidate.json"));
            let prepared=owner.prepare(&authority,&ingress,policy).unwrap();
            let typed:EthereumActivationDraft=serde_json::from_value(prepared["draft"].clone()).unwrap();
            let selected:synergy_aivm::ethereum_execution::EvmCompatibilityPolicy=serde_json::from_slice(&typed.spec.policy_bytes).unwrap();
            assert_eq!(lower_hex(&selected.fee_collector),"72f57b74c0b2d556589ceb393103bea0f631933b");
            assert_eq!(typed.spec.genesis_hash,spec.genesis_hash);
            assert_eq!(typed.spec.frozen_epoch,authority.epoch.epoch);
            assert_eq!(typed.spec.activation_height,typed.proposal.expires_at_height+256);
        }
        let review=owner.review(&authority,&ingress,&draft).unwrap();
        assert_eq!(review["review_root"],review_root);
        let approval=owner.approve(&authority,&ingress,&draft,&review_root).unwrap();
        assert!(owner.approve(&authority,&ingress,&draft,&"ff".repeat(32)).is_err());
        let mut changed=draft.clone();changed.proposal.proposal_id.push_str("-conflicting");
        changed.proposal.proposal_root=changed.proposal.canonical_root().unwrap();
        assert!(owner.approve(&authority,&ingress,&changed,&changed.review_root().unwrap()).is_err());
        drop(owner);
        let mut reopened=create();
        assert_eq!(reopened.approve(&authority,&ingress,&draft,&review_root).unwrap(),approval);
        assert_eq!(reopened.approval_status(&authority,&draft,&review_root).unwrap(),approval);
        if index==0 {
            // Crash between exact durable reservation and signature publication:
            // the production owner resumes this same scope autonomously.
            let path=root.join("ethereum-initial.json");
            let mut reserved:serde_json::Value=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            reserved["vote"]=serde_json::Value::Null;
            fs::write(&path,serde_json::to_vec(&reserved).unwrap()).unwrap();
            drop(reopened);
            reopened=create();
            reopened.recover_pending(&authority,&ingress);
            let recovered=reopened.approval_status(&authority,&draft,&review_root).unwrap();
            let recovered:GovernanceVote=serde_json::from_value(recovered["vote"].clone()).unwrap();
            authority.verify(&recovered).unwrap();
            assert_eq!(recovered.proposal_root,draft.proposal.proposal_root);
        }
        actual_votes.push(serde_json::from_value::<GovernanceVote>(approval["vote"].clone()).unwrap());
        if index==2 {assert!(reopened.assemble(&authority,&ingress,&draft,&review_root,actual_votes.clone()).is_err());}
        if index==3 {
            let assembled=reopened.assemble(&authority,&ingress,&draft,&review_root,actual_votes.clone()).unwrap();
            let verified:GovernanceExecution=serde_json::from_value(assembled["execution"].clone()).unwrap();
            activation::authorize_request(&authority,&verified).unwrap();
            assert_eq!(verified.proposal,execution.proposal);
        }
    }
    // A caller-provided one-signature Constitution cannot weaken frozen PoSy.
    let weak = proposal(&spec, &authority, &prepared.ids, &signers, 1);
    assert!(weak
        .verify(authority.as_ref(), &weak.authorization_root, 10)
        .is_ok());
    assert!(activation::authorize_request(&authority, &weak).is_err());
    let three = proposal(&spec, &authority, &prepared.ids, &signers, 3);
    assert!(activation::authorize_request(&authority, &three).is_err());
    for mut bad in [spec.clone(), spec.clone(), spec.clone(), spec.clone()]
        .into_iter()
        .enumerate()
    {
        match bad.0 {
            0 => bad.1.chain_id = 9969,
            1 => bad.1.genesis_hash = "11".repeat(32),
            2 => bad.1.activation_height = 285,
            _ => bad.1.policy_sha256 = "22".repeat(32),
        }
        let signed = proposal(&bad.1, &authority, &prepared.ids, &signers, 4);
        assert!(
            activation::authorize_request(&authority, &signed).is_err(),
            "fully signed wrong scope accepted"
        );
    }
    let mut altered = execution.clone();
    altered.votes[0].signature[0] ^= 1;
    assert!(activation::authorize_request(&authority, &altered).is_err());
    assert!(activation::install(&authority, &execution, 9, &initial).is_err());
    transaction.unsigned.class = synergy_transaction::TransactionClass::System;
    transaction.unsigned.amount_nwei = 0;
    transaction.unsigned.fee_limit.gas_limit = 1_000_000;
    transaction.unsigned.timestamp_unix = authority.consensus_timestamp_unix(20).unwrap();
    transaction.unsigned.payload = synergy_transaction::TransactionAction::Governance {
        authorization_id: execution.authorization_root.clone(),
        operation: serde_json::to_vec(&execution).unwrap(),
    }
    .encode()
    .unwrap();
    transaction.signature = fixture_sign(
        &account_secret,
        SignatureAlgorithm::MlDsa87,
        "transaction-presented-key",
        "SYNERGY-TRANSACTION-SIGNING-V1",
        None,
        &transaction.unsigned.signing_bytes().unwrap(),
    );
    assert_eq!(
        activation::processing_transaction(&authority, &transaction).unwrap(),
        Some(10)
    );
    let wire = synergy_transaction::encode_processing_transaction(&transaction).unwrap();
    let decoded = synergy_transaction::decode_processing_transaction(&wire).unwrap();
    let retained =
        synergy_execution::reserve_execution_metadata([wire.as_slice()], &budget).unwrap();
    assert!(retained.bytes() >= synergy_transaction::processing_decode_scratch(&wire));
    drop(retained);
    assert_eq!(
        serde_json::to_vec(&decoded).unwrap(),
        serde_json::to_vec(&transaction).unwrap()
    );
    assert_eq!(
        decoded.unsigned.signing_bytes().unwrap(),
        transaction.unsigned.signing_bytes().unwrap()
    );
    for mut altered in [wire.clone(), wire.clone(), wire.clone()]
        .into_iter()
        .enumerate()
    {
        match altered.0 {
            0 => altered.1.push(0),
            1 => {
                altered.1.pop();
            }
            _ => altered.1[8..12].copy_from_slice(&u32::MAX.to_be_bytes()),
        }
        assert!(synergy_transaction::decode_processing_transaction(&altered.1).is_err());
    }
    eprintln!(
        "Native governed operation bytes={} signed-transaction bytes={}",
        transaction.unsigned.payload.len(),
        serde_json::to_vec(&transaction).unwrap().len()
    );
    let before = initial.accounts[&transaction.unsigned.sender].clone();
    let context = synergy_etdag::ProcessingContext {
        context_version: 1,
        profile_id: synergy_etdag::PROCESSING_PROFILE_ID.into(),
        authority: authority.protected_target(None, 3).unwrap().0,
    };
    let encrypted = processing_wallet_admission_fixture_provider(
        &transaction,
        &context,
        &authority,
        &account_secret,
        Some(&provider),
    );
    let encoded = serde_json::to_vec(&encrypted).unwrap();
    eprintln!(
        "Actual native governance encrypted admission bytes={}",
        encoded.len()
    );
    assert!(
        encoded.len() <= 1024 * 1024,
        "governance quorum proof does not fit canonical native admission"
    );
    let result = crate::services::execution::qualification_governance_transition(
        configuration,
        authority.clone(),
        transaction.clone(),
        20,
        &initial,
    )
    .unwrap();
    eprintln!("Native governance execution receipts={:?}", result.receipts);
    assert_eq!(
        result.state.accounts[&transaction.unsigned.sender].nonce,
        before.nonce + 1
    );
    assert_eq!(
        result.state.accounts[&transaction.unsigned.sender].balance_nwei,
        before.balance_nwei - result.total_fees_nwei
    );
    assert_eq!(result.state.protocol[EVM_POLICY_KEY], spec.policy_bytes);
    assert!(activation::install(&authority, &execution, 20, &result.state).is_err());
    let replay = crate::services::execution::qualification_governance_transition(
        configuration,
        authority.clone(),
        transaction.clone(),
        21,
        &result.state,
    )
    .unwrap();
    assert_eq!(
        replay.receipts[0].status,
        synergy_transaction::ReceiptStatus::Reverted
    );
    assert_eq!(replay.receipts[0].gas_used, 0);
    assert_eq!(replay.total_fees_nwei, 0);
    assert_eq!(
        replay.state.accounts[&transaction.unsigned.sender],
        result.state.accounts[&transaction.unsigned.sender]
    );
    assert_eq!(replay.state.protocol[EVM_POLICY_KEY], spec.policy_bytes);
    let mut world = result.state;
    let selected = authority
        .ethereum_activation(&world, Some(&budget))
        .unwrap()
        .unwrap();
    assert!(!activation::is_active(&selected, &world).unwrap());
    assert_eq!(activation::authorization_update_height(&world).unwrap(), 20);
    crate::services::rpc::proofs::require_public_world(&world, None).unwrap();
    crate::services::rpc::proofs::bounded_document(world.as_ref()).unwrap();
    let staged_root = activation::authorization_root(&world);
    assert_ne!(staged_root, activation::authorization_root(&initial));
    // Caller-context parent identities exercise the actual canonical history
    // transition. This component fixture does not claim a PoSy finality proof.
    let mut parent = synergy_state::state_root(&world).unwrap();
    let mut expected = BTreeMap::new();
    for height in 21..=286 {
        expected.insert(height - 1, synergy_posy::parse_hash_bytes(&parent).unwrap());
        crate::services::processing_pipeline::ethereum::advance_native_history(
            &authority, &selected, height, &parent, &mut world,
        )
        .unwrap();
        if height < 286 {
            assert!(!activation::is_active(&selected, &world).unwrap());
        }
        parent = synergy_block::hash_block_bytes(
            &serde_json::to_vec(&(height, &parent, synergy_state::state_root(&world).unwrap()))
                .unwrap(),
        );
    }
    assert!(activation::is_active(&selected, &world).unwrap());
    assert_eq!(
        activation::authorization_update_height(&world).unwrap(),
        286
    );
    crate::services::rpc::proofs::require_public_world(&world, None).unwrap();
    crate::services::rpc::proofs::bounded_document(world.as_ref()).unwrap();
    assert_ne!(staged_root, activation::authorization_root(&world));
    for (height, hash) in expected.range(30..) {
        assert_eq!(
            world.protocol[&format!("aivm/ethereum/v1/native-parent/{height:020}")],
            hash
        );
    }
    let path = prepared.root.join("governed-restart-world.json");
    let permit =
        synergy_state::world_resources::reserve_world_write(&world, None, &budget).unwrap();
    fs::write(&path, serde_json::to_vec(world.as_ref()).unwrap()).unwrap();
    drop(permit);
    *authority.ethereum_activation_cache.lock().unwrap() = None;
    let reopened =
        synergy_state::world_resources::decode_budgeted_world(&fs::read(&path).unwrap(), &budget)
            .unwrap();
    let recovered = authority
        .ethereum_activation(&reopened, Some(&budget))
        .unwrap()
        .unwrap();
    assert!(activation::is_active(&recovered, &reopened).unwrap());
    assert_eq!(recovered.activation_height, 286);
    let mut hashes = expected;
    hashes.insert(286, synergy_posy::parse_hash_bytes(&parent).unwrap());
    hashes.retain(|height, _| *height >= 31);
    let context = EvmBlockContext {
        chain_id: 99999,
        genesis: synergy_posy::parse_hash_bytes(&spec.genesis_hash).unwrap(),
        policy_sha256: synergy_posy::parse_hash_bytes(&spec.policy_sha256).unwrap(),
        height: 287,
        timestamp: authority.consensus_timestamp_unix(287).unwrap(),
        gas_used_before: 0,
        randomness: synergy_posy::parse_hash_bytes(&authority.epoch.finalized_epoch_seed_root)
            .unwrap(),
        recent_block_hashes: &hashes,
        protected_credit_verifier: None,
    };
    let deployed = execute_legacy_evm(
        &hex_decode(
            counter["transactions"][0]["raw"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        ),
        &context,
        &reopened,
        &budget,
    )
    .unwrap();
    assert!(deployed.receipt.success);
    crate::services::rpc::proofs::require_public_world(&deployed.world, None).unwrap();
    crate::services::rpc::proofs::bounded_document(deployed.world.as_ref()).unwrap();
    let expired = crate::services::execution::qualification_governance_transition(
        configuration,
        authority.clone(),
        transaction.clone(),
        31,
        &initial,
    )
    .unwrap();
    let expired_world = expired.state;
    assert_eq!(
        expired_world.accounts[&transaction.unsigned.sender].nonce,
        before.nonce + 1
    );
    assert_eq!(
        expired_world.accounts[&transaction.unsigned.sender].balance_nwei,
        before.balance_nwei - expired.total_fees_nwei
    );
    assert!(!expired_world.protocol.contains_key(EVM_POLICY_KEY));
    assert!(expired_world
        .protocol
        .keys()
        .any(|key| key.starts_with("governance/aivm-ethereum-outcome-v1/")));
    assert_eq!(
        fs::read(configuration.genesis_path.as_ref().unwrap()).unwrap(),
        genesis_bytes,
        "same Genesis bytes changed"
    );
    account_secret.fill(0);
    eprintln!(
        "Actual APQE frozen governance/native settlement/scope/history/restart acceptance PASS"
    );
}

/// Independent normal node processes exercise the same-Genesis amendment as
/// an encrypted account transaction. No fixture writes a running node's state.
pub(super) fn qualify_five_process(
    prepared: &PreparedSocketFixture,
    children: &mut [std::process::Child],
    binary: &Path,
    provider: &ApqeProviderConfiguration,
    original: &SignedTransaction,
    secret: &[u8],
) {
    use super::secure_process_canary::process_rpc;
    let configs = &prepared.configurations;
    let address = configs[0].rpc.listen_address.unwrap();
    let authority = authority::load(&configs[0]).unwrap().unwrap();
    assert!(authority.ethereum_genesis().is_none());
    let originals = configs
        .iter()
        .map(|config| fs::read(config.genesis_path.as_ref().unwrap()).unwrap())
        .collect::<Vec<_>>();
    assert!(configs.iter().all(|config| process_rpc(
        config.rpc.listen_address.unwrap(),
        "eth_chainId",
        serde_json::json!([])
    )
    .is_err()));
    let context: synergy_etdag::ProcessingContext = serde_json::from_value(
        process_rpc(
            address,
            "synergy_getProcessingContextV1",
            serde_json::json!({}),
        )
        .unwrap()["context"]
            .clone(),
    )
    .unwrap();
    let earliest = context.authority.source_finalized_height + 4;
    let expires = earliest + 24;
    let policy_bytes =
        serde_json::to_vec(&super::ethereum_qualification::fixture_policy()).unwrap();
    let spec = activation::EthereumActivationSpec {
        schema_version: 1,
        profile_id: synergy_genesis::network::ETHEREUM_COMPATIBILITY_PROFILE_V1.into(),
        chain_id: 99999,
        network_id: authority.epoch.network_id.clone(),
        genesis_hash: activation::genesis_hash(&authority).unwrap().into(),
        frozen_epoch: authority.epoch.epoch,
        frozen_epoch_context_root: authority.epoch.root().unwrap(),
        install_height: earliest,
        activation_height: expires + activation::HISTORY_WARMUP_BLOCKS,
        policy_sha256: lower_hex(&synergy_aegis::AegisProtectedPrimitives.sha256(&policy_bytes)),
        policy_bytes,
    };
    let signers = configs
        .iter()
        .take(4)
        .map(|config| posy::qualification_protocol_signer(config, &authority).unwrap())
        .collect::<Vec<_>>();
    let execution = proposal_window(&spec, &authority, &prepared.ids, &signers, 4, expires);
    let mut transaction = original.clone();
    transaction.unsigned.class = synergy_transaction::TransactionClass::System;
    transaction.unsigned.amount_nwei = 0;
    transaction.unsigned.fee_limit.gas_limit = 1_000_000;
    transaction.unsigned.payload = synergy_transaction::TransactionAction::Governance {
        authorization_id: execution.authorization_root.clone(),
        operation: serde_json::to_vec(&execution).unwrap(),
    }
    .encode()
    .unwrap();
    transaction.signature = fixture_sign(
        secret,
        SignatureAlgorithm::MlDsa87,
        "transaction-presented-key",
        "SYNERGY-TRANSACTION-SIGNING-V1",
        None,
        &transaction.unsigned.signing_bytes().unwrap(),
    );
    let admission = processing_wallet_admission_fixture_provider(
        &transaction,
        &context,
        &authority,
        secret,
        Some(provider),
    );
    let queued = process_rpc(
        address,
        "synergy_submitProcessingTransactionV1",
        serde_json::to_value(&admission).unwrap(),
    )
    .unwrap();
    let ack_deadline = Instant::now() + Duration::from_secs(30);
    let acknowledged = loop {
        let receipt = process_rpc(
            address,
            "synergy_getProtectedAdmissionReceipt",
            serde_json::json!({"receipt_id":queued["receipt_id"]}),
        )
        .unwrap();
        assert!(
            !matches!(
                receipt["lifecycle_status"].as_str(),
                Some("failed" | "rejected")
            ),
            "original governance rejected before durable ACK: {receipt}"
        );
        if receipt["admitted"] == true && receipt["durable"] == true {
            break receipt;
        }
        assert!(
            Instant::now() < ack_deadline,
            "original governance durable ACK deadline: {receipt}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    eprintln!("Same-Genesis governance durable original ACK={acknowledged}; window={earliest}..={expires}, effective={}",spec.activation_height);
    children[0].kill().unwrap();
    children[0].wait().unwrap();
    let log = fs::OpenOptions::new()
        .append(true)
        .open(prepared.root.join("node-0/process.log"))
        .unwrap();
    children[0] = std::process::Command::new(binary)
        .args(["start", "--config"])
        .arg(prepared.root.join("node-0/config.json"))
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    // No resubmission or fixture redial after the ACK/restart.
    let deadline = Instant::now() + Duration::from_secs(7200);
    let mut last = 0;
    let mut settled = false;
    loop {
        for (index, child) in children.iter_mut().enumerate() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "governed owner{index} exited: {}",
                fs::read_to_string(prepared.root.join(format!("node-{index}/process.log")))
                    .unwrap()
            );
        }
        let telemetry = configs
            .iter()
            .map(|config| {
                process_rpc(
                    config.rpc.listen_address.unwrap(),
                    "synergy_chainTelemetry",
                    serde_json::json!({}),
                )
            })
            .collect::<Vec<_>>();
        let height = telemetry
            .iter()
            .map(|row| {
                row.as_ref()
                    .ok()
                    .and_then(|row| row.get("finalized_height")?.as_u64())
                    .unwrap_or(0)
            })
            .min()
            .unwrap_or(0);
        if telemetry.iter().all(Result::is_ok) && height > last {
            last = height;
            let chain = configs
                .iter()
                .map(|config| {
                    process_rpc(
                        config.rpc.listen_address.unwrap(),
                        "eth_chainId",
                        serde_json::json!([]),
                    )
                })
                .collect::<Vec<_>>();
            for (observed, capability) in telemetry.iter().zip(&chain) {
                if observed.as_ref().unwrap()["finalized_height"]
                    .as_u64()
                    .unwrap()
                    < spec.activation_height
                {
                    assert!(
                        capability.is_err(),
                        "EVM activated before its signed height"
                    );
                }
            }
            eprintln!(
                "Same-Genesis original governance restart+history H{height}/{}",
                spec.activation_height
            );
            if height > expires && !settled {
                let fee = (75_000 + serde_json::to_vec(&execution).unwrap().len() as u128) * 40;
                for config in configs {
                    let account=process_rpc(config.rpc.listen_address.unwrap(),"synergy_getAccount",
                        serde_json::json!({"address":transaction.unsigned.sender,"at_height":height})).unwrap();
                    assert_eq!(
                        account["nonce"], 1,
                        "original amendment must settle once after autonomous restart"
                    );
                    assert_eq!(
                        account["balance_nwei"],
                        (10_000_000 - fee).to_string(),
                        "exact native governance fee"
                    );
                    let proof=process_rpc(config.rpc.listen_address.unwrap(),"synergy_getFinalizedProofPageV1",
                        serde_json::json!({"height":height,"kind":"world_state","offset":0,"limit":1})).unwrap();
                    assert_eq!(proof["commitment"]["type"], "full_canonical_world_preimage");
                }
                settled = true;
            }
            if height >= spec.activation_height {
                assert!(
                    chain.iter().all(|row| row
                        .as_ref()
                        .is_ok_and(|value| *value == serde_json::json!("0x1869f"))),
                    "signed activation missing: {chain:?}"
                );
                let commitments = configs
                    .iter()
                    .map(|config| {
                        process_rpc(
                            config.rpc.listen_address.unwrap(),
                            "synergy_chainTelemetry",
                            serde_json::json!({"at_height":height}),
                        )
                        .unwrap()["common_finalized_commitment"]
                            .clone()
                    })
                    .collect::<Vec<_>>();
                assert!(!commitments[0].is_null());
                assert!(commitments.iter().all(|row| row == &commitments[0]));
                // Capability maturity and publication of the new exact
                // finalized admission anchor are separate native-owner steps.
                let refresh_deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    let contexts = configs
                        .iter()
                        .map(|config| {
                            process_rpc(
                                config.rpc.listen_address.unwrap(),
                                "synergy_getProcessingContextV1",
                                serde_json::json!({}),
                            )
                        })
                        .collect::<Vec<_>>();
                    if contexts.iter().all(|row| {
                        row.as_ref().is_ok_and(|value| {
                            value["context"]["authority"]["source_finalized_height"]
                                .as_u64()
                                .is_some_and(|source| source >= spec.activation_height)
                        })
                    }) {
                        break;
                    }
                    assert!(Instant::now()<refresh_deadline,"governed finalized admission anchors did not refresh autonomously: {contexts:?}");
                    std::thread::sleep(Duration::from_secs(1));
                }
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "governance/history autonomous finality deadline: {telemetry:?}"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    for (config, bytes) in configs.iter().zip(originals) {
        assert_eq!(
            fs::read(config.genesis_path.as_ref().unwrap()).unwrap(),
            bytes
        );
    }
    eprintln!("Actual five-process same-Genesis frozen-quorum activation + original ACK restart PASS H{last}; Solidity/RPC acceptance follows");
}

pub(super) fn qualify_final_world_pages(configs: &[NodeConfiguration]) {
    use super::secure_process_canary::process_rpc;
    let height = configs
        .iter()
        .map(|config| {
            process_rpc(
                config.rpc.listen_address.unwrap(),
                "synergy_chainTelemetry",
                serde_json::json!({}),
            )
            .unwrap()["finalized_height"]
                .as_u64()
                .unwrap()
        })
        .min()
        .unwrap();
    for config in configs {
        let proof = process_rpc(
            config.rpc.listen_address.unwrap(),
            "synergy_getFinalizedProofPageV1",
            serde_json::json!({"height":height,"kind":"world_state","offset":0,"limit":1}),
        )
        .unwrap();
        assert_eq!(proof["commitment"]["type"], "full_canonical_world_preimage");
        assert!(proof["total_bytes"].as_u64().unwrap() <= 1024 * 1024);
        eprintln!(
            "Governed+Solidity finalized World actual bounded proof H{height}, bytes={}",
            proof["total_bytes"]
        );
    }
}
