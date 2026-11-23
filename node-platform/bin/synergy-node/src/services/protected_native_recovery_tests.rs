use super::*;
use synergy_address_engine::apqe::{
    address::{ValidatedSec1PublicPoint, derive_account_identifier},
    authorization::{ORDINARY_POLICY_DELAY_SECONDS, RECOVERY_DELAY_SECONDS, RecoveryAuthority},
    enrollment::{
        CanonicalPrimaryCompanionEnrollment, PrimaryCompanionEnrollmentData,
        PrimaryCompanionPublicPolicy, PublicPolicy, RoleRecord,
        native_recovery::{NATIVE_RECOVERY_CONSENT_CONTEXT, NATIVE_RECOVERY_POSSESSION_CONTEXT},
    },
    identity::WalletUuid,
    provider::{Profile, SecretKey},
};
use synergy_state::{AccountState, FinalizedStateStore};

#[test]
#[ignore = "requires independently authenticated native ML-DSA-87 validation artifact"]
fn native_only_recovery_attachment_preserves_account_and_ledger_across_restart() {
    let fixed_bytes = |text: &str| -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    };
    let provider = unsafe {
        PqProvider::<Mldsa87>::open_verified(
            std::path::PathBuf::from(std::env::var_os("CORE_APQE_MLDSA87_LIBRARY").unwrap()),
            fixed_bytes(&std::env::var("CORE_APQE_MLDSA87_SHA256").unwrap())
                .try_into()
                .unwrap(),
            Profile::Validation,
        )
    }
    .unwrap();
    let keys: [(PublicKey<Mldsa87>, SecretKey<Mldsa87>); 3] =
        std::array::from_fn(|_| provider.generate_keypair().unwrap());
    let [d, p, r] = std::array::from_fn(|index| RoleRecord {
        role_id: index as u8,
        participant_id: [index as u8 + 1; 32],
        key_version: 1,
        auth_algorithm: 1,
        auth_public_key: keys[index].0.as_bytes(),
    });
    // Existing finalized account precondition. No ECDSA shares or ownership
    // signatures are needed for this native policy transition qualification.
    let public = fixed_bytes(
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    );
    let point = ValidatedSec1PublicPoint::parse(&Primitives, &public).unwrap();
    let account = derive_account_identifier(&Primitives, &point).unwrap();
    let address = account.to_native(&Primitives).unwrap();
    let genesis = NativeGenesisHash::from_bytes([3; 32]);
    let wire = inspection::candidate_wire_profile().unwrap();
    let chain = ExternalChainPolicy::new(ChainId::from_u64(1), genesis).unwrap();
    let manifest = [5; 32];
    let registry = CandidateProtectedAccounts::new(
        ChainId::from_u64(99_999),
        chain,
        &wire,
        UnactivatedCommitmentProfile::candidate_concat_v1(),
        vec![manifest],
    )
    .unwrap();
    let dp = PrimaryCompanionPublicPolicy {
        genesis,
        account,
        policy_epoch: 0,
        roles: [d, p],
        evm_public_key: *point.as_sec1_bytes(),
        provider_manifest_hash: manifest,
        ordinary_change_delay: ORDINARY_POLICY_DELAY_SECONDS,
        recovery_delay: 0,
        status: 0,
    };
    let enrollment = PrimaryCompanionEnrollmentData {
        genesis,
        account,
        evm_public_key: dp.evm_public_key,
        public_policy: dp,
        dkg_transcript_commitment: &[6; 32],
        nonce: [7; 32],
        issued_at: 90,
        expires_at: 100,
        wallet_uuid: WalletUuid::from_bytes([8; 16]),
    }
    .encode(&wire)
    .unwrap();
    let initial = CanonicalPrimaryCompanionEnrollment::decode(&enrollment, &wire).unwrap();
    let original_hash = initial.policy_hash().unwrap();
    let next = PublicPolicy {
        genesis,
        account,
        policy_epoch: 1,
        roles: [d, p, r],
        evm_public_key: dp.evm_public_key,
        provider_manifest_hash: manifest,
        ordinary_change_delay: ORDINARY_POLICY_DELAY_SECONDS,
        recovery_delay: RECOVERY_DELAY_SECONDS,
        status: 0,
    };
    let proposed = CanonicalNativeRecoveryPublicPolicy::encode(&next, &wire).unwrap();
    assert!(CanonicalPublicPolicy::decode(&proposed, &wire).is_err());
    let new_hash = CanonicalNativeRecoveryPublicPolicy::decode(&proposed, &wire)
        .unwrap()
        .hash()
        .unwrap();
    let mut world = WorldState::default();
    world.accounts.insert(
        address.clone(),
        AccountState {
            balance_nwei: 500,
            nonce: 0,
            code_hash: None,
        },
    );
    world.protocol.insert(
        account_key(account),
        encode(&PolicyRecord {
            network: registry.network,
            account: *account.as_bytes(),
            policy_epoch: 0,
            policy_hash: original_hash,
            enrollment: enrollment.clone(),
            registered_height: 4,
            replacement_policy: None,
            native_recovery_since: None,
        })
        .unwrap(),
    );
    let (pointer, proof) = super::super::tests::finalized(10, &world);
    let source = registry
        .finalized_snapshot(&world, &pointer, &proof, 100)
        .unwrap();
    let checkpoint = registry
        .native_recovery_checkpoint(
            &source,
            &proof,
            account,
            initial.binding_fields().unwrap().enrollment_hash,
        )
        .unwrap();
    let request = NativeRecoveryApproval {
        operation: NativeRecoveryOperation::AttachRecoveryDevice,
        checkpoint,
        current_policy_epoch: 0,
        current_policy_hash: original_hash,
        new_policy_hash: new_hash,
        intent_id: [9; 32],
        valid_until_finalized_height: 20,
        earliest_activation_time: 7_312,
    };
    let bytes = request.encode().unwrap();
    assert_eq!(NativeRecoveryApproval::decode(&bytes).unwrap(), request);
    let sign = |index: usize, digest: [u8; 64], context| {
        let role = next.roles[index];
        EnrollmentSignature {
            schema_version: 1,
            role_id: role.role_id,
            participant_id: role.participant_id,
            key_version: role.key_version,
            auth_algorithm: role.auth_algorithm,
            signed_digest: digest,
            signature: provider
                .sign(&digest, &keys[index].1, SignOptions::Pure { context })
                .unwrap(),
        }
    };
    let consent = [0, 1].map(|i| {
        sign(
            i,
            request.consent_digest().unwrap(),
            NATIVE_RECOVERY_CONSENT_CONTEXT,
        )
    });
    let r_proof = sign(
        2,
        request.possession_digest().unwrap(),
        NATIVE_RECOVERY_POSSESSION_CONTEXT,
    );
    let stage = |working: &WorldState, possession: &EnrollmentSignature| {
        registry.prepare_native_recovery_attachment(
            &provider,
            &source,
            &proof,
            &source,
            working,
            Position {
                height: 11,
                consensus_time: 101,
            },
            &bytes,
            &proposed,
            &consent,
            possession,
        )
    };
    // Retain the exact finality subject used for the signed checkpoint.
    let denied_proof = sign(
        2,
        request.possession_digest().unwrap(),
        NATIVE_RECOVERY_CONSENT_CONTEXT,
    );
    assert!(stage(&world, &denied_proof).is_err());
    let mut changed = world.clone();
    changed.accounts.get_mut(&address).unwrap().balance_nwei += 1;
    assert!(stage(&changed, &r_proof).is_err());
    let mut staged = world.clone();
    stage(&world, &r_proof).unwrap().apply(&mut staged).unwrap();
    assert!(stage(&staged, &r_proof).is_err());
    assert_eq!(staged.accounts, world.accounts);
    assert!(
        registry
            .prepare_native_recovery_activation(
                &source,
                &staged,
                Position {
                    height: 12,
                    consensus_time: 7_312
                },
                account,
            )
            .is_err()
    );

    // Spend accounting can advance during the delayed attachment. Activation
    // must preserve the most recent canonical ledger, including its nonce.
    let ledger = staged.accounts.get_mut(&address).unwrap();
    ledger.balance_nwei -= 12;
    ledger.nonce += 1;
    let (pointer, proof) = super::super::tests::finalized(12, &staged);
    let selected = registry
        .finalized_snapshot(&staged, &pointer, &proof, 103)
        .unwrap();
    let execute = |working: &WorldState, time| {
        registry.prepare_native_recovery_activation(
            &selected,
            working,
            Position {
                height: 13,
                consensus_time: time,
            },
            account,
        )
    };
    assert!(execute(&staged, 7_311).is_err());
    let mut swapped = staged.clone();
    swapped.protocol.get_mut(&state_key(account)).unwrap()[0] ^= 1;
    assert!(execute(&swapped, 7_312).is_err());
    let mut active = staged.clone();
    execute(&staged, 7_312).unwrap().apply(&mut active).unwrap();
    assert_eq!(active.accounts, staged.accounts);
    assert!(!active.protocol.contains_key(&state_key(account)));
    assert!(
        active
            .protocol
            .contains_key(&receipt_key(account, &request.intent_id))
    );
    assert!(execute(&active, 7_312).is_err());

    let (pointer, finality) = super::super::tests::finalized(13, &active);
    let directory = super::super::tests::Scratch::new();
    let mut store = FinalizedStateStore::load(&directory.0).unwrap();
    store
        .commit_verified_world_state(pointer.clone(), &active)
        .unwrap();
    let reopened = FinalizedStateStore::load(&directory.0)
        .unwrap()
        .current_world_state()
        .unwrap()
        .unwrap();
    let finalized = registry
        .finalized_snapshot(&reopened, &pointer, &finality, 7_312)
        .unwrap();
    let record = registry.read_policy(&reopened, account).unwrap();
    assert_eq!(record.enrollment, enrollment);
    assert_eq!(record.native_recovery_since, Some(13));
    let current = registry.current_policy(&record).unwrap();
    assert!(current.with_recovery().is_err());
    assert_eq!(current.terms().evm_public_key, point.as_sec1_bytes());
    let (state, policy) = registry
        .current_native_authority(&finalized, &reopened, account, 7_312)
        .unwrap();
    assert_eq!(policy.recovery_authority(), RecoveryAuthority::NativeOnly);
    assert_eq!(state.next_nonce, 1);
    assert_eq!(state.network_account.account, account);
}
