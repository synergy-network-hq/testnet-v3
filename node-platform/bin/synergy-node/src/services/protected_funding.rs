//! Engineering qualification of ordinary treasury funding against finalized
//! protected enrollment. The active runtime has no protected credit policy.
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use synergy_address_engine::{
    apqe::{
        address::parse_address, crypto_engine::CryptoEngine, provider::SignOptions, SecretBytes,
    },
    types::Algorithm,
};
use synergy_block::BlockBody;
use synergy_config::ApqeProviderConfiguration;
use synergy_execution::{
    BlockExecutionError, BlockExecutionScheduler, FeeSchedule, NativeDispatchError,
    NativeDispatcher, NativeOperation, TransactionDispatch, TransactionExecutionContext,
};
use synergy_state::FinalizedStateStore;
use synergy_transaction::{NetworkBinding, ReceiptStatus, SignedTransaction};

use super::super::{
    execution::TransactionPqvmVerifier,
    socket_qualification::funded_transaction_fixture_for_network_provider_chain,
};
use super::{
    account_key, tests, AccountIdentifier, ChainId, FinalizedSnapshot, Primitives, WorldState,
};

struct FundingCredit<'a> {
    selected_network: &'a NetworkBinding,
    source: &'a FinalizedSnapshot<'a>,
}

impl NativeOperation for FundingCredit<'_> {
    type Error = &'static str;

    fn authorize_protected_credit(
        &self,
        receiver: &str,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<(), NativeDispatchError> {
        let denied = NativeDispatchError::AccountNotEnrolled;
        let registry = self.source.registry;
        if context.network != self.selected_network
            || ChainId::from_u64(context.network.chain_id).as_be_bytes()
                != &registry.network.native_chain
            || context.block_height <= self.source.position.height
        {
            return Err(denied);
        }
        let account = parse_address(&Primitives, receiver).map_err(|_| denied.clone())?;
        account
            .validate_spending_destination()
            .map_err(|_| denied.clone())?;
        let address = registry
            .require_finalized_recipient(self.source, state, account)
            .map_err(|_| denied.clone())?;
        if address != receiver {
            return Err(denied);
        }
        Ok(())
    }

    fn execute_native(
        &self,
        _module: &str,
        _method: &str,
        _input: &[u8],
        _transaction: &SignedTransaction,
        _context: TransactionExecutionContext<'_>,
        _state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        Err("unsupported funding fixture action")
    }
}

const INITIAL_ALLOCATION_NWEI: u128 = 5_000_000_000_000_000;
const FUNDED_AMOUNT_NWEI: u128 = 100_000_000_000;
const GAS: u64 = 21_000;
const FEE_PER_GAS_NWEI: u64 = 40;

pub(super) struct FundingFixture {
    transaction: SignedTransaction,
    selected_network: NetworkBinding,
    account: AccountIdentifier,
    verifier: TransactionPqvmVerifier,
}

impl FundingFixture {
    pub(super) fn new(
        engine: Arc<Mutex<CryptoEngine>>,
        provider: &ApqeProviderConfiguration,
        selected_network: NetworkBinding,
        account: AccountIdentifier,
        timestamp: u64,
    ) -> (Self, WorldState) {
        let (mut transaction, world, key) = funded_transaction_fixture_for_network_provider_chain(
            &selected_network.network_id,
            INITIAL_ALLOCATION_NWEI,
            Some(provider),
            selected_network.chain_id,
        );
        transaction.unsigned.receiver = account.to_native(&Primitives).unwrap();
        transaction.unsigned.amount_nwei = FUNDED_AMOUNT_NWEI;
        transaction.unsigned.timestamp_unix = timestamp;
        let key = SecretBytes::from_bytes(key);
        transaction.signature = engine
            .lock()
            .unwrap()
            .sign(
                Algorithm::MlDsa87,
                key.as_bytes(),
                &transaction.unsigned.signing_bytes().unwrap(),
                SignOptions::default(),
            )
            .unwrap();
        let verifier =
            TransactionPqvmVerifier::from_fixture_engine(engine, selected_network.chain_id)
                .unwrap();
        (
            Self {
                transaction,
                selected_network,
                account,
                verifier,
            },
            world,
        )
    }

    pub(super) fn qualify(
        self,
        before_enrollment: &FinalizedSnapshot<'_>,
        enrolled: &FinalizedSnapshot<'_>,
        mut store: FinalizedStateStore,
        path: &Path,
    ) {
        let world = enrolled.world;
        let treasury = self.transaction.unsigned.sender.clone();
        let recipient = self.transaction.unsigned.receiver.clone();
        let height = enrolled.position.height + 1;
        let timestamp = self.transaction.unsigned.timestamp_unix;
        let schedule = FeeSchedule {
            base_fee_per_gas_nwei: FEE_PER_GAS_NWEI,
            collector: "test-collector".into(),
        };
        let body = BlockBody {
            transactions: vec![self.transaction],
        };
        let execute =
            |source: &FinalizedSnapshot<'_>, ordered: &WorldState, input: &BlockBody, height| {
                BlockExecutionScheduler::new(
                    NativeDispatcher::new(FundingCredit {
                        selected_network: &self.selected_network,
                        source,
                    }),
                    self.verifier.clone(),
                    schedule.clone(),
                )
                .unwrap()
                .execute_async_at(
                    input,
                    &self.selected_network,
                    height,
                    timestamp,
                    ordered,
                    source.world,
                )
            };
        let denied = |result| {
            assert!(matches!(
                result,
                Err(BlockExecutionError::Dispatcher { message, .. })
                    if message.ends_with("ACCOUNT_NOT_ENROLLED")
            ));
        };
        // A registration in the speculative parent is insufficient.
        denied(execute(before_enrollment, world, &body, height));
        let mut missing_policy = world.clone();
        missing_policy
            .protocol
            .remove(&account_key(self.account))
            .unwrap();
        denied(execute(enrolled, &missing_policy, &body, height));
        let mut missing_ledger = world.clone();
        missing_ledger.accounts.remove(&recipient).unwrap();
        denied(execute(enrolled, &missing_ledger, &body, height));

        let mut altered = body.clone();
        altered.transactions[0].unsigned.amount_nwei += 1;
        assert!(matches!(
            execute(enrolled, world, &altered, height),
            Err(BlockExecutionError::Signature { .. })
        ));

        let outcome = execute(enrolled, world, &body, height).unwrap();
        let fee = u128::from(GAS) * u128::from(FEE_PER_GAS_NWEI);
        let [receipt] = outcome.receipts.as_slice() else {
            panic!("expected one funding receipt")
        };
        assert_eq!(receipt.transaction_id, body.transactions[0].id().unwrap());
        assert_eq!(receipt.status, ReceiptStatus::Applied);
        assert_eq!(receipt.gas_used, GAS);
        assert_eq!(receipt.state_root_after, outcome.state_root);
        assert_eq!(outcome.total_fees_nwei, fee);
        assert_eq!(
            outcome.state.accounts[&treasury].balance_nwei,
            INITIAL_ALLOCATION_NWEI - FUNDED_AMOUNT_NWEI - fee
        );
        assert_eq!(outcome.state.accounts[&treasury].nonce, 1);
        assert_eq!(world.accounts[&recipient].balance_nwei, 0);
        assert_eq!(
            outcome.state.accounts[&recipient].balance_nwei,
            FUNDED_AMOUNT_NWEI
        );
        assert_eq!(
            outcome.state.accounts[&recipient].nonce,
            world.accounts[&recipient].nonce
        );
        assert_eq!(
            outcome.state.accounts[&schedule.collector].balance_nwei,
            world.accounts[&schedule.collector].balance_nwei + fee
        );
        assert_eq!(outcome.state.protocol, world.protocol);

        // These store fixtures exercise deterministic persistence, without
        // generating a consensus certificate or starting a validator.
        let (pointer, record) = tests::finalized(height, &outcome.state);
        store
            .commit_verified_world_transition(pointer.clone(), world, &outcome.state)
            .unwrap();
        drop(store);
        let restored = FinalizedStateStore::load(path)
            .unwrap()
            .current_world_state()
            .unwrap()
            .unwrap();
        assert_eq!(restored, outcome.state);
        let source = enrolled
            .registry
            .finalized_snapshot(&restored, &pointer, &record, timestamp)
            .unwrap();
        let replay = execute(&source, &restored, &body, height + 1).unwrap();
        assert_eq!(replay.receipts[0].status, ReceiptStatus::Reverted);
        assert_eq!(
            replay.receipts[0].error_code.as_deref(),
            Some("async_parent_nonce_stale_v1")
        );
        assert_eq!(replay.total_fees_nwei, 0);
        assert_eq!(replay.state, restored);
    }
}
