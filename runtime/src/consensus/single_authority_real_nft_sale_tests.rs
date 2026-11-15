//! Exercises real NF1 participants and settlement through local durable finality.

use super::*;
use crate::aegis_tx_tool::AegisTxSubmissionEnvelope;
use crate::crypto::aegis_pqvm::{AegisPqKeyLifecycleRecord, AegisPqvmSigner};
use crate::execution::TransactionReceipt;
use crate::sts::{
    encode_sts_payload, estimate_sts_gas, CreateNftCollectionParams, MintNftParams,
    StsSignedPayload, StsTx, TokenClass,
};
use crate::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqSignature, ChainId, NetworkId, Transaction, UmaId,
};

struct StsAccount {
    signer: AegisPqvmSigner,
    address: String,
    key_id: AegisPqKeyId,
}

impl StsAccount {
    fn new() -> Self {
        let mut signer = AegisPqvmSigner::initialize_required().expect("Aegis STS signer");
        let (mut public, mut private) = PQCManager::new()
            .generate_keypair(PQCAlgorithm::MLDSA87)
            .expect("ephemeral ML-DSA-87 keys");
        let address = crate::address::generate_wallet_address(&hex::encode(&public.key_data));
        public.key_id.clone_from(&address);
        private.public_key_id.clone_from(&address);
        let key_id = signer
            .register_existing_keypair(
                &address,
                public,
                private,
                vec![AegisPqKeyRole::Transaction],
                Epoch(0),
            )
            .expect("register Chain 1266 transaction key");
        Self {
            address,
            key_id,
            signer,
        }
    }

    fn sign(&mut self, nonce: u64, op: StsTx) -> AegisTxSubmissionEnvelope {
        let gas_limit = estimate_sts_gas(&op);
        let mut transaction = Transaction {
            version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            epoch: Epoch(0),
            sender_uma_or_account: self.address.clone(),
            receiver_uma_or_account: self.address.clone(),
            account_nonce_or_sequence: nonce,
            amount_nwei: 1,
            gas_limit,
            max_fee_nwei: u128::from(gas_limit) * 40,
            ttl_height: Height(120),
            explicit_dependencies: Vec::new(),
            read_set_hint: Vec::new(),
            write_set_hint: vec!["sts:global".to_string()],
            payload: encode_sts_payload(&StsSignedPayload::new(op)).expect("native STS payload"),
            signer_uma_id: UmaId(self.address.clone()),
            aegis_pq_key_id: self.key_id.clone(),
            aegis_pq_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        transaction.aegis_pq_signature = self
            .signer
            .sign_transaction(
                &transaction.signing_bytes().expect("canonical preimage"),
                &self.key_id,
            )
            .expect("ML-DSA-87 transaction signature");
        assert_eq!(transaction.aegis_pq_signature.algorithm, "mldsa87");

        AegisTxSubmissionEnvelope {
            transaction,
            public_key: self
                .signer
                .public_key_record(&self.key_id)
                .expect("public key"),
            lifecycle_record: AegisPqKeyLifecycleRecord {
                uma_id: self.address.clone(),
                key_id: self.key_id.clone(),
                roles: vec![AegisPqKeyRole::Transaction],
                active_from_epoch: Epoch(0),
                active_until_epoch: None,
                revoked_from_epoch: None,
            },
        }
    }
}

fn finalize_sts(
    driver: &mut SingleAuthorityDriver,
    dir: &TempDir,
    envelope: &AegisTxSubmissionEnvelope,
    excluded_candidates: &[AegisTxSubmissionEnvelope],
) -> (crate::block::Block, TransactionReceipt) {
    let mut candidates = Vec::new();
    for candidate in std::iter::once(envelope).chain(excluded_candidates) {
        let legacy =
            admit_single_authority_transaction(candidate, driver.chain(), &candidates, now_unix())
                .expect("canonical signed admission");
        candidates.push(legacy);
    }
    let expected_hash = candidates[0].hash();
    let height = driver.next_height();
    let block = driver
        .produce_next_block(candidates)
        .expect("produce signed and finalized STS block");
    assert_eq!(block.block_index, height);
    assert_eq!(block.transactions.len(), 1);
    assert_eq!(block.transactions[0].hash(), expected_hash);
    block
        .verify_proposer_signature()
        .expect("authority signature");

    let frames = recover_receipt_frames(&dir.0.join("receipts.ndjson")).expect("durable receipts");
    let frame = &frames[&height];
    assert_eq!(frame.block_hash, block.hash);
    assert_eq!(frame.receipts.len(), 1);
    let receipt = &frame.receipts[0];
    let accepted =
        crate::execution::verified_context_for_block(std::slice::from_ref(&envelope.transaction))
            .expect("typed execution identity");
    assert!(accepted.contains_key(&receipt.tx_id));
    assert_eq!(receipt.status, ReceiptStatus::Success, "{}", receipt.error);
    assert_eq!(receipt.state_root_after, frame.state_root_after);
    assert_eq!(driver.finalized_parent().state_root, frame.state_root_after);
    (block, receipt.clone())
}

#[test]
fn t03_real_signed_nf1_sale_is_finalized_with_native_payment() {
    // Create and mint replay under pre-activation rules. The listing is the
    // first sale operation at the activation boundary.
    crate::execution::with_nf1_sales_test_activation(3, exercise_sale);
}

fn exercise_sale() {
    let dir = TempDir::new("nf1-sale");
    let mut seller = StsAccount::new();
    let mut buyer = StsAccount::new();
    assert_ne!(seller.address, buyer.address);
    let fixture = build_canonical_genesis_fixture(
        &dir.0,
        &[
            (seller.address.clone(), SENDER_GENESIS_BALANCE_NWEI),
            (buyer.address.clone(), SENDER_GENESIS_BALANCE_NWEI),
        ],
    );
    let (public, private) = authority_keypair();
    let mut driver = SingleAuthorityDriver::start(inputs(&dir, &fixture, &public, &private))
        .expect("local isolated Chain 1266 driver");

    let collection_params = CreateNftCollectionParams {
        class: TokenClass::NF1StandardNft,
        creator: seller.address.clone(),
        creator_nonce: 0,
        name: "Spark Sale Fixture".to_string(),
        symbol: "SPARKSALE".to_string(),
        metadata_uri: None,
        metadata_hash: None,
        metadata_mutable: false,
        image_uri: None,
        image_hash: None,
        collection_authority: None,
        mint_authority: None,
        metadata_authority: None,
        royalty_basis_points: None,
        royalty_recipient: None,
        transferable: true,
        requires_issuer_approval: false,
        created_at: now_unix(),
    };
    let create = seller.sign(0, StsTx::CreateNftCollection(collection_params.clone()));
    const PRICE_NWEI: u128 = 1_000_000_000;
    let premature_list = seller.sign(
        1,
        StsTx::ListNftForSnrg {
            nft_id: "future-nf1-sale".to_string(),
            price_nwei: PRICE_NWEI,
            expires_at_height: 30,
        },
    );
    let following_nonce = seller.sign(
        2,
        StsTx::CreateNftCollection(CreateNftCollectionParams {
            creator_nonce: 2,
            symbol: "FUTURE".to_string(),
            ..collection_params
        }),
    );
    // Defend the fresh candidate even if an upstream gate was bypassed. The
    // lower valid create is finalized, and mint can reuse the excluded nonce.
    finalize_sts(
        &mut driver,
        &dir,
        &create,
        &[premature_list, following_nonce],
    );
    let collection_id = driver
        .execution_state()
        .sts_state
        .nft_collections
        .values()
        .find(|collection| collection.creator == seller.address && collection.symbol == "SPARKSALE")
        .expect("finalized seller collection")
        .collection_id
        .clone();

    let mint = seller.sign(
        1,
        StsTx::MintNft(MintNftParams {
            collection_id: collection_id.clone(),
            to: seller.address.clone(),
            metadata_uri: None,
            metadata_hash: None,
            metadata_mutable: false,
            transferable: None,
            requires_issuer_approval: None,
            expires_at: None,
            minted_at: now_unix(),
        }),
    );
    finalize_sts(&mut driver, &dir, &mint, &[]);
    let nft_id = driver
        .execution_state()
        .sts_state
        .nfts_for_collection(&collection_id)
        .into_iter()
        .find(|nft| nft.owner == seller.address)
        .expect("finalized mint owned by seller")
        .nft_id
        .clone();

    let list = seller.sign(
        2,
        StsTx::ListNftForSnrg {
            nft_id: nft_id.clone(),
            price_nwei: PRICE_NWEI,
            expires_at_height: 30,
        },
    );
    finalize_sts(&mut driver, &dir, &list, &[]);
    let before = driver.execution_state();
    let listing = before
        .sts_state
        .nft_sale_listing(&nft_id)
        .expect("finalized listing");
    assert_eq!(listing.seller, seller.address);
    assert_eq!(listing.price_nwei, PRICE_NWEI);
    let listing_id = listing.listing_id.clone();
    let seller_before = balance(before, &seller.address);
    let buyer_before = balance(before, &buyer.address);
    let fee_collector = crate::token::fee_collector_address().expect("collector");
    let collector_before = balance(before, &fee_collector);

    let buy = buyer.sign(
        0,
        StsTx::BuyNftForSnrg {
            nft_id: nft_id.clone(),
            listing_id: listing_id.clone(),
            expected_seller: seller.address.clone(),
            price_nwei: PRICE_NWEI,
        },
    );
    let (block, receipt) = finalize_sts(&mut driver, &dir, &buy, &[]);
    let after = driver.execution_state();
    assert_eq!(after.sts_state.nft(&nft_id).unwrap().owner, buyer.address);
    assert!(after.sts_state.nft_sale_listing(&nft_id).is_none());
    assert_eq!(balance(after, &seller.address), seller_before + PRICE_NWEI);
    let fee = receipt
        .fee_breakdown
        .as_ref()
        .unwrap()
        .total_network_fee_nwei;
    assert!(fee > 0);
    assert_eq!(
        balance(after, &buyer.address),
        buyer_before - PRICE_NWEI - fee
    );
    assert_eq!(balance(after, &fee_collector), collector_before + fee);

    let event = after
        .sts_state
        .events
        .last()
        .expect("canonical settlement event");
    assert_eq!(event.event_type, "StsNftSaleSettled");
    assert_eq!(event.token_id.as_deref(), Some(nft_id.as_str()));
    assert_eq!(event.owner.as_deref(), Some(seller.address.as_str()));
    assert_eq!(event.recipient.as_deref(), Some(buyer.address.as_str()));
    assert_eq!(event.attributes["execution_tx_id"], receipt.tx_id.0);
    assert_eq!(event.attributes["listing_id"], listing_id);
    assert_eq!(event.attributes["price_nwei"], PRICE_NWEI.to_string());
    for (field, amount) in [
        ("seller_balance_before_nwei", seller_before),
        ("seller_balance_after_nwei", seller_before + PRICE_NWEI),
        ("buyer_balance_before_nwei", buyer_before),
        ("buyer_balance_after_nwei", buyer_before - PRICE_NWEI - fee),
        ("network_fee_nwei", fee),
    ] {
        assert_eq!(event.attributes[field], amount.to_string());
    }
    assert_eq!(event.attributes["block_height"], "4");
    let settled_state_root = compute_state_root_after(after).expect("settled state root");
    let settled_event = event.clone();
    drop(driver);

    let driver = SingleAuthorityDriver::start(inputs(&dir, &fixture, &public, &private))
        .expect("restore the finalized STS sale");
    assert_eq!(driver.finalized_parent().height, 4);
    assert_eq!(driver.finalized_parent().block_hash, block.hash);
    assert_eq!(driver.finalized_parent().state_root, settled_state_root);
    let recovered = driver.execution_state();
    assert_eq!(
        compute_state_root_after(recovered).expect("recovered state root"),
        settled_state_root
    );
    assert_eq!(recovered.sts_state.events.last(), Some(&settled_event));
    assert_eq!(
        recovered.sts_state.nft(&nft_id).unwrap().owner,
        buyer.address
    );
    assert_eq!(
        balance(recovered, &seller.address),
        seller_before + PRICE_NWEI
    );
    assert_eq!(
        balance(recovered, &buyer.address),
        buyer_before - PRICE_NWEI - fee
    );
    assert!(
        admit_single_authority_transaction(&buy, driver.chain(), &[], now_unix()).is_err(),
        "the finalized buyer nonce must prevent replay"
    );

    let receipt_root =
        crate::execution::compute_receipt_root(&[receipt]).expect("settled receipt root");
    println!(
        "Local NF1 sale: finalized_height={} price_nwei={} seller_credit_nwei={} buyer_debit_nwei={} network_fee_nwei={} receipt_root={}",
        block.block_index,
        PRICE_NWEI,
        balance(recovered, &seller.address) - seller_before,
        buyer_before - balance(recovered, &buyer.address),
        fee,
        receipt_root.to_hex(),
    );
}
