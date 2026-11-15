use super::{
    canonical_network_fee_breakdown, compute_state_root_after, record_fee_event, ExecutionState,
    ReceiptStatus, StsSignedPayload, SynQExecutionContext, Transaction, TransactionReceipt, TxId,
};
use crate::sts::{estimate_sts_gas, StsTx};
use crate::synergy_types::{ChainId, NetworkId};
use std::collections::BTreeMap;

pub(super) fn is_sale(tx: &StsTx) -> bool {
    matches!(
        tx,
        StsTx::ListNftForSnrg { .. } | StsTx::CancelNftSale { .. } | StsTx::BuyNftForSnrg { .. }
    )
}

/// Compute the entire balance patch before publishing any changes. A buyer
/// must cover principal and fee even if they also receive the collector credit.
fn balance_patch(
    state: &ExecutionState,
    buyer: &str,
    collector: &str,
    fee: u128,
    payment: Option<(&str, u128)>,
) -> Result<BTreeMap<String, u128>, &'static str> {
    let balance = |account: &str| state.balances_nwei.get(account).copied().unwrap_or(0);
    let price = payment.map_or(0, |(_, price)| price);
    let total = fee.checked_add(price).ok_or("NFT_SALE_DEBIT_OVERFLOW")?;
    let remaining = balance(buyer)
        .checked_sub(total)
        .ok_or("NFT_SALE_INSUFFICIENT_FUNDS")?;
    let mut patch = BTreeMap::new();
    if total > 0 {
        patch.insert(buyer.to_owned(), remaining);
    }
    let mut credit = |recipient: &str, amount: u128| -> Result<(), &'static str> {
        if amount > 0 {
            let current = patch
                .entry(recipient.to_owned())
                .or_insert_with(|| balance(recipient));
            *current = current
                .checked_add(amount)
                .ok_or("NFT_SALE_CREDIT_OVERFLOW")?;
        }
        Ok(())
    };
    if let Some((seller, price)) = payment {
        credit(seller, price)?;
    }
    credit(collector, fee)?;
    Ok(patch)
}

pub(super) fn execute(
    id: TxId,
    tx: &Transaction,
    state: &mut ExecutionState,
    payload: &StsSignedPayload,
    context: SynQExecutionContext,
) -> Result<TransactionReceipt, String> {
    let sender = tx.sender_uma_or_account.as_str();
    let gas = estimate_sts_gas(&payload.tx);
    let gas_used = tx.gas_limit.min(gas);
    let fee_breakdown = canonical_network_fee_breakdown(tx, gas_used, tx.max_fee_nwei, false)?;
    let fee = fee_breakdown.total_network_fee_nwei;
    let collector = crate::token::fee_collector_address()?;

    let mut candidate = state.sts_state.clone();
    let attempted = (|| {
        payload
            .require_testnet()
            .map_err(|error| error.to_string())?;
        if tx.chain_id != ChainId::synergy_testnet_v3()
            || tx.network_id != NetworkId::synergy_testnet_v3()
            || tx.receiver_uma_or_account != sender
            || tx.amount_nwei != 1
            || tx.gas_limit < gas
            || tx.max_fee_nwei == 0
            || !tx.write_set_hint.iter().any(|key| key == "sts:global")
            || crate::address::is_network_burn_address(sender)
        {
            return Err("NFT_SALE_INVALID_CARRIER".to_owned());
        }
        let settlement = match &payload.tx {
            StsTx::ListNftForSnrg {
                nft_id,
                price_nwei,
                expires_at_height,
            } => {
                candidate
                    .list_nft_for_snrg(
                        sender,
                        nft_id,
                        *price_nwei,
                        *expires_at_height,
                        context.runtime_block_height,
                        tx.account_nonce_or_sequence,
                    )
                    .map_err(|error| error.to_string())?;
                None
            }
            StsTx::CancelNftSale { nft_id, listing_id } => {
                candidate
                    .cancel_nft_sale(sender, nft_id, listing_id)
                    .map_err(|error| error.to_string())?;
                None
            }
            StsTx::BuyNftForSnrg {
                nft_id,
                listing_id,
                expected_seller,
                price_nwei,
            } => Some(
                candidate
                    .buy_nft_for_snrg(
                        sender,
                        nft_id,
                        listing_id,
                        expected_seller,
                        *price_nwei,
                        context.runtime_block_height,
                        context.runtime_block_timestamp_unix,
                    )
                    .map_err(|error| error.to_string())?,
            ),
            _ => return Err("NFT_SALE_UNEXPECTED_OPERATION".into()),
        };
        let payment = settlement
            .as_ref()
            .map(|terms| (terms.seller.as_str(), terms.price_nwei));
        let patch =
            balance_patch(state, sender, &collector, fee, payment).map_err(str::to_owned)?;
        if let Some((seller, _)) = payment {
            let event = candidate
                .events
                .last_mut()
                .filter(|event| event.event_type == "StsNftSaleSettled")
                .ok_or("NFT_SALE_EFFECT_MISSING")?;
            let balance = |account: &str| {
                state
                    .balances_nwei
                    .get(account)
                    .copied()
                    .unwrap_or_default()
            };
            for (key, value) in [
                ("buyer_balance_before_nwei", balance(sender)),
                (
                    "buyer_balance_after_nwei",
                    patch
                        .get(sender)
                        .copied()
                        .unwrap_or_else(|| balance(sender)),
                ),
                ("seller_balance_before_nwei", balance(seller)),
                (
                    "seller_balance_after_nwei",
                    patch
                        .get(seller)
                        .copied()
                        .unwrap_or_else(|| balance(seller)),
                ),
                ("network_fee_nwei", fee),
            ] {
                event.attributes.insert(key.to_owned(), value.to_string());
            }
            event
                .attributes
                .insert("execution_tx_id".into(), id.0.clone());
            event.attributes.insert(
                "block_height".into(),
                context.runtime_block_height.to_string(),
            );
            event
                .attributes
                .insert("fee_collector".into(), collector.clone());
        }
        Ok(patch)
    })();

    let (status, error) = match attempted {
        Ok(patch) => {
            state.balances_nwei.extend(patch);
            state.sts_state = candidate;
            record_fee_event(
                state,
                &id,
                sender,
                &fee_breakdown,
                context.runtime_block_height,
                true,
            );
            (ReceiptStatus::Success, String::new())
        }
        Err(error) => {
            if let Ok(fee_only) = balance_patch(state, sender, &collector, fee, None) {
                state.balances_nwei.extend(fee_only);
                record_fee_event(
                    state,
                    &id,
                    sender,
                    &fee_breakdown,
                    context.runtime_block_height,
                    false,
                );
            }
            (ReceiptStatus::Failed, error)
        }
    };
    Ok(TransactionReceipt {
        tx_id: id,
        status,
        gas_used,
        error,
        state_root_after: compute_state_root_after(state)?,
        synq_verification: None,
        synq_aivm: None,
        synq_error_code: None,
        synq_error_message: None,
        fee_breakdown: Some(fee_breakdown),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::{
        execute_block_contents, with_nf1_sales_test_activation, ExecutionBlockContext,
        ExecutionResult,
    };
    use crate::sts::{
        encode_sts_payload, CreateNftCollectionParams, MintNftParams, TokenClass,
        STS_TESTNET_CHAIN_ID, STS_TESTNET_NETWORK,
    };
    use crate::synergy_types::{AegisPqKeyId, AegisPqSignature, Epoch, Height, UmaId};

    const PRICE: u128 = 1_000_000_000;
    const TIME: u64 = 1_795_000_000;

    fn step(
        state: ExecutionState,
        sender: &str,
        nonce: u64,
        height: u64,
        op: StsTx,
    ) -> ExecutionResult {
        with_nf1_sales_test_activation(10, || execute_step(&state, sender, nonce, height, op))
            .expect("native-sale block execution")
    }

    fn execute_step(
        state: &ExecutionState,
        sender: &str,
        nonce: u64,
        height: u64,
        op: StsTx,
    ) -> Result<ExecutionResult, String> {
        let mut state = state.clone();
        let gas_limit = estimate_sts_gas(&op);
        let transaction = Transaction {
            version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            epoch: Epoch(0),
            sender_uma_or_account: sender.to_owned(),
            receiver_uma_or_account: sender.to_owned(),
            account_nonce_or_sequence: nonce,
            amount_nwei: 1,
            gas_limit,
            max_fee_nwei: 40,
            ttl_height: Height(height + 120),
            explicit_dependencies: Vec::new(),
            read_set_hint: Vec::new(),
            write_set_hint: vec!["sts:global".into()],
            payload: encode_sts_payload(&StsSignedPayload {
                version: 1,
                chain_id: STS_TESTNET_CHAIN_ID,
                network: STS_TESTNET_NETWORK.into(),
                tx: op,
            })
            .expect("STS wire format"),
            signer_uma_id: UmaId(sender.to_owned()),
            aegis_pq_key_id: AegisPqKeyId("test-authorized-key".into()),
            aegis_pq_signature: AegisPqSignature {
                algorithm: "mldsa87".into(),
                signature_bytes: vec![1],
            },
        };
        // At the executor boundary consensus supplies the verified authorization.
        state
            .mark_authorized_at(&transaction, TIME)
            .expect("mark fixture authorized");
        execute_block_contents(
            &ExecutionBlockContext {
                height: Height(height),
                timestamp_ms: TIME * 1_000,
            },
            &[transaction],
            &state,
        )
    }

    fn minted() -> (ExecutionState, String, String, String) {
        let seller = crate::address::generate_wallet_address("spark-nf1-local-seller");
        let buyer = crate::address::generate_wallet_address("spark-nf1-local-buyer");
        let mut state = ExecutionState::new()
            .with_balance(&seller, PRICE)
            .with_balance(&buyer, PRICE * 2);
        let collection_id = state
            .sts_state
            .create_nft_collection(CreateNftCollectionParams {
                class: TokenClass::NF1StandardNft,
                creator: seller.clone(),
                creator_nonce: 1,
                name: "Spark NF1 Sale Fixture".into(),
                symbol: "SPKSALE".into(),
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
                created_at: TIME - 2,
            })
            .expect("NF1 collection");
        let nft_id = state
            .sts_state
            .mint_nft(
                &seller,
                MintNftParams {
                    collection_id,
                    to: seller.clone(),
                    metadata_uri: None,
                    metadata_hash: None,
                    metadata_mutable: false,
                    transferable: None,
                    requires_issuer_approval: None,
                    expires_at: None,
                    minted_at: TIME - 1,
                },
            )
            .expect("NF1 instance");
        (state, seller, buyer, nft_id)
    }

    fn listed() -> (ExecutionState, String, String, String, String) {
        let (state, seller, buyer, nft_id) = minted();
        let list = step(
            state,
            &seller,
            0,
            10,
            StsTx::ListNftForSnrg {
                nft_id: nft_id.clone(),
                price_nwei: PRICE,
                expires_at_height: 25,
            },
        );
        assert_eq!(
            list.receipts[0].status,
            ReceiptStatus::Success,
            "{:?}",
            list.receipts[0]
        );
        let listing = list
            .state
            .sts_state
            .nft_sale_listing(&nft_id)
            .expect("active listing");
        let listing_id = listing.listing_id.clone();
        (list.state, seller, buyer, nft_id, listing_id)
    }

    fn buy(nft_id: &str, listing_id: &str, seller: &str, price: u128) -> StsTx {
        StsTx::BuyNftForSnrg {
            nft_id: nft_id.into(),
            listing_id: listing_id.into(),
            expected_seller: seller.into(),
            price_nwei: price,
        }
    }

    #[test]
    fn native_nf1_sale_requires_the_pinned_activation_height() {
        let _guard = crate::rewards::reward_ledger_test_guard();
        let (before, seller, _, nft_id) = minted();
        let original = compute_state_root_after(&before).unwrap();
        let sale = StsTx::ListNftForSnrg {
            nft_id: nft_id.clone(),
            price_nwei: PRICE,
            expires_at_height: 25,
        };
        let payload = encode_sts_payload(&StsSignedPayload::new(sale.clone())).unwrap();
        assert!(crate::execution::is_nf1_sale_payload(&payload));
        with_nf1_sales_test_activation(10, || {
            let legacy_error = crate::sts::StsError::InvalidMetadata.to_string();
            let early = execute_step(&before, &seller, 0, 9, sale.clone()).unwrap_err();
            assert_eq!(early, legacy_error);
            assert_eq!(compute_state_root_after(&before).unwrap(), original);

            let active = execute_step(&before, &seller, 0, 10, sale.clone()).unwrap();
            assert_eq!(active.receipts[0].status, ReceiptStatus::Success);
            assert!(active.state.sts_state.nft_sale_listing(&nft_id).is_some());
            assert_ne!(active.state_root_after, original);

            // Removing or replacing an activation can never reinterpret a
            // finalized sale block as an ordinary failed transaction.
            let missing_at_height = with_nf1_sales_test_activation(11, || {
                execute_step(&before, &seller, 0, 10, sale.clone())
            });
            assert_eq!(missing_at_height.unwrap_err(), legacy_error);

            let replay = execute_step(&before, &seller, 0, 10, sale).unwrap();
            assert_eq!(replay.state_root_after, active.state_root_after);
            assert_eq!(replay.receipt_root, active.receipt_root);
        });
    }

    #[test]
    fn native_nf1_purchase_commits_payment_and_ownership_in_one_receipt() {
        let _guard = crate::rewards::reward_ledger_test_guard();
        let (before, seller, buyer, nft_id, listing_id) = listed();
        let after = step(
            before.clone(),
            &buyer,
            0,
            11,
            buy(&nft_id, &listing_id, &seller, PRICE),
        );
        let receipt = &after.receipts[0];
        assert_eq!(receipt.status, ReceiptStatus::Success);
        let fee = receipt
            .fee_breakdown
            .as_ref()
            .unwrap()
            .total_network_fee_nwei;
        assert_eq!(after.state.sts_state.nft(&nft_id).unwrap().owner, buyer);
        assert_eq!(
            after.state.balances_nwei[&seller],
            before.balances_nwei[&seller] + PRICE
        );
        assert_eq!(
            after.state.balances_nwei[&buyer],
            before.balances_nwei[&buyer] - PRICE - fee
        );
        assert!(after.state.sts_state.nft_sale_listing(&nft_id).is_none());
        let event = after.state.sts_state.events.last().unwrap();
        assert_eq!(event.attributes["execution_tx_id"], receipt.tx_id.0);
        assert_eq!(
            event.attributes["seller_balance_after_nwei"],
            after.state.balances_nwei[&seller].to_string()
        );
        assert_eq!(
            event.attributes["buyer_balance_after_nwei"],
            after.state.balances_nwei[&buyer].to_string()
        );

        let replay = step(
            after.state.clone(),
            &buyer,
            1,
            12,
            buy(&nft_id, &listing_id, &seller, PRICE),
        );
        assert_eq!(replay.receipts[0].status, ReceiptStatus::Failed);
        assert_eq!(
            replay.state.balances_nwei[&seller],
            after.state.balances_nwei[&seller]
        );
        assert_eq!(replay.state.sts_state.nft(&nft_id).unwrap().owner, buyer);
    }

    #[test]
    fn failed_native_nf1_purchase_keeps_ownership_and_sale_principal() {
        let _guard = crate::rewards::reward_ledger_test_guard();
        let (before, seller, buyer, nft_id, listing_id) = listed();
        let insufficient = before.clone().with_balance(&buyer, PRICE - 1);
        let saturated = before.clone().with_balance(&seller, u128::MAX);
        for (state, price, height) in [
            (before.clone(), PRICE - 1, 11),
            (before, PRICE, 25),
            (insufficient, PRICE, 11),
            (saturated, PRICE, 11),
        ] {
            let after = step(
                state.clone(),
                &buyer,
                0,
                height,
                buy(&nft_id, &listing_id, &seller, price),
            );
            assert_eq!(after.receipts[0].status, ReceiptStatus::Failed);
            assert_eq!(after.state.sts_state, state.sts_state);
            assert_eq!(
                after.state.balances_nwei[&seller],
                state.balances_nwei[&seller]
            );
            let fee = after.receipts[0]
                .fee_breakdown
                .as_ref()
                .unwrap()
                .total_network_fee_nwei;
            assert_eq!(
                after.state.balances_nwei[&buyer],
                state.balances_nwei[&buyer] - fee
            );
        }
    }
}
