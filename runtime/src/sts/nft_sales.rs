use super::{
    require_nft_active, sts_hash, validate_actor_ref, validate_amount, NftInstance, StsError,
    StsEvent, StsState, TokenClass, STS_TESTNET_CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// Domain and field order are consensus inputs. The signed seller nonce makes a
// canceled or expired listing distinguishable from a later listing of the same NFT.
const LISTING_ID_DOMAIN: &str = "synergy-sts-nf1-snrg-listing-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftSaleListing {
    pub listing_id: String,
    pub nft_id: String,
    pub seller: String,
    pub price_nwei: u128,
    pub expires_at_height: u64,
}

impl NftSaleListing {
    /// A listing expires at the stated height, including buys in that block.
    pub fn is_active_at(&self, height: u64) -> bool {
        height < self.expires_at_height
    }
}

impl StsState {
    pub fn nft_sale_listing(&self, nft_id: &str) -> Option<&NftSaleListing> {
        self.nft_sale_listings.get(nft_id)
    }

    pub fn nft_sale_listings(&self) -> &BTreeMap<String, NftSaleListing> {
        &self.nft_sale_listings
    }

    /// Called with the signer, nonce, and block height from the execution context.
    pub fn list_nft_for_snrg(
        &mut self,
        seller: &str,
        nft_id: &str,
        price_nwei: u128,
        expires_at_height: u64,
        current_height: u64,
        seller_nonce: u64,
    ) -> Result<NftSaleListing, StsError> {
        validate_actor_ref(seller)?;
        validate_amount(price_nwei)?;
        if expires_at_height <= current_height {
            return Err(StsError::NftSaleInvalidExpiry);
        }
        self.sale_eligible_nft(seller, nft_id)?;
        if self
            .nft_sale_listing(nft_id)
            .is_some_and(|listing| listing.is_active_at(current_height))
        {
            return Err(StsError::NftSaleAlreadyListed);
        }

        let listing = NftSaleListing {
            listing_id: hex::encode(sts_hash(
                LISTING_ID_DOMAIN,
                &[
                    &STS_TESTNET_CHAIN_ID.to_be_bytes(),
                    nft_id.as_bytes(),
                    seller.as_bytes(),
                    &seller_nonce.to_be_bytes(),
                ],
            )),
            nft_id: nft_id.to_string(),
            seller: seller.to_string(),
            price_nwei,
            expires_at_height,
        };
        self.nft_sale_listings
            .insert(nft_id.to_string(), listing.clone());
        Ok(listing)
    }

    /// Cancel only the listing signed by its seller. The seller can also remove
    /// an expired listing without waiting for a replacement.
    pub fn cancel_nft_sale(
        &mut self,
        seller: &str,
        nft_id: &str,
        listing_id: &str,
    ) -> Result<NftSaleListing, StsError> {
        let listing = self
            .nft_sale_listing(nft_id)
            .ok_or(StsError::NftSaleListingNotFound)?;
        if listing.seller != seller {
            return Err(StsError::Unauthorized);
        }
        if listing.listing_id != listing_id {
            return Err(StsError::NftSaleTermsMismatch);
        }
        self.nft_sale_listings
            .remove(nft_id)
            .ok_or(StsError::NftSaleListingNotFound)
    }

    /// Mutates an isolated execution candidate. The executor must commit this
    /// candidate together with the matching native payment, or discard both.
    pub fn buy_nft_for_snrg(
        &mut self,
        buyer: &str,
        nft_id: &str,
        listing_id: &str,
        expected_seller: &str,
        price_nwei: u128,
        current_height: u64,
        block_timestamp_seconds: u64,
    ) -> Result<NftSaleListing, StsError> {
        validate_actor_ref(buyer)?;
        let listing = self
            .nft_sale_listing(nft_id)
            .ok_or(StsError::NftSaleListingNotFound)?
            .clone();
        if listing.listing_id != listing_id
            || listing.seller != expected_seller
            || listing.price_nwei != price_nwei
        {
            return Err(StsError::NftSaleTermsMismatch);
        }
        if listing.seller == buyer {
            return Err(StsError::Unauthorized);
        }
        if !listing.is_active_at(current_height) {
            return Err(StsError::NftSaleExpired);
        }
        let collection_id = self
            .sale_eligible_nft(&listing.seller, nft_id)?
            .collection_id
            .clone();

        // The seller's finalized listing gives this purchase authority to
        // transfer this NFT on the exact terms above. This also clears the listing.
        self.transfer_nft(
            &listing.seller,
            nft_id,
            &listing.seller,
            buyer,
            block_timestamp_seconds,
        )?;
        self.push_event(StsEvent {
            event_type: "StsNftSaleSettled".to_string(),
            token_id: Some(nft_id.to_string()),
            sender: buyer.to_string(),
            owner: Some(listing.seller.clone()),
            recipient: Some(buyer.to_string()),
            amount: Some("1".to_string()),
            timestamp: block_timestamp_seconds,
            attributes: BTreeMap::from([
                ("collection_id".to_string(), collection_id),
                ("listing_id".to_string(), listing.listing_id.clone()),
                ("price_nwei".to_string(), listing.price_nwei.to_string()),
                ("payment_asset".to_string(), "SNRG".to_string()),
            ]),
        });
        Ok(listing)
    }

    fn sale_eligible_nft(&self, seller: &str, nft_id: &str) -> Result<&NftInstance, StsError> {
        let nft = self
            .nft_instances
            .get(nft_id)
            .ok_or(StsError::InvalidTokenId)?;
        if nft.owner != seller {
            return Err(StsError::Unauthorized);
        }
        let collection = self
            .nft_collections
            .get(&nft.collection_id)
            .ok_or(StsError::InvalidTokenId)?;
        if nft.class != TokenClass::NF1StandardNft
            || collection.class != TokenClass::NF1StandardNft
            || !collection.transferable
            || !nft.transferable
            || nft.requires_issuer_approval
            || collection.requires_issuer_approval
            || collection.royalty_basis_points.unwrap_or(0) != 0
            || nft.expires_at.is_some()
        {
            return Err(StsError::PolicyNotEnabled);
        }
        // NF1 is non-expiring. This still enforces active, unfrozen ownership.
        require_nft_active(nft, 0)?;
        Ok(nft)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sts::{
        decode_sts_payload, encode_sts_payload, CreateNftCollectionParams, MintNftParams,
        StsSignedPayload, StsTx,
    };

    const SELLER: &str = "test-seller";
    const BUYER: &str = "test-buyer";
    const OTHER: &str = "other-buyer";
    const TIME: u64 = 1_790_000_000;
    const PRICE: u128 = 1_000_000_000;

    fn nft(class: TokenClass, royalty: Option<u16>) -> (StsState, String) {
        let mut state = StsState::new();
        let collection_id = state
            .create_nft_collection(CreateNftCollectionParams {
                class,
                creator: SELLER.to_string(),
                creator_nonce: 7,
                name: "Spark collectibles".to_string(),
                symbol: "SPARK".to_string(),
                metadata_uri: None,
                metadata_hash: None,
                metadata_mutable: false,
                image_uri: None,
                image_hash: None,
                collection_authority: None,
                mint_authority: None,
                metadata_authority: None,
                royalty_basis_points: royalty,
                royalty_recipient: royalty.map(|_| SELLER.to_string()),
                transferable: true,
                requires_issuer_approval: false,
                created_at: TIME,
            })
            .unwrap();
        let id = state
            .mint_nft(
                SELLER,
                MintNftParams {
                    collection_id,
                    to: SELLER.to_string(),
                    metadata_uri: None,
                    metadata_hash: None,
                    metadata_mutable: false,
                    transferable: None,
                    requires_issuer_approval: None,
                    expires_at: None,
                    minted_at: TIME,
                },
            )
            .unwrap();
        (state, id)
    }

    #[test]
    fn settlement_requires_exact_terms_and_changes_the_nft_once() {
        let (mut state, id) = nft(TokenClass::NF1StandardNft, None);
        let order = state
            .list_nft_for_snrg(SELLER, &id, PRICE, 20, 10, 1)
            .unwrap();
        assert_eq!(order.listing_id.len(), 64);
        let initial = state.clone();
        for (buyer, listing_id, seller, price, height, err) in [
            (
                BUYER,
                order.listing_id.as_str(),
                OTHER,
                PRICE,
                11,
                StsError::NftSaleTermsMismatch,
            ),
            (
                BUYER,
                order.listing_id.as_str(),
                SELLER,
                PRICE + 1,
                11,
                StsError::NftSaleTermsMismatch,
            ),
            (
                BUYER,
                "different-listing",
                SELLER,
                PRICE,
                11,
                StsError::NftSaleTermsMismatch,
            ),
            (
                SELLER,
                order.listing_id.as_str(),
                SELLER,
                PRICE,
                11,
                StsError::Unauthorized,
            ),
            (
                BUYER,
                order.listing_id.as_str(),
                SELLER,
                PRICE,
                20,
                StsError::NftSaleExpired,
            ),
        ] {
            assert_eq!(
                state.buy_nft_for_snrg(buyer, &id, listing_id, seller, price, height, TIME + 1),
                Err(err)
            );
            assert_eq!(state, initial);
        }
        assert_eq!(
            state.list_nft_for_snrg(SELLER, &id, PRICE, 30, 12, 2),
            Err(StsError::NftSaleAlreadyListed)
        );
        assert_eq!(
            state.buy_nft_for_snrg(BUYER, &id, &order.listing_id, SELLER, PRICE, 19, TIME + 2),
            Ok(order.clone())
        );
        assert_eq!(state.nft(&id).unwrap().owner, BUYER);
        assert!(state.nft_sale_listing(&id).is_none());
        assert_eq!(
            state.buy_nft_for_snrg(OTHER, &id, &order.listing_id, SELLER, PRICE, 19, TIME + 2),
            Err(StsError::NftSaleListingNotFound)
        );
        let event = state.events.last().unwrap();
        assert_eq!(event.event_type, "StsNftSaleSettled");
        assert_eq!(event.token_id.as_deref(), Some(id.as_str()));
        assert_eq!(event.sender, BUYER);
        assert_eq!(event.owner.as_deref(), Some(SELLER));
        assert_eq!(event.recipient.as_deref(), Some(BUYER));
        assert_eq!(event.attributes["listing_id"], order.listing_id);
        assert_eq!(event.attributes["price_nwei"], PRICE.to_string());
    }

    #[test]
    fn cancel_expire_transfer_and_burn_invalidate_listings() {
        let (mut state, id) = nft(TokenClass::NF1StandardNft, Some(0));
        assert_eq!(
            state.list_nft_for_snrg(SELLER, &id, 0, 20, 10, 0),
            Err(StsError::InvalidAmount)
        );
        assert_eq!(
            state.list_nft_for_snrg(SELLER, &id, PRICE, 10, 10, 0),
            Err(StsError::NftSaleInvalidExpiry)
        );
        assert_eq!(
            state.list_nft_for_snrg(OTHER, &id, PRICE, 20, 10, 0),
            Err(StsError::Unauthorized)
        );
        let first = state
            .list_nft_for_snrg(SELLER, &id, PRICE, 20, 10, 0)
            .unwrap();
        assert_eq!(
            state.cancel_nft_sale(OTHER, &id, &first.listing_id),
            Err(StsError::Unauthorized)
        );
        let replacement = state
            .list_nft_for_snrg(SELLER, &id, PRICE, 30, 20, 1)
            .unwrap();
        assert_ne!(replacement.listing_id, first.listing_id);
        assert_eq!(
            state.cancel_nft_sale(SELLER, &id, &first.listing_id),
            Err(StsError::NftSaleTermsMismatch)
        );
        state
            .cancel_nft_sale(SELLER, &id, &replacement.listing_id)
            .unwrap();

        let canceled = state
            .list_nft_for_snrg(SELLER, &id, PRICE, 30, 21, 2)
            .unwrap();
        assert_ne!(canceled.listing_id, replacement.listing_id);
        assert!(state
            .transfer_nft(OTHER, &id, SELLER, BUYER, TIME + 1)
            .is_err());
        assert!(state.nft_sale_listing(&id).is_some());
        state
            .transfer_nft(SELLER, &id, SELLER, BUYER, TIME + 1)
            .unwrap();
        assert!(state.nft_sale_listing(&id).is_none());
        state
            .list_nft_for_snrg(BUYER, &id, PRICE, 30, 22, 0)
            .unwrap();
        state.burn_nft(BUYER, &id, BUYER, TIME + 2).unwrap();
        assert!(state.nft_sale_listing(&id).is_none());
        assert!(state
            .list_nft_for_snrg(BUYER, &id, PRICE, 30, 23, 1)
            .is_err());
    }

    #[test]
    fn unsupported_collections_and_frozen_nfts_are_rejected() {
        for (class, royalty) in [
            (TokenClass::NF1StandardNft, Some(250)),
            (TokenClass::NF2ControlledNft, None),
        ] {
            let (mut state, id) = nft(class, royalty);
            assert_eq!(
                state.list_nft_for_snrg(SELLER, &id, PRICE, 20, 10, 0),
                Err(StsError::PolicyNotEnabled)
            );
        }
        let (mut state, id) = nft(TokenClass::NF1StandardNft, None);
        state.nft_instances.get_mut(&id).unwrap().frozen = true;
        assert_eq!(
            state.list_nft_for_snrg(SELLER, &id, PRICE, 20, 10, 0),
            Err(StsError::AccountFrozen)
        );
    }

    #[test]
    fn sale_payloads_round_trip_but_cannot_replay_without_execution_context() {
        let baseline = StsState::new();
        let json = serde_json::to_string(&baseline).unwrap();
        assert_eq!(
            json,
            r#"{"schema_version":1,"token_registry":{},"fungible_balances":{},"fungible_snapshots":{},"next_snapshot_id":1,"nft_collections":{},"nft_instances":{},"multi_asset_collections":{},"multi_asset_items":{},"multi_asset_balances":{},"credential_schemas":{},"credential_records":{},"events":[]}"#
        );
        assert_eq!(serde_json::from_str::<StsState>(&json).unwrap(), baseline);

        let (mut state, id) = nft(TokenClass::NF1StandardNft, None);
        let price = u128::MAX;
        let listing = state
            .list_nft_for_snrg(SELLER, &id, price, 20, 10, 1)
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<StsState>(&serde_json::to_vec(&state).unwrap()).unwrap(),
            state
        );
        for op in [
            StsTx::ListNftForSnrg {
                nft_id: id.clone(),
                price_nwei: price,
                expires_at_height: 20,
            },
            StsTx::CancelNftSale {
                nft_id: id.clone(),
                listing_id: listing.listing_id.clone(),
            },
            StsTx::BuyNftForSnrg {
                nft_id: id.clone(),
                listing_id: listing.listing_id.clone(),
                expected_seller: SELLER.to_string(),
                price_nwei: price,
            },
        ] {
            let payload = StsSignedPayload::new(op);
            assert_eq!(
                decode_sts_payload(&encode_sts_payload(&payload).unwrap()).unwrap(),
                Some(payload.clone())
            );
            let before = state.clone();
            assert_eq!(
                state.apply_signed_payload(SELLER, &payload),
                Err(StsError::NftSaleExecutionContextRequired)
            );
            assert_eq!(state, before);
        }
    }
}
