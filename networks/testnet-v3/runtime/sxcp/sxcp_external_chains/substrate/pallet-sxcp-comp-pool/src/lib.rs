//! Pallet implementing a simple compensation pool. Collects fees and stakes
//! and allows pro‑rata reward distribution. This skeleton does not perform
//! actual reward calculations; it emits events for demonstration only.

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
use frame_system::pallet_prelude::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
    }

    #[pallet::storage]
    pub(super) type Stakes<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

    #[pallet::storage]
    pub(super) type PendingRewards<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        FeeDeposited(T::AccountId, u64),
        StakeAdded(T::AccountId, u64),
        RewardClaimed(T::AccountId, u64),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Deposit a fee. In a real implementation this would involve transferring
        /// funds to the pallet account. Here we simply emit an event with the amount.
        #[pallet::weight(10_000)]
        pub fn deposit_fee(origin: OriginFor<T>, amount: u64) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::deposit_event(Event::FeeDeposited(who, amount));
            Ok(())
        }
        /// Stake some amount to become eligible for rewards. Stake accumulates in
        /// storage for each account.
        #[pallet::weight(10_000)]
        pub fn add_stake(origin: OriginFor<T>, amount: u64) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Stakes::<T>::mutate(&who, |s| *s = s.saturating_add(amount));
            Self::deposit_event(Event::StakeAdded(who, amount));
            Ok(())
        }
        /// Claim pending rewards. Rewards are reset to zero after claiming.
        #[pallet::weight(10_000)]
        pub fn claim_rewards(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let reward = PendingRewards::<T>::take(&who);
            Self::deposit_event(Event::RewardClaimed(who, reward));
            Ok(())
        }
    }
}