//! Pallet tracking relayer stakes and enabling deposits and withdrawals. This
//! skeleton does not perform reward distribution; that is handled by the
//! compensation pool.

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
    pub(super) type Stake<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        StakeDeposited(T::AccountId, u64),
        StakeWithdrawn(T::AccountId, u64),
    }

    #[pallet::error]
    pub enum Error<T> {
        InsufficientStake,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Deposit stake. This increases the caller's stake balance.
        #[pallet::weight(10_000)]
        pub fn deposit_stake(origin: OriginFor<T>, amount: u64) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Stake::<T>::mutate(&who, |s| *s = s.saturating_add(amount));
            Self::deposit_event(Event::StakeDeposited(who, amount));
            Ok(())
        }
        /// Withdraw stake. Fails if the caller does not have enough stake.
        #[pallet::weight(10_000)]
        pub fn withdraw_stake(origin: OriginFor<T>, amount: u64) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Stake::<T>::try_mutate(&who, |s| -> DispatchResult {
                ensure!(*s >= amount, Error::<T>::InsufficientStake);
                *s -= amount;
                Ok(())
            })?;
            Self::deposit_event(Event::StakeWithdrawn(who, amount));
            Ok(())
        }
    }
}