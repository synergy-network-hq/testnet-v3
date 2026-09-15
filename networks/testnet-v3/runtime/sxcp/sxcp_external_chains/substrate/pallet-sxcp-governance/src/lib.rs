//! Pallet providing governance controls for SXCP on Substrate. Allows an
//! administrator (root) to set parameters such as deposit limits and pause
//! operations. This skeleton does not enforce the pause flag on other
//! pallets; integration would be required.

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
    pub(super) type DepositLimit<T> = StorageValue<_, u64, ValueQuery>;
    #[pallet::storage]
    pub(super) type Paused<T> = StorageValue<_, bool, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        DepositLimitChanged(u64),
        Paused,
        Unpaused,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Set a new deposit limit. Only callable by Root.
        #[pallet::weight(10_000)]
        pub fn set_deposit_limit(origin: OriginFor<T>, limit: u64) -> DispatchResult {
            ensure_root(origin)?;
            DepositLimit::<T>::put(limit);
            Self::deposit_event(Event::DepositLimitChanged(limit));
            Ok(())
        }
        /// Pause SXCP operations. Only callable by Root.
        #[pallet::weight(10_000)]
        pub fn pause(origin: OriginFor<T>) -> DispatchResult {
            ensure_root(origin)?;
            Paused::<T>::put(true);
            Self::deposit_event(Event::Paused);
            Ok(())
        }
        /// Unpause SXCP operations.
        #[pallet::weight(10_000)]
        pub fn unpause(origin: OriginFor<T>) -> DispatchResult {
            ensure_root(origin)?;
            Paused::<T>::put(false);
            Self::deposit_event(Event::Unpaused);
            Ok(())
        }
    }
}