//! Pallet that stores a confirmation threshold and provides a call to check
//! whether a given block number is final. This is simplified for demonstration.

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
    pub(super) type Confirmations<T> = StorageValue<_, T::BlockNumber, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ThresholdSet(T::BlockNumber),
        FinalityChecked(bool),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Set the confirmation threshold (in blocks). Only root can call.
        #[pallet::weight(10_000)]
        pub fn set_threshold(origin: OriginFor<T>, threshold: T::BlockNumber) -> DispatchResult {
            ensure_root(origin)?;
            Confirmations::<T>::put(threshold);
            Self::deposit_event(Event::ThresholdSet(threshold));
            Ok(())
        }
        /// Check whether a block is final. Returns an event with the result.
        #[pallet::weight(10_000)]
        pub fn is_final(origin: OriginFor<T>, target: T::BlockNumber) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let threshold = Confirmations::<T>::get();
            let current = <frame_system::Pallet<T>>::block_number();
            let diff = current.saturating_sub(target);
            let finality = diff >= threshold;
            Self::deposit_event(Event::FinalityChecked(finality));
            Ok(())
        }
    }
}