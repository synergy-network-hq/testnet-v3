//! Pallet for state proof validation in SXCP. Stores a Merkle root and
//! verifies inclusion proofs. This is a simplified version for demonstration.

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
        type Hash: Parameter + Member + MaybeSerializeDeserialize + Ord + Default + Copy;
    }

    #[pallet::storage]
    pub(super) type Root<T: Config> = StorageValue<_, T::Hash, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        RootUpdated(T::Hash),
        ProofVerified(bool),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Set a new Merkle root. Only root origin can call this.
        #[pallet::weight(10_000)]
        pub fn set_root(origin: OriginFor<T>, root: T::Hash) -> DispatchResult {
            ensure_root(origin)?;
            Root::<T>::put(root);
            Self::deposit_event(Event::RootUpdated(root));
            Ok(())
        }
        /// Verify a proof. This dummy implementation always returns true.
        #[pallet::weight(10_000)]
        pub fn verify(origin: OriginFor<T>, _leaf: T::Hash, _proof: Vec<T::Hash>) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            Self::deposit_event(Event::ProofVerified(true));
            Ok(())
        }
    }
}