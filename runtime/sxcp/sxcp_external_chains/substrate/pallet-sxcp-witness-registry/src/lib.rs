//! Pallet implementing a witness registry for the Synergy Cross‑Chain Protocol on Substrate.
//! Maintains a set of authorised relayers with reputation scores.

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
    #[pallet::getter(fn relayer_info)]
    pub type Relayers<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, (bool, u64)>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        RelayerAdded(T::AccountId),
        RelayerRemoved(T::AccountId),
        ReputationUpdated(T::AccountId, i64, u64),
    }

    #[pallet::error]
    pub enum Error<T> {
        RelayerAlreadyExists,
        RelayerNotFound,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Add a new relayer with zero reputation.
        #[pallet::weight(10_000)]
        pub fn add_relayer(origin: OriginFor<T>, relayer: T::AccountId) -> DispatchResult {
            let _ = ensure_root(origin)?;
            ensure!(!Relayers::<T>::contains_key(&relayer), Error::<T>::RelayerAlreadyExists);
            Relayers::<T>::insert(&relayer, (true, 0));
            Self::deposit_event(Event::RelayerAdded(relayer));
            Ok(())
        }
        /// Remove an existing relayer.
        #[pallet::weight(10_000)]
        pub fn remove_relayer(origin: OriginFor<T>, relayer: T::AccountId) -> DispatchResult {
            let _ = ensure_root(origin)?;
            ensure!(Relayers::<T>::contains_key(&relayer), Error::<T>::RelayerNotFound);
            Relayers::<T>::remove(&relayer);
            Self::deposit_event(Event::RelayerRemoved(relayer));
            Ok(())
        }
        /// Update a relayer's reputation. Root call.
        #[pallet::weight(10_000)]
        pub fn update_reputation(origin: OriginFor<T>, relayer: T::AccountId, delta: i64) -> DispatchResult {
            let _ = ensure_root(origin)?;
            Relayers::<T>::try_mutate(&relayer, |maybe| -> DispatchResult {
                let (active, ref mut rep) = maybe.as_mut().ok_or(Error::<T>::RelayerNotFound)?;
                if delta >= 0 {
                    *rep = rep.saturating_add(delta as u64);
                } else {
                    let d = (-delta) as u64;
                    if *rep > d { *rep -= d; } else { *rep = 0; }
                }
                Self::deposit_event(Event::ReputationUpdated(relayer.clone(), delta, *rep));
                Ok(())
            })
        }
    }
}