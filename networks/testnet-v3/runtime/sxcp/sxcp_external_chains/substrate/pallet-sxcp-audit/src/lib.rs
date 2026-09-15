//! Pallet for audit logging in SXCP. Records events and stores them in
//! on‑chain storage for indexing. This example simply appends logs to a
//! vector; in production, consider using events instead.

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

    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub struct LogEntry<T: Config> {
        pub actor: T::AccountId,
        pub event_hash: T::Hash,
        pub action: Vec<u8>,
        pub block_number: T::BlockNumber,
    }

    #[pallet::storage]
    pub(super) type Logs<T: Config> = StorageValue<_, Vec<LogEntry<T>>, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        LogRecorded(T::AccountId, T::Hash, Vec<u8>),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Record an audit event. The caller supplies an event hash and an
        /// arbitrary action string.
        #[pallet::weight(10_000)]
        pub fn record(origin: OriginFor<T>, event_hash: T::Hash, action: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Logs::<T>::mutate(|logs| {
                logs.push(LogEntry { actor: who.clone(), event_hash, action: action.clone(), block_number: <frame_system::Pallet<T>>::block_number() });
            });
            Self::deposit_event(Event::LogRecorded(who, event_hash, action));
            Ok(())
        }
    }
}