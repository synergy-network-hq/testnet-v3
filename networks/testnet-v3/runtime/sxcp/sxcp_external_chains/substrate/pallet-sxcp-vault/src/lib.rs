//! Pallet implementing a simple vault for the Synergy Cross‑Chain Protocol (SXCP).
//! This pallet is intended for Substrate‑based chains and demonstrates how to
//! record hash‑timelocked deposits and allow claims and refunds. It is a
//! skeleton for educational purposes and omits balance transfers and
//! cryptographic checks.

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
        /// The overarching event type.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// The block number type, used for timeouts.
        type BlockNumber: Parameter + Member + AtLeast32Bit + Default + Copy;
        /// A hashing function for deposit IDs. The runtime’s hash type is used.
        type Hash: Parameter + Member + MaybeSerializeDeserialize + Ord + Default + Copy;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A deposit was created. [depositor, amount, hash_lock, timeout]
        DepositCreated(T::AccountId, u64, T::Hash, T::BlockNumber),
        /// A deposit was claimed. [claimer, amount, deposit_id]
        DepositClaimed(T::AccountId, u64, T::Hash),
        /// A deposit was refunded. [refundee, amount, deposit_id]
        DepositRefunded(T::AccountId, u64, T::Hash),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// The deposit does not exist.
        DepositNotFound,
        /// The deposit has already been claimed or refunded.
        AlreadyClaimed,
        /// The caller is not the depositor.
        NotDepositor,
        /// The timeout has not yet expired.
        NotExpired,
    }

    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub struct DepositRecord<T: Config> {
        pub depositor: T::AccountId,
        pub amount: u64,
        pub hash_lock: T::Hash,
        pub timeout: T::BlockNumber,
        pub claimed: bool,
    }

    #[pallet::storage]
    #[pallet::getter(fn deposits)]
    pub type Deposits<T: Config> = StorageMap<_, Blake2_128Concat, T::Hash, DepositRecord<T>>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Create a new deposit under a hash‑time lock. The caller must specify
        /// a unique deposit ID (hash), the amount (for demonstration only) and
        /// a timeout block number after which the funds can be refunded.
        #[pallet::weight(10_000)]
        pub fn deposit(origin: OriginFor<T>, deposit_id: T::Hash, amount: u64, timeout: T::BlockNumber) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(!Deposits::<T>::contains_key(&deposit_id), Error::<T>::DepositNotFound);
            let current = <frame_system::Pallet<T>>::block_number();
            ensure!(timeout > current, Error::<T>::NotExpired);
            let record = DepositRecord { depositor: who.clone(), amount, hash_lock: deposit_id, timeout, claimed: false };
            Deposits::<T>::insert(deposit_id, record);
            Self::deposit_event(Event::DepositCreated(who, amount, deposit_id, timeout));
            Ok(())
        }

        /// Claim a deposit by providing the preimage. For simplicity this call
        /// only checks that the deposit exists and has not been claimed. It
        /// ignores the actual preimage and amount transfer logic.
        #[pallet::weight(10_000)]
        pub fn claim(origin: OriginFor<T>, deposit_id: T::Hash, _preimage: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Deposits::<T>::try_mutate_exists(deposit_id, |maybe_record| -> DispatchResult {
                let mut record = maybe_record.take().ok_or(Error::<T>::DepositNotFound)?;
                ensure!(!record.claimed, Error::<T>::AlreadyClaimed);
                // In a real implementation verify preimage matches hash_lock
                record.claimed = true;
                *maybe_record = Some(record);
                Self::deposit_event(Event::DepositClaimed(who, record.amount, deposit_id));
                Ok(())
            })
        }

        /// Refund a deposit after the timeout. Only the original depositor can
        /// call this function. The deposit must not already be claimed.
        #[pallet::weight(10_000)]
        pub fn refund(origin: OriginFor<T>, deposit_id: T::Hash) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Deposits::<T>::try_mutate_exists(deposit_id, |maybe_record| -> DispatchResult {
                let mut record = maybe_record.take().ok_or(Error::<T>::DepositNotFound)?;
                ensure!(!record.claimed, Error::<T>::AlreadyClaimed);
                ensure!(record.depositor == who, Error::<T>::NotDepositor);
                let current = <frame_system::Pallet<T>>::block_number();
                ensure!(current >= record.timeout, Error::<T>::NotExpired);
                record.claimed = true;
                *maybe_record = Some(record);
                Self::deposit_event(Event::DepositRefunded(who, record.amount, deposit_id));
                Ok(())
            })
        }
    }
}