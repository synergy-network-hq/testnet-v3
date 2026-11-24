//! Conventional Ethereum value-transfer settlement in the canonical native
//! World. This adapter creates neither another ledger nor finality authority.
//! The selected network must provide its authenticated address association;
//! inventing a second 0x balance namespace is not a valid resolver.
use std::collections::BTreeMap;
use synergy_aivm::ethereum::{EthereumDecodeError, NativeLegacyTerms};
use synergy_aivm::ethereum_admission::{AuthenticatedLegacyTransaction, EthereumAdmissionError};
use synergy_state::{AccountChange, StateDiff, StateError, WorldState};

pub trait EthereumLedgerResolver {
    /// Return the existing canonical native ledger key associated with bytes20
    /// by the selected network's authenticated identity rules.
    fn account_key(&self, account: &[u8; 20], state: &WorldState) -> Result<String, String>;

    /// A syntactically matching synw/0x pair is not registration evidence.
    /// The protocol owner must establish protected recipient credit eligibility.
    fn authorize_credit(
        &self,
        _account: &[u8; 20],
        key: &str,
        _state: &WorldState,
    ) -> Result<(), String> {
        if key.starts_with("synw") {
            Err("ACCOUNT_NOT_ENROLLED".into())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EthereumTransferContext<'a> {
    pub chain_id: u64,
    pub block_height: u64,
    pub maximum_gas: u64,
    pub base_fee_nwei: u64,
    pub fee_collector: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthereumTransferError {
    Authorization(EthereumAdmissionError),
    Transaction(EthereumDecodeError),
    WrongNetwork,
    InvalidContext,
    UnsupportedContractExecution,
    AddressAssociation(String),
    FeeCollectorIsSender,
    InsufficientBalance,
    ArithmeticOverflow,
    State(StateError),
}
impl std::fmt::Display for EthereumTransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for EthereumTransferError {}

/// A speculative execution result only. The canonical candidate/PoSy path must
/// commit its containing World and publish the authenticated finalized receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthereumTransferExecution {
    pub transaction_hash: [u8; 32],
    pub gas_used: u64,
    pub fee_nwei: u128,
}

pub fn execute_ethereum_transfer(
    authenticated: &AuthenticatedLegacyTransaction,
    resolver: &impl EthereumLedgerResolver,
    context: EthereumTransferContext<'_>,
    world: &mut WorldState,
) -> Result<EthereumTransferExecution, EthereumTransferError> {
    use EthereumTransferError as Error;
    let tx = authenticated.transaction();
    if context.chain_id == 0 || authenticated.signer().chain_id() != context.chain_id {
        return Err(Error::WrongNetwork);
    }
    if context.block_height == 0
        || context.base_fee_nwei == 0
        || context.fee_collector.trim().is_empty()
    {
        return Err(Error::InvalidContext);
    }
    authenticated
        .validate_account_policy(world)
        .map_err(Error::Authorization)?;
    let recipient = tx
        .recipient
        .as_ref()
        .filter(|_| tx.data.is_empty())
        .ok_or(Error::UnsupportedContractExecution)?;
    let sender_key = resolver
        .account_key(authenticated.signer().account_id(), world)
        .map_err(Error::AddressAssociation)?;
    let recipient_key = resolver
        .account_key(recipient, world)
        .map_err(Error::AddressAssociation)?;
    if sender_key.trim().is_empty() || recipient_key.trim().is_empty() {
        return Err(Error::InvalidContext);
    }
    // Protected native keys are always refused for conventional ECDSA even if a
    // malformed/missing policy or faulty resolver obscures the bytes20 class.
    if sender_key.starts_with("synw") {
        return Err(Error::Authorization(
            EthereumAdmissionError::ProtectedAccountRequiresQualifiedThresholdAuthorization,
        ));
    }
    if sender_key == context.fee_collector {
        return Err(Error::FeeCollectorIsSender);
    }
    let sender = world.accounts.get(&sender_key).cloned().unwrap_or_default();
    if sender.code_hash.is_some()
        || world
            .accounts
            .get(&recipient_key)
            .is_some_and(|a| a.code_hash.is_some())
    {
        return Err(Error::UnsupportedContractExecution);
    }
    resolver
        .authorize_credit(recipient, &recipient_key, world)
        .map_err(Error::AddressAssociation)?;
    let NativeLegacyTerms {
        value_nwei,
        gas_price_nwei,
        maximum_debit_nwei,
        ..
    } = tx
        .validate_execution_limits(
            sender.nonce,
            super::dispatcher::NATIVE_TRANSFER_GAS,
            context.maximum_gas,
            context.base_fee_nwei,
        )
        .map_err(Error::Transaction)?;
    if sender.balance_nwei < maximum_debit_nwei {
        return Err(Error::InsufficientBalance);
    }
    let gas_used = super::dispatcher::NATIVE_TRANSFER_GAS;
    let fee_nwei = u128::from(gas_used) * u128::from(gas_price_nwei);
    let debit = value_nwei
        .checked_add(fee_nwei)
        .ok_or(Error::ArithmeticOverflow)?;
    let mut changes = BTreeMap::new();
    changes.insert(
        sender_key.clone(),
        AccountChange {
            account: sender_key.clone(),
            debit_nwei: debit,
            credit_nwei: 0,
            expected_nonce: Some(tx.nonce),
            code_hash: None,
        },
    );
    for (key, amount) in [
        (recipient_key, value_nwei),
        (context.fee_collector.to_owned(), fee_nwei),
    ] {
        let change = changes.entry(key.clone()).or_insert(AccountChange {
            account: key,
            debit_nwei: 0,
            credit_nwei: 0,
            expected_nonce: None,
            code_hash: None,
        });
        change.credit_nwei = change
            .credit_nwei
            .checked_add(amount)
            .ok_or(Error::ArithmeticOverflow)?;
    }
    let diff = StateDiff {
        changes: changes.into_values().collect(),
        protocol_changes: vec![],
    };
    // The existing World write-set implementation stages all touched accounts
    // before mutating any of them, including recipient/collector overflows.
    diff.apply(world).map_err(Error::State)?;
    Ok(EthereumTransferExecution {
        transaction_hash: tx.transaction_hash,
        gas_used,
        fee_nwei,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_aivm::ethereum_admission::authenticate_conventional_eip155;
    use synergy_state::{state_root, AccountState};

    // Generated independently with ethers6.15.0 Wallet.signTransaction(type0,
    // chain9969) and the public EIP155 example's disposable0x46 test key.
    const RAW: &str = "f86e098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080824e06a0eaca0990550d84e331bbac792e1e1e9f471e9a8c6bcfc264de521e65c876c0f7a01e14c17b0297ee738948dcd8656a2d2d01306ede28edfd0be72fc2dc27f9d0d1";
    fn raw() -> Vec<u8> {
        RAW.as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    struct Resolver {
        recipient: &'static str,
    }
    impl EthereumLedgerResolver for Resolver {
        fn account_key(&self, id: &[u8; 20], _: &WorldState) -> Result<String, String> {
            if *id == [0x35; 20] {
                return Ok(self.recipient.into());
            }
            if *id
                == [
                    0x9d, 0x8a, 0x62, 0xf6, 0x56, 0xa8, 0xd1, 0x61, 0x5c, 0x12, 0x94, 0xfd, 0x71,
                    0xe9, 0xcf, 0xb3, 0xe4, 0x85, 0x5a, 0x4f,
                ]
            {
                return Ok("native-sender".into());
            }
            Err("no authenticated association".into())
        }
    }
    fn world() -> WorldState {
        let mut world = WorldState::default();
        world.accounts.insert(
            "native-sender".into(),
            AccountState {
                balance_nwei: 2_000_000_000,
                nonce: 9,
                code_hash: None,
            },
        );
        world
    }
    fn context() -> EthereumTransferContext<'static> {
        EthereumTransferContext {
            chain_id: 9969,
            block_height: 10,
            maximum_gas: 30_000_000,
            base_fee_nwei: 1,
            fee_collector: "native-treasury",
        }
    }
    #[test]
    fn ethers_chain9969_transfer_settles_once_in_native_world_and_is_deterministic() {
        let mut a = world();
        let mut b = a.clone();
        let auth = authenticate_conventional_eip155(&raw(), 9969, &a).unwrap();
        let resolver = Resolver {
            recipient: "native-recipient",
        };
        let first = execute_ethereum_transfer(&auth, &resolver, context(), &mut a).unwrap();
        assert_eq!(first.gas_used, 21_000);
        assert_eq!(first.fee_nwei, 420_000);
        assert_eq!(
            first.transaction_hash,
            [
                0x51, 0x60, 0x26, 0x7c, 0xae, 0x8b, 0x34, 0x27, 0xf4, 0x7b, 0x3e, 0xf0, 0xd2, 0x88,
                0x97, 0x18, 0xf4, 0x7f, 0x11, 0x99, 0x48, 0x30, 0x8f, 0x1c, 0xe5, 0xe2, 0x29, 0x22,
                0x94, 0x28, 0x4e, 0xc3
            ]
        );
        execute_ethereum_transfer(&auth, &resolver, context(), &mut b).unwrap();
        assert_eq!(state_root(&a).unwrap(), state_root(&b).unwrap());
        assert_eq!(a.accounts["native-sender"].balance_nwei, 999_580_000);
        assert_eq!(a.accounts["native-sender"].nonce, 10);
        assert_eq!(a.accounts["native-recipient"].balance_nwei, 1_000_000_000);
        assert_eq!(a.accounts["native-treasury"].balance_nwei, 420_000);
        assert_eq!(
            a.accounts.values().map(|a| a.balance_nwei).sum::<u128>(),
            2_000_000_000
        );
        let before = a.clone();
        assert!(execute_ethereum_transfer(&auth, &resolver, context(), &mut a).is_err());
        assert_eq!(a, before);
    }
    #[test]
    fn settlement_failures_are_atomic_and_protected_policy_is_rechecked() {
        let mut world = world();
        let auth = authenticate_conventional_eip155(&raw(), 9969, &world).unwrap();
        world.accounts.insert(
            "native-recipient".into(),
            AccountState {
                balance_nwei: u128::MAX,
                ..Default::default()
            },
        );
        let original = world.clone();
        assert!(execute_ethereum_transfer(
            &auth,
            &Resolver {
                recipient: "native-recipient"
            },
            context(),
            &mut world
        )
        .is_err());
        assert_eq!(world, original);
        world.protocol.insert(
            "apqe-protected-account-candidate/v1/policy/9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"
                .into(),
            vec![0xff],
        );
        let original = world.clone();
        assert!(matches!(
            execute_ethereum_transfer(
                &auth,
                &Resolver {
                    recipient: "native-recipient"
                },
                context(),
                &mut world
            ),
            Err(EthereumTransferError::Authorization(_))
        ));
        assert_eq!(world, original);
    }
    #[test]
    fn rejects_wrong_domain_contract_destination_and_unenrolled_protected_credit() {
        let mut world = world();
        let auth = authenticate_conventional_eip155(&raw(), 9969, &world).unwrap();
        let original = world.clone();
        for chain_id in [1266, 99999, 469] {
            assert_eq!(
                execute_ethereum_transfer(
                    &auth,
                    &Resolver {
                        recipient: "native-recipient"
                    },
                    EthereumTransferContext {
                        chain_id,
                        ..context()
                    },
                    &mut world
                ),
                Err(EthereumTransferError::WrongNetwork)
            );
        }
        assert!(execute_ethereum_transfer(
            &auth,
            &Resolver {
                recipient: "synw-unenrolled"
            },
            context(),
            &mut world
        )
        .is_err());
        assert_eq!(world, original);
        world.accounts.insert(
            "native-recipient".into(),
            AccountState {
                code_hash: Some("contract".into()),
                ..Default::default()
            },
        );
        let original = world.clone();
        assert_eq!(
            execute_ethereum_transfer(
                &auth,
                &Resolver {
                    recipient: "native-recipient"
                },
                context(),
                &mut world
            ),
            Err(EthereumTransferError::UnsupportedContractExecution)
        );
        assert_eq!(world, original);
    }

    #[test]
    fn recipient_treasury_collision_merges_once_and_treasury_overflow_rolls_back() {
        let mut world = world();
        let auth = authenticate_conventional_eip155(&raw(), 9969, &world).unwrap();
        execute_ethereum_transfer(
            &auth,
            &Resolver {
                recipient: "native-treasury",
            },
            context(),
            &mut world,
        )
        .unwrap();
        assert_eq!(
            world.accounts["native-treasury"].balance_nwei,
            1_000_420_000
        );
        assert_eq!(world.accounts["native-treasury"].nonce, 0);
        assert_eq!(world.accounts["native-sender"].nonce, 10);
        let mut original = super::tests::world();
        original.accounts.insert(
            "native-treasury".into(),
            AccountState {
                balance_nwei: u128::MAX,
                ..Default::default()
            },
        );
        let mut candidate = original.clone();
        assert!(execute_ethereum_transfer(
            &auth,
            &Resolver {
                recipient: "native-recipient"
            },
            context(),
            &mut candidate
        )
        .is_err());
        assert_eq!(candidate, original);
    }
}
