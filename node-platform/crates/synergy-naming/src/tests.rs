use synergy_node_ownership::NodeOwnerResolver;
use synergy_protocol_types::{BlockReference, Height, NodeAddress, ProtocolHash};

use super::*;

const NODE_ONE: &str = "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn";
const NODE_TWO: &str = "synv21lrh6jcxaejkj4zv994j7qwn2rk6u3zat22n";

#[derive(Clone)]
struct Owners {
    node_address: NodeAddress,
    wallet: String,
}

impl NodeOwnerResolver for Owners {
    fn current_owner(&self, node_address: &NodeAddress) -> Result<Option<String>, String> {
        Ok((node_address == &self.node_address).then(|| self.wallet.clone()))
    }
}

#[derive(Clone, Copy)]
struct Verifier;

impl NamingAuthorizationVerifier for Verifier {
    fn verify(
        &self,
        action: &NamingAction,
        authorization: &NamingAuthorization,
    ) -> Result<(), String> {
        if action
            .signing_payload()
            .map_err(|error| error.to_string())?
            .is_empty()
            || authorization.proof != b"owner-proof"
        {
            return Err("invalid owner proof".into());
        }
        Ok(())
    }
}

fn wallet(seed: u8) -> String {
    synergy_address::generate_wallet_address(&format!("{seed:02x}").repeat(1_793)).unwrap()
}

fn authorization(wallet: String, nonce: u64) -> NamingAuthorization {
    NamingAuthorization {
        owner_wallet: wallet,
        nonce,
        proof: b"owner-proof".to_vec(),
    }
}

fn finalized(height: u64) -> BlockReference {
    BlockReference::new(
        Height::new(height),
        ProtocolHash::new([(height + 1) as u8; 32]),
        ProtocolHash::new([height as u8; 32]),
    )
    .unwrap()
}

#[test]
fn node_id_normalizes_case_without_changing_protocol_identity() {
    let node_id = NodeId::parse("Atlas.NODE").unwrap();
    assert_eq!(node_id.as_str(), "atlas.node");
}

#[test]
fn registration_becomes_visible_only_after_finalized_application() {
    let node_address = NodeAddress::parse(NODE_ONE).unwrap();
    let owner = wallet(1);
    let engine = NamingEngine::new(
        Owners {
            node_address: node_address.clone(),
            wallet: owner.clone(),
        },
        Verifier,
    );
    let transition = engine
        .prepare_registration(
            &NamingRegistrySnapshot::default(),
            RegistrationRequest {
                node_id: NodeId::parse("atlas.node").unwrap(),
                node_address: node_address.clone(),
                authorization: authorization(owner, 1),
            },
        )
        .unwrap();
    let mut state = NamingRegistrySnapshot::default();
    assert_eq!(resolve(&state, &NodeId::parse("atlas.node").unwrap()), None);
    state
        .apply_finalized(FinalizedNamingBatch {
            finalized_at: finalized(1),
            transitions: vec![transition],
        })
        .unwrap();
    assert_eq!(
        resolve(&state, &NodeId::parse("atlas.node").unwrap()),
        Some(node_address)
    );
}

#[test]
fn rename_uses_current_external_owner_not_naming_record_history() {
    let node_address = NodeAddress::parse(NODE_ONE).unwrap();
    let old_owner = wallet(1);
    let new_owner = wallet(2);
    let old_engine = NamingEngine::new(
        Owners {
            node_address: node_address.clone(),
            wallet: old_owner.clone(),
        },
        Verifier,
    );
    let mut state = NamingRegistrySnapshot::default();
    let registration = old_engine
        .prepare_registration(
            &state,
            RegistrationRequest {
                node_id: NodeId::parse("atlas.node").unwrap(),
                node_address: node_address.clone(),
                authorization: authorization(old_owner.clone(), 1),
            },
        )
        .unwrap();
    state
        .apply_finalized(FinalizedNamingBatch {
            finalized_at: finalized(1),
            transitions: vec![registration],
        })
        .unwrap();
    let new_engine = NamingEngine::new(
        Owners {
            node_address: node_address.clone(),
            wallet: new_owner,
        },
        Verifier,
    );
    let error = new_engine
        .prepare_rename(
            &state,
            RenameRequest {
                current_node_id: NodeId::parse("atlas.node").unwrap(),
                replacement_node_id: NodeId::parse("atlas-east.node").unwrap(),
                node_address,
                authorization: authorization(old_owner, 2),
            },
        )
        .unwrap_err();
    assert_eq!(error, NamingError::OwnerWalletMismatch);
}

#[test]
fn duplicate_node_id_is_rejected_by_finalized_state() {
    let first_node = NodeAddress::parse(NODE_ONE).unwrap();
    let second_node = NodeAddress::parse(NODE_TWO).unwrap();
    let first_owner = wallet(1);
    let first_engine = NamingEngine::new(
        Owners {
            node_address: first_node.clone(),
            wallet: first_owner.clone(),
        },
        Verifier,
    );
    let mut state = NamingRegistrySnapshot::default();
    let registration = first_engine
        .prepare_registration(
            &state,
            RegistrationRequest {
                node_id: NodeId::parse("atlas.node").unwrap(),
                node_address: first_node,
                authorization: authorization(first_owner, 1),
            },
        )
        .unwrap();
    state
        .apply_finalized(FinalizedNamingBatch {
            finalized_at: finalized(1),
            transitions: vec![registration],
        })
        .unwrap();
    let second_owner = wallet(2);
    let second_engine = NamingEngine::new(
        Owners {
            node_address: second_node.clone(),
            wallet: second_owner.clone(),
        },
        Verifier,
    );
    assert_eq!(
        second_engine
            .prepare_registration(
                &state,
                RegistrationRequest {
                    node_id: NodeId::parse("atlas.node").unwrap(),
                    node_address: second_node,
                    authorization: authorization(second_owner, 1),
                },
            )
            .unwrap_err(),
        NamingError::DuplicateNodeId
    );
}
