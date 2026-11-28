//! Pure current Genesis compiler; no production execution, key generation or I/O.
use super::{
    account::AccountRecord,
    policy::{verify_node, NodeRecord},
    profiles::ProfileCatalog,
    GenesisError,
};
use std::collections::BTreeSet;
use synergy_address_engine::apqe::{
    crypto_engine::CryptoEngine, r1_framing::NetworkRef, srpa_registry, HashAlgorithm, Primitives,
};
use synergy_protocol_types::{
    c14n02::Encoder, NodeRole, R1GenesisReference, R1NetworkCoordinate, R1NetworkRef, R1ProfileRef,
    R1ProfileSetReference,
};
use synergy_state::r1::*;
pub const MAX_CORE_BYTES: usize = 16 * 1024 * 1024;
pub const GENESIS_PROFILE: &str = "SYNERGY-GENESIS-R1";
/// Root-approved initial voter data frozen into Genesis. This representation does
/// not independently prove physical independence, randomness or formation finality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialVoter {
    pub identity: String,
    pub weight: u128,
}
pub struct GenesisCoreInput {
    pub network: R1NetworkRef,
    pub genesis_time: u64,
    pub catalog: ProfileCatalog,
    pub nodes: Vec<NodeRecord>,
    pub accounts: Vec<AccountRecord>,
    pub initial_voters: Vec<InitialVoter>,
    pub allocations: Vec<R1GenesisAllocation>,
    pub restricted_records: Vec<R1RestrictedOpening>,
}
pub struct CompiledR1Genesis {
    coordinate: R1NetworkCoordinate,
    canonical_bytes: Vec<u8>,
    state: ComputedGenesisState,
    initial_voters: Vec<InitialVoter>,
    nodes: Vec<NodeRecord>,
}
impl CompiledR1Genesis {
    pub fn coordinate(&self) -> &R1NetworkCoordinate {
        &self.coordinate
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    pub fn state(&self) -> &ComputedGenesisState {
        &self.state
    }
    pub fn nodes(&self) -> &[NodeRecord] {
        &self.nodes
    }
    pub fn initial_voters(&self) -> &[InitialVoter] {
        &self.initial_voters
    }
}
fn profile(e: &mut Encoder, name: &str, revision: u32) -> Result<(), GenesisError> {
    e.ascii(name, 128)?;
    e.u32(revision)?;
    Ok(())
}
fn native(e: &mut Encoder, text: &str) -> Result<(), GenesisError> {
    let id=synergy_address_engine::apqe::native_identity_presentation_r1::NativeIdentityPresentation::parse(text).map_err(|_|GenesisError::Identity)?;
    e.ascii(id.namespace(), 6)?;
    e.fixed(id.raw48())?;
    Ok(())
}
fn protocol_records(
    catalog: &ProfileCatalog,
) -> Result<Vec<R1GenesisProtocolRecord>, GenesisError> {
    let mut records = vec![R1GenesisProtocolRecord {
        key: R1StateKey {
            domain: R1StateDomain::ProtocolConfiguration,
            owner: R1StateOwner::Protocol,
            local_key: b"activated-profiles".to_vec(),
        },
        value: R1StateValue::ProtocolRecord {
            profile_name: "APQE-PROFILE-SET".into(),
            profile_revision: 1,
            canonical_bytes: catalog.canonical_frame()?,
        },
    }];
    for literal in srpa_registry::LITERALS {
        let suffix = u16::from_str_radix(&literal[37..], 16).map_err(|_| GenesisError::Registry)?;
        let mut e = Encoder::new(64);
        e.u16(suffix)?;
        e.boolean(false)?; // assigned literal; no operation privilege granted
        records.push(R1GenesisProtocolRecord {
            key: R1StateKey {
                domain: R1StateDomain::SrpaRegistry,
                owner: R1StateOwner::Srpa { suffix },
                local_key: Vec::new(),
            },
            value: R1StateValue::ProtocolRecord {
                profile_name: "SYNERGY-SRPA-ASSIGNMENTS-R1".into(),
                profile_revision: 1,
                canonical_bytes: e.finish()?,
            },
        });
    }
    if records.len() != 70 {
        return Err(GenesisError::Registry);
    }
    Ok(records)
}
pub fn compile(
    input: GenesisCoreInput,
    independently_expected_catalog: &ProfileCatalog,
    engine: &CryptoEngine,
) -> Result<CompiledR1Genesis, GenesisError> {
    synergy_address_engine::apqe::preparation::require_nonproduction_fixture(
        input.network.chain_id,
    )
    .map_err(|_| GenesisError::Ceremony)?;
    if &input.catalog != independently_expected_catalog
        || input.genesis_time == 0
        || input.nodes.is_empty()
        || input.nodes.len() > 4096
        || input.accounts.len() > 65536
        || input.allocations.len() > 65536
        || input.initial_voters.is_empty()
        || input.initial_voters.len() > input.nodes.len()
    {
        return Err(GenesisError::Bound);
    }
    input.catalog.validate_provider(engine)?;
    let n = NetworkRef {
        chain_id: input.network.chain_id,
        nic: input.network.nic,
    };
    let mut identities = BTreeSet::new();
    let mut node_roots = BTreeSet::new();
    let mut runtime_keys = BTreeSet::new();
    for node in &input.nodes {
        verify_node(node.clone(), n, engine)?;
        if !identities.insert(node.identity.clone())
            || !node_roots.insert(node.birth_root.public_key.clone())
            || node
                .role_keys
                .iter()
                .any(|role| !runtime_keys.insert(role.key.public_key.clone()))
        {
            return Err(GenesisError::Duplicate);
        }
    }
    fn ordered<'a>(ids: impl Iterator<Item = &'a str>) -> Result<(), GenesisError> {
        let mut previous = None;
        for text in ids {
            let id = synergy_address_engine::apqe::native_identity_presentation_r1::NativeIdentityPresentation::parse(text).map_err(|_|GenesisError::Identity)?;
            let key = (id.namespace().to_owned(), *id.raw48());
            if previous.as_ref().is_some_and(|p| p >= &key) {
                return Err(GenesisError::Order);
            }
            previous = Some(key);
        }
        Ok(())
    }
    ordered(input.nodes.iter().map(|n| n.identity.as_str()))?;
    ordered(input.accounts.iter().map(|a| a.identity.as_str()))?;
    ordered(input.initial_voters.iter().map(|v| v.identity.as_str()))?;
    if input
        .allocations
        .windows(2)
        .any(|w| w[0].allocation_id >= w[1].allocation_id)
    {
        return Err(GenesisError::Order);
    }
    let accounts = input
        .accounts
        .iter()
        .map(|a| a.verify(n, engine))
        .collect::<Result<Vec<_>, _>>()?;
    let mut total_weight = 0u128;
    for voter in &input.initial_voters {
        if voter.weight == 0
            || !input.nodes.iter().any(|node| {
                node.identity == voter.identity && node.primary_role == NodeRole::Validator
            })
        {
            return Err(GenesisError::Voter);
        };
        total_weight = total_weight
            .checked_add(voter.weight)
            .ok_or(GenesisError::Voter)?;
    }
    let mut e = Encoder::with_domain("SYNERGY/GENESIS/01", MAX_CORE_BYTES)?;
    e.u16(1)?;
    e.u64(input.network.chain_id)?;
    e.fixed(&input.network.nic)?;
    profile(&mut e, GENESIS_PROFILE, 1)?;
    e.u64(input.genesis_time)?;
    e.bytes(&input.catalog.canonical_frame()?, 1024 * 1024)?;
    e.u32(input.nodes.len() as u32)?;
    for node in &input.nodes {
        node.encode_into(&mut e, n)?;
    }
    e.u32(input.accounts.len() as u32)?;
    for account in &input.accounts {
        account.encode_into(&mut e, n)?;
    }
    e.u32(input.initial_voters.len() as u32)?;
    for v in &input.initial_voters {
        native(&mut e, &v.identity)?;
        e.u128(v.weight)?;
    }
    e.u32(input.allocations.len() as u32)?;
    for a in &input.allocations {
        e.ascii(&a.allocation_id, 128)?;
        e.u128(a.amount_nwei)?;
        match &a.destination {
            R1GenesisDestination::Account { identity } => {
                e.u8(0)?;
                native(&mut e, identity)?
            }
            R1GenesisDestination::ValidatorBond {
                validator,
                owner,
                beneficiary,
            } => {
                e.u8(1)?;
                native(&mut e, validator)?;
                native(&mut e, owner)?;
                native(&mut e, beneficiary)?
            }
            R1GenesisDestination::UnassignedValidatorFunding => {
                e.u8(2)?;
            }
        }
    }
    if input.restricted_records.len() != 4
        || input
            .restricted_records
            .windows(2)
            .any(|w| w[0].kind >= w[1].kind)
    {
        return Err(GenesisError::Registry);
    }
    e.u32(4)?;
    for r in &input.restricted_records {
        e.u16(r.kind as u16)?;
        e.u128(r.balance_nwei)?;
        e.fixed(&r.policy_commitment)?;
    }
    e.u32(srpa_registry::LITERALS.len() as u32)?;
    for literal in srpa_registry::LITERALS {
        let suffix = u16::from_str_radix(&literal[37..], 16).map_err(|_| GenesisError::Registry)?;
        e.u16(suffix)?;
        e.boolean(false)?;
    }
    let state_input = R1GenesisStateInput {
        network: input.network,
        accounts,
        allocations: input.allocations,
        restricted_records: input.restricted_records,
        profile_definitions: protocol_records(&input.catalog)?,
    };
    let state = compile_genesis(&state_input).map_err(|_| GenesisError::State)?;
    profile(&mut e, &state.profile.name, state.profile.revision)?;
    e.fixed(&state.root)?;
    profile(&mut e, RECEIPT_PROFILE_NAME, RECEIPT_PROFILE_REVISION)?;
    e.fixed(&state.receipts_root)?;
    let canonical_bytes = e.finish()?;
    let digest = Primitives
        .hash(HashAlgorithm::Sha3384, &canonical_bytes)
        .map_err(|_| GenesisError::Primitive)?
        .try_into()
        .map_err(|_| GenesisError::Primitive)?;
    let coordinate = R1NetworkCoordinate {
        network: input.network,
        genesis: R1GenesisReference {
            profile: R1ProfileRef {
                name: GENESIS_PROFILE.into(),
                revision: 1,
            },
            digest,
        },
        activated_profiles: R1ProfileSetReference {
            profile: R1ProfileRef {
                name: "APQE-PROFILE-SET".into(),
                revision: 1,
            },
            commitment: input.catalog.commitment()?,
        },
    };
    Ok(CompiledR1Genesis {
        coordinate,
        canonical_bytes,
        state,
        initial_voters: input.initial_voters,
        nodes: input.nodes,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_srpa_hex_literals_roundtrip_including_alphabetic_suffixes() {
        for literal in srpa_registry::LITERALS {
            let suffix = u16::from_str_radix(&literal[37..], 16).unwrap();
            assert_eq!(format!("syn{:038x}", suffix), *literal);
        }
        assert!(srpa_registry::LITERALS.iter().any(|s| s.ends_with("0706")));
        assert!(srpa_registry::LITERALS.iter().any(|s| s.ends_with("0a00")));
        assert!(srpa_registry::recognize("syn00000000000000000000000000000000003515").is_err());
    }
}
