//! Strict selected-profile decoding. Unknown fields/profiles/options/trailing
//! bytes never become Genesis inputs. Canonical bytes are recomputed afterward.
use super::{
    account::AccountRecord,
    compiler::{GenesisCoreInput, InitialVoter, GENESIS_PROFILE, MAX_CORE_BYTES},
    policy::NodeRecord,
    profiles::ProfileCatalog,
    GenesisError,
};
use synergy_address_engine::apqe::{
    native_identity_presentation_r1::NativeIdentityPresentation, r1_framing::NetworkRef,
    srpa_registry,
};
use synergy_protocol_types::{c14n02::Decoder, R1NetworkRef};
use synergy_state::r1::*;
fn count(d: &mut Decoder<'_>, max: usize, min: usize) -> Result<usize, GenesisError> {
    let n = d.u32()? as usize;
    if n > max || n > d.remaining() / min {
        return Err(GenesisError::Bound);
    };
    Ok(n)
}
fn profile(d: &mut Decoder<'_>, name: &str, revision: u32) -> Result<(), GenesisError> {
    if d.ascii(128)? != name || d.u32()? != revision {
        return Err(GenesisError::Profile);
    }
    Ok(())
}
fn native(d: &mut Decoder<'_>) -> Result<String, GenesisError> {
    let ns = d.ascii(6)?.to_owned();
    NativeIdentityPresentation::from_raw(&ns, d.fixed()?)
        .map(|x| x.to_text())
        .map_err(|_| GenesisError::Identity)
}
pub fn decode(bytes: &[u8], catalog: &ProfileCatalog) -> Result<GenesisCoreInput, GenesisError> {
    let mut d = Decoder::new(bytes, MAX_CORE_BYTES)?;
    if d.u16()? != 2 || d.ascii(128)? != "SYNERGY/GENESIS/01" || d.u16()? != 1 {
        return Err(GenesisError::Encoding);
    }
    let network = R1NetworkRef {
        chain_id: d.u64()?,
        nic: d.fixed()?,
    };
    if network.chain_id == 0 { return Err(GenesisError::Identity); }
    let n = NetworkRef {
        chain_id: network.chain_id,
        nic: network.nic,
    };
    profile(&mut d, GENESIS_PROFILE, 1)?;
    let genesis_time = d.u64()?;
    if d.bytes(1024 * 1024)? != catalog.canonical_frame()? {
        return Err(GenesisError::Profile);
    }
    let mut nodes = Vec::new();
    for _ in 0..count(&mut d, 4096, 200)? {
        nodes.push(NodeRecord::decode_from(&mut d, n)?);
    }
    let mut accounts = Vec::new();
    for _ in 0..count(&mut d, 65536, 100)? {
        accounts.push(AccountRecord::decode_from(&mut d, n)?);
    }
    let mut initial_voters = Vec::new();
    for _ in 0..count(&mut d, 4096, 70)? {
        initial_voters.push(InitialVoter {
            identity: native(&mut d)?,
            weight: d.u128()?,
        });
    }
    let mut allocations = Vec::new();
    for _ in 0..count(&mut d, 65536, 21)? {
        let allocation_id = d.ascii(128)?.to_owned();
        let amount_nwei = d.u128()?;
        let destination = match d.u8()? {
            0 => R1GenesisDestination::Account {
                identity: native(&mut d)?,
            },
            1 => R1GenesisDestination::ValidatorBond {
                validator: native(&mut d)?,
                owner: native(&mut d)?,
                beneficiary: native(&mut d)?,
            },
            2 => R1GenesisDestination::UnassignedValidatorFunding,
            _ => return Err(GenesisError::Encoding),
        };
        allocations.push(R1GenesisAllocation {
            allocation_id,
            amount_nwei,
            destination,
        });
    }
    if d.u32()? != 4 {
        return Err(GenesisError::Registry);
    }
    let mut restricted_records = Vec::new();
    for kind in [
        RestrictedRecordKind::Treasury,
        RestrictedRecordKind::TreasuryRecovery,
        RestrictedRecordKind::SecurityForfeiture,
        RestrictedRecordKind::FeeRoundingEscrow,
    ] {
        if d.u16()? != kind as u16 {
            return Err(GenesisError::Registry);
        };
        restricted_records.push(R1RestrictedOpening {
            kind,
            balance_nwei: d.u128()?,
            policy_commitment: d.fixed()?,
        });
    }
    if d.u32()? as usize != srpa_registry::LITERALS.len() {
        return Err(GenesisError::Registry);
    }
    for literal in srpa_registry::LITERALS {
        if d.u16()?
            != u16::from_str_radix(&literal[37..], 16).map_err(|_| GenesisError::Registry)?
            || d.boolean()?
        {
            return Err(GenesisError::Registry);
        }
    }
    profile(&mut d, STATE_PROFILE_NAME, STATE_PROFILE_REVISION)?;
    let _claimed_state_root = d.fixed::<48>()?;
    profile(&mut d, RECEIPT_PROFILE_NAME, RECEIPT_PROFILE_REVISION)?;
    let _claimed_receipts_root = d.fixed::<48>()?;
    d.finish()?;
    // Caller MUST recompile and exact-byte compare. These two claimed roots are
    // never passed into the state constructor and can never choose its result.
    Ok(GenesisCoreInput {
        network,
        genesis_time,
        catalog: catalog.clone(),
        nodes,
        accounts,
        initial_voters,
        allocations,
        restricted_records,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1::profiles::{ProfileDefinition, ProfileKind};
    use synergy_protocol_types::c14n02::Encoder;
    #[test]
    fn received_byte_decoder_bounds_and_native_context_do_not_authorize_construction() {
        let catalog = ProfileCatalog::new(
            ProfileKind::ALL
                .into_iter()
                .map(|k| {
                    ProfileDefinition::from_target_matrix(k,crate::r1::artifact_matrix::PlatformArtifactMatrix::darwin_public_validation_only(crate::r1::artifact_matrix::ArtifactPins{mldsa65:[7;32],mldsa87:[7;32],mlkem1024:[7;32]})).unwrap()
                })
                .collect(),
        )
        .unwrap();
        let mut e = Encoder::with_domain("SYNERGY/GENESIS/01", MAX_CORE_BYTES).unwrap();
        e.u16(1).unwrap();
        e.u64(9969).unwrap();
        e.fixed(&[7; 64]).unwrap();
        assert!(matches!(
            decode(&e.finish().unwrap(), &catalog),
            Err(GenesisError::Encoding)
        ));
        let mut e = Encoder::with_domain("SYNERGY/GENESIS/01", MAX_CORE_BYTES).unwrap();
        e.u16(1).unwrap();
        e.u64(u64::MAX - 1).unwrap();
        e.fixed(&[7; 64]).unwrap();
        e.ascii(GENESIS_PROFILE, 128).unwrap();
        e.u32(1).unwrap();
        e.u64(1).unwrap();
        e.bytes(&catalog.canonical_frame().unwrap(), 1024 * 1024)
            .unwrap();
        e.u32(u32::MAX).unwrap();
        assert!(matches!(
            decode(&e.finish().unwrap(), &catalog),
            Err(GenesisError::Bound)
        ));
        assert!(decode(&vec![0; MAX_CORE_BYTES + 1], &catalog).is_err());
    }
}
