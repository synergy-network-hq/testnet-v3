//! Selected engineering bridge from QACE PayloadCore3 to PoSy header fields.
//! This computes public commitments only. It does not verify execution, parent
//! state, availability, required system effects, authority or profile activation.
use crate::r1_payload::{PayloadError, R1PayloadCore, MAX_CORE_BYTES, MAX_OPERATIONS};
use synergy_address::r1_public::{HashAlgorithm, Primitives};
use synergy_protocol_types::c14n02::Encoder;

pub const PROFILE_NAME: &str = "QACE-POSY-COMMITMENTS-R1";
pub const PROFILE_REVISION: u32 = 1;
pub const PROFILE_SCHEMA: &str = "QACE-POSY-COMMITMENTS-R1/1;core=QACE-PAYLOAD-R1/1;execution_profile=core.execution_profile;pre_state=core.pre_state;post_state=core.post_state;receipts=core.receipts_root;payload=core.execution_digest;dependencies=core.manifest_root;resources=H(QACE/RESOURCE-TOTALS/02,sixU64coreResourceOrder);protocol_effects=H(QACE/PROTOCOL-EFFECTS/03,coreSystemVector,sevenU128coreFeeOrder);H=APQE-SHA3-384(C14N02-U16(2),ASCII(domain),value);payload_bytes=core.canonical_bytes.len;transaction_count=core.user_operations.len;gas_used=core.resources.fuel_sum;no-execution-or-activation-authority";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadHeaderCommitments {
    pub execution_profile: [u8; 48],
    pub pre_state: [u8; 48],
    pub post_state: [u8; 48],
    pub receipts: [u8; 48],
    pub payload: [u8; 48],
    pub dependencies: [u8; 48],
    pub resources: [u8; 48],
    pub protocol_effects: [u8; 48],
    pub payload_bytes: u64,
    pub transaction_count: u32,
    pub gas_used: u64,
}
fn digest(e: Encoder) -> Result<[u8; 48], PayloadError> {
    Primitives
        .hash(HashAlgorithm::Sha3384, &e.finish()?)
        .map_err(|_| PayloadError::Codec)?
        .try_into()
        .map_err(|_| PayloadError::Codec)
}
/// All fields are derived from one exact validated core. The caller must first
/// independently reexecute that core against its authenticated actual parent.
pub fn from_payload(core: &R1PayloadCore) -> Result<PayloadHeaderCommitments, PayloadError> {
    core.validate_shape()?;
    let canonical = core.canonical_bytes()?;
    let mut r = Encoder::with_domain("QACE/RESOURCE-TOTALS/02", 256)?;
    let resources = core.resources;
    for value in [
        resources.fuel_sum,
        resources.input_bytes_sum,
        resources.output_bytes_sum,
        resources.state_read_bytes_sum,
        resources.state_written_bytes_sum,
        resources.memory_peak_max,
    ] {
        r.u64(value)?;
    }
    let mut effects = Encoder::with_domain("QACE/PROTOCOL-EFFECTS/03", MAX_CORE_BYTES)?;
    effects.vector(&core.system_transitions, MAX_OPERATIONS, |e, s| {
        e.u8(s.phase)?;
        e.u32(s.ordinal)?;
        e.fixed(&s.operation_profile)?;
        e.u16(s.kind)?;
        e.fixed(&s.operation)?;
        e.fixed(&s.result)
    })?;
    let f = core.fees;
    for value in [
        f.debited,
        f.charged,
        f.refunded,
        f.validator_class,
        f.treasury_class,
        f.escrow_before,
        f.escrow_after,
    ] {
        effects.u128(value)?;
    }
    Ok(PayloadHeaderCommitments {
        execution_profile: core.execution_profile,
        pre_state: core.pre_state,
        post_state: core.post_state,
        receipts: core.receipts_root,
        payload: core.execution_digest()?,
        dependencies: core.manifest_root,
        resources: digest(r)?,
        protocol_effects: digest(effects)?,
        payload_bytes: u64::try_from(canonical.len()).map_err(|_| PayloadError::Bounds)?,
        transaction_count: u32::try_from(core.user_operations.len())
            .map_err(|_| PayloadError::Bounds)?,
        gas_used: resources.fuel_sum,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> R1PayloadCore {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/r1_payload_public.json")).unwrap();
        R1PayloadCore::decode(&hex::decode(v["core_hex"].as_str().unwrap()).unwrap()).unwrap()
    }
    #[test]
    fn r1_header_mapping_matches_independent_python_big_endian_sha3384_vectors() {
        let core = fixture();
        let c = from_payload(&core).unwrap();
        assert_eq!(hex::encode(c.resources), "c479d21bfd6804fb476d82691c95cf2e3af74d6b52cee72ad4cd4c312b04798df0e0677b696fc3dca4661b42bd564899");
        assert_eq!(hex::encode(c.protocol_effects), "def428182c6091b2de8df7e62d19ce8cb737f0159704523e19d98f72366c75fa949d338eaea7edadd89d372546114817");
        assert_eq!(c.payload, core.execution_digest().unwrap());
        assert_eq!(c.pre_state, core.pre_state);
        assert_eq!(c.post_state, core.post_state);
        assert_eq!(c.receipts, core.receipts_root);
        assert_eq!(c.dependencies, core.manifest_root);
        assert_eq!(c.execution_profile, core.execution_profile);
        assert_eq!(
            c.payload_bytes,
            core.canonical_bytes().unwrap().len() as u64
        );
        assert_eq!(c.transaction_count, 1);
        assert_eq!(c.gas_used, 7);
    }
    #[test]
    fn r1_header_mapping_empty_user_still_commits_system_effects_and_fee_carry() {
        let mut core = fixture();
        core.user_operations.clear();
        core.transactions_root = crate::r1_payload::transactions_root(&[]).unwrap();
        let before = from_payload(&core).unwrap();
        assert_eq!(before.transaction_count, 0);
        core.system_transitions.clear();
        core.fees = crate::r1_payload::R1FeeTotals {
            escrow_before: 1,
            escrow_after: 1,
            ..Default::default()
        };
        let after = from_payload(&core).unwrap();
        assert_eq!(hex::encode(after.protocol_effects),"3080b298a05ad9c1cadcc1ba83d7768b2bb920fda1d780c707c3823c8bdc10a69b7ad5bfb69a9f1fa8e91cfeddd3330a");
        assert_ne!(before.protocol_effects, after.protocol_effects);
        let carry = after.protocol_effects;
        core.fees.escrow_before = 0;
        core.fees.escrow_after = 0;
        assert_ne!(from_payload(&core).unwrap().protocol_effects, carry);
        core.fees.escrow_after = 1;
        assert!(from_payload(&core).is_err());
    }
}
