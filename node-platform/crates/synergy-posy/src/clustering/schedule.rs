use sha3::{Digest, Sha3_512};

use crate::{
    parse_hash_bytes, FrozenValidatorRegistry, PosyError, PosyResult, ValidatorId,
    POSY_LEADER_SCHEDULE_DOMAIN,
};

pub fn derive_epoch_leader_ring(
    finalized_epoch_seed_root: &str,
    registry: &FrozenValidatorRegistry,
) -> PosyResult<Vec<ValidatorId>> {
    let seed = parse_hash_bytes(finalized_epoch_seed_root)?;
    if seed == [0; 32] {
        return Err(PosyError::invalid(
            "cannot derive leader ring from zero epoch seed",
        ));
    }
    let mut ranked = registry
        .active()
        .map(|validator| {
            let mut hasher = Sha3_512::new();
            hasher.update(POSY_LEADER_SCHEDULE_DOMAIN.as_bytes());
            hasher.update(seed);
            hasher.update(validator.validator_id.as_bytes());
            (hasher.finalize().to_vec(), validator.validator_id.clone())
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    Ok(ranked.into_iter().map(|(_, validator)| validator).collect())
}
