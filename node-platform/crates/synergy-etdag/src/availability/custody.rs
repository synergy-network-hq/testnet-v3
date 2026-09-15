use synergy_data_availability::{
    verify_availability_proof, AvailabilityProof, DataShard, ProofVerifier, ShardStore,
};

use crate::{EtdagDigest, EtdagError};

pub fn accept_vertex_shard(
    verifier: &impl ProofVerifier,
    store: &impl ShardStore,
    vertex_id: &EtdagDigest,
    proof: &AvailabilityProof,
    shard: &DataShard,
    current_height: u64,
) -> Result<(), EtdagError> {
    vertex_id.validate()?;
    shard
        .validate(synergy_data_availability::serve::MAX_SHARD_BYTES)
        .map_err(EtdagError::InvalidEnvelope)?;
    if proof.object_root != vertex_id.0
        || shard.object_root != vertex_id.0
        || proof.shard_root != shard.payload_root
        || proof.shard_index != shard.index
    {
        return Err(EtdagError::InvalidEnvelope(
            "availability proof is not bound to the ETDAG vertex shard".into(),
        ));
    }
    verify_availability_proof(verifier, proof, current_height)
        .map_err(EtdagError::InvalidEnvelope)?;
    store
        .put_custody_if_absent(proof, shard, current_height)
        .map_err(EtdagError::Storage)
}
