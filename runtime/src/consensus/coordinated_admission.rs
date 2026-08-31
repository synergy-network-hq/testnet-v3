//! Deterministic user-transaction admission for `coordinated_round_robin_v1`.
//!
//! A typed user transaction does not carry its public-key lifecycle witness in
//! the transaction body.  P1 therefore carries the exact ordered Aegis
//! submission envelopes with the producer proposal, roots them, and verifies
//! each at the block's consensus timestamp.  This is neither a PoSy
//! certificate nor an ETDAG admission path.

use crate::aegis_tx_tool::{verify_aegis_submission_envelope_at, AegisTxSubmissionEnvelope};
use crate::synergy_types::{CanonicalSerialize, Hash, Height, Transaction, TxId};

/// The root is zero only for the canonical empty admission set.  A non-empty
/// set is length-prefixed to reject ambiguous concatenations.
pub fn coordinated_transaction_admission_root(
    admissions: &[AegisTxSubmissionEnvelope],
) -> Result<Hash, String> {
    if admissions.is_empty() {
        return Ok(Hash::zero());
    }
    let mut material = Vec::new();
    material.extend_from_slice(
        &u64::try_from(admissions.len())
            .map_err(|_| "coordinated admission count exceeds u64".to_string())?
            .to_be_bytes(),
    );
    for admission in admissions {
        let bytes = serde_json::to_vec(admission)
            .map_err(|error| format!("serialize coordinated transaction admission: {error}"))?;
        material.extend_from_slice(
            &u64::try_from(bytes.len())
                .map_err(|_| "coordinated admission is too large".to_string())?
                .to_be_bytes(),
        );
        material.extend_from_slice(&bytes);
    }
    Ok(Hash::from_domain_bytes(
        "SYNERGY_COORDINATED_TRANSACTION_ADMISSION_ROOT_V1",
        &material,
    ))
}

/// Validates the witness list in exact block order.  The consensus timestamp
/// is supplied by the signed assignment, never by a local clock, so all six
/// validators obtain the same admission result.
pub fn verify_coordinated_transaction_admissions(
    transactions: &[Transaction],
    admissions: &[AegisTxSubmissionEnvelope],
    height: Height,
    consensus_timestamp_unix: u64,
) -> Result<Hash, String> {
    if transactions.len() != admissions.len() {
        return Err(
            "coordinated block transaction admissions do not match transaction count".to_string(),
        );
    }
    for (transaction, admission) in transactions.iter().zip(admissions) {
        if &admission.transaction != transaction {
            return Err(
                "coordinated transaction admission does not match the ordered block transaction"
                    .to_string(),
            );
        }
        transaction
            .chain_id
            .require_testnet_v3()
            .map_err(|error| format!("coordinated transaction chain binding: {error}"))?;
        transaction
            .network_id
            .require_testnet_v3()
            .map_err(|error| format!("coordinated transaction network binding: {error}"))?;
        if transaction.ttl_height.0 < height.0 {
            return Err(
                "coordinated transaction expired before its assigned block height".to_string(),
            );
        }
        verify_aegis_submission_envelope_at(admission, consensus_timestamp_unix)
            .map_err(|error| format!("verify coordinated transaction admission: {error}"))?;
    }
    coordinated_transaction_admission_root(admissions)
}

/// The producer-signed header commits to both the ordinary transaction order
/// and the witness root.  Empty blocks retain their established P1 frontier
/// value to avoid changing their canonical representation.
pub fn coordinated_dag_frontier_root(
    parent_block_hash: Hash,
    tx_order_root: Hash,
    admission_root: Hash,
) -> Hash {
    let mut material = Vec::new();
    material.extend_from_slice(&parent_block_hash.0);
    material.extend_from_slice(&tx_order_root.0);
    if admission_root.is_zero() {
        return Hash::from_domain_bytes("SYNERGY_COORDINATED_EMPTY_DAG_FRONTIER_V1", &material);
    }
    material.extend_from_slice(&admission_root.0);
    Hash::from_domain_bytes("SYNERGY_COORDINATED_ADMITTED_DAG_FRONTIER_V1", &material)
}

pub fn coordinated_transaction_ids(transactions: &[Transaction]) -> Result<Vec<TxId>, String> {
    transactions
        .iter()
        .map(|transaction| {
            Ok(TxId::from_hash(Hash::from_domain_bytes(
                "SYNERGY_EXECUTION_TX_ID_V1",
                &transaction.canonical_bytes()?,
            )))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aegis_tx_tool::{sign_with_new_aegis_transaction_key, AegisTxBuildOptions};

    #[test]
    fn coordinated_admission_binds_the_exact_user_transaction_and_witness() {
        let report = sign_with_new_aegis_transaction_key(AegisTxBuildOptions::default())
            .expect("sign user transaction");
        let root = verify_coordinated_transaction_admissions(
            std::slice::from_ref(&report.transaction),
            std::slice::from_ref(&report.submission_envelope),
            Height(1),
            1_000,
        )
        .expect("admission validates at consensus timestamp");
        assert!(!root.is_zero());

        let mut altered = report.submission_envelope.clone();
        altered.transaction.amount_nwei = altered.transaction.amount_nwei.saturating_add(1);
        assert!(verify_coordinated_transaction_admissions(
            std::slice::from_ref(&report.transaction),
            std::slice::from_ref(&altered),
            Height(1),
            1_000,
        )
        .is_err());
    }
}
