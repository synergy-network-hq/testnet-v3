//! Certified-envelope ordering from the frozen Testnet-v3 ETDAG runtime.
//!
//! This is a pure supporting calculation. The caller must authenticate the
//! cutoff, certified vertices, finality context, and ordering seed before
//! passing their eligible envelope references here.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

const DOMAIN_ORDER_KEY: &str = "PoSy/ETDAG/Order/v3";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertifiedEnvelopeRef {
    pub tx_commitment: EtdagDigest,
    pub sender_id: String,
    pub nonce_slot: u64,
    pub certified_dag_round: u64,
    pub gas_class_units: u64,
    pub ciphertext_bytes: u64,
    pub fee_class: u32,
    pub protocol_dependencies: Vec<EtdagDigest>,
}

impl CertifiedEnvelopeRef {
    pub fn validate(&self) -> Result<(), EtdagError> {
        self.tx_commitment.validate()?;
        if self.sender_id.trim().is_empty()
            || self.gas_class_units == 0
            || self.ciphertext_bytes == 0
        {
            return Err(EtdagError::InvalidEnvelope(
                "invalid ETDAG certified envelope reference".into(),
            ));
        }
        let unique = self.protocol_dependencies.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.protocol_dependencies.len()
            || self
                .protocol_dependencies
                .iter()
                .any(|dependency| dependency == &self.tx_commitment)
        {
            return Err(EtdagError::InvalidEnvelope(
                "invalid ETDAG protocol dependencies".into(),
            ));
        }
        for dependency in &self.protocol_dependencies {
            dependency.validate()?;
        }
        Ok(())
    }
}

fn order_key(seed: &EtdagDigest, commitment: &EtdagDigest) -> Result<EtdagDigest, EtdagError> {
    EtdagDigest::from_canonical(DOMAIN_ORDER_KEY, &(seed, commitment))
}

/// Canonically order a certified eligible set, then choose its prefix within
/// the protected gas and ciphertext-byte limits. The ordering is independent
/// of arrival order and ciphertext content. A non-fitting item ends selection;
/// later items must not be chosen around it.
pub fn canonical_content_blind_order(
    eligible: &[CertifiedEnvelopeRef],
    order_seed: &EtdagDigest,
    max_gas: u64,
    max_bytes: u64,
) -> Result<Vec<CertifiedEnvelopeRef>, EtdagError> {
    order_seed.validate()?;
    let mut by_commitment = BTreeMap::new();
    for envelope in eligible {
        envelope.validate()?;
        if by_commitment
            .insert(envelope.tx_commitment.clone(), envelope.clone())
            .is_some()
        {
            return Err(EtdagError::DuplicateEnvelope);
        }
    }
    let mut dependencies = by_commitment
        .keys()
        .map(|commitment| (commitment.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for envelope in by_commitment.values() {
        for dependency in &envelope.protocol_dependencies {
            if !by_commitment.contains_key(dependency) {
                return Err(EtdagError::UnknownParent(dependency.0.clone()));
            }
            dependencies
                .get_mut(&envelope.tx_commitment)
                .ok_or_else(|| EtdagError::Corrupt("ETDAG dependency map is incomplete".into()))?
                .insert(dependency.clone());
        }
    }
    let mut by_sender = BTreeMap::<String, Vec<&CertifiedEnvelopeRef>>::new();
    for envelope in by_commitment.values() {
        by_sender
            .entry(envelope.sender_id.clone())
            .or_default()
            .push(envelope);
    }
    for sender_envelopes in by_sender.values_mut() {
        sender_envelopes.sort_by(|left, right| {
            left.nonce_slot
                .cmp(&right.nonce_slot)
                .then_with(|| left.tx_commitment.cmp(&right.tx_commitment))
        });
        for pair in sender_envelopes.windows(2) {
            if pair[0].nonce_slot == pair[1].nonce_slot {
                return Err(EtdagError::InvalidEnvelope(
                    "ETDAG eligible set contains sender nonce conflict".into(),
                ));
            }
            dependencies
                .get_mut(&pair[1].tx_commitment)
                .ok_or_else(|| {
                    EtdagError::Corrupt("ETDAG sender dependency map is incomplete".into())
                })?
                .insert(pair[0].tx_commitment.clone());
        }
    }

    let mut indegree = dependencies
        .iter()
        .map(|(commitment, parents)| (commitment.clone(), parents.len()))
        .collect::<BTreeMap<_, _>>();
    let mut children = BTreeMap::<EtdagDigest, BTreeSet<EtdagDigest>>::new();
    for (child, parents) in &dependencies {
        for parent in parents {
            children
                .entry(parent.clone())
                .or_default()
                .insert(child.clone());
        }
    }
    let mut ready = BTreeSet::<(u64, EtdagDigest, EtdagDigest)>::new();
    for (commitment, degree) in &indegree {
        if *degree == 0 {
            let envelope = by_commitment.get(commitment).ok_or_else(|| {
                EtdagError::Corrupt("ETDAG indegree item is missing envelope".into())
            })?;
            ready.insert((
                envelope.certified_dag_round,
                order_key(order_seed, commitment)?,
                commitment.clone(),
            ));
        }
    }
    let mut ordered = Vec::with_capacity(eligible.len());
    while let Some(next) = ready.iter().next().cloned() {
        ready.remove(&next);
        let commitment = next.2;
        ordered.push(
            by_commitment
                .get(&commitment)
                .ok_or_else(|| EtdagError::Corrupt("ETDAG ready item is missing".into()))?
                .clone(),
        );
        for child in children.get(&commitment).cloned().unwrap_or_default() {
            let degree = indegree
                .get_mut(&child)
                .ok_or_else(|| EtdagError::Corrupt("ETDAG child is missing indegree".into()))?;
            *degree = degree
                .checked_sub(1)
                .ok_or_else(|| EtdagError::Corrupt("ETDAG indegree underflow".into()))?;
            if *degree == 0 {
                let envelope = by_commitment
                    .get(&child)
                    .ok_or_else(|| EtdagError::Corrupt("ETDAG child is missing envelope".into()))?;
                ready.insert((
                    envelope.certified_dag_round,
                    order_key(order_seed, &child)?,
                    child,
                ));
            }
        }
    }
    if ordered.len() != eligible.len() {
        return Err(EtdagError::Cycle);
    }

    let mut selected = Vec::new();
    let mut gas = 0u64;
    let mut bytes = 0u64;
    for envelope in ordered {
        let next_gas = gas
            .checked_add(envelope.gas_class_units)
            .ok_or(EtdagError::InvalidCapacity)?;
        let next_bytes = bytes
            .checked_add(envelope.ciphertext_bytes)
            .ok_or(EtdagError::InvalidCapacity)?;
        if next_gas > max_gas || next_bytes > max_bytes {
            break;
        }
        gas = next_gas;
        bytes = next_bytes;
        selected.push(envelope);
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> EtdagDigest {
        EtdagDigest::from_domain_bytes("test", label.as_bytes())
    }

    fn envelope(id: &str, sender: &str, nonce: u64, round: u64) -> CertifiedEnvelopeRef {
        CertifiedEnvelopeRef {
            tx_commitment: digest(id),
            sender_id: sender.into(),
            nonce_slot: nonce,
            certified_dag_round: round,
            gas_class_units: 2,
            ciphertext_bytes: 512,
            fee_class: 1,
            protocol_dependencies: Vec::new(),
        }
    }

    #[test]
    fn input_order_cannot_change_canonical_order() {
        let input = vec![
            envelope("a", "alice", 0, 1),
            envelope("b", "bob", 0, 2),
            envelope("c", "carol", 0, 1),
        ];
        let mut reversed = input.clone();
        reversed.reverse();
        let seed = digest("finality-seed");
        let first = canonical_content_blind_order(&input, &seed, 100, 10000).unwrap();
        let second = canonical_content_blind_order(&reversed, &seed, 100, 10000).unwrap();
        assert_eq!(first, second);
        assert_eq!(first[2].tx_commitment, digest("b"));
    }

    #[test]
    fn protocol_and_sender_nonce_dependencies_precede_children() {
        let first = envelope("first", "alice", 1, 3);
        let second = envelope("second", "alice", 2, 0);
        let mut dependent = envelope("dependent", "bob", 0, 0);
        dependent
            .protocol_dependencies
            .push(second.tx_commitment.clone());
        let ordered = canonical_content_blind_order(
            &[dependent.clone(), second.clone(), first.clone()],
            &digest("seed"),
            100,
            10000,
        )
        .unwrap();
        let ids = ordered
            .into_iter()
            .map(|item| item.tx_commitment)
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                first.tx_commitment,
                second.tx_commitment,
                dependent.tx_commitment
            ]
        );
    }

    #[test]
    fn conflicting_nonce_missing_dependency_and_cycle_fail_closed() {
        let a = envelope("a", "alice", 1, 0);
        let b = envelope("b", "alice", 1, 0);
        assert!(canonical_content_blind_order(&[a.clone(), b], &digest("seed"), 10, 1000).is_err());
        let mut missing = a.clone();
        missing.protocol_dependencies.push(digest("missing"));
        assert!(matches!(
            canonical_content_blind_order(&[missing], &digest("seed"), 10, 1000),
            Err(EtdagError::UnknownParent(_))
        ));
        let mut cycle_a = envelope("cycle-a", "alice", 0, 0);
        let mut cycle_b = envelope("cycle-b", "bob", 0, 0);
        cycle_a
            .protocol_dependencies
            .push(cycle_b.tx_commitment.clone());
        cycle_b
            .protocol_dependencies
            .push(cycle_a.tx_commitment.clone());
        assert_eq!(
            canonical_content_blind_order(&[cycle_a, cycle_b], &digest("seed"), 10, 1000),
            Err(EtdagError::Cycle)
        );
    }

    #[test]
    fn capacity_selects_prefix_and_does_not_skip_first_nonfitting_item() {
        let a = envelope("a", "alice", 0, 0);
        let b = envelope("b", "alice", 1, 0);
        let c = envelope("c", "alice", 2, 0);
        let ordered =
            canonical_content_blind_order(&[c, b, a.clone()], &digest("seed"), 4, 2048).unwrap();
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].tx_commitment, a.tx_commitment);
    }
}
