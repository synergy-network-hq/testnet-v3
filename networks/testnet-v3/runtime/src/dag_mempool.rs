use crate::crypto::aegis_pqvm::{
    AegisPqvmDomainSeparatedHash, AegisPqvmVerifier, SYNERGY_DAG_NODE_V1, SYNERGY_TX_V1,
};
use crate::synergy_types::{
    CanonicalSerialize, Epoch, Hash, Height, Transaction, TxDependency, TxDependencyType, TxId,
    TxNode, TxNodeStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSelectionLimits {
    pub max_txs: usize,
    pub max_gas: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DagAdmissionResult {
    pub tx_id: TxId,
    pub ready: bool,
    pub missing_dependencies: Vec<TxId>,
}

#[derive(Debug, Clone)]
pub struct DagMempool<'a> {
    verifier: &'a AegisPqvmVerifier,
    current_epoch: Epoch,
    current_height: Height,
    nodes: BTreeMap<TxId, TxNode>,
    transactions: BTreeMap<TxId, Transaction>,
    dependencies: BTreeMap<TxId, BTreeSet<TxId>>,
}

impl<'a> DagMempool<'a> {
    pub fn new(
        verifier: &'a AegisPqvmVerifier,
        current_epoch: Epoch,
        current_height: Height,
    ) -> Self {
        Self {
            verifier,
            current_epoch,
            current_height,
            nodes: BTreeMap::new(),
            transactions: BTreeMap::new(),
            dependencies: BTreeMap::new(),
        }
    }

    pub fn admit_transaction(&mut self, tx: Transaction) -> Result<DagAdmissionResult, String> {
        self.verify_stateless(&tx)?;
        self.verify_aegis_pq_signature(&tx)?;
        let tx_id = self.tx_id(&tx)?;
        let canonical_tx_bytes_hash = tx.canonical_tx_bytes_hash()?;
        let mut inferred_dependencies = self.infer_dependencies(&tx)?;
        inferred_dependencies.sort_by(|a, b| a.tx_id.cmp(&b.tx_id));

        let mut node = TxNode {
            tx_id: tx_id.clone(),
            canonical_tx_bytes_hash,
            sender_uma_or_account: tx.sender_uma_or_account.clone(),
            account_nonce_or_sequence: tx.account_nonce_or_sequence,
            explicit_dependencies: tx.explicit_dependencies.clone(),
            inferred_dependencies,
            read_set_hint: sorted(tx.read_set_hint.clone()),
            write_set_hint: sorted(tx.write_set_hint.clone()),
            gas_limit: tx.gas_limit,
            max_fee_nwei: tx.max_fee_nwei,
            aegis_pq_signature: tx.aegis_pq_signature.clone(),
            aegis_pq_key_id: tx.aegis_pq_key_id.clone(),
            admission_epoch: self.current_epoch,
            admission_height: self.current_height,
            status: TxNodeStatus::Ready,
        };
        let missing_dependencies = self.mark_missing_dependencies(&mut node);
        let ready = missing_dependencies.is_empty();
        if !ready {
            node.status = TxNodeStatus::PendingMissingDependencies;
        }
        self.add_to_dag(tx, node)?;
        Ok(DagAdmissionResult {
            tx_id,
            ready,
            missing_dependencies,
        })
    }

    pub fn verify_stateless(&self, tx: &Transaction) -> Result<(), String> {
        let bytes = tx.canonical_bytes()?;
        let decoded = Transaction::assert_canonical_bytes(&bytes)?;
        if decoded != *tx {
            return Err(
                "transaction did not round-trip through canonical serialization".to_string(),
            );
        }
        tx.chain_id.require_testnet_v3()?;
        tx.network_id.require_testnet_v3()?;
        if tx.version == 0 {
            return Err("transaction version must be non-zero".to_string());
        }
        if tx.gas_limit == 0 {
            return Err("gas_limit must be non-zero".to_string());
        }
        if tx.max_fee_nwei == 0 {
            return Err("max_fee_nwei must be non-zero".to_string());
        }
        if tx.ttl_height.0 < self.current_height.0 {
            return Err("transaction TTL expired".to_string());
        }
        if tx.aegis_pq_signature.signature_bytes.is_empty() {
            return Err("transaction is missing Aegis PQC signature".to_string());
        }
        Ok(())
    }

    pub fn verify_aegis_pq_signature(&self, tx: &Transaction) -> Result<(), String> {
        self.verifier
            .verify_transaction_signature_checked(tx)
            .map_err(|error| error.to_string())
    }

    pub fn infer_dependencies(&self, tx: &Transaction) -> Result<Vec<TxDependency>, String> {
        let mut deps = Vec::new();
        if tx.account_nonce_or_sequence > 0 {
            if let Some((previous_tx_id, _)) = self
                .nodes
                .iter()
                .filter(|(_, node)| node.sender_uma_or_account == tx.sender_uma_or_account)
                .find(|(_, node)| {
                    node.account_nonce_or_sequence + 1 == tx.account_nonce_or_sequence
                })
            {
                deps.push(TxDependency {
                    dependency_type: TxDependencyType::AccountSequence,
                    tx_id: previous_tx_id.clone(),
                });
            }
        }

        let read_set: BTreeSet<_> = tx.read_set_hint.iter().cloned().collect();
        let write_set: BTreeSet<_> = tx.write_set_hint.iter().cloned().collect();
        for (existing_tx_id, existing) in &self.nodes {
            let existing_reads: BTreeSet<_> = existing.read_set_hint.iter().cloned().collect();
            let existing_writes: BTreeSet<_> = existing.write_set_hint.iter().cloned().collect();
            let write_write = !write_set.is_disjoint(&existing_writes);
            let read_write =
                !read_set.is_disjoint(&existing_writes) || !write_set.is_disjoint(&existing_reads);
            if write_write || read_write {
                deps.push(TxDependency {
                    dependency_type: TxDependencyType::ResourceConflict,
                    tx_id: existing_tx_id.clone(),
                });
            }
        }
        deps.sort_by(|a, b| {
            dependency_rank(&a.dependency_type)
                .cmp(&dependency_rank(&b.dependency_type))
                .then_with(|| a.tx_id.cmp(&b.tx_id))
        });
        deps.dedup_by(|a, b| a.tx_id == b.tx_id && a.dependency_type == b.dependency_type);
        Ok(deps)
    }

    pub fn add_to_dag(&mut self, tx: Transaction, tx_node: TxNode) -> Result<(), String> {
        let tx_id = tx_node.tx_id.clone();
        if self.nodes.contains_key(&tx_id) {
            return Err(format!(
                "transaction {} already exists in DAG mempool",
                tx_id.0
            ));
        }
        let deps = tx_node
            .explicit_dependencies
            .iter()
            .chain(tx_node.inferred_dependencies.iter())
            .map(|dependency| dependency.tx_id.clone())
            .collect::<BTreeSet<_>>();
        self.dependencies.insert(tx_id.clone(), deps);
        self.transactions.insert(tx_id.clone(), tx);
        self.nodes.insert(tx_id, tx_node);
        self.recompute_all_inferred_dependencies();
        Ok(())
    }

    pub fn mark_missing_dependencies(&self, tx_node: &mut TxNode) -> Vec<TxId> {
        let mut missing = tx_node
            .explicit_dependencies
            .iter()
            .chain(tx_node.inferred_dependencies.iter())
            .filter(|dependency| !self.nodes.contains_key(&dependency.tx_id))
            .map(|dependency| dependency.tx_id.clone())
            .collect::<Vec<_>>();
        missing.sort();
        missing.dedup();
        if !missing.is_empty() {
            tx_node.status = TxNodeStatus::PendingMissingDependencies;
        }
        missing
    }

    pub fn ready_frontier(&self) -> Vec<TxId> {
        let mut ready = self
            .nodes
            .iter()
            .filter(|(tx_id, node)| {
                matches!(node.status, TxNodeStatus::Ready)
                    && self
                        .dependencies
                        .get(tx_id)
                        .map(|deps| deps.iter().all(|dep| self.nodes.contains_key(dep)))
                        .unwrap_or(true)
            })
            .map(|(tx_id, _)| tx_id.clone())
            .collect::<Vec<_>>();
        ready.sort_by(|a, b| self.order_key(a).cmp(&self.order_key(b)));
        ready
    }

    pub fn ancestor_closed_set(
        &self,
        frontier: &[TxId],
        limits: BlockSelectionLimits,
    ) -> Result<Vec<TxId>, String> {
        let mut closure = BTreeSet::new();
        for tx_id in frontier {
            self.collect_ancestors(tx_id, &mut closure)?;
            closure.insert(tx_id.clone());
        }
        let ordered =
            self.deterministic_topological_sort(&closure.into_iter().collect::<Vec<_>>())?;
        let mut selected = Vec::new();
        let mut gas = 0u64;
        for tx_id in ordered {
            let node = self
                .nodes
                .get(&tx_id)
                .ok_or_else(|| format!("missing DAG node {}", tx_id.0))?;
            if selected.len() >= limits.max_txs {
                break;
            }
            if gas.saturating_add(node.gas_limit) > limits.max_gas {
                break;
            }
            gas = gas.saturating_add(node.gas_limit);
            selected.push(tx_id);
        }
        Ok(selected)
    }

    pub fn deterministic_topological_sort(&self, tx_ids: &[TxId]) -> Result<Vec<TxId>, String> {
        let included = tx_ids.iter().cloned().collect::<BTreeSet<_>>();
        let mut indegree = BTreeMap::<TxId, usize>::new();
        let mut children = BTreeMap::<TxId, BTreeSet<TxId>>::new();
        for tx_id in &included {
            indegree.insert(tx_id.clone(), 0);
        }
        for tx_id in &included {
            for dep in self.dependencies.get(tx_id).into_iter().flatten() {
                if included.contains(dep) {
                    *indegree.entry(tx_id.clone()).or_insert(0) += 1;
                    children
                        .entry(dep.clone())
                        .or_default()
                        .insert(tx_id.clone());
                }
            }
        }

        let mut ready = indegree
            .iter()
            .filter(|(_, degree)| **degree == 0)
            .map(|(tx_id, _)| tx_id.clone())
            .collect::<Vec<_>>();
        ready.sort_by(|a, b| self.order_key(a).cmp(&self.order_key(b)));
        let mut output = Vec::new();
        while let Some(next) = ready.first().cloned() {
            ready.remove(0);
            output.push(next.clone());
            for child in children.get(&next).cloned().unwrap_or_default() {
                let degree = indegree
                    .get_mut(&child)
                    .ok_or_else(|| format!("topological child {} missing indegree", child.0))?;
                *degree -= 1;
                if *degree == 0 {
                    ready.push(child);
                    ready.sort_by(|a, b| self.order_key(a).cmp(&self.order_key(b)));
                }
            }
        }
        if output.len() != included.len() {
            return Err("DAG dependency cycle detected".to_string());
        }
        Ok(output)
    }

    pub fn compute_dag_frontier_root(&self) -> Result<Hash, String> {
        let mut frontier = self.ready_frontier();
        frontier.sort();
        serde_json::to_vec(&frontier)
            .map(|bytes| Hash::from_domain_bytes(SYNERGY_DAG_NODE_V1, &bytes))
            .map_err(|error| format!("frontier root serialize failed: {error}"))
    }

    pub fn compute_tx_order_root(&self, ordered_tx_ids: &[TxId]) -> Result<Hash, String> {
        serde_json::to_vec(ordered_tx_ids)
            .map(|bytes| Hash::from_domain_bytes("SYNERGY_TX_ORDER_ROOT_V1", &bytes))
            .map_err(|error| format!("tx order root serialize failed: {error}"))
    }

    pub fn prune_finalized(&mut self, finalized_tx_ids: &[TxId]) {
        for tx_id in finalized_tx_ids {
            self.nodes.remove(tx_id);
            self.transactions.remove(tx_id);
            self.dependencies.remove(tx_id);
        }
        for deps in self.dependencies.values_mut() {
            for tx_id in finalized_tx_ids {
                deps.remove(tx_id);
            }
        }
    }

    pub fn transaction(&self, tx_id: &TxId) -> Option<&Transaction> {
        self.transactions.get(tx_id)
    }

    fn tx_id(&self, tx: &Transaction) -> Result<TxId, String> {
        Ok(AegisPqvmDomainSeparatedHash::hash_transaction(
            SYNERGY_TX_V1,
            tx.chain_id,
            &tx.network_id,
            &tx.canonical_bytes()?,
        ))
    }

    fn collect_ancestors(&self, tx_id: &TxId, out: &mut BTreeSet<TxId>) -> Result<(), String> {
        for dep in self.dependencies.get(tx_id).into_iter().flatten() {
            if out.insert(dep.clone()) {
                self.collect_ancestors(dep, out)?;
            }
        }
        Ok(())
    }

    fn order_key(&self, tx_id: &TxId) -> (usize, String, u64, u64, String) {
        let depth = self.depth(tx_id, &mut BTreeSet::new());
        let Some(node) = self.nodes.get(tx_id) else {
            return (usize::MAX, String::new(), 0, 0, tx_id.0.clone());
        };
        (
            depth,
            node.sender_uma_or_account.clone(),
            node.account_nonce_or_sequence,
            deterministic_fee_priority_bucket(node.max_fee_nwei),
            tx_id.0.clone(),
        )
    }

    fn order_key_without_depth(&self, tx_id: &TxId) -> (String, u64, u64, String) {
        let Some(node) = self.nodes.get(tx_id) else {
            return (String::new(), 0, 0, tx_id.0.clone());
        };
        (
            node.sender_uma_or_account.clone(),
            node.account_nonce_or_sequence,
            deterministic_fee_priority_bucket(node.max_fee_nwei),
            tx_id.0.clone(),
        )
    }

    fn recompute_all_inferred_dependencies(&mut self) {
        let ids = self.nodes.keys().cloned().collect::<Vec<_>>();
        let mut inferred_by_tx = BTreeMap::<TxId, Vec<TxDependency>>::new();
        for tx_id in &ids {
            let Some(node) = self.nodes.get(tx_id) else {
                continue;
            };
            let mut inferred = Vec::new();
            for candidate_id in &ids {
                if candidate_id == tx_id {
                    continue;
                }
                let Some(candidate) = self.nodes.get(candidate_id) else {
                    continue;
                };
                if candidate.sender_uma_or_account == node.sender_uma_or_account
                    && candidate.account_nonce_or_sequence + 1 == node.account_nonce_or_sequence
                {
                    inferred.push(TxDependency {
                        dependency_type: TxDependencyType::AccountSequence,
                        tx_id: candidate_id.clone(),
                    });
                }
                let reads: BTreeSet<_> = node.read_set_hint.iter().cloned().collect();
                let writes: BTreeSet<_> = node.write_set_hint.iter().cloned().collect();
                let candidate_reads: BTreeSet<_> =
                    candidate.read_set_hint.iter().cloned().collect();
                let candidate_writes: BTreeSet<_> =
                    candidate.write_set_hint.iter().cloned().collect();
                let conflicts = !writes.is_disjoint(&candidate_writes)
                    || !reads.is_disjoint(&candidate_writes)
                    || !writes.is_disjoint(&candidate_reads);
                if conflicts
                    && self.order_key_without_depth(candidate_id)
                        < self.order_key_without_depth(tx_id)
                {
                    inferred.push(TxDependency {
                        dependency_type: TxDependencyType::ResourceConflict,
                        tx_id: candidate_id.clone(),
                    });
                }
            }
            inferred.sort_by(|a, b| {
                dependency_rank(&a.dependency_type)
                    .cmp(&dependency_rank(&b.dependency_type))
                    .then_with(|| a.tx_id.cmp(&b.tx_id))
            });
            inferred.dedup_by(|a, b| a.tx_id == b.tx_id && a.dependency_type == b.dependency_type);
            inferred_by_tx.insert(tx_id.clone(), inferred);
        }
        for (tx_id, inferred) in inferred_by_tx {
            let Some(existing_node) = self.nodes.get(&tx_id) else {
                continue;
            };
            let deps = existing_node
                .explicit_dependencies
                .iter()
                .chain(inferred.iter())
                .map(|dependency| dependency.tx_id.clone())
                .collect::<BTreeSet<_>>();
            let missing = deps.iter().any(|dep| !self.nodes.contains_key(dep));
            self.dependencies.insert(tx_id.clone(), deps);
            if let Some(node) = self.nodes.get_mut(&tx_id) {
                node.inferred_dependencies = inferred;
                node.status = if missing {
                    TxNodeStatus::PendingMissingDependencies
                } else {
                    TxNodeStatus::Ready
                };
            }
        }
    }

    fn depth(&self, tx_id: &TxId, visiting: &mut BTreeSet<TxId>) -> usize {
        if !visiting.insert(tx_id.clone()) {
            return usize::MAX / 2;
        }
        let max_parent = self
            .dependencies
            .get(tx_id)
            .map(|deps| {
                deps.iter()
                    .map(|dep| self.depth(dep, visiting))
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        visiting.remove(tx_id);
        max_parent.saturating_add(1)
    }
}

pub fn compute_tx_order_root(ordered_tx_ids: &[TxId]) -> Result<Hash, String> {
    serde_json::to_vec(ordered_tx_ids)
        .map(|bytes| Hash::from_domain_bytes("SYNERGY_TX_ORDER_ROOT_V1", &bytes))
        .map_err(|error| format!("tx order root serialize failed: {error}"))
}

fn deterministic_fee_priority_bucket(max_fee_nwei: u128) -> u64 {
    match max_fee_nwei {
        0..=999 => 0,
        1_000..=9_999 => 1,
        10_000..=99_999 => 2,
        100_000..=999_999 => 3,
        _ => 4,
    }
}

fn dependency_rank(dependency_type: &TxDependencyType) -> u8 {
    match dependency_type {
        TxDependencyType::AccountSequence => 0,
        TxDependencyType::ExplicitDependency => 1,
        TxDependencyType::ResourceConflict => 2,
        TxDependencyType::SxcpOrExternalProofDependency => 3,
    }
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::synergy_types::{AegisPqKeyRole, AegisPqSignature, ChainId, NetworkId, UmaId};

    fn signed_tx(
        signer: &mut AegisPqvmSigner,
        key_id: &crate::synergy_types::AegisPqKeyId,
        sender: &str,
        nonce: u64,
        write: &[&str],
        deps: Vec<TxDependency>,
    ) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            epoch: Epoch(0),
            sender_uma_or_account: sender.to_string(),
            receiver_uma_or_account: "receiver".to_string(),
            account_nonce_or_sequence: nonce,
            amount_nwei: 1,
            gas_limit: 10,
            max_fee_nwei: 1000,
            ttl_height: Height(100),
            explicit_dependencies: deps,
            read_set_hint: Vec::new(),
            write_set_hint: write.iter().map(|value| value.to_string()).collect(),
            payload: Vec::new(),
            signer_uma_id: UmaId(sender.to_string()),
            aegis_pq_key_id: key_id.clone(),
            aegis_pq_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        tx.aegis_pq_signature = signer
            .sign_transaction(&tx.signing_bytes().expect("tx bytes"), key_id)
            .expect("real tx signature");
        tx
    }

    fn mempool_fixture() -> (AegisPqvmSigner, crate::synergy_types::AegisPqKeyId) {
        let mut signer = AegisPqvmSigner::initialize_required().expect("aegis");
        let key_id = signer
            .generate_and_register_key("alice", vec![AegisPqKeyRole::Transaction], Epoch(0))
            .expect("key");
        (signer, key_id)
    }

    #[test]
    fn same_dag_inserted_in_different_orders_produces_same_order_root() {
        let (mut signer_a, key_id_a) = mempool_fixture();
        let tx0 = signed_tx(&mut signer_a, &key_id_a, "alice", 0, &["a"], Vec::new());
        let tx1 = signed_tx(&mut signer_a, &key_id_a, "alice", 1, &["b"], Vec::new());
        let tx2 = signed_tx(&mut signer_a, &key_id_a, "alice", 2, &["c"], Vec::new());
        let verifier_a = signer_a.verifier();
        let mut a = DagMempool::new(&verifier_a, Epoch(0), Height(0));
        let ids_a = vec![
            a.admit_transaction(tx0.clone()).unwrap().tx_id,
            a.admit_transaction(tx1.clone()).unwrap().tx_id,
            a.admit_transaction(tx2.clone()).unwrap().tx_id,
        ];
        let order_a = a.deterministic_topological_sort(&ids_a).unwrap();
        let root_a = a.compute_tx_order_root(&order_a).unwrap();

        let verifier_b = signer_a.verifier();
        let mut b = DagMempool::new(&verifier_b, Epoch(0), Height(0));
        let ids_b = vec![
            b.admit_transaction(tx2).unwrap().tx_id,
            b.admit_transaction(tx0).unwrap().tx_id,
            b.admit_transaction(tx1).unwrap().tx_id,
        ];
        let order_b = b.deterministic_topological_sort(&ids_b).unwrap();
        let root_b = b.compute_tx_order_root(&order_b).unwrap();
        assert_eq!(root_a, root_b);
    }

    #[test]
    fn missing_dependency_prevents_readiness() {
        let (mut signer, key_id) = mempool_fixture();
        let missing = TxId("missing".to_string());
        let tx = signed_tx(
            &mut signer,
            &key_id,
            "alice",
            0,
            &["a"],
            vec![TxDependency {
                dependency_type: TxDependencyType::ExplicitDependency,
                tx_id: missing.clone(),
            }],
        );
        let verifier = signer.verifier();
        let mut mempool = DagMempool::new(&verifier, Epoch(0), Height(0));
        let result = mempool.admit_transaction(tx).unwrap();
        assert!(!result.ready);
        assert_eq!(result.missing_dependencies, vec![missing]);
    }

    #[test]
    fn account_nonce_and_write_conflict_create_dependency_edges() {
        let (mut signer, key_id) = mempool_fixture();
        let tx0 = signed_tx(&mut signer, &key_id, "alice", 0, &["resource"], Vec::new());
        let tx1 = signed_tx(&mut signer, &key_id, "alice", 1, &["other"], Vec::new());
        let tx2 = signed_tx(&mut signer, &key_id, "alice", 2, &["resource"], Vec::new());
        let verifier = signer.verifier();
        let mut mempool = DagMempool::new(&verifier, Epoch(0), Height(0));
        let id0 = mempool.admit_transaction(tx0).unwrap().tx_id;
        let id1 = mempool.admit_transaction(tx1).unwrap().tx_id;
        let id2 = mempool.admit_transaction(tx2).unwrap().tx_id;
        let deps2 = mempool.dependencies.get(&id2).unwrap();
        assert!(deps2.contains(&id1));
        assert!(deps2.contains(&id0));
    }

    #[test]
    fn invalid_signature_wrong_chain_network_and_revoked_key_are_rejected() {
        let (mut signer, key_id) = mempool_fixture();
        let mut bad_sig = signed_tx(&mut signer, &key_id, "alice", 0, &["a"], Vec::new());
        bad_sig.aegis_pq_signature.signature_bytes[0] ^= 0x01;
        let verifier = signer.verifier();
        let mut mempool = DagMempool::new(&verifier, Epoch(0), Height(0));
        assert!(mempool.admit_transaction(bad_sig).is_err());

        let mut wrong_chain = signed_tx(&mut signer, &key_id, "alice", 1, &["b"], Vec::new());
        wrong_chain.chain_id = ChainId(999);
        assert!(mempool.admit_transaction(wrong_chain).is_err());

        let mut wrong_network = signed_tx(&mut signer, &key_id, "alice", 2, &["c"], Vec::new());
        wrong_network.network_id = NetworkId("wrong".to_string());
        assert!(mempool.admit_transaction(wrong_network).is_err());

        signer.registry.revoke_key("alice", &key_id, Epoch(0));
        let verifier = signer.verifier();
        let mut mempool = DagMempool::new(&verifier, Epoch(0), Height(0));
        let revoked = signed_tx(&mut signer, &key_id, "alice", 3, &["d"], Vec::new());
        assert!(mempool.admit_transaction(revoked).is_err());
    }
}
