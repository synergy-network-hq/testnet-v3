use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::ProtectedCutMarker;
use crate::{
    availability::verify_availability_certificate, crypto::SignatureVerifier,
    AvailabilityCertificate, EtdagDigest, EtdagError, EtdagGraph, TargetAdmissionContextV3,
};

const MAX_CUT_VERTICES: usize = 4096;

/// Frozen cluster bindings supplied by the verified governance owner.
/// Transport membership must never be used to construct this map.
pub type CutoffMembers = BTreeMap<String, (String, u64)>;

/// Wire evidence. Deserializing or validating roots does not grant authority;
/// only `verify` constructs a `VerifiedProtectedCut`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedCutProof {
    pub proof_version: u32,
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub cutoff_context_root: EtdagDigest,
    pub markers: Vec<ProtectedCutMarker>,
    pub certified_vertices: Vec<EtdagDigest>,
    pub eligible_envelopes: Vec<crate::CertifiedEnvelopeRef>,
    pub semantic_root: EtdagDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProtectedCut(ProtectedCutProof);

impl VerifiedProtectedCut {
    pub fn proof(&self) -> &ProtectedCutProof {
        &self.0
    }
    pub fn vertices(&self) -> &[EtdagDigest] {
        &self.0.certified_vertices
    }
    pub fn semantic_root(&self) -> &EtdagDigest {
        &self.0.semantic_root
    }
}

impl ProtectedCutProof {
    pub fn derive(
        context: &TargetAdmissionContextV3,
        cutoff_context_root: &EtdagDigest,
        markers: &[ProtectedCutMarker],
        graph: &EtdagGraph,
        certificates: &BTreeMap<EtdagDigest, AvailabilityCertificate>,
        members: &CutoffMembers,
        verifier: &impl SignatureVerifier,
    ) -> Result<VerifiedProtectedCut, EtdagError> {
        context.validate()?;
        cutoff_context_root.validate()?;
        let context_root = context.root()?;
        if cutoff_context_root.is_zero()
            || graph.context_root() != &context_root
            || graph.target_height() != context.target_height
            || graph.len() > MAX_CUT_VERTICES
        {
            return Err(EtdagError::ContextMismatch);
        }
        let total_weight = members.values().try_fold(0u64, |sum, (key, weight)| {
            if key.trim().is_empty() || *weight == 0 {
                return Err(EtdagError::ContextMismatch);
            }
            sum.checked_add(*weight).ok_or(EtdagError::InvalidCapacity)
        })?;
        if members.len() as u64 != context.assigned_cluster_validator_count
            || total_weight != context.assigned_cluster_total_voting_weight
        {
            return Err(EtdagError::ContextMismatch);
        }
        let required = crate::certificate_quorum(members.len())?;
        if markers.len() < required || markers.len() > members.len() {
            return Err(EtdagError::InsufficientAvailability {
                signed: markers.len(),
                required,
            });
        }
        let mut canonical_markers = markers.to_vec();
        canonical_markers.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        let mut authors = BTreeSet::new();
        let mut marker_weight = 0u128;
        let mut pending = BTreeSet::new();
        for marker in &canonical_markers {
            marker.validate()?;
            if marker.context_root != context_root
                || marker.target_height != context.target_height
                || &marker.cutoff_context_root != cutoff_context_root
            {
                return Err(EtdagError::ContextMismatch);
            }
            let (key, weight) = members
                .get(&marker.validator_id)
                .ok_or_else(|| EtdagError::UnauthorizedValidator(marker.validator_id.clone()))?;
            if key != &marker.key_id || !authors.insert(&marker.validator_id) {
                return Err(EtdagError::UnauthorizedValidator(
                    marker.validator_id.clone(),
                ));
            }
            verifier.verify(
                &marker.validator_id,
                key,
                &marker.signing_bytes()?,
                &marker.signature,
            )?;
            marker_weight += u128::from(*weight);
            pending.extend(marker.frontier.iter().cloned());
        }
        if marker_weight * 3 <= u128::from(total_weight) * 2 {
            return Err(EtdagError::InsufficientAvailability {
                signed: authors.len(),
                required,
            });
        }
        let member_ids = members.keys().cloned().collect();
        let mut closure = BTreeSet::new();
        let mut envelopes = BTreeSet::new();
        while let Some(id) = pending.pop_first() {
            if closure.contains(&id) {
                continue;
            }
            let vertex = graph
                .get(&id)
                .ok_or_else(|| EtdagError::MissingArtifact(id.0.clone()))?;
            vertex.validate()?;
            crate::dag::validate_vertex_identity(vertex)?;
            let (author_key, _) = members
                .get(&vertex.author_id)
                .ok_or_else(|| EtdagError::UnauthorizedValidator(vertex.author_id.clone()))?;
            verifier.verify(
                &vertex.author_id,
                author_key,
                id.0.as_bytes(),
                &vertex.author_signature,
            )?;
            let certificate = certificates
                .get(&id)
                .ok_or_else(|| EtdagError::MissingArtifact(id.0.clone()))?;
            if certificate.context_root != context_root || certificate.vertex_id != id {
                return Err(EtdagError::ContextMismatch);
            }
            verify_availability_certificate(certificate, &member_ids, verifier)?;
            let mut weight = 0u128;
            for vote in &certificate.votes {
                let (key, frozen_weight) = members
                    .get(&vote.validator_id)
                    .ok_or_else(|| EtdagError::UnauthorizedValidator(vote.validator_id.clone()))?;
                if key != &vote.key_id {
                    return Err(EtdagError::InvalidSignature);
                }
                weight += u128::from(*frozen_weight);
            }
            if weight * 3 <= u128::from(total_weight) * 2 {
                return Err(EtdagError::InsufficientAvailability {
                    signed: certificate.votes.len(),
                    required,
                });
            }
            if !envelopes.insert(&vertex.envelope.envelope_id) {
                return Err(EtdagError::DuplicateEnvelope);
            }
            closure.insert(id);
            pending.extend(vertex.parents.iter().cloned());
            if closure.len() + pending.len() > MAX_CUT_VERTICES {
                return Err(EtdagError::InvalidCapacity);
            }
        }
        // Quorum authenticates close statements; taking their union does not
        // establish agreement on a cut. Every counted marker must cover the
        // same certified causal closure. Otherwise a different valid signer
        // subset could change the PoSy-visible batch. Redundant ancestors in
        // a frontier remain valid because only semantic closure is compared.
        for marker in &canonical_markers {
            let mut marker_closure = BTreeSet::new();
            let mut ancestors: BTreeSet<_> = marker.frontier.iter().cloned().collect();
            while let Some(id) = ancestors.pop_first() {
                if !marker_closure.insert(id.clone()) {
                    continue;
                }
                let vertex = graph
                    .get(&id)
                    .ok_or_else(|| EtdagError::MissingArtifact(id.0.clone()))?;
                ancestors.extend(vertex.parents.iter().cloned());
            }
            if marker_closure != closure {
                return Err(EtdagError::MissingArtifact(
                    "quorum cutoff markers covering one common causal closure".into(),
                ));
            }
        }
        let mut eligible_envelopes = Vec::with_capacity(closure.len());
        for id in &closure {
            let vertex = graph
                .get(id)
                .ok_or_else(|| EtdagError::MissingArtifact(id.0.clone()))?;
            eligible_envelopes.push(vertex.envelope_ref.clone());
        }
        eligible_envelopes.sort_by(|a, b| a.tx_commitment.cmp(&b.tx_commitment));
        let certified_vertices: Vec<_> = closure.into_iter().collect();
        let semantic_root = EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_PROTECTED_CUT_V2",
            &(
                &context_root,
                context.target_height,
                cutoff_context_root,
                &certified_vertices,
                &eligible_envelopes,
            ),
        )?;
        Ok(VerifiedProtectedCut(Self {
            proof_version: 2,
            context_root,
            target_height: context.target_height,
            cutoff_context_root: cutoff_context_root.clone(),
            markers: canonical_markers,
            certified_vertices,
            eligible_envelopes,
            semantic_root,
        }))
    }

    pub fn verify(
        &self,
        context: &TargetAdmissionContextV3,
        expected_cutoff: &EtdagDigest,
        graph: &EtdagGraph,
        certificates: &BTreeMap<EtdagDigest, AvailabilityCertificate>,
        members: &CutoffMembers,
        verifier: &impl SignatureVerifier,
    ) -> Result<VerifiedProtectedCut, EtdagError> {
        let verified = Self::derive(
            context,
            expected_cutoff,
            &self.markers,
            graph,
            certificates,
            members,
            verifier,
        )?;
        if self != verified.proof() {
            return Err(EtdagError::ConflictingArtifact(
                "protected cut differs from verified causal closure".into(),
            ));
        }
        Ok(verified)
    }
}
