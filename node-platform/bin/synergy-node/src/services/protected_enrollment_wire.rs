//! Bounded unratified enrollment content after authenticated decryption.
//!
//! The frozen CDDL leaves the three leading bstr slots unnamed. The candidate
//! sponsored decoder proposes an exact interpretation of those original slots.
//! The decoder does not authenticate signatures, EIP-712 ownership, DKG, sponsor
//! authority, or encryption and cannot admit work to the live ETDAG.
#![allow(dead_code)]
use super::protected_action_wire::{self as action_wire, Reader, ENROLL_COMMIT, ENROLL_REVEAL};
use synergy_address_engine::apqe::{
    enrollment::EnrollmentSignature,
    provider::{variants::Mldsa87, PublicKey, Signature},
};
use synergy_identity::authorization::IdentityAuthorizationCarrier;

// Engineering parser resource ceilings, not approved protocol fee/action limits.
pub(super) const MAX_CONTENT_BYTES: usize = 128 * 1024;
pub(super) const MAX_OPAQUE_BYTES: usize = 32 * 1024;

pub(super) enum EnrollmentContent<'a> {
    Commit { opaque: [&'a [u8]; 3] },
    Reveal(Box<EnrollmentReveal<'a>>),
}

pub(super) struct EnrollmentReveal<'a> {
    pub(super) opaque: [&'a [u8]; 3],
    pub(super) ordinary: [EnrollmentSignature; 2],
    pub(super) recovery: Option<EnrollmentSignature>,
    pub(super) ownership: [u8; 65],
    pub(super) salt: [u8; 32],
}

pub(super) struct SponsoredEnrollment<'a> {
    pub(super) sponsor_intent: &'a [u8],
    pub(super) payload: &'a [u8],
    pub(super) binding: IdentityAuthorizationCarrier,
    pub(super) signing_key: PublicKey<Mldsa87>,
    pub(super) signature: Signature<Mldsa87>,
    pub(super) reveal: Option<Box<EnrollmentReveal<'a>>>,
}

/// Proposed slot order: original sponsor intent, original action payload,
/// then CBOR [canonical identity carrier JSON, public key, pure signature].
/// Downstream authorization must use the returned original intent and payload.
pub(super) fn decode_sponsored(bytes: &[u8]) -> Result<SponsoredEnrollment<'_>, &'static str> {
    let (action, slots, reveal) = match decode(bytes)? {
        EnrollmentContent::Commit { opaque } => (ENROLL_COMMIT, opaque, None),
        EnrollmentContent::Reveal(reveal) => (ENROLL_REVEAL, reveal.opaque, Some(reveal)),
    };
    let [sponsor_intent, payload, evidence] = slots;
    if action_wire::decode_sponsor(sponsor_intent)?.action != action {
        return Err("INVALID_SPONSOR_ACTION");
    }
    if let action_wire::Payload::Reveal { salt, .. } = action_wire::decode(action, payload)? {
        if reveal.as_ref().is_none_or(|reveal| reveal.salt != salt) {
            return Err("ENROLLMENT_CONTENT_SALT_MISMATCH");
        }
    }
    let mut evidence = Reader::new(evidence);
    evidence.byte(0x83)?;
    let binding = evidence.bytes(1, MAX_OPAQUE_BYTES)?;
    let key = evidence.bytes(1, MAX_OPAQUE_BYTES)?;
    let signature = evidence.bytes(1, MAX_OPAQUE_BYTES)?;
    evidence.finish()?;
    Ok(SponsoredEnrollment {
        sponsor_intent,
        payload,
        binding: IdentityAuthorizationCarrier::from_canonical_json(binding)
            .map_err(|_| "INVALID_SPONSOR_CARRIER")?,
        signing_key: PublicKey::from_bytes(key).map_err(|_| "INVALID_SPONSOR_PUBLIC_KEY")?,
        signature: Signature::from_bytes(signature).map_err(|_| "INVALID_SPONSOR_SIGNATURE_SIZE")?,
        reveal,
    })
}

fn role(reader: &mut Reader<'_>, expected: u8) -> Result<EnrollmentSignature, &'static str> {
    let proof = reader.transfer_role(expected)?;
    Ok(EnrollmentSignature {
        schema_version: 1,
        role_id: expected,
        participant_id: proof.participant_id,
        key_version: proof.key_version,
        auth_algorithm: 1,
        signed_digest: proof.digest,
        signature: Signature::<Mldsa87>::from_bytes(proof.signature)
            .map_err(|_| "INVALID_ENROLLMENT_CONTENT_SIGNATURE_SIZE")?,
    })
}

/// Syntax and resource validation only, never sponsor/enrollment verification.
pub(super) fn decode(bytes: &[u8]) -> Result<EnrollmentContent<'_>, &'static str> {
    if bytes.len() > MAX_CONTENT_BYTES {
        return Err("ENROLLMENT_CONTENT_SIZE");
    }
    let mut reader = Reader::new(bytes);
    let head = *bytes.first().ok_or("NONCANONICAL_PROTECTED_PAYLOAD")?;
    if !matches!(head, 0x84 | 0x87 | 0x88) {
        return Err("NONCANONICAL_PROTECTED_PAYLOAD");
    }
    reader.byte(head)?;
    let action = reader.uint()?;
    if !matches!((head, action), (0x84, x) if x == u64::from(ENROLL_COMMIT))
        && !matches!((head, action), (0x87 | 0x88, x) if x == u64::from(ENROLL_REVEAL))
    {
        return Err("INVALID_ENROLLMENT_CONTENT_ACTION");
    }
    let opaque = [
        reader.bytes(0, MAX_OPAQUE_BYTES)?,
        reader.bytes(0, MAX_OPAQUE_BYTES)?,
        reader.bytes(0, MAX_OPAQUE_BYTES)?,
    ];
    let parsed = if action == u64::from(ENROLL_COMMIT) {
        EnrollmentContent::Commit { opaque }
    } else {
        reader.byte(0x82)?;
        let ordinary = [role(&mut reader, 0)?, role(&mut reader, 1)?];
        let recovery = if head == 0x88 {
            Some(role(&mut reader, 2)?)
        } else {
            None
        };
        let ownership = reader.fixed()?;
        let salt = reader.fixed()?;
        EnrollmentContent::Reveal(Box::new(EnrollmentReveal {
            opaque,
            ordinary,
            recovery,
            ownership,
            salt,
        }))
    };
    reader.finish()?;
    Ok(parsed)
}

#[cfg(test)]
fn uint(n: u64, out: &mut Vec<u8>) {
    match n {
        0..=23 => out.push(n as u8),
        24..=255 => out.extend_from_slice(&[0x18, n as u8]),
        256..=65535 => {
            out.push(0x19);
            out.extend_from_slice(&(n as u16).to_be_bytes())
        }
        65536..=4294967295 => {
            out.push(0x1a);
            out.extend_from_slice(&(n as u32).to_be_bytes())
        }
        _ => {
            out.push(0x1b);
            out.extend_from_slice(&n.to_be_bytes())
        }
    }
}

#[cfg(test)]
fn bstr(bytes: &[u8], out: &mut Vec<u8>) {
    let mut length = Vec::new();
    uint(bytes.len() as u64, &mut length);
    length[0] |= 0x40;
    out.extend_from_slice(&length);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
pub(super) fn encode_sponsored_fixture(
    sponsor_intent: &[u8],
    payload: &[u8],
    evidence: [&[u8]; 3],
    reveal: Option<super::protected_accounts::EnrollmentProofs<'_>>,
) -> Vec<u8> {
    let mut evidence_bytes = vec![0x83];
    for item in evidence {
        bstr(item, &mut evidence_bytes);
    }
    let (array, action) = if reveal.is_some() {
        (0x88, ENROLL_REVEAL)
    } else {
        (0x84, ENROLL_COMMIT)
    };
    let mut bytes = vec![array];
    uint(u64::from(action), &mut bytes);
    for item in [sponsor_intent, payload, evidence_bytes.as_slice()] {
        bstr(item, &mut bytes);
    }
    if let Some(proofs) = reveal {
        bytes.push(0x82);
        for proof in proofs.ordinary.iter().chain([proofs.recovery]) {
            bytes.extend_from_slice(&[0x87, 1, 1]);
            uint(proof.key_version, &mut bytes);
            bytes.push(proof.role_id);
            bstr(&proof.participant_id, &mut bytes);
            bstr(&proof.signed_digest, &mut bytes);
            bstr(proof.signature.as_bytes(), &mut bytes);
        }
        bstr(proofs.ownership, &mut bytes);
        bstr(proofs.salt, &mut bytes);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    fn commit(slots: [&[u8]; 3]) -> Vec<u8> {
        let mut out = vec![0x84];
        uint(u64::from(ENROLL_COMMIT), &mut out);
        for slot in slots {
            bstr(slot, &mut out)
        }
        out
    }
    fn reveal(
        roles: [u8; 3],
        signature_size: usize,
        ownership_size: usize,
        salt_size: usize,
    ) -> (Vec<u8>, [usize; 3]) {
        let mut out = vec![0x88];
        uint(u64::from(ENROLL_REVEAL), &mut out);
        for slot in [
            &b"opaque sponsor?"[..],
            &b"unassigned binding"[..],
            &b""[..],
        ] {
            bstr(slot, &mut out)
        }
        out.push(0x82);
        let mut offsets = [0; 3];
        for (i, role) in roles.into_iter().enumerate() {
            offsets[i] = out.len();
            out.extend_from_slice(&[0x87, 1, 1]);
            uint(1, &mut out);
            out.push(role);
            bstr(&[i as u8 + 1; 32], &mut out);
            bstr(&[i as u8 + 10; 64], &mut out);
            bstr(&vec![i as u8 + 20; signature_size], &mut out);
        }
        bstr(&vec![30; ownership_size], &mut out);
        bstr(&vec![40; salt_size], &mut out);
        (out, offsets)
    }

    #[test]
    fn commit_retains_unassigned_slots_without_interpreting_them() {
        let bytes = commit([&[], &[0xff, 0x00], b"not a sponsor intent"]);
        let EnrollmentContent::Commit { opaque } = decode(&bytes).unwrap() else {
            panic!("commit")
        };
        assert_eq!(
            opaque,
            [&[][..], &[0xff, 0x00][..], &b"not a sponsor intent"[..]]
        );
        assert!(
            (bytes.as_ptr() as usize..bytes.as_ptr() as usize + bytes.len())
                .contains(&(opaque[1].as_ptr() as usize))
        );
    }
    #[test]
    fn reveal_preserves_exact_assigned_role_proofs_ownership_and_salt() {
        let (bytes, _) = reveal([0, 1, 2], 4627, 65, 32);
        let EnrollmentContent::Reveal(reveal) = decode(&bytes).unwrap() else {
            panic!("reveal")
        };
        let EnrollmentReveal {
            opaque,
            ordinary,
            recovery,
            ownership,
            salt,
        } = *reveal;
        assert_eq!(opaque[0], b"opaque sponsor?");
        assert!(opaque[2].is_empty());
        for (i, proof) in ordinary.iter().chain(recovery.as_ref()).enumerate() {
            assert_eq!(proof.role_id, i as u8);
            assert_eq!(proof.key_version, 1);
            assert_eq!(proof.schema_version, 1);
            assert_eq!(proof.auth_algorithm, 1);
            assert_eq!(proof.participant_id, [i as u8 + 1; 32]);
            assert_eq!(proof.signed_digest, [i as u8 + 10; 64]);
            assert_eq!(proof.signature.as_bytes(), &[i as u8 + 20; 4627]);
        }
        assert_eq!(ownership, [30; 65]);
        assert_eq!(salt, [40; 32]);
    }
    #[test]
    fn wrong_roles_proof_modes_and_fixed_lengths_fail_closed() {
        for roles in [[1, 0, 2], [0, 0, 2], [0, 1, 0], [0, 2, 1]] {
            assert!(decode(&reveal(roles, 4627, 65, 32).0).is_err())
        }
        for (sig, own, salt) in [
            (4626, 65, 32),
            (4628, 65, 32),
            (4627, 64, 32),
            (4627, 66, 32),
            (4627, 65, 31),
            (4627, 65, 33),
        ] {
            assert!(decode(&reveal([0, 1, 2], sig, own, salt).0).is_err())
        }
        let (bytes, offsets) = reveal([0, 1, 2], 4627, 65, 32);
        for offset in offsets {
            for relative in [0, 1, 2] {
                let mut bad = bytes.clone();
                bad[offset + relative] = 0;
                assert!(decode(&bad).is_err())
            }
        }
    }

    #[test]
    fn two_role_reveal_has_no_recovery_slot_and_preserves_direct_three_roles() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!("protected_quick_setup_vectors.json")).unwrap();
        let (dpr, offsets) = reveal([0,1,2], 4627, 65, 32);
        let mut dp = dpr.clone();
        dp[0] = 0x87;
        dp.drain(offsets[2]..offsets[2] + (offsets[2] - offsets[1]));
        for (named, bytes, recovery) in [
            ("dp_sponsored_reveal", &dp, false),
            ("dpr_sponsored_reveal", &dpr, true),
        ] {
            let EnrollmentContent::Reveal(reveal) = decode(bytes).unwrap() else {
                panic!("expected strict reveal frame");
            };
            assert_eq!(reveal.recovery.is_some(), recovery);
            assert_eq!(reveal.ordinary.map(|item| item.role_id), [0, 1]);
            assert_eq!(vectors[named]["encoded_bytes"].as_u64().unwrap() as usize, bytes.len());
            assert_eq!(vectors[named]["sha256"].as_str().unwrap(), crate::services::apqe_transport::sha256(bytes));
        }
        dp[0] = 0x88;
        assert!(decode(&dp).is_err());
    }
    #[test]
    fn canonical_framing_rejects_trailing_truncation_tags_and_overlong_encodings() {
        let (bytes, offsets) = reveal([0, 1, 2], 4627, 65, 32);
        for end in [
            0,
            1,
            2,
            3,
            4,
            20,
            offsets[0],
            offsets[1] - 1,
            offsets[2] + 8,
            bytes.len() - 1,
        ] {
            assert!(decode(&bytes[..end]).is_err())
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        let mut tagged = vec![0xc0];
        tagged.extend_from_slice(&bytes);
        assert!(decode(&tagged).is_err());
        let mut indefinite = bytes.clone();
        indefinite[0] = 0x9f;
        assert!(decode(&indefinite).is_err());
        let mut wrong_action = bytes.clone();
        wrong_action[3] = 1;
        assert!(decode(&wrong_action).is_err());
        let mut overlong_action = vec![0x88, 0x1a, 0, 0, 0x70, 0x02];
        overlong_action.extend_from_slice(&bytes[4..]);
        assert!(decode(&overlong_action).is_err());
        let mut version = bytes.clone();
        version.splice(offsets[0] + 3..offsets[0] + 4, [0x18, 1]);
        assert!(decode(&version).is_err());
        let mut bstr = commit([b"x", b"", b""]);
        bstr.splice(4..5, [0x58, 1]);
        assert!(decode(&bstr).is_err());
    }
    #[test]
    fn parser_bounds_are_enforced_before_allocating_proof_buffers() {
        let at_limit = vec![7; MAX_OPAQUE_BYTES];
        assert!(decode(&commit([&at_limit, &[], &[]])).is_ok());
        let over = vec![7; MAX_OPAQUE_BYTES + 1];
        assert!(decode(&commit([&over, &[], &[]])).is_err());
        assert!(decode(&vec![0; MAX_CONTENT_BYTES + 1]).is_err());
        let mut wrong = commit([&[], &[], &[]]);
        wrong[0] = 0x88;
        assert!(decode(&wrong).is_err());
    }
}
