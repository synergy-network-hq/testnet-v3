//! Presentation/control-flow regression ONLY. Echo proof fixtures below are
//! deliberately not cryptographic signatures or native session qualification.
//! They exercise the actual handshake production functions after the externally
//! supplied signature-verifier boundary, using fixed public nonproduction data.
use synergy_network::handshake::{
    build_handshake_proof, verify_handshake, HandshakeChallenge, HandshakeMetadata, HandshakeOffer,
    HandshakeSignatureVerifier, HandshakeSigner, PeerKeyAlgorithm, TransportIdentity,
};
use synergy_protocol_types::{NodeAddress, NodeClass, NodeRole, SessionId};

struct PresentationFlowFixture;
impl HandshakeSigner for PresentationFlowFixture {
    type Error = &'static str;
    fn sign_handshake(
        &self,
        _: PeerKeyAlgorithm,
        transcript: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(transcript.to_vec())
    }
}
impl HandshakeSignatureVerifier for PresentationFlowFixture {
    type Error = &'static str;
    fn verify_handshake_signature(
        &self,
        _: &str,
        _: PeerKeyAlgorithm,
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        if transcript == signature {
            Ok(())
        } else {
            Err("noncryptographic transcript fixture mismatch")
        }
    }
}

fn offer(text: &str) -> HandshakeOffer {
    let metadata = HandshakeMetadata {
        node_address: NodeAddress::parse(text).unwrap(),
        network_id: "PUBLIC_SYNTHETIC_NONPRODUCTION_NOT_A_NETWORK".into(),
        genesis_hash: "PUBLIC_SYNTHETIC_NOT_A_GENESIS_COMMITMENT".into(),
        protocol_version: "PRESENTATION_FLOW_TEST_ONLY".into(),
        key_algorithm: PeerKeyAlgorithm::Mldsa87,
    };
    let identity = TransportIdentity::new(text, NodeRole::Validator, &["status".into()]).unwrap();
    HandshakeOffer::new(
        metadata,
        identity,
        HandshakeChallenge::new([0x11; 32], 10, 30).unwrap(),
    )
    .unwrap()
}

#[test]
fn actual_handshake_path_preserves_current72_byte_peer_after_verifier_boundary() {
    for digit in 1..=5 {
        let text = format!(
            "synv{digit}.2.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v"
        );
        let offer = offer(&text);
        let answer = HandshakeChallenge::new([0x22; 32], 10, 30).unwrap();
        let proof =
            build_handshake_proof(&offer, SessionId(7), &answer, &PresentationFlowFixture).unwrap();
        let result = verify_handshake(
            &offer,
            &proof,
            &answer,
            &offer.metadata,
            SessionId(7),
            11,
            &PresentationFlowFixture,
        )
        .unwrap();
        assert_eq!(result.peer().node_address.as_str(), text);
        assert_eq!(
            result.peer().node_address.class(),
            NodeClass::try_from(digit).unwrap()
        );
        assert!(!result.may_determine_finality());
        assert!(!result.role().may_determine_finality());
    }
}

#[test]
fn current_payload_case_and_session_changes_do_not_survive_the_same_transcript() {
    let original = offer(&format!("synv1.2.{}", "A".repeat(64)));
    let changed = offer(&format!("synv1.2.{}", "a".repeat(64)));
    let answer = HandshakeChallenge::new([0x22; 32], 10, 30).unwrap();
    let proof =
        build_handshake_proof(&original, SessionId(7), &answer, &PresentationFlowFixture).unwrap();
    assert!(verify_handshake(
        &changed,
        &proof,
        &answer,
        &original.metadata,
        SessionId(7),
        11,
        &PresentationFlowFixture
    )
    .is_err());
    assert!(verify_handshake(
        &original,
        &proof,
        &answer,
        &original.metadata,
        SessionId(8),
        11,
        &PresentationFlowFixture
    )
    .is_err());
}

#[test]
fn historical_peer_path_remains_explicit_and_current_malformed_text_is_not_accepted() {
    let historical = "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn";
    assert_eq!(
        NodeAddress::parse_historical(historical).unwrap(),
        NodeAddress::parse(historical).unwrap()
    );
    let text = format!("synv1.2.{}", "A".repeat(64));
    for bad in [
        format!("{text}\n"),
        format!("{text}="),
        text.replace(".2.", ".3."),
        text.replace("synv1", "synv6"),
    ] {
        assert!(TransportIdentity::new(&bad, NodeRole::Validator, &[]).is_err());
    }
}
