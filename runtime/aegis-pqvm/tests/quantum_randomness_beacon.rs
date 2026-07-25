use aegis_pqvm::quantum_randomness_beacon::{
    verify_beacon_standalone, BeaconPolicy, EntropySource, QuantumBeacon, VerificationResult,
};

struct DeterministicEntropy {
    name: &'static str,
    byte: u8,
}

impl EntropySource for DeterministicEntropy {
    fn sample(&mut self, bytes: usize) -> Result<Vec<u8>, String> {
        Ok(vec![self.byte; bytes])
    }

    fn source_name(&self) -> &str {
        self.name
    }
}

struct FailingEntropy {
    name: &'static str,
}

impl EntropySource for FailingEntropy {
    fn sample(&mut self, _bytes: usize) -> Result<Vec<u8>, String> {
        Err("forced entropy failure".to_string())
    }

    fn source_name(&self) -> &str {
        self.name
    }
}

#[cfg(feature = "mldsa")]
#[test]
fn beacon_commitment_is_verified_stateful_and_standalone() {
    let mut beacon = QuantumBeacon::new();
    beacon.add_entropy_source(Box::new(DeterministicEntropy {
        name: "aux_entropy",
        byte: 0x42,
    }));

    let output = beacon.generate_beacon("default").unwrap();
    assert_eq!(beacon.verify_beacon(&output), VerificationResult::Valid);

    let verification_key = beacon.get_verification_key().unwrap();
    assert_eq!(
        verify_beacon_standalone(&output, verification_key, None),
        VerificationResult::Valid
    );

    let mut tampered = output.clone();
    tampered.proof.commitment[0] ^= 0x01;

    assert_eq!(
        beacon.verify_beacon(&tampered),
        VerificationResult::InvalidCommitment
    );
    assert_eq!(
        verify_beacon_standalone(&tampered, verification_key, None),
        VerificationResult::InvalidCommitment
    );
}

#[cfg(feature = "mldsa")]
#[test]
fn beacon_policy_fields_are_enforced() {
    let mut beacon = QuantumBeacon::new();
    beacon.register_policy(BeaconPolicy {
        id: "strict".to_string(),
        description: "strict policy".to_string(),
        min_entropy_sources: 1,
        epoch_duration_seconds: 3_600,
        require_hardware_entropy: true,
    });

    let output = beacon.generate_beacon("strict").unwrap();

    let second_attempt = beacon.generate_beacon("strict");
    assert!(second_attempt.is_err());
    assert!(second_attempt
        .unwrap_err()
        .contains("Epoch policy violation"));

    beacon.register_policy(BeaconPolicy {
        id: "strict".to_string(),
        description: "strict policy tightened after issuance".to_string(),
        min_entropy_sources: 2,
        epoch_duration_seconds: 3_600,
        require_hardware_entropy: true,
    });
    assert_eq!(
        beacon.verify_beacon(&output),
        VerificationResult::PolicyViolation
    );
}

#[cfg(feature = "mldsa")]
#[test]
fn beacon_entropy_failures_are_reported_without_panics() {
    let mut beacon = QuantumBeacon::new();
    beacon.add_entropy_source(Box::new(FailingEntropy {
        name: "failing_entropy",
    }));

    let result = beacon.generate_beacon("default");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("failing_entropy"));
}
