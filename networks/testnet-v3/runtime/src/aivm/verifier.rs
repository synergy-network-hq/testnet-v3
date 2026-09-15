use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use hex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    pub provider_id: String,
    pub timestamp: u64,
    pub hardware_attestation: HardwareAttestation,
    pub software_attestation: SoftwareAttestation,
    pub tcb_status: TCBStatus,
    pub signature: String,
    pub report_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareAttestation {
    pub cpu_svn: String,
    pub tee_type: String,
    pub measurement: String,
    pub platform_info: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareAttestation {
    pub software_version: String,
    pub dependencies_hash: String,
    pub configuration_hash: String,
    pub runtime_hash: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TCBStatus {
    UpToDate,
    OutOfDate,
    Revoked,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub is_valid: bool,
    pub trust_score: f64,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub verified_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderVerification {
    pub provider_id: String,
    pub verification_history: Vec<VerificationResult>,
    pub last_verified: u64,
    pub trust_level: TrustLevel,
    pub attestation_frequency: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustLevel {
    Untrusted,
    Low,
    Medium,
    High,
    Trusted,
}

#[derive(Debug)]
pub struct AIVMVerifier {
    attestations: Arc<Mutex<HashMap<String, Vec<AttestationReport>>>>,
    verifications: Arc<Mutex<HashMap<String, ProviderVerification>>>,
    trusted_roots: Arc<Mutex<Vec<String>>>,
    verification_cache: Arc<Mutex<HashMap<String, VerificationResult>>>,
}

impl AIVMVerifier {
    pub fn new() -> Self {
        AIVMVerifier {
            attestations: Arc::new(Mutex::new(HashMap::new())),
            verifications: Arc::new(Mutex::new(HashMap::new())),
            trusted_roots: Arc::new(Mutex::new(Vec::new())),
            verification_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_trusted_root(&self, root_hash: String) -> Result<(), String> {
        if let Ok(mut roots) = self.trusted_roots.lock() {
            if !roots.contains(&root_hash) {
                roots.push(root_hash);
            }
            Ok(())
        } else {
            Err("Failed to acquire trusted roots lock".to_string())
        }
    }

    pub fn submit_attestation(&self, report: AttestationReport) -> Result<String, String> {
        let provider_id = report.provider_id.clone();
        let report_hash = self.calculate_report_hash(&report);

        // Verify report signature and content
        let verification = self.verify_attestation_report(&report)?;

        if !verification.is_valid {
            return Err(format!("Attestation verification failed: {:?}", verification.errors));
        }

        // Store attestation
        if let Ok(mut attestations) = self.attestations.lock() {
            let provider_attestations = attestations.entry(provider_id.clone()).or_insert_with(Vec::new);
            provider_attestations.push(report);
        }

        // Update provider verification
        self.update_provider_verification(&provider_id, verification)?;

        Ok(report_hash)
    }

    pub fn verify_provider(&self, provider_id: &str) -> Result<VerificationResult, String> {
        // Check cache first
        let cache_key = format!("verify_{}", provider_id);
        if let Ok(cache) = self.verification_cache.lock() {
            if let Some(cached_result) = cache.get(&cache_key) {
                return Ok(cached_result.clone());
            }
        }

        let mut result = VerificationResult {
            is_valid: false,
            trust_score: 0.0,
            warnings: Vec::new(),
            errors: Vec::new(),
            verified_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Get provider's attestation history
        let attestations = {
            if let Ok(attestations) = self.attestations.lock() {
                attestations.get(provider_id).cloned().unwrap_or_default()
            } else {
                result.errors.push("Failed to access attestations".to_string());
                return Ok(result);
            }
        };

        if attestations.is_empty() {
            result.errors.push("No attestations found for provider".to_string());
            return Ok(result);
        }

        // Analyze attestation history
        let latest_attestation = &attestations[attestations.len() - 1];

        // Check TCB status
        if latest_attestation.tcb_status != TCBStatus::UpToDate {
            result.warnings.push("TCB is not up to date".to_string());
            result.trust_score -= 20.0;
        }

        // Check hardware attestation
        if !latest_attestation.hardware_attestation.verified {
            result.errors.push("Hardware attestation failed".to_string());
            result.trust_score -= 50.0;
        }

        // Check software attestation
        if !latest_attestation.software_attestation.verified {
            result.warnings.push("Software attestation failed".to_string());
            result.trust_score -= 30.0;
        }

        // Calculate trust score based on attestation frequency
        let attestation_age_hours = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - latest_attestation.timestamp) / 3600;

        if attestation_age_hours > 24 {
            result.warnings.push("Attestation is older than 24 hours".to_string());
            result.trust_score -= 10.0;
        }

        // Check attestation frequency (should be at least daily)
        if attestations.len() >= 2 {
            let first_attestation = &attestations[0];
            let time_span_hours = (latest_attestation.timestamp - first_attestation.timestamp) / 3600;
            let expected_attestations = time_span_hours / 24; // One per day

            if attestations.len() < expected_attestations as usize / 2 {
                result.warnings.push("Irregular attestation frequency".to_string());
                result.trust_score -= 15.0;
            }
        }

        // Determine if provider is valid
        result.is_valid = result.errors.is_empty() && result.trust_score > 50.0;
        result.trust_score = result.trust_score.max(0.0).min(100.0);

        // Cache the result
        if let Ok(mut cache) = self.verification_cache.lock() {
            cache.insert(cache_key, result.clone());
        }

        Ok(result)
    }

    pub fn get_provider_trust_level(&self, provider_id: &str) -> TrustLevel {
        match self.verify_provider(provider_id) {
            Ok(result) => {
                if result.is_valid {
                    if result.trust_score >= 90.0 {
                        TrustLevel::Trusted
                    } else if result.trust_score >= 75.0 {
                        TrustLevel::High
                    } else if result.trust_score >= 60.0 {
                        TrustLevel::Medium
                    } else {
                        TrustLevel::Low
                    }
                } else {
                    TrustLevel::Untrusted
                }
            }
            Err(_) => TrustLevel::Untrusted,
        }
    }

    pub fn get_attestation_history(&self, provider_id: &str) -> Vec<AttestationReport> {
        if let Ok(attestations) = self.attestations.lock() {
            attestations.get(provider_id).cloned().unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    pub fn get_verification_history(&self, provider_id: &str) -> Vec<VerificationResult> {
        if let Ok(verifications) = self.verifications.lock() {
            if let Some(provider_verification) = verifications.get(provider_id) {
                provider_verification.verification_history.clone()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    }

    fn verify_attestation_report(&self, report: &AttestationReport) -> Result<VerificationResult, String> {
        let mut result = VerificationResult {
            is_valid: true,
            trust_score: 100.0,
            warnings: Vec::new(),
            errors: Vec::new(),
            verified_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Verify report signature
        if !self.verify_signature(&report.signature, &report.report_hash) {
            result.errors.push("Invalid report signature".to_string());
            result.is_valid = false;
            result.trust_score -= 50.0;
        }

        // Verify hardware attestation
        if !report.hardware_attestation.verified {
            result.warnings.push("Hardware attestation not verified".to_string());
            result.trust_score -= 25.0;
        }

        // Verify software attestation
        if !report.software_attestation.verified {
            result.warnings.push("Software attestation not verified".to_string());
            result.trust_score -= 25.0;
        }

        // Check TCB status
        if report.tcb_status == TCBStatus::Revoked {
            result.errors.push("TCB has been revoked".to_string());
            result.is_valid = false;
            result.trust_score = 0.0;
        } else if report.tcb_status == TCBStatus::OutOfDate {
            result.warnings.push("TCB is out of date".to_string());
            result.trust_score -= 20.0;
        }

        Ok(result)
    }

    fn verify_signature(&self, signature: &str, data: &str) -> bool {
        // In a real implementation, this would verify cryptographic signatures
        // For now, we'll do a simple check
        !signature.is_empty() && !data.is_empty()
    }

    fn calculate_report_hash(&self, report: &AttestationReport) -> String {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(&report.provider_id);
        hasher.update(&report.timestamp.to_le_bytes());
        hasher.update(&report.hardware_attestation.measurement);
        hasher.update(&report.software_attestation.software_version);
        hex::encode(hasher.finalize())
    }

    fn update_provider_verification(
        &self,
        provider_id: &str,
        verification: VerificationResult,
    ) -> Result<(), String> {
        if let Ok(mut verifications) = self.verifications.lock() {
            let provider_verification = verifications.entry(provider_id.to_string()).or_insert_with(|| {
                ProviderVerification {
                    provider_id: provider_id.to_string(),
                    verification_history: Vec::new(),
                    last_verified: 0,
                    trust_level: TrustLevel::Untrusted,
                    attestation_frequency: 3600, // 1 hour default
                }
            });

            provider_verification.verification_history.push(verification.clone());
            provider_verification.last_verified = verification.verified_at;

            // Update trust level based on latest verification
            provider_verification.trust_level = if verification.is_valid {
                if verification.trust_score >= 90.0 {
                    TrustLevel::Trusted
                } else if verification.trust_score >= 75.0 {
                    TrustLevel::High
                } else if verification.trust_score >= 60.0 {
                    TrustLevel::Medium
                } else {
                    TrustLevel::Low
                }
            } else {
                TrustLevel::Untrusted
            };

            // Keep only last 100 verifications
            if provider_verification.verification_history.len() > 100 {
                provider_verification.verification_history = provider_verification.verification_history.split_off(
                    provider_verification.verification_history.len() - 100
                );
            }

            Ok(())
        } else {
            Err("Failed to acquire verifications lock".to_string())
        }
    }

    pub fn get_verification_stats(&self) -> HashMap<String, String> {
        let mut stats = HashMap::new();

        if let Ok(verifications) = self.verifications.lock() {
            let total_providers = verifications.len();
            let trusted_providers = verifications.values()
                .filter(|v| v.trust_level == TrustLevel::Trusted)
                .count();
            let high_trust_providers = verifications.values()
                .filter(|v| v.trust_level == TrustLevel::High)
                .count();

            stats.insert("total_providers".to_string(), total_providers.to_string());
            stats.insert("trusted_providers".to_string(), trusted_providers.to_string());
            stats.insert("high_trust_providers".to_string(), high_trust_providers.to_string());
        }

        if let Ok(attestations) = self.attestations.lock() {
            let total_attestations: usize = attestations.values().map(|v| v.len()).sum();
            stats.insert("total_attestations".to_string(), total_attestations.to_string());
        }

        stats
    }

    pub fn clear_verification_cache(&self) {
        if let Ok(mut cache) = self.verification_cache.lock() {
            cache.clear();
        }
    }

    pub fn initialize_builtin_verification(&self) -> Result<(), String> {
        // Add some trusted root certificates for common TEE providers
        let trusted_roots = vec![
            "intel_sgx_root".to_string(),
            "amd_sev_root".to_string(),
            "nvidia_tee_root".to_string(),
        ];

        for root in trusted_roots {
            self.add_trusted_root(root)?;
        }

        Ok(())
    }
}
