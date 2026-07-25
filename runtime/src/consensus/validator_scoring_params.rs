use serde::{Deserialize, Serialize};

pub const BPS_DENOMINATOR: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorScoringConfig {
    pub uptime_weight_bps: u64,
    pub responsiveness_weight_bps: u64,
    pub consensus_participation_weight_bps: u64,
    pub validation_accuracy_weight_bps: u64,
    pub cluster_contribution_weight_bps: u64,
    pub config_compliance_weight_bps: u64,
    pub telemetry_integrity_weight_bps: u64,
    pub previous_score_weight_bps: u64,
    pub epoch_score_weight_bps: u64,
    pub max_clean_recovery_bps: u64,
    pub category_a_score_cap_bps: u64,
    pub category_b_score_cap_bps: u64,
    pub category_b_reward_cap_bps: u64,
    pub category_c_penalty_bps: u64,
}

impl Default for ValidatorScoringConfig {
    fn default() -> Self {
        Self {
            uptime_weight_bps: 2_000,
            responsiveness_weight_bps: 2_000,
            consensus_participation_weight_bps: 2_000,
            validation_accuracy_weight_bps: 2_000,
            cluster_contribution_weight_bps: 1_000,
            config_compliance_weight_bps: 500,
            telemetry_integrity_weight_bps: 500,
            previous_score_weight_bps: 8_000,
            epoch_score_weight_bps: 2_000,
            max_clean_recovery_bps: 500,
            category_a_score_cap_bps: 2_500,
            category_b_score_cap_bps: 7_000,
            category_b_reward_cap_bps: 6_000,
            category_c_penalty_bps: 250,
        }
    }
}

impl ValidatorScoringConfig {
    pub fn validate(&self) -> Result<(), String> {
        let epoch_weight_sum = self
            .uptime_weight_bps
            .checked_add(self.responsiveness_weight_bps)
            .and_then(|value| value.checked_add(self.consensus_participation_weight_bps))
            .and_then(|value| value.checked_add(self.validation_accuracy_weight_bps))
            .and_then(|value| value.checked_add(self.cluster_contribution_weight_bps))
            .and_then(|value| value.checked_add(self.config_compliance_weight_bps))
            .and_then(|value| value.checked_add(self.telemetry_integrity_weight_bps))
            .ok_or_else(|| "validator scoring epoch weights overflow".to_string())?;
        if epoch_weight_sum != BPS_DENOMINATOR {
            return Err(format!(
                "validator scoring epoch weights must sum to 10000 bps, got {epoch_weight_sum}"
            ));
        }

        let rolling_weight_sum = self
            .previous_score_weight_bps
            .checked_add(self.epoch_score_weight_bps)
            .ok_or_else(|| "validator scoring rolling weights overflow".to_string())?;
        if rolling_weight_sum != BPS_DENOMINATOR {
            return Err(format!(
                "validator scoring rolling weights must sum to 10000 bps, got {rolling_weight_sum}"
            ));
        }

        for (name, value) in [
            ("max_clean_recovery_bps", self.max_clean_recovery_bps),
            ("category_a_score_cap_bps", self.category_a_score_cap_bps),
            ("category_b_score_cap_bps", self.category_b_score_cap_bps),
            ("category_b_reward_cap_bps", self.category_b_reward_cap_bps),
            ("category_c_penalty_bps", self.category_c_penalty_bps),
        ] {
            if value > BPS_DENOMINATOR {
                return Err(format!("{name} must be <= 10000 bps"));
            }
        }

        Ok(())
    }
}
