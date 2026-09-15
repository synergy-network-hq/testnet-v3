use crate::error::{AivmError, AivmErrorCode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AivmGasMeter {
    gas_limit: u64,
    gas_used: u64,
    pq_gas_limit: u64,
    pq_gas_used: u64,
}

impl AivmGasMeter {
    pub fn new(gas_limit: u64, pq_gas_limit: u64) -> Self {
        Self {
            gas_limit,
            gas_used: 0,
            pq_gas_limit,
            pq_gas_used: 0,
        }
    }

    pub fn charge_gas(&mut self, amount: u64) -> Result<(), AivmError> {
        self.gas_used = checked_charge(
            self.gas_used,
            self.gas_limit,
            amount,
            AivmErrorCode::Gas,
            "ordinary gas",
        )?;
        Ok(())
    }

    pub fn charge_pq_gas(&mut self, amount: u64) -> Result<(), AivmError> {
        self.pq_gas_used = checked_charge(
            self.pq_gas_used,
            self.pq_gas_limit,
            amount,
            AivmErrorCode::PqGas,
            "PQ-Gas",
        )?;
        Ok(())
    }

    pub fn gas_used(&self) -> u64 {
        self.gas_used
    }

    pub fn pq_gas_used(&self) -> u64 {
        self.pq_gas_used
    }

    pub fn remaining_gas(&self) -> u64 {
        self.gas_limit - self.gas_used
    }

    pub fn remaining_pq_gas(&self) -> u64 {
        self.pq_gas_limit - self.pq_gas_used
    }
}

fn checked_charge(
    used: u64,
    limit: u64,
    amount: u64,
    code: AivmErrorCode,
    lane: &str,
) -> Result<u64, AivmError> {
    let next = used.checked_add(amount).ok_or_else(|| {
        AivmError::new(
            code,
            format!("{lane} charge overflow: used {used}, requested {amount}"),
        )
    })?;
    if next > limit {
        return Err(AivmError::new(
            code,
            format!("{lane} exhausted: used {used}, limit {limit}, requested {amount}"),
        ));
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_and_pq_gas_are_metered_independently() {
        let mut meter = AivmGasMeter::new(100, 20);
        meter.charge_gas(80).unwrap();
        meter.charge_pq_gas(15).unwrap();

        assert_eq!(meter.gas_used(), 80);
        assert_eq!(meter.pq_gas_used(), 15);
        assert_eq!(meter.remaining_gas(), 20);
        assert_eq!(meter.remaining_pq_gas(), 5);
    }

    #[test]
    fn exhaustion_preserves_the_meter_lane_error_code() {
        let mut meter = AivmGasMeter::new(5, 7);

        assert_eq!(meter.charge_gas(6).unwrap_err().code, AivmErrorCode::Gas);
        assert_eq!(
            meter.charge_pq_gas(8).unwrap_err().code,
            AivmErrorCode::PqGas
        );
    }
}
