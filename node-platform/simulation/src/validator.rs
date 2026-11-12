#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimValidator {
    pub id: String,
    pub weight: u64,
    pub active: bool,
    pub jailed: bool,
    pub last_signed_height: u64,
}
impl SimValidator {
    pub fn can_sign(&self) -> bool {
        self.active && !self.jailed
    }
    pub fn sign_height(&mut self, height: u64) -> Result<(), String> {
        if !self.can_sign() {
            return Err("validator lacks active authority".into());
        }
        if height <= self.last_signed_height {
            return Err("double-sign or stale height refused".into());
        }
        self.last_signed_height = height;
        Ok(())
    }
}
