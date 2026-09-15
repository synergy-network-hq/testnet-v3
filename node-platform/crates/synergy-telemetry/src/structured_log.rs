use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredLogRecord {
    pub timestamp_ms: u64,
    pub level: String,
    pub subsystem: String,
    pub message: String,
    pub fields: BTreeMap<String, String>,
}

impl StructuredLogRecord {
    pub fn validate(&self) -> Result<(), String> {
        if self.level.trim().is_empty()
            || self.subsystem.trim().is_empty()
            || self.message.trim().is_empty()
            || self.message.len() > 8192
            || self.fields.len() > 64
            || self.fields.keys().any(|key| is_secret_field(key))
        {
            return Err("invalid or secret-bearing structured log record".into());
        }
        Ok(())
    }
}

fn is_secret_field(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "password" | "private_key" | "secret" | "setup_key" | "token"
    )
}
