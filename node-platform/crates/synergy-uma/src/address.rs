use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UmaAddress(String);

impl UmaAddress {
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if !value.starts_with("uma1")
            || value.len() < 16
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err("invalid UMA address".into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
