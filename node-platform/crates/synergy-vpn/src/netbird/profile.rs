#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetbirdProfile {
    pub management_url: String,
    pub admin_url: Option<String>,
    pub interface_name: String,
}

impl NetbirdProfile {
    pub fn validate(&self) -> Result<(), String> {
        if !self.management_url.starts_with("https://")
            || self.interface_name.trim().is_empty()
            || self
                .admin_url
                .as_ref()
                .is_some_and(|url| !url.starts_with("https://"))
        {
            return Err("invalid NetBird profile".into());
        }
        Ok(())
    }
}
