#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionReport {
    pub software: &'static str,
    pub management_schema: u16,
    pub config_schema: u16,
}

pub const fn report() -> VersionReport {
    VersionReport {
        software: env!("CARGO_PKG_VERSION"),
        management_schema: synergy_node_core::MANAGEMENT_SCHEMA_VERSION,
        config_schema: synergy_config::CONFIG_SCHEMA_VERSION,
    }
}
