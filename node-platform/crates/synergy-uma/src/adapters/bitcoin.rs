pub fn validate_bitcoin_destination(address: &str) -> Result<(), String> {
    if (address.starts_with("bc1") || address.starts_with("tb1"))
        && (14..=90).contains(&address.len())
        && address.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        Ok(())
    } else {
        Err("invalid Bitcoin UMA destination".into())
    }
}
