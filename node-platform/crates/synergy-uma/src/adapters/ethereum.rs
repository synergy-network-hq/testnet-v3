pub fn validate_ethereum_destination(address: &str) -> Result<(), String> {
    if address.len() == 42
        && address.starts_with("0x")
        && address[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err("invalid Ethereum UMA destination".into())
    }
}
