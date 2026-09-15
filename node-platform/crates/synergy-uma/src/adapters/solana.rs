pub fn validate_solana_destination(address: &str) -> Result<(), String> {
    const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if (32..=44).contains(&address.len()) && address.chars().all(|character| BASE58.contains(character))
    {
        Ok(())
    } else {
        Err("invalid Solana UMA destination".into())
    }
}
