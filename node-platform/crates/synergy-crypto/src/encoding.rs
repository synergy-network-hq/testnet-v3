pub fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 15) as usize] as char)
    }
    out
}
pub fn hex_decode(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || value.len() / 2 > maximum {
        return Err("invalid bounded hex".into());
    }
    let bytes = value.as_bytes();
    (0..bytes.len())
        .step_by(2)
        .map(|i| Ok((nibble(bytes[i])? << 4) | nibble(bytes[i + 1])?))
        .collect()
}
fn nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("hex must be lowercase canonical".into()),
    }
}
