//! Canonical padded standard base64 for bounded new protocol byte fields.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
const MAX_BYTES: usize = 16 * 1024;
pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
    if bytes.len() > MAX_BYTES {
        return Err(serde::ser::Error::custom(
            "protocol byte field exceeds bound",
        ));
    }
    STANDARD.encode(bytes).serialize(serializer)
}
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let text = String::deserialize(deserializer)?;
    if text.len() > ((MAX_BYTES + 2) / 3) * 4 {
        return Err(serde::de::Error::custom(
            "encoded protocol bytes exceed bound",
        ));
    }
    let bytes = STANDARD.decode(&text).map_err(serde::de::Error::custom)?;
    if bytes.len() > MAX_BYTES || STANDARD.encode(&bytes) != text {
        return Err(serde::de::Error::custom(
            "noncanonical protocol byte encoding",
        ));
    }
    Ok(bytes)
}

pub fn encode(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() > MAX_BYTES {
        return Err("protocol byte field exceeds bound".into());
    }
    Ok(STANDARD.encode(bytes))
}
pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    if text.len() > ((MAX_BYTES + 2) / 3) * 4 {
        return Err("encoded protocol bytes exceed bound".into());
    }
    let bytes = STANDARD
        .decode(text)
        .map_err(|_| "invalid protocol byte encoding")?;
    if bytes.len() > MAX_BYTES || STANDARD.encode(&bytes) != text {
        return Err("noncanonical protocol byte encoding".into());
    }
    Ok(bytes)
}
