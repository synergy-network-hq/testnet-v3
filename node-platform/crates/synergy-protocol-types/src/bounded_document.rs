//! Bounded public-proof transport encoding. Native commitment bytes do not
//! change; receivers authenticate the exact re-expanded original document.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::Write;
const MAX_DOCUMENT: usize = 1024 * 1024;
pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
    if bytes.is_empty() || bytes.len() > MAX_DOCUMENT {
        return Err(serde::ser::Error::custom(
            "bounded original proof document required",
        ));
    }
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
    encoder
        .write_all(bytes)
        .map_err(serde::ser::Error::custom)?;
    let compressed = encoder.finish().map_err(serde::ser::Error::custom)?;
    let mut payload = (bytes.len() as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(&compressed);
    STANDARD.encode(payload).serialize(serializer)
}
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let encoded = String::deserialize(deserializer)?;
    if encoded.len() > 2 * MAX_DOCUMENT {
        return Err(serde::de::Error::custom(
            "encoded proof exceeds transport bound",
        ));
    }
    let payload = STANDARD
        .decode(&encoded)
        .map_err(serde::de::Error::custom)?;
    if payload.len() < 5 || STANDARD.encode(&payload) != encoded {
        return Err(serde::de::Error::custom(
            "noncanonical bounded proof encoding",
        ));
    }
    let length =
        u32::from_be_bytes(payload[..4].try_into().map_err(serde::de::Error::custom)?) as usize;
    if length == 0 || length > MAX_DOCUMENT {
        return Err(serde::de::Error::custom(
            "proof expansion exceeds document bound",
        ));
    }
    let mut raw = vec![0u8; length];
    let mut decoder = flate2::Decompress::new(false);
    let status = decoder
        .decompress(&payload[4..], &mut raw, flate2::FlushDecompress::Finish)
        .map_err(serde::de::Error::custom)?;
    if status != flate2::Status::StreamEnd
        || decoder.total_in() != (payload.len() - 4) as u64
        || decoder.total_out() != length as u64
    {
        return Err(serde::de::Error::custom(
            "truncated, trailing or oversized proof expansion",
        ));
    }
    Ok(raw)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Serialize, Deserialize)]
    struct Document {
        #[serde(with = "super")]
        bytes: Vec<u8>,
    }
    #[test]
    fn bounded_public_transport_preserves_original_and_rejects_expansion() {
        let d = Document {
            bytes: b"exact native commitment".to_vec(),
        };
        let encoded = serde_json::to_vec(&d).unwrap();
        let round: Document = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(round.bytes, d.bytes);
        let mut p = (MAX_DOCUMENT as u32 + 1).to_be_bytes().to_vec();
        p.push(0);
        assert!(serde_json::from_value::<Document>(
            serde_json::json!({"bytes":STANDARD.encode(p)})
        )
        .is_err());
    }
}
