//! Bounded transport encoding of a complete, unchanged signed governance TX.
//! Decoding is not authorization; the native governance owner verifies quorum.
use crate::{SignedTransaction, TransactionAction, TransactionClass};
use std::io::Write;
const MAGIC: &[u8; 8] = b"SYNGOVD1";
pub const MAX_PROCESSING_DECODE_BYTES: usize = 1024 * 1024;
const MAX_GOVERNANCE_WIRE_BYTES: usize = 65536 - 20;

fn governance(transaction: &SignedTransaction) -> bool {
    transaction.unsigned.class == TransactionClass::System
        && matches!(
            transaction.unsigned.action(),
            Ok(TransactionAction::Governance { .. })
        )
}
pub fn processing_decode_scratch(bytes: &[u8]) -> usize {
    if bytes.starts_with(MAGIC) {
        MAX_PROCESSING_DECODE_BYTES * 16 + 65536
    } else {
        0
    }
}
pub fn encode_processing_transaction(transaction: &SignedTransaction) -> Result<Vec<u8>, String> {
    struct Capped(Vec<u8>);
    impl Write for Capped {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self
                .0
                .len()
                .checked_add(bytes.len())
                .is_none_or(|length| length > MAX_PROCESSING_DECODE_BYTES)
            {
                return Err(std::io::Error::other(
                    "native processing JSON exceeds decode bound",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    transaction
        .validate_structure()
        .map_err(|error| error.to_string())?;
    let mut raw = Capped(Vec::new());
    serde_json::to_writer(&mut raw, transaction).map_err(|error| error.to_string())?;
    if raw.0.len() <= MAX_GOVERNANCE_WIRE_BYTES || !governance(transaction) {
        return Ok(raw.0);
    }
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
    encoder
        .write_all(&raw.0)
        .map_err(|error| error.to_string())?;
    let encoded = encoder.finish().map_err(|error| error.to_string())?;
    let mut output = Vec::with_capacity(12 + encoded.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&(raw.0.len() as u32).to_be_bytes());
    output.extend_from_slice(&encoded);
    if output.len() > MAX_GOVERNANCE_WIRE_BYTES {
        return Err("qualified governance transaction exceeds existing ciphertext class".into());
    }
    Ok(output)
}
pub fn decode_processing_transaction(bytes: &[u8]) -> Result<SignedTransaction, String> {
    if !bytes.starts_with(MAGIC) {
        if bytes.len() > MAX_PROCESSING_DECODE_BYTES {
            return Err("native processing plaintext exceeds bound".into());
        }
        return serde_json::from_slice(bytes).map_err(|error| error.to_string());
    }
    if bytes.len() < 13 || bytes.len() > MAX_GOVERNANCE_WIRE_BYTES {
        return Err("invalid bounded governance wire length".into());
    }
    let length = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if length == 0 || length > MAX_PROCESSING_DECODE_BYTES {
        return Err("governance expansion exceeds bound".into());
    }
    let mut raw = vec![0; length];
    let mut decoder = flate2::Decompress::new(false);
    let status = decoder
        .decompress(&bytes[12..], &mut raw, flate2::FlushDecompress::Finish)
        .map_err(|error| error.to_string())?;
    if status != flate2::Status::StreamEnd
        || decoder.total_in() != ((bytes.len() - 12) as u64)
        || decoder.total_out() != (length as u64)
        || raw.starts_with(MAGIC)
    {
        return Err("truncated, trailing or nested governance encoding".into());
    }
    let transaction: SignedTransaction =
        serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
    if !governance(&transaction) {
        return Err("compressed plaintext is restricted to native governance".into());
    }
    transaction
        .validate_structure()
        .map_err(|error| error.to_string())?;
    Ok(transaction)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expansion_and_stream_boundaries_fail_closed_before_json_authorization() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&((MAX_PROCESSING_DECODE_BYTES + 1) as u32).to_be_bytes());
        bytes.push(0);
        assert!(decode_processing_transaction(&bytes).is_err());
        for data in [b"{}".as_slice(), MAGIC.as_slice()] {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
            encoder.write_all(data).unwrap();
            let encoded = encoder.finish().unwrap();
            let mut bytes = MAGIC.to_vec();
            bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
            bytes.extend(encoded);
            assert!(decode_processing_transaction(&bytes).is_err());
            bytes.push(1);
            assert!(decode_processing_transaction(&bytes).is_err());
            bytes.truncate(12);
            assert!(decode_processing_transaction(&bytes).is_err());
        }
    }
}
