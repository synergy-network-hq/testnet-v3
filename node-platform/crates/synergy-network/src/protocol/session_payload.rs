//! Authority-neutral application routing inside an authenticated APQE record.
use synergy_protocol_types::ProtocolKind;

use super::{protocol_id, protocol_kind};

/// Version, existing protocol identifier and exact payload length.
pub const SESSION_PAYLOAD_HEADER_BYTES: usize = 6;
/// APQE's fixed maximum record plaintext, including this routing header.
pub const MAX_SESSION_PAYLOAD_BYTES: usize = 1_048_576;

pub fn encode_session_payload(
    protocol: ProtocolKind,
    payload: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, &'static str> {
    let total = payload
        .len()
        .checked_add(SESSION_PAYLOAD_HEADER_BYTES)
        .ok_or("session payload length overflow")?;
    if payload.is_empty() || payload.len() > maximum || total > MAX_SESSION_PAYLOAD_BYTES {
        return Err("session payload exceeds fixed bounds");
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&[1, protocol_id(protocol)]);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub fn decode_session_payload(
    bytes: &[u8],
    maximum: usize,
) -> Result<(ProtocolKind, &[u8]), &'static str> {
    if bytes.len() < SESSION_PAYLOAD_HEADER_BYTES
        || bytes.len() > MAX_SESSION_PAYLOAD_BYTES
        || bytes[0] != 1
    {
        return Err("invalid session payload version or length");
    }
    let protocol = protocol_kind(bytes[1]).map_err(|_| "unknown session protocol")?;
    let length = u32::from_be_bytes(
        bytes[2..6]
            .try_into()
            .map_err(|_| "invalid session length")?,
    ) as usize;
    let payload = &bytes[SESSION_PAYLOAD_HEADER_BYTES..];
    if length == 0 || length != payload.len() || length > maximum {
        return Err("invalid session payload bounds");
    }
    Ok((protocol, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routes_every_existing_protocol_without_changing_payload_bytes() {
        for id in 1..=9 {
            let protocol = protocol_kind(id).unwrap();
            let wire =
                encode_session_payload(protocol, b"canonical signed protocol bytes", 64).unwrap();
            assert_eq!(&wire[..6], &[1, id, 0, 0, 0, 31]);
            assert_eq!(
                decode_session_payload(&wire, 64),
                Ok((protocol, b"canonical signed protocol bytes".as_slice()))
            );
        }
    }
    #[test]
    fn rejects_unknown_version_protocol_empty_trailing_and_oversized_payloads() {
        let wire = encode_session_payload(ProtocolKind::Posy, b"body", 4).unwrap();
        for (index, value) in [(0, 2), (1, 0), (5, 3), (5, 5)] {
            let mut altered = wire.clone();
            altered[index] = value;
            assert!(decode_session_payload(&altered, 4).is_err());
        }
        assert!(decode_session_payload(&wire, 3).is_err());
        assert!(encode_session_payload(ProtocolKind::Posy, &[], 4).is_err());
        assert!(encode_session_payload(
            ProtocolKind::Posy,
            &vec![1; MAX_SESSION_PAYLOAD_BYTES],
            usize::MAX
        )
        .is_err());
        for length in 0..wire.len() {
            assert!(decode_session_payload(&wire[..length], 4).is_err());
        }
    }
}
