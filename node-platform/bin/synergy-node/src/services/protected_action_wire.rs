//! Unratified v1 action payloads nested in APQE's canonical native intent.
//! No production transaction decoder or RPC route uses this module.
#![allow(dead_code)]

use synergy_address_engine::apqe::{address::AccountIdentifier, native_intent::NativeIntentBody};

pub(super) const ENROLL_COMMIT: u16 = 0x7001;
pub(super) const ENROLL_REVEAL: u16 = 0x7002;
pub(super) const TRANSFER: u16 = 0x7003;
pub(super) const POLICY_SCHEDULE: u16 = 0x7004;
pub(super) const POLICY_CANCEL: u16 = 0x7005;
pub(super) const POLICY_ACTIVATE: u16 = 0x7006;
pub(super) const RECOVERY_SCHEDULE: u16 = 0x7007;
pub(super) const RECOVERY_VETO: u16 = 0x7008;
pub(super) const RECOVERY_CANCEL: u16 = 0x7009;
pub(super) const RECOVERY_ACTIVATE: u16 = 0x700a;

pub(super) const MAX_ENROLLMENT: usize = 24 * 1024;
pub(super) const MAX_POLICY: usize = 10 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Payload<'a> {
    Commit([u8; 32]),
    Reveal {
        enrollment: &'a [u8],
        salt: [u8; 32],
    },
    Transfer {
        recipient: AccountIdentifier,
        amount: u128,
    },
    Schedule {
        role: u8,
        old_policy: [u8; 32],
        new_policy: &'a [u8],
        new_policy_hash: [u8; 32],
        reason: u16,
        activation_at: u64,
        continuity: Option<[u8; 32]>,
    },
    Pending([u8; 32]),
}

pub(super) fn decode(action: u16, bytes: &[u8]) -> Result<Payload<'_>, &'static str> {
    let fields = match action {
        ENROLL_COMMIT | POLICY_CANCEL | POLICY_ACTIVATE | RECOVERY_VETO | RECOVERY_CANCEL
        | RECOVERY_ACTIVATE => 2,
        ENROLL_REVEAL | TRANSFER => 3,
        POLICY_SCHEDULE => 7,
        RECOVERY_SCHEDULE => 8,
        _ => return Err("UNKNOWN_PROTECTED_ACTION"),
    };
    let mut reader = Reader(bytes);
    reader.byte(0xa0 | fields)?;
    reader.byte(0)?;
    if reader.take(1)? != [1] {
        return Err("UNSUPPORTED_PROTECTED_ACTION_VERSION");
    }
    reader.byte(1)?;
    let value = match action {
        ENROLL_COMMIT => Payload::Commit(reader.nonzero32()?),
        ENROLL_REVEAL => {
            let enrollment = reader.bytes(1, MAX_ENROLLMENT)?;
            reader.byte(2)?;
            Payload::Reveal {
                enrollment,
                salt: reader.fixed()?,
            }
        }
        TRANSFER => {
            let account = reader.fixed()?;
            reader.byte(2)?;
            let amount: [u8; 32] = reader.fixed()?;
            if amount[..16] != [0; 16] || amount[16..] == [0; 16] {
                return Err("INVALID_PROTECTED_AMOUNT");
            }
            Payload::Transfer {
                recipient: AccountIdentifier::from_bytes(account),
                amount: u128::from_be_bytes(amount[16..].try_into().expect("fixed size")),
            }
        }
        POLICY_SCHEDULE | RECOVERY_SCHEDULE => {
            let role = reader.take(1)?[0];
            if role > 1 {
                return Err("INVALID_PROTECTED_ROLE");
            }
            reader.byte(2)?;
            let old_policy = reader.nonzero32()?;
            reader.byte(3)?;
            let new_policy = reader.bytes(1, MAX_POLICY)?;
            reader.byte(4)?;
            let new_policy_hash = reader.nonzero32()?;
            reader.byte(5)?;
            let reason = u16::try_from(reader.uint()?).map_err(|_| "INVALID_PROTECTED_REASON")?;
            reader.byte(6)?;
            let activation_at = reader.uint()?;
            if reason != 1 || activation_at == 0 {
                return Err("INVALID_PROTECTED_SCHEDULE");
            }
            let continuity = if action == RECOVERY_SCHEDULE {
                reader.byte(7)?;
                Some(reader.nonzero32()?)
            } else {
                None
            };
            Payload::Schedule {
                role,
                old_policy,
                new_policy,
                new_policy_hash,
                reason,
                activation_at,
                continuity,
            }
        }
        _ => Payload::Pending(reader.nonzero32()?),
    };
    if !reader.0.is_empty() {
        return Err("NONCANONICAL_PROTECTED_PAYLOAD");
    }
    Ok(value)
}

pub(super) fn decode_transfer(
    intent: &NativeIntentBody<'_>,
) -> Result<(AccountIdentifier, u128), String> {
    match decode(intent.action_type, intent.action_payload)? {
        Payload::Transfer { recipient, amount } => Ok((recipient, amount)),
        _ => Err("expected PROTECTED_TRANSFER".into()),
    }
}

pub(super) struct SponsorIntent<'a> {
    pub genesis: [u8; 32],
    pub payer: &'a str,
    pub nonce: u64,
    pub action: u16,
    pub payload_hash: [u8; 32],
    pub max_fee: [u8; 32],
    pub valid_until: u64,
}

pub(super) fn decode_sponsor(bytes: &[u8]) -> Result<SponsorIntent<'_>, &'static str> {
    let mut r = Reader(bytes);
    for byte in [0xa8, 0, 1, 1] {
        r.byte(byte)?;
    }
    let genesis = r.nonzero32()?;
    r.byte(2)?;
    // A funds-bearing native address is short, canonical lowercase text.
    r.byte(0x78)?;
    let n = usize::from(r.take(1)?[0]);
    if !(24..=128).contains(&n) {
        return Err("INVALID_SPONSOR_PAYER");
    }
    let payer = std::str::from_utf8(r.take(n)?).map_err(|_| "INVALID_SPONSOR_PAYER")?;
    if !payer.starts_with("syna1") || !payer.is_ascii() {
        return Err("INVALID_SPONSOR_PAYER");
    }
    r.byte(3)?;
    let nonce = r.uint()?;
    r.byte(4)?;
    let action = match r.uint()? {
        x if x == u64::from(ENROLL_COMMIT) => ENROLL_COMMIT,
        x if x == u64::from(ENROLL_REVEAL) => ENROLL_REVEAL,
        _ => return Err("INVALID_SPONSOR_ACTION"),
    };
    r.byte(5)?;
    let payload_hash = r.nonzero32()?;
    r.byte(6)?;
    let max_fee = r.nonzero32()?;
    r.byte(7)?;
    let valid_until = r.uint()?;
    if !r.0.is_empty() {
        return Err("NONCANONICAL_PROTECTED_PAYLOAD");
    }
    Ok(SponsorIntent {
        genesis,
        payer,
        nonce,
        action,
        payload_hash,
        max_fee,
        valid_until,
    })
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        let (head, tail) = self
            .0
            .split_at_checked(n)
            .ok_or("NONCANONICAL_PROTECTED_PAYLOAD")?;
        self.0 = tail;
        Ok(head)
    }
    fn byte(&mut self, byte: u8) -> Result<(), &'static str> {
        (self.take(1)? == [byte])
            .then_some(())
            .ok_or("NONCANONICAL_PROTECTED_PAYLOAD")
    }
    fn bytes(&mut self, min: usize, max: usize) -> Result<&'a [u8], &'static str> {
        let n = match self.take(1)?[0] {
            head @ 0x40..=0x57 => usize::from(head - 0x40),
            0x58 => {
                let n = usize::from(self.take(1)?[0]);
                if n < 24 {
                    return Err("NONCANONICAL_PROTECTED_PAYLOAD");
                }
                n
            }
            0x59 => {
                let n = usize::from(u16::from_be_bytes(
                    self.take(2)?.try_into().expect("fixed size"),
                ));
                if n < 256 {
                    return Err("NONCANONICAL_PROTECTED_PAYLOAD");
                }
                n
            }
            _ => return Err("NONCANONICAL_PROTECTED_PAYLOAD"),
        };
        if !(min..=max).contains(&n) {
            return Err("PROTECTED_PAYLOAD_SIZE");
        }
        self.take(n)
    }
    fn uint(&mut self) -> Result<u64, &'static str> {
        let head = self.take(1)?[0];
        let (width, min) = match head {
            0..=23 => return Ok(head.into()),
            24 => (1, 24),
            25 => (2, 256),
            26 => (4, 65_536),
            27 => (8, 1_u64 << 32),
            _ => return Err("NONCANONICAL_PROTECTED_PAYLOAD"),
        };
        let mut bytes = [0; 8];
        bytes[8 - width..].copy_from_slice(self.take(width)?);
        let value = u64::from_be_bytes(bytes);
        (value >= min)
            .then_some(value)
            .ok_or("NONCANONICAL_PROTECTED_PAYLOAD")
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], &'static str> {
        self.bytes(N, N)?
            .try_into()
            .map_err(|_| "NONCANONICAL_PROTECTED_PAYLOAD")
    }
    fn nonzero32(&mut self) -> Result<[u8; 32], &'static str> {
        let bytes = self.fixed()?;
        if bytes == [0; 32] {
            return Err("INVALID_PROTECTED_REFERENCE");
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_action_candidate_vectors() {
        let source = include_str!("../../../../../docs/protected-accounts-canary-v1/protected-conformance-v1/action-payloads.json");
        let vectors: serde_json::Value = serde_json::from_str(source).unwrap();
        let rows = vectors.as_array().unwrap();
        for row in rows {
            let id = u16::try_from(row["action"].as_u64().unwrap()).unwrap();
            let hex = row["payload"].as_str().unwrap();
            let raw: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            let result = decode(id, &raw);
            match row["error"].as_str() {
                Some(error) => assert_eq!(result.unwrap_err(), error, "{}", row["name"]),
                None => {
                    assert!(result.is_ok(), "{}: {result:?}", row["name"]);
                }
            }
            if let Some(encoded) = row["native_intent"].as_str() {
                let bytes: Vec<u8> = (0..encoded.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
                    .collect();
                let intent =
                    synergy_address_engine::apqe::native_intent::CanonicalNativeIntent::decode(
                        &bytes,
                        MAX_ENROLLMENT,
                    )
                    .unwrap();
                assert_eq!(intent.body().action_type, id);
                assert_eq!(intent.body().action_payload, raw);
                let digest = intent.digest().unwrap();
                let digest_hex: String = digest
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                assert_eq!(digest_hex, row["native_digest"].as_str().unwrap());
            }
        }
    }
}
