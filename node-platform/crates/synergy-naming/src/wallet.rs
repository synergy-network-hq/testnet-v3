//! Wallet aliases are authenticated native actions in canonical WorldState.
//! No RPC or local registry may mutate this state. The caller supplies the
//! sender only after native transaction authorization and nonce validation.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const WALLET_PROTOCOL_STATE_KEY: &str = "synergy/naming/wallets/v1";
pub const MAX_WALLET_NAMING_BYTES: usize = 1024 * 1024;
const RESERVED: &str = "admin administrator api app atlas bridge burn chain claims compliance contact core dao dev docs explorer faucet foundation governance help legal mail network no-reply noah official operator ops owner pay payments root rpc security staking support swap syn synid synergy synergy-network synergywallet test testnet token treasury validator wallet webhook www";

pub fn normalize_wallet_syn_id(value: &str) -> Result<String, String> {
    if !value.is_ascii() {
        return Err("SynID must be ASCII".into());
    }
    let value = value.trim().to_ascii_lowercase();
    let label = value.strip_suffix(".syn").ok_or("SynID must end in .syn")?;
    if !(3..=32).contains(&label.len())
        || !label.as_bytes()[0].is_ascii_alphanumeric()
        || !label
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Err("invalid wallet SynID".into());
    }
    if RESERVED.split_whitespace().any(|r| {
        label == r || label.starts_with(&format!("{r}-")) || label.ends_with(&format!("-{r}"))
    }) {
        return Err("reserved wallet SynID".into());
    }
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletSynIdRecord {
    pub syn_id: String,
    pub address: String,
    pub registered_height: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletSynIdRegistry {
    records: BTreeMap<String, WalletSynIdRecord>,
}
impl WalletSynIdRegistry {
    pub fn decode(bytes: Option<&[u8]>) -> Result<Self, String> {
        let registry: Self = match bytes {
            None => Self::default(),
            Some(bytes) if bytes.len() <= MAX_WALLET_NAMING_BYTES => {
                serde_json::from_slice(bytes).map_err(|e| e.to_string())?
            }
            Some(_) => return Err("wallet naming state exceeds bound".into()),
        };
        for (key, value) in &registry.records {
            if normalize_wallet_syn_id(key)? != *key
                || value.syn_id != *key
                || value.registered_height == 0
                || !wallet_address(&value.address)
            {
                return Err("invalid canonical wallet naming state".into());
            }
        }
        Ok(registry)
    }
    pub fn resolve(&self, name: &str) -> Result<Option<&WalletSynIdRecord>, String> {
        Ok(self.records.get(&normalize_wallet_syn_id(name)?))
    }
    pub fn reverse(&self, address: &str) -> Result<Vec<&WalletSynIdRecord>, String> {
        if !wallet_address(address) {
            return Err("canonical wallet address required".into());
        }
        Ok(self
            .records
            .values()
            .filter(|v| v.address == address)
            .collect())
    }
    /// Called only from verified native execution. Owner is always the signed
    /// transaction sender, never an address field supplied in naming input.
    pub fn register_authenticated(
        &mut self,
        name: &str,
        sender: &str,
        height: u64,
    ) -> Result<(), String> {
        let name = normalize_wallet_syn_id(name)?;
        if !wallet_address(sender) || height == 0 {
            return Err("canonical wallet sender and execution height required".into());
        }
        if let Some(record) = self.records.get(&name) {
            return if record.address == sender {
                Ok(())
            } else {
                Err("SynID already belongs to another wallet".into())
            };
        }
        self.records.insert(
            name.clone(),
            WalletSynIdRecord {
                syn_id: name,
                address: sender.into(),
                registered_height: height,
            },
        );
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_WALLET_NAMING_BYTES {
            return Err("wallet naming state exceeds bound".into());
        }
        Ok(bytes)
    }
}
fn wallet_address(address: &str) -> bool {
    (address.starts_with("synw1") || address.starts_with("syna1"))
        && synergy_address::is_valid_address(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn address(byte: u8) -> String {
        synergy_address::generate_wallet_address(&hex_key(byte)).unwrap()
    }
    fn hex_key(byte: u8) -> String {
        format!("{byte:02x}").repeat(1793)
    }
    #[test]
    fn wallet_alias_is_immutable_and_survives_canonical_roundtrip() {
        let owner = address(1);
        let attacker = address(2);
        let mut s = WalletSynIdRegistry::default();
        s.register_authenticated("JDH.syn", &owner, 10).unwrap();
        assert!(s.register_authenticated("jdh.syn", &attacker, 11).is_err());
        s.register_authenticated("jdh.syn", &owner, 11).unwrap();
        let s = WalletSynIdRegistry::decode(Some(&s.encode().unwrap())).unwrap();
        assert_eq!(s.resolve("jdh.syn").unwrap().unwrap().address, owner);
        assert_eq!(s.reverse(&owner).unwrap().len(), 1);
        assert_eq!(s.resolve("jdh.syn").unwrap().unwrap().registered_height, 10);
    }
    #[test]
    fn malformed_reserved_and_unowned_names_fail_closed() {
        let owner = address(3);
        let mut s = WalletSynIdRegistry::default();
        for name in [
            "admin.syn",
            "team-admin.syn",
            "a.syn",
            "a.b.syn",
            "ééé.syn",
            "jdh.node",
        ] {
            assert!(s.register_authenticated(name, &owner, 1).is_err(), "{name}");
        }
        assert!(s
            .register_authenticated("jdh.syn", "synw1invalid", 1)
            .is_err());
        assert!(s.register_authenticated("jdh.syn", &owner, 0).is_err());
        assert!(WalletSynIdRegistry::decode(Some(br#"{"records":{"jdh.syn":{"syn_id":"other.syn","address":"bad","registered_height":1}}}"#)).is_err());
        assert!(s.resolve("jdh.syn").unwrap().is_none());
    }
}
