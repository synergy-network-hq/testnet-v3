//! Explicit keyless EVM computation handles. A handle is NOT a native identity,
//! key, classical account or spending authority. Both indices retain all48
//! native bytes and the complete N; no truncation or classical-key import.
use synergy_address::r1_public::NativeIdentityPresentation;
use synergy_protocol_types::{
    c14n02::{Decoder, Encoder},
    R1NetworkRef,
};
use synergy_state::r1::{
    R1StateDomain, R1StateError, R1StateKey, R1StateMap, R1StateOwner, R1StateValue,
};
pub const PROFILE_NAME: &str = "AIVM-EVM-HANDLES-R1";
pub const PROFILE_REVISION: u32 = 1;
pub const PROFILE_SCHEMA:&str=concat!(
 "AIVM-EVM-HANDLES-R1/1;keyless-EVM-computation-handles-only;never-native-spending-authority;codec=QACE-C14N02;",
 "Counter=(U16(0),chainU64,NIC64,nextHandle20BE);Binding=(U16(1),chainU64,NIC64,handle20,ASCII8namespace,nativeRaw48);",
 "state=ProtocolConfiguration/Protocol;aivm/evm/r1/next;by-handle/||handle20;by-owner/||ASCII-namespace||0||raw48;allProtocolRecord(thisprofile);",
 "explicitGenesisCounterRequired;handles0..255reserved;checked160bitmonotoneallocation;bidirectional-exact-equality;nohash48to20;noECDSA-owner-inference;",
 "nativefinancial-owner-requires-existing-fullAccountAuthorization;contract-synq-requires-existing-ContractBinding;",
 "counter+bothindices-oneatomicbatch;collision/partialmapping/missingcounter/overflow-reject;registration-is-computed-data-not-enrollment/admission/finality;",
 "EVM-CREATE-addresses-use-explicit-contract-handle-registration;no-unregistered20byte-native-balance-or-fabricated-synq;",
 "actualprofile-selection+independentexecution/precision/balance-conservation+nativeauthority-qualified-before-activation"
);
#[derive(Debug, PartialEq, Eq)]
pub enum HandleError {
    Context,
    Codec,
    MissingCounter,
    MissingOwner,
    Collision,
    Corrupt,
    Exhausted,
    State(R1StateError),
}
impl From<R1StateError> for HandleError {
    fn from(e: R1StateError) -> Self {
        Self::State(e)
    }
}
impl From<synergy_protocol_types::c14n02::Error> for HandleError {
    fn from(_: synergy_protocol_types::c14n02::Error) -> Self {
        Self::Codec
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputationBinding {
    pub network: R1NetworkRef,
    pub handle: [u8; 20],
    pub native: NativeIdentityPresentation,
}
fn prefix_key(prefix: &[u8], suffix: &[u8]) -> R1StateKey {
    let mut local_key = prefix.to_vec();
    local_key.extend_from_slice(suffix);
    R1StateKey {
        domain: R1StateDomain::ProtocolConfiguration,
        owner: R1StateOwner::Protocol,
        local_key,
    }
}
fn counter_key() -> R1StateKey {
    prefix_key(b"aivm/evm/r1/next", &[])
}
fn handle_key(handle: &[u8; 20]) -> R1StateKey {
    prefix_key(b"aivm/evm/r1/by-handle/", handle)
}
fn owner_key(id: &NativeIdentityPresentation) -> R1StateKey {
    let mut suffix = id.namespace().as_bytes().to_vec();
    suffix.push(0);
    suffix.extend_from_slice(id.raw48());
    prefix_key(b"aivm/evm/r1/by-owner/", &suffix)
}
fn permitted(handle: &[u8; 20]) -> bool {
    let mut first = [0; 20];
    first[18] = 1;
    handle >= &first
}
fn valid_network(n: R1NetworkRef) -> Result<(), HandleError> {
    if n.chain_id == 0 {
        return Err(HandleError::Context);
    }
    Ok(())
}
fn counter_bytes(n: R1NetworkRef, next: &[u8; 20]) -> Result<Vec<u8>, HandleError> {
    valid_network(n)?;
    if !permitted(next) {
        return Err(HandleError::Codec);
    }
    let mut e = Encoder::new(128);
    e.u16(0)?;
    e.u64(n.chain_id)?;
    e.fixed(&n.nic)?;
    e.fixed(next)?;
    Ok(e.finish()?)
}
fn value(bytes: Vec<u8>) -> R1StateValue {
    R1StateValue::ProtocolRecord {
        profile_name: PROFILE_NAME.into(),
        profile_revision: 1,
        canonical_bytes: bytes,
    }
}
fn record<'a>(s: &'a R1StateMap, k: &R1StateKey) -> Result<Option<&'a [u8]>, HandleError> {
    match s.get(k) {
        None => Ok(None),
        Some(R1StateValue::ProtocolRecord {
            profile_name,
            profile_revision: 1,
            canonical_bytes,
        }) if profile_name == PROFILE_NAME => Ok(Some(canonical_bytes)),
        _ => Err(HandleError::Corrupt),
    }
}
impl ComputationBinding {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HandleError> {
        valid_network(self.network)?;
        if !permitted(&self.handle)
            || !matches!(
                self.native.namespace(),
                "synw" | "syns" | "syna" | "synm" | "synu" | "synq"
            )
        {
            return Err(HandleError::Codec);
        }
        let mut e = Encoder::new(256);
        e.u16(1)?;
        e.u64(self.network.chain_id)?;
        e.fixed(&self.network.nic)?;
        e.fixed(&self.handle)?;
        e.ascii(self.native.namespace(), 8)?;
        e.fixed(self.native.raw48())?;
        Ok(e.finish()?)
    }
    fn decode(bytes: &[u8], n: R1NetworkRef) -> Result<Self, HandleError> {
        let mut d = Decoder::new(bytes, 256)?;
        if d.u16()? != 1 || d.u64()? != n.chain_id || d.fixed::<64>()? != n.nic {
            return Err(HandleError::Context);
        }
        let handle = d.fixed()?;
        let ns = d.ascii(8)?;
        let native =
            NativeIdentityPresentation::from_raw(ns, d.fixed()?).map_err(|_| HandleError::Codec)?;
        d.finish()?;
        let out = Self {
            network: n,
            handle,
            native,
        };
        if out.canonical_bytes()? != bytes {
            return Err(HandleError::Codec);
        }
        Ok(out)
    }
}
/// Explicit pure Genesis accounting initialization. Never invent a default
/// counter when opening existing state; caller must bind it in selected policy.
pub fn initialize(s: &mut R1StateMap, n: R1NetworkRef, first: [u8; 20]) -> Result<(), HandleError> {
    if s.get(&counter_key()).is_some()
        || s.entries().any(|(k, _)| {
            k.domain == R1StateDomain::ProtocolConfiguration
                && (k.local_key.starts_with(b"aivm/evm/r1/by-handle/")
                    || k.local_key.starts_with(b"aivm/evm/r1/by-owner/"))
        })
    {
        return Err(HandleError::Collision);
    }
    s.apply_batch(&[(counter_key(), Some(value(counter_bytes(n, &first)?)))])?;
    Ok(())
}
fn next(s: &R1StateMap, n: R1NetworkRef) -> Result<[u8; 20], HandleError> {
    let b = record(s, &counter_key())?.ok_or(HandleError::MissingCounter)?;
    let mut d = Decoder::new(b, 128)?;
    if d.u16()? != 0 || d.u64()? != n.chain_id || d.fixed::<64>()? != n.nic {
        return Err(HandleError::Context);
    }
    let out = d.fixed()?;
    d.finish()?;
    if counter_bytes(n, &out)? != b {
        return Err(HandleError::Codec);
    }
    Ok(out)
}
fn increment(mut h: [u8; 20]) -> Result<[u8; 20], HandleError> {
    for b in h.iter_mut().rev() {
        let (n, overflow) = b.overflowing_add(1);
        *b = n;
        if !overflow {
            return Ok(h);
        }
    }
    Err(HandleError::Exhausted)
}
pub fn by_handle(
    s: &R1StateMap,
    n: R1NetworkRef,
    h: [u8; 20],
) -> Result<Option<ComputationBinding>, HandleError> {
    let Some(b) = record(s, &handle_key(&h))? else {
        return Ok(None);
    };
    let out = ComputationBinding::decode(b, n)?;
    if out.handle != h || record(s, &owner_key(&out.native))? != Some(b) {
        return Err(HandleError::Corrupt);
    }
    Ok(Some(out))
}
pub fn by_owner(
    s: &R1StateMap,
    n: R1NetworkRef,
    id: &NativeIdentityPresentation,
) -> Result<Option<ComputationBinding>, HandleError> {
    let Some(b) = record(s, &owner_key(id))? else {
        return Ok(None);
    };
    let out = ComputationBinding::decode(b, n)?;
    if &out.native != id || record(s, &handle_key(&out.handle))? != Some(b) {
        return Err(HandleError::Corrupt);
    }
    Ok(Some(out))
}
fn owner_exists(s: &R1StateMap, id: &NativeIdentityPresentation) -> Result<(), HandleError> {
    let domain = if id.namespace() == "synq" {
        R1StateDomain::ContractBinding
    } else {
        R1StateDomain::AccountAuthorization
    };
    let key = R1StateKey::native(domain, &id.to_text())?;
    match (id.namespace(), s.get(&key)) {
        ("synq", Some(R1StateValue::ProtocolRecord { .. })) => Ok(()),
        (_, Some(R1StateValue::AccountPolicy { .. }))
            if matches!(id.namespace(), "synw" | "syns" | "syna" | "synm" | "synu") =>
        {
            Ok(())
        }
        _ => Err(HandleError::MissingOwner),
    }
}
/// Pure data transition only. Actual admission/native ownership and state
/// authority are established by the canonical AIVM/execution caller.
pub fn assign_next(
    s: &mut R1StateMap,
    n: R1NetworkRef,
    id: NativeIdentityPresentation,
) -> Result<ComputationBinding, HandleError> {
    if let Some(old) = by_owner(s, n, &id)? {
        return Ok(old);
    }
    owner_exists(s, &id)?;
    let h = next(s, n)?;
    let after = increment(h)?;
    if record(s, &handle_key(&h))?.is_some() {
        return Err(HandleError::Collision);
    }
    let out = ComputationBinding {
        network: n,
        handle: h,
        native: id,
    };
    let bytes = out.canonical_bytes()?;
    s.apply_batch(&[
        (counter_key(), Some(value(counter_bytes(n, &after)?))),
        (handle_key(&h), Some(value(bytes.clone()))),
        (owner_key(&out.native), Some(value(bytes))),
    ])?;
    Ok(out)
}
/// Contract CREATE/CREATE2 supplies its actual interpreter-computed handle.
/// This never derives a native contract identity or accepts a classical signer.
pub fn register_contract(
    s: &mut R1StateMap,
    n: R1NetworkRef,
    id: NativeIdentityPresentation,
    h: [u8; 20],
) -> Result<ComputationBinding, HandleError> {
    if id.namespace() != "synq" {
        return Err(HandleError::MissingOwner);
    }
    owner_exists(s, &id)?;
    next(s, n)?;
    if by_owner(s, n, &id)?.is_some() || record(s, &handle_key(&h))?.is_some() {
        return Err(HandleError::Collision);
    }
    let out = ComputationBinding {
        network: n,
        handle: h,
        native: id,
    };
    let b = out.canonical_bytes()?;
    s.apply_batch(&[
        (handle_key(&h), Some(value(b.clone()))),
        (owner_key(&out.native), Some(value(b))),
    ])?;
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn n() -> R1NetworkRef {
        R1NetworkRef {
            chain_id: u64::MAX - 1,
            nic: [7; 64],
        }
    }
    fn handle(v: u16) -> [u8; 20] {
        let mut h = [0; 20];
        h[18..].copy_from_slice(&v.to_be_bytes());
        h
    }
    fn account(s: &mut R1StateMap, raw: [u8; 48]) -> NativeIdentityPresentation {
        // Explicit synthetic map data only; this test asserts no birth/crypto authority.
        let id = NativeIdentityPresentation::from_raw("syns", raw).unwrap();
        s.insert(
            R1StateKey::native(R1StateDomain::AccountAuthorization, &id.to_text()).unwrap(),
            R1StateValue::AccountPolicy {
                policy_epoch: 1,
                policy_commitment: vec![4; 64],
                full_policy_frame: vec![5],
            },
        )
        .unwrap();
        id
    }
    #[test]
    fn handles_preserve_full_identity_without_classical_key_or_balance() {
        let mut s = R1StateMap::new();
        let a = account(&mut s, [9; 48]);
        let mut tail = [9; 48];
        tail[47] ^= 1;
        let b = account(&mut s, tail);
        let before = s.clone();
        assert_eq!(
            assign_next(&mut s, n(), a.clone()),
            Err(HandleError::MissingCounter)
        );
        assert_eq!(s, before);
        assert!(initialize(&mut s, n(), handle(255)).is_err());
        assert_eq!(s, before);
        initialize(&mut s, n(), handle(256)).unwrap();
        let first = assign_next(&mut s, n(), a.clone()).unwrap();
        let second = assign_next(&mut s, n(), b.clone()).unwrap();
        assert_eq!(first.handle, handle(256));
        assert_eq!(second.handle, handle(257));
        assert_ne!(first.native, second.native);
        assert_eq!(
            by_handle(&s, n(), first.handle).unwrap(),
            Some(first.clone())
        );
        assert_eq!(by_owner(&s, n(), &b).unwrap(), Some(second));
        let size = s.len();
        assert_eq!(assign_next(&mut s, n(), a.clone()).unwrap(), first);
        assert_eq!(s.len(), size);
        assert!(s
            .get(&R1StateKey::native(R1StateDomain::NativeBalance, &a.to_text()).unwrap())
            .is_none());
        let mut wrong = n();
        wrong.nic[63] ^= 1;
        assert!(matches!(by_owner(&s, wrong, &a), Err(HandleError::Context)));
        let encoded = first.canonical_bytes().unwrap();
        assert!(encoded.windows(48).any(|w| w == a.raw48()));
    }
    #[test]
    fn malformed_partial_or_conflicting_mappings_never_alias_native_authority() {
        let mut s = R1StateMap::new();
        let a = account(&mut s, [3; 48]);
        initialize(&mut s, n(), handle(256)).unwrap();
        let binding = assign_next(&mut s, n(), a.clone()).unwrap();
        s.apply_batch(&[(handle_key(&binding.handle), None)])
            .unwrap();
        let before = s.clone();
        assert_eq!(by_owner(&s, n(), &a), Err(HandleError::Corrupt));
        assert_eq!(assign_next(&mut s, n(), a), Err(HandleError::Corrupt));
        assert_eq!(s, before);
        let mut s = R1StateMap::new();
        let a = account(&mut s, [5; 48]);
        initialize(&mut s, n(), [255; 20]).unwrap();
        let before = s.clone();
        assert_eq!(assign_next(&mut s, n(), a), Err(HandleError::Exhausted));
        assert_eq!(s, before);
    }
    #[test]
    fn contract_computation_handle_needs_existing_full_native_binding() {
        let mut s = R1StateMap::new();
        initialize(&mut s, n(), handle(256)).unwrap();
        let id = NativeIdentityPresentation::from_raw("synq", [4; 48]).unwrap();
        assert_eq!(
            register_contract(&mut s, n(), id.clone(), handle(900)),
            Err(HandleError::MissingOwner)
        );
        s.insert(
            R1StateKey::native(R1StateDomain::ContractBinding, &id.to_text()).unwrap(),
            R1StateValue::ProtocolRecord {
                profile_name: "PUBLIC-SYNTHETIC-CONTRACT-DATA".into(),
                profile_revision: 1,
                canonical_bytes: vec![1],
            },
        )
        .unwrap();
        let binding = register_contract(&mut s, n(), id.clone(), handle(900)).unwrap();
        assert_eq!(binding.native, id);
        let before = s.clone();
        assert_eq!(
            register_contract(&mut s, n(), id, handle(901)),
            Err(HandleError::Collision)
        );
        assert_eq!(s, before);
    }
}
