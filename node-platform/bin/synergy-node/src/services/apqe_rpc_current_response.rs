//! Candidate CURRENT-only large public-read response carrier, not activation.
//! Native owners must select the reviewed carrier profile and retain each actual
//! resource lease through final I/O. Historical RPC/record bytes are untouched.
use std::{sync::Arc, time::Instant};
use synergy_address_engine::apqe::{
    current_session::{CurrentSessionContext, SessionHop, SessionPurpose},
    engineering_transport::SessionDriver,
    network_birth_r1::ProfileRef,
    r1_framing::{self as c, Value},
};
use synergy_rpc::{provider::RpcResponseCapacity, server::RpcOutput};
use synergy_state::world_resources::WorldResourceBudget;
const MAX_FRAME: usize = 1 << 20;
const MAX_CHUNK: usize = 1_000_000;
const MAX_TOTAL: usize = 64 * 1024 * 1024;
const PROFILE: ProfileRef<'static> = ProfileRef {
    name: synergy_protocol_types::r1_rpc_response::PROFILE_NAME,
    revision: synergy_protocol_types::r1_rpc_response::PROFILE_REVISION,
};
const DOMAIN: &str = "RPC.PUBLIC.RESPONSE.CHUNK";
pub use synergy_protocol_types::r1_rpc_response::PROFILE_SCHEMA;

/// Exact profile selection from the genuine private received Genesis. This
/// authenticates the catalog choice, not finality, provider/host qualification,
/// operation permission or the chain data carried in a response.
pub struct SelectedCurrentResponseProfile {
    genesis: Arc<synergy_genesis::r1::VerifiedR1Genesis>,
}
impl SelectedCurrentResponseProfile {
    pub fn from_verified_genesis(
        genesis: Arc<synergy_genesis::r1::VerifiedR1Genesis>,
    ) -> Result<Arc<Self>, synergy_rpc::RpcError> {
        use synergy_address_engine::apqe::{HashAlgorithm, Primitives};
        let expected = Primitives
            .hash(HashAlgorithm::Sha3384, PROFILE_SCHEMA)
            .map_err(|_| {
                synergy_rpc::RpcError::unavailable("current response schema digest unavailable")
            })?;
        let selected = genesis
            .compiled()
            .catalog()
            .definitions()
            .iter()
            .any(|definition| {
                definition.kind.name() == PROFILE.name
                    && definition.kind.revision() == PROFILE.revision
                    && definition.schema_digest.as_slice() == expected.as_slice()
            });
        if !selected {
            return Err(synergy_rpc::RpcError::unavailable(
                "current response profile is not selected by authenticated Genesis catalog",
            ));
        }
        Ok(Arc::new(Self { genesis }))
    }
    fn check(&self, context: &CurrentSessionContext) -> Result<(), String> {
        scope(context)?;
        let expected = self.genesis.coordinate();
        if context.network.chain_id != expected.network.chain_id
            || context.network.nic != expected.network.nic
            || context.genesis != expected.genesis.digest
            || context.activated_profiles != expected.activated_profiles.commitment
        {
            return Err("current response selected profile coordinate mismatch".into());
        }
        Ok(())
    }
}
fn scope(context: &CurrentSessionContext) -> Result<(), String> {
    if context.purpose != SessionPurpose::PublicRpc
        || !matches!(
            context.hop,
            SessionHop::GatewayToSentry | SessionHop::SentryToValidator
        )
    {
        return Err("current response requires the confirmed public RPC hop".into());
    }
    context
        .canonical_bytes()
        .map_err(|_| "invalid current response context".to_string())?;
    Ok(())
}
fn same_coordinate(a: &CurrentSessionContext, b: &CurrentSessionContext) -> bool {
    a.network == b.network && a.genesis == b.genesis && a.activated_profiles == b.activated_profiles
}
fn maximum(capacity: &RpcResponseCapacity) -> Result<usize, String> {
    let n = capacity.maximum_encoded_bytes();
    if !(256..=MAX_TOTAL).contains(&n) {
        Err("current response native capacity is outside carrier bounds".into())
    } else {
        Ok(n)
    }
}
/// Uses the actual shared native pool, never a new/default budget. A lease is
/// accounting only and authenticates neither a peer nor returned chain data.
pub fn reserve_receive_capacity(
    budget: &Arc<WorldResourceBudget>,
    encoded_maximum: usize,
) -> Result<RpcResponseCapacity, String> {
    if !(256..=MAX_TOTAL).contains(&encoded_maximum) {
        return Err("invalid current response native maximum".into());
    }
    let peak = encoded_maximum
        .max(8 * 1024 * 1024)
        .checked_mul(3)
        .and_then(|n| n.checked_add(1024))
        .ok_or("current response capacity overflow")?;
    let lease = budget
        .reserve(peak)
        .map_err(|_| "current response shared memory unavailable")?;
    RpcResponseCapacity::new(encoded_maximum, Box::new(lease))
        .map_err(|_| "invalid current response capacity".into())
}
fn encode(
    context: &CurrentSessionContext,
    id: &[u8; 16],
    total: usize,
    offset: usize,
    chunk: &[u8],
) -> Result<Vec<u8>, String> {
    if total == 0
        || total > MAX_TOTAL
        || chunk.is_empty()
        || chunk.len() > MAX_CHUNK
        || offset.checked_add(chunk.len()).is_none_or(|n| n > total)
    {
        return Err("invalid bounded current response chunk".into());
    }
    c::frame(
        DOMAIN,
        PROFILE,
        Some(context.network),
        Value::Array(vec![
            c::bytes(id),
            c::bytes(&context.genesis),
            c::bytes(&context.activated_profiles),
            Value::Unsigned(total as u64),
            Value::Unsigned(offset as u64),
            c::bytes(chunk),
        ]),
        MAX_FRAME,
    )
    .map_err(|_| "current response frame encoding failed".into())
}
struct Chunk {
    total: usize,
    offset: usize,
    bytes: Vec<u8>,
}
fn array(v: &Value, n: usize) -> Result<&[Value], String> {
    if let Value::Array(v) = v {
        if v.len() == n {
            return Ok(v);
        }
    }
    Err("invalid current response array".into())
}
fn uint(v: &Value) -> Result<usize, String> {
    if let Value::Unsigned(v) = v {
        return usize::try_from(*v).map_err(|_| "current response length overflow".into());
    }
    Err("invalid current response length".into())
}
fn decode(
    context: &CurrentSessionContext,
    id: &[u8; 16],
    frame: &[u8],
    maximum: usize,
) -> Result<Chunk, String> {
    let value =
        Value::decode(frame, MAX_FRAME).map_err(|_| "invalid canonical current response frame")?;
    let v = array(&value, 6)?;
    if v[0] != c::bytes(b"SYNERGY/APQE")
        || v[1] != Value::Unsigned(1)
        || v[2] != c::text(DOMAIN)
        || v[3] != c::profile(PROFILE)
        || v[4] != c::network(context.network)
    {
        return Err("current response profile/network mismatch".into());
    }
    let b = array(&v[5], 6)?;
    if b[0] != c::bytes(id)
        || b[1] != c::bytes(&context.genesis)
        || b[2] != c::bytes(&context.activated_profiles)
    {
        return Err("current response correlation/coordinate mismatch".into());
    }
    let total = uint(&b[3])?;
    let offset = uint(&b[4])?;
    let Value::Bytes(bytes) = &b[5] else {
        return Err("invalid current response chunk bytes".into());
    };
    if total == 0
        || total > maximum
        || total > MAX_TOTAL
        || bytes.is_empty()
        || bytes.len() > MAX_CHUNK
        || offset.checked_add(bytes.len()).is_none_or(|n| n > total)
    {
        return Err("current response declared size exceeds native reservation".into());
    }
    Ok(Chunk {
        total,
        offset,
        bytes: bytes.clone(),
    })
}
/// Exact original response plus its actual allocation lease. Returned content
/// is unverified chain data; the native reader independently verifies proofs.
pub struct CurrentResponse {
    selection: Option<Arc<SelectedCurrentResponseProfile>>,
    id: [u8; 16],
    context: CurrentSessionContext,
    body: Vec<u8>,
    capacity: RpcResponseCapacity,
}
impl CurrentResponse {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn transport_id(&self) -> &[u8; 16] {
        &self.id
    }
    /// Native HTTP owner retains the returned lease through its final write, just
    /// as RpcOutput::into_parts requires. Dropping it early violates that contract.
    pub fn into_parts(self) -> (Vec<u8>, RpcResponseCapacity) {
        (self.body, self.capacity)
    }
    /// Reuses the SAME original bytes/ID/lease across a separately confirmed hop.
    pub fn forward<'a>(
        self,
        mut driver: SessionDriver<'a>,
        deadline: Instant,
    ) -> Result<CurrentResponseSender<'a>, String> {
        let selection = self
            .selection
            .as_ref()
            .ok_or("current response has no native selected profile")?
            .clone();
        let next = driver
            .current_context(Instant::now())
            .map_err(|e| e.to_string())?
            .clone();
        selection.check(&next)?;
        if !same_coordinate(&self.context, &next) {
            return Err("forwarded current response coordinate changed".into());
        }
        CurrentResponseSender::from_reserved(
            self.id,
            self.body,
            self.capacity,
            next,
            driver,
            selection,
            deadline,
        )
    }
}
pub struct CurrentResponseSender<'a> {
    _selection: Arc<SelectedCurrentResponseProfile>,
    driver: SessionDriver<'a>,
    id: [u8; 16],
    context: CurrentSessionContext,
    body: Vec<u8>,
    capacity: Option<RpcResponseCapacity>,
    offset: usize,
    inflight: bool,
    complete: bool,
    deadline: Instant,
}
impl<'a> CurrentResponseSender<'a> {
    pub fn from_rpc_output(
        id: [u8; 16],
        output: RpcOutput,
        selection: Arc<SelectedCurrentResponseProfile>,
        mut driver: SessionDriver<'a>,
        deadline: Instant,
    ) -> Result<Self, String> {
        let context = driver
            .current_context(Instant::now())
            .map_err(|e| e.to_string())?
            .clone();
        selection.check(&context)?;
        let (body, capacity) = output.into_parts();
        Self::from_reserved(
            id,
            body,
            capacity.ok_or("current response requires native output reservation")?,
            context,
            driver,
            selection,
            deadline,
        )
    }
    fn from_reserved(
        id: [u8; 16],
        body: Vec<u8>,
        capacity: RpcResponseCapacity,
        context: CurrentSessionContext,
        driver: SessionDriver<'a>,
        selection: Arc<SelectedCurrentResponseProfile>,
        deadline: Instant,
    ) -> Result<Self, String> {
        // An owning envelope keeps body-before-lease drop order on every
        // rejected constructor path, as well as normal completed delivery.
        let owned = CurrentResponse {
            selection: Some(selection.clone()),
            id,
            context,
            body,
            capacity,
        };
        selection.check(&owned.context)?;
        let max = maximum(&owned.capacity)?;
        if owned.body.is_empty() || owned.body.len() > max || deadline <= Instant::now() {
            return Err("current response output exceeds reservation/deadline".into());
        }
        Ok(Self {
            _selection: selection,
            driver,
            id: owned.id,
            body: owned.body,
            capacity: Some(owned.capacity),
            context: owned.context,
            offset: 0,
            inflight: false,
            complete: false,
            deadline,
        })
    }
    /// At most one record is queued. The source lease survives until the final
    /// queued ciphertext has ACTUALLY flushed (driver.can_queue after poll_io).
    pub fn poll(&mut self) -> Result<bool, String> {
        let result = (|| {
            self.check()?;
            if self.complete {
                return Ok(true);
            }
            if self.driver.poll_io().map_err(|e| e.to_string())?.is_some() {
                return Err("unexpected inbound current response application record".into());
            }
            self.check()?;
            if self.inflight {
                if !self.driver.can_queue() {
                    return Ok(false);
                }
                self.inflight = false;
            }
            if self.offset == self.body.len() {
                self.complete = true;
                return Ok(true);
            }
            if !self.driver.can_queue() {
                return Ok(false);
            }
            let end = self.offset.saturating_add(MAX_CHUNK).min(self.body.len());
            let frame = encode(
                &self.context,
                &self.id,
                self.body.len(),
                self.offset,
                &self.body[self.offset..end],
            )?;
            self.driver
                .queue_application(&frame)
                .map_err(|e| e.to_string())?;
            self.offset = end;
            self.inflight = true;
            Ok(false)
        })();
        if result.is_err() {
            self.driver.retire();
            self.retire()
        }
        result
    }
    fn check(&mut self) -> Result<(), String> {
        if self.capacity.is_none() || Instant::now() >= self.deadline {
            return Err("current response sender expired/retired".into());
        }
        if self
            .driver
            .current_context(Instant::now())
            .map_err(|e| e.to_string())?
            != &self.context
        {
            return Err("current response session binding changed".into());
        }
        Ok(())
    }
    pub fn retire(&mut self) {
        self.driver.retire();
        self.body = Vec::new();
        self.capacity = None;
        self.complete = false;
        self.inflight = false;
    }
}
struct ResponseAssembly {
    id: [u8; 16],
    context: CurrentSessionContext,
    total: Option<usize>,
    body: Vec<u8>,
    capacity: Option<RpcResponseCapacity>,
    done: bool,
    deadline: Instant,
}
impl ResponseAssembly {
    fn from_reserved(
        id: [u8; 16],
        capacity: RpcResponseCapacity,
        context: CurrentSessionContext,
        deadline: Instant,
    ) -> Result<Self, String> {
        scope(&context)?;
        maximum(&capacity)?;
        if deadline <= Instant::now() {
            return Err("current response deadline expired".into());
        }
        Ok(Self {
            id,
            context,
            capacity: Some(capacity),
            total: None,
            body: Vec::new(),
            done: false,
            deadline,
        })
    }
    pub fn poll(
        &mut self,
        driver: &mut SessionDriver<'_>,
    ) -> Result<Option<CurrentResponse>, String> {
        let result = (|| {
            self.check(driver)?;
            let Some(plain) = driver.poll_io().map_err(|e| e.to_string())? else {
                return Ok(None);
            };
            self.check(driver)?;
            self.accept(plain.as_bytes())
        })();
        if result.is_err() {
            driver.retire();
            self.retire()
        }
        result
    }
    fn check(&self, driver: &mut SessionDriver<'_>) -> Result<(), String> {
        if self.done || self.capacity.is_none() || Instant::now() >= self.deadline {
            return Err("current response receiver expired/retired".into());
        }
        if driver
            .current_context(Instant::now())
            .map_err(|e| e.to_string())?
            != &self.context
        {
            return Err("current response session binding changed".into());
        }
        Ok(())
    }
    fn accept(&mut self, frame: &[u8]) -> Result<Option<CurrentResponse>, String> {
        let result = self.accept_inner(frame);
        if result.is_err() {
            self.retire();
        }
        result
    }
    fn accept_inner(&mut self, frame: &[u8]) -> Result<Option<CurrentResponse>, String> {
        if self.done || Instant::now() >= self.deadline {
            return Err("current response receiver already consumed/expired".into());
        }
        let cap = self
            .capacity
            .as_ref()
            .ok_or("current response receiver retired")?;
        let chunk = decode(&self.context, &self.id, frame, maximum(cap)?)?;
        if chunk.offset != self.body.len() || self.total.is_some_and(|n| n != chunk.total) {
            return Err("current response gaps/replay/changed total rejected".into());
        }
        if self.total.is_none() {
            self.body
                .try_reserve_exact(chunk.total)
                .map_err(|_| "current response reserved allocation failed")?;
            self.total = Some(chunk.total)
        }
        self.body.extend_from_slice(&chunk.bytes);
        if self.body.len() != chunk.total {
            return Ok(None);
        }
        self.done = true;
        Ok(Some(CurrentResponse {
            selection: None,
            id: self.id,
            context: self.context.clone(),
            body: std::mem::take(&mut self.body),
            capacity: self
                .capacity
                .take()
                .ok_or("missing current response lease")?,
        }))
    }
    pub fn retire(&mut self) {
        self.body = Vec::new();
        self.capacity = None;
        self.done = true;
    }
}

/// The exact confirmed transport is owned for the WHOLE exchange. Equal
/// CurrentSessionContexts do not make two different cryptographic sessions
/// interchangeable; no caller can replace this private driver between chunks.
pub struct CurrentResponseReceiver<'a> {
    selection: Arc<SelectedCurrentResponseProfile>,
    driver: SessionDriver<'a>,
    assembly: ResponseAssembly,
}
impl<'a> CurrentResponseReceiver<'a> {
    pub fn new(
        id: [u8; 16],
        capacity: RpcResponseCapacity,
        selection: Arc<SelectedCurrentResponseProfile>,
        mut driver: SessionDriver<'a>,
        deadline: Instant,
    ) -> Result<Self, String> {
        let result = (|| {
            let context = driver
                .current_context(Instant::now())
                .map_err(|e| e.to_string())?
                .clone();
            selection.check(&context)?;
            ResponseAssembly::from_reserved(id, capacity, context, deadline)
        })();
        match result {
            Ok(assembly) => Ok(Self {
                selection,
                driver,
                assembly,
            }),
            Err(e) => {
                driver.retire();
                Err(e)
            }
        }
    }
    pub fn poll(&mut self) -> Result<Option<CurrentResponse>, String> {
        let mut result = self.assembly.poll(&mut self.driver);
        if let Ok(Some(response)) = &mut result {
            response.selection = Some(self.selection.clone());
            self.driver.retire();
        }
        result
    }
    pub fn retire(&mut self) {
        self.driver.retire();
        self.assembly.retire();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> CurrentSessionContext {
        use synergy_address::r1_public::NativeIdentityPresentation;
        use synergy_address_engine::apqe::{current_session::*, r1_framing::NetworkRef};
        CurrentSessionContext {
            network: NetworkRef {
                chain_id: u64::MAX - 1,
                nic: [0x11; 64],
            },
            genesis: [0x22; 48],
            activated_profiles: [0x33; 64],
            registry_epoch: 1,
            registry_commitment: [0x44; 64],
            hop: SessionHop::GatewayToSentry,
            purpose: SessionPurpose::PublicRpc,
            initiator: SessionEndpoint {
                role: TransportRole::Gateway,
                node: NativeIdentityPresentation::from_raw("synv5", [0x55; 48])
                    .unwrap()
                    .to_text(),
                transport_key_id: "PUBLIC-SYNTHETIC-GATEWAY".into(),
                key_generation: 1,
            },
            responder: SessionEndpoint {
                role: TransportRole::Sentry,
                node: NativeIdentityPresentation::from_raw("synv1", [0x66; 48])
                    .unwrap()
                    .to_text(),
                transport_key_id: "PUBLIC-SYNTHETIC-SENTRY".into(),
                key_generation: 1,
            },
        }
    }
    fn receiver(budget: &Arc<WorldResourceBudget>, maximum: usize) -> ResponseAssembly {
        ResponseAssembly::from_reserved(
            [7; 16],
            reserve_receive_capacity(budget, maximum).unwrap(),
            context(),
            Instant::now() + std::time::Duration::from_secs(3),
        )
        .unwrap()
    }
    #[test]
    fn multi_record_body_and_original_id_are_exact_and_lease_survives_completion() {
        let budget = WorldResourceBudget::new(64 * 1024 * 1024);
        let mut receiver = receiver(&budget, 4_000_000);
        let original = (0..2_500_003).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let mut completed = None;
        for (offset, chunk) in original.chunks(MAX_CHUNK).enumerate() {
            let frame = encode(
                &context(),
                &[7; 16],
                original.len(),
                offset * MAX_CHUNK,
                chunk,
            )
            .unwrap();
            assert!(frame.len() <= MAX_FRAME);
            completed = receiver.accept(&frame).unwrap();
            assert!(budget.used() > 0);
        }
        let response = completed.unwrap();
        assert_eq!(response.transport_id(), &[7; 16]);
        assert_eq!(response.body(), original);
        assert!(receiver.done);
        assert!(receiver.capacity.is_none());
        assert!(budget.used() > 0);
        let (bytes, lease) = response.into_parts();
        assert_eq!(bytes, original);
        drop(bytes);
        assert!(budget.used() > 0);
        drop(lease);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn gaps_replay_changed_total_and_transport_mix_retire_before_delivery() {
        for variant in 0..4 {
            let budget = WorldResourceBudget::new(32 * 1024 * 1024);
            let mut r = receiver(&budget, 4096);
            let first = encode(&context(), &[7; 16], 6, 0, b"abc").unwrap();
            assert!(r.accept(&first).unwrap().is_none());
            let bad = match variant {
                0 => encode(&context(), &[7; 16], 6, 4, b"de").unwrap(),
                1 => first,
                2 => encode(&context(), &[7; 16], 7, 3, b"def").unwrap(),
                _ => encode(&context(), &[8; 16], 6, 3, b"def").unwrap(),
            };
            assert!(r.accept(&bad).is_err());
            assert!(r.done && r.body.is_empty() && r.capacity.is_none());
            assert_eq!(budget.used(), 0);
            assert!(r
                .accept(&encode(&context(), &[7; 16], 6, 3, b"def").unwrap())
                .is_err());
        }
    }
    #[test]
    fn exact_full_network_genesis_profiles_and_carrier_profile_are_required() {
        for variant in 0..5 {
            let budget = WorldResourceBudget::new(32 * 1024 * 1024);
            let mut r = receiver(&budget, 4096);
            let mut c = context();
            match variant {
                0 => c.network.nic[0] ^= 1,
                1 => c.network.chain_id = u64::MAX,
                2 => c.genesis[0] ^= 1,
                3 => c.activated_profiles[0] ^= 1,
                _ => {}
            }
            let mut frame = encode(&c, &[7; 16], 3, 0, b"abc").unwrap();
            if variant == 4 {
                let Value::Array(mut fields) = Value::decode(&frame, MAX_FRAME).unwrap() else {
                    panic!("frame")
                };
                fields[3] = c::profile(ProfileRef {
                    name: "UNSELECTED-RESPONSE-PROFILE",
                    revision: 1,
                });
                frame = Value::Array(fields).encode(MAX_FRAME).unwrap();
            }
            assert!(r.accept(&frame).is_err());
            assert_eq!(budget.used(), 0);
        }
    }
    #[test]
    fn declared_native_maximum_is_checked_before_large_allocation_and_lease_released() {
        let budget = WorldResourceBudget::new(32 * 1024 * 1024);
        let mut r = receiver(&budget, 4096);
        assert!(r
            .accept(&encode(&context(), &[7; 16], 4097, 0, b"x").unwrap())
            .is_err());
        assert!(r.body.is_empty());
        assert_eq!(budget.used(), 0);
        assert!(encode(&context(), &[7; 16], MAX_TOTAL + 1, 0, b"x").is_err());
        assert!(encode(&context(), &[7; 16], 1, 0, b"").is_err());
        assert!(reserve_receive_capacity(&budget, MAX_TOTAL + 1).is_err());
    }
    #[test]
    fn actual_shared_pool_exhaustion_and_response_drop_hold_real_accounting() {
        let budget = WorldResourceBudget::new(50 * 1024 * 1024);
        let lease = reserve_receive_capacity(&budget, 16 * 1024 * 1024).unwrap();
        assert_eq!(budget.used(), 48 * 1024 * 1024 + 1024);
        assert!(reserve_receive_capacity(&budget, 256).is_err());
        let response = CurrentResponse {
            selection: None,
            id: [7; 16],
            body: b"test-only response".to_vec(),
            capacity: lease,
            context: context(),
        };
        assert!(budget.used() > 0);
        drop(response);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn peer_relay_and_expired_data_constructor_never_create_current_response_stream() {
        let budget = WorldResourceBudget::new(32 * 1024 * 1024);
        let mut c = context();
        c.purpose = SessionPurpose::PeerRelay;
        assert!(ResponseAssembly::from_reserved(
            [7; 16],
            reserve_receive_capacity(&budget, 4096).unwrap(),
            c,
            Instant::now() + std::time::Duration::from_secs(3)
        )
        .is_err());
        assert_eq!(budget.used(), 0);
        assert!(ResponseAssembly::from_reserved(
            [7; 16],
            reserve_receive_capacity(&budget, 4096).unwrap(),
            context(),
            Instant::now()
        )
        .is_err());
        assert_eq!(budget.used(), 0);
    }
}
