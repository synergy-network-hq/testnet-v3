//! Authenticated, isolated-canary transport artifacts and independent worker custody.
//! A registry signature grants routing/key binding only; governed PoSy authority
//! remains the membership owner. No received message chooses a trust anchor.
use super::{
    authority,
    network_secure::{SecureConnectionMaterial, SecureTransportFactory},
};
use std::{
    collections::{BTreeMap,BTreeSet},
    fs,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc,Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use synergy_address_engine::{
    apqe::{
        engineering_transport::{
            load_transport_worker, CurrentTransportTrust, SessionContext, SessionError,
        },
        fixed_digest,
        provider::{variants::Mldsa65, PublicKey, SignOptions},
        FixedDigest, HashAlgorithm, Primitives,
    },
    encrypt::EncryptedEnvelope,
    types::Algorithm,
    validator_provisioning::{EnrollmentRequest, NetworkBinding},
};
use synergy_config::NodeConfiguration;
use synergy_protocol_types::NodeAddress;

pub(super) use super::apqe_registry_wire::{
    signing_bytes, RegistryPayload, SignedRegistry, TransportEntry, REGISTRY_CONTEXT,
};
pub(super) fn sha256(bytes: &[u8]) -> String {
    hex_bytes(&fixed_digest(&Primitives, FixedDigest::Sha256, bytes))
}
fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
pub(super) fn clock() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| "clock before Unix epoch".into())
}
pub(super) fn ascii(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|v| (0x21..=0x7e).contains(&v))
}
pub(super) fn read(path: &Path, max: u64, private: bool) -> Result<Vec<u8>, String> {
    if !path.is_absolute() {
        return Err("canary input must be absolute".into());
    }
    let before = Stamp::capture(path)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|e| format!("open canary input: {e}"))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max {
        return Err("canary input must be a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if private
            && (metadata.permissions().mode() & 0o077 != 0
                || metadata.uid() != unsafe { libc::geteuid() })
        {
            return Err("canary secret input is accessible to another user".into());
        }
        if before.identity
            != (
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        {
            return Err("canary input replaced during open".into());
        }
    }
    let mut out = Vec::new();
    let result = file.take(max + 1).read_to_end(&mut out);
    if result.is_err() || out.is_empty() || out.len() as u64 > max || !before.unchanged() {
        if private {
            drop(synergy_address_engine::apqe::SecretBytes::from_bytes(out));
        }
        return Err("canary input read failed or changed during read".into());
    }
    Ok(out)
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Stamp {
    path: PathBuf,
    len: u64,
    modified: SystemTime,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
}
impl Stamp {
    pub(super) fn capture(path: &Path) -> Result<Self, String> {
        let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !m.is_file() || m.file_type().is_symlink() {
            return Err("canary trust artifact is no longer a regular file".into());
        }
        Ok(Self {
            path: path.into(),
            len: m.len(),
            modified: m.modified().map_err(|e| e.to_string())?,
            #[cfg(unix)]
            identity: {
                use std::os::unix::fs::MetadataExt;
                (m.dev(), m.ino(), m.ctime(), m.ctime_nsec())
            },
        })
    }
    pub(super) fn unchanged(&self) -> bool {
        Self::capture(&self.path).is_ok_and(|now| now == *self)
    }
}
pub(super) struct Snapshot {
    earned:BTreeMap<String,synergy_governance::FinalizedValidatorAdmissionRecord>,
    shadow:BTreeSet<String>,
    pub(super) payload: RegistryPayload,
    pub(super) registry_bytes: Vec<u8>,
    pub(super) genesis_bytes: Vec<u8>,
    pub(super) network: NetworkBinding,
    pub(super) entries: Vec<TransportEntry>,
    pub(super) stamps: Vec<Stamp>,
}
impl Clone for Snapshot {fn clone(&self)->Self{Self{earned:self.earned.clone(),shadow:self.shadow.clone(),payload:self.payload.clone(),registry_bytes:self.registry_bytes.clone(),genesis_bytes:self.genesis_bytes.clone(),network:NetworkBinding{chain_id_hex:self.network.chain_id_hex.clone(),genesis_sha256:self.network.genesis_sha256.clone()},entries:self.entries.clone(),stamps:self.stamps.clone()}}}
impl Snapshot {
    pub(super) fn load(config:&NodeConfiguration,anchors:&[String;2])->Result<Self,String>{
        let snapshot=Self::load_origin(config,anchors)?;
        let local:synergy_identity::PublicNodeIdentity=serde_json::from_slice(&read(&config.public_identity_path,65536,false)?).map_err(|_|"invalid installed public identity")?;
        if snapshot.entry(local.validate().map_err(|e|format!("{e:?}"))?.node_address.as_str()).is_ok(){return Ok(snapshot);}
        match authority::load(config)?{Some(current)=>snapshot.with_current(&current),None=>Ok(snapshot)}
    }
    pub(super) fn load_origin(config: &NodeConfiguration, anchors: &[String; 2]) -> Result<Self, String> {
        config.validate().map_err(|e| e.to_string())?;
        let selected = config
            .apqe_transport
            .as_ref()
            .ok_or("no explicit APQE canary transport")?;
        let authority_path = config
            .consensus
            .authority_binding
            .as_deref()
            .ok_or("missing PoSy authority")?;
        let genesis_path = config
            .genesis_path
            .as_deref()
            .ok_or("missing signed Genesis")?;
        let root_path = config
            .consensus
            .authority_trust_key_path
            .as_deref()
            .ok_or("missing Genesis root")?;
        let paths = [
            selected.registry_path.as_path(),
            selected.registry_trust_key_path.as_path(),
            authority_path,
            genesis_path,
            root_path,
            config.manifest_path.as_path(),
        ];
        let mut before: Vec<_> = paths
            .iter()
            .map(|p| Stamp::capture(p))
            .collect::<Result<_, _>>()?;
        let trust_key = read(&selected.registry_trust_key_path, 8192, false)?;
        let genesis_trust_key = read(root_path, 8192, false)?;
        if trust_key.len() != 2592
            || sha256(&trust_key) != anchors[0]
            || sha256(&genesis_trust_key) != anchors[1]
        {
            return Err("canary pinned trust root changed or is not ML-DSA-87".into());
        }
        let (genesis_hash, network) =
            crate::commands::selected_network::verify_with_custody_binding(config)?;
        let genesis_bytes = read(genesis_path, 16 * 1024 * 1024, false)?;
        let current = authority::load_signed(config)?
            .ok_or("canary requires authenticated PoSy membership")?;
        // Successor membership requires the canonical durable finalized transition
        // witness. A freshly root-signed epoch alone cannot activate membership.
        if let Some(witness) = authority::transition_witness_path(config, &current)? {
            before.push(Stamp::capture(&witness)?);
            let bytes = read(&witness, 4 * 1024 * 1024, false)?;
            authority::verify_stored_transition(config, &current, &bytes)?;
        }
        let registry_bytes = read(&selected.registry_path, 1024 * 1024, false)?;
        let signed: SignedRegistry = serde_json::from_slice(&registry_bytes)
            .map_err(|e| format!("decode APQE transport registry: {e}"))?;
        let engine = super::apqe_provider::load(config)?;
        let ok = engine
            .try_lock()
            .map_err(|_| "canary provider is unavailable")?
            .verify(
                Algorithm::MlDsa87,
                &trust_key,
                &signing_bytes(&signed.payload)?,
                &signed.signature,
                SignOptions::Pure {
                    context: REGISTRY_CONTEXT,
                },
            )
            .map_err(|e| e.to_string())?;
        if !ok {
            return Err("invalid ML-DSA-87 transport registry signature".into());
        }
        let payload = signed.payload;
        let now = clock()?;
        if payload.schema_version != 1
            || payload.scope != "isolated-development-canary"
            || payload.chain_id != config.chain_id
            || payload.network_id != config.network_id
            || payload.protocol != "posy/3.0"
            || payload.genesis_hash != genesis_hash
            || payload.genesis_artifact_sha256 != network.genesis_sha256
            || payload.authority_binding_sha256 != sha256(current.binding_bytes())
            || payload.epoch != current.epoch.epoch
            || payload.generation == 0
            || payload.valid_from_unix > now
            || payload.expires_at_unix <= now
            || payload.expires_at_unix <= payload.valid_from_unix
        {
            return Err(
                "APQE transport registry differs from authenticated current canary state".into(),
            );
        }
        if payload.validators.len() != current.registry.active_count() {
            return Err(
                "transport registry must cover exactly the current active validator set".into(),
            );
        }
        let mut ids = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        let mut key_ids = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        let consensus: Vec<_> = current
            .registry
            .active()
            .map(|v| {
                current
                    .consensus_binding(&v.validator_id)
                    .map(|(id, key)| (id.to_owned(), key.to_vec()))
            })
            .collect::<Result<_, _>>()?;
        for entry in &payload.validators {
            NodeAddress::parse(entry.node_address.clone())
                .map_err(|e| format!("invalid transport node: {e}"))?;
            current
                .registry
                .active_validator(&entry.node_address)
                .map_err(|e| e.to_string())?;
            if entry.dial_address.port() == 0
                || entry.dial_address.ip().is_unspecified()
                || entry.dial_address.ip().is_multicast()
                || !endpoints.insert(entry.dial_address)
                || !ascii(&entry.transport_key_id, 128)
                || entry.transport_key_version == 0
                || entry.transport_public_key.len() != 1952
                || entry.transport_public_key == genesis_trust_key
                || entry.enrollment_sha256.len() != 64
                || !entry
                    .enrollment_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || !ids.insert(&entry.node_address)
                || !key_ids.insert(&entry.transport_key_id)
                || !public_keys.insert(&entry.transport_public_key)
                || consensus.iter().any(|(id, key)| {
                    id == &entry.transport_key_id || key == &entry.transport_public_key
                })
            {
                return Err("duplicate, cross-role or malformed transport credential".into());
            }
        }
        if !before.iter().all(Stamp::unchanged) {
            return Err("canary trust artifacts changed during verification".into());
        }
        let snapshot=Self {
            earned:BTreeMap::new(),shadow:BTreeSet::new(),
            entries: payload.validators.clone(),
            payload,
            registry_bytes,
            genesis_bytes,
            network,
            stamps: before,
        };
        Ok(snapshot)
    }
    fn with_current(mut self,authority:&authority::VerifiedAuthority)->Result<Self,String>{
        self.entries=self.payload.validators.clone();self.earned.clear();self.shadow.clear();
        if authority.epoch.chain_id!=self.payload.chain_id||authority.epoch.network_id!=self.payload.network_id
            ||authority.authenticated_genesis_hash()?!=self.payload.genesis_hash{return Err("transport authority changed network".into());}
        let current_root=authority.epoch.root().map_err(|e|e.to_string())?;
        for record in authority.earned_transport_records()? {
            let active=authority.registry.active_validator(&record.validator_id).is_ok();
            let shadow=record.frozen_epoch_context_root==current_root&&record.effective_epoch==authority.epoch.epoch.checked_add(1).ok_or("transport epoch overflow")?;
            if !active&&!shadow{continue;}
            if self.entries.iter().any(|e|e.node_address==record.validator_id){return Err("earned transport identity collides with signed origin".into());}
            let entry=TransportEntry{node_address:record.validator_id.clone(),dial_address:record.dial_address.parse().map_err(|_|"invalid earned endpoint")?,
                transport_key_id:record.transport_key_id.clone(),transport_key_version:1,transport_public_key:record.transport_public_key.clone(),enrollment_sha256:record.enrollment_sha256.clone(),revoked:false};
            if shadow {self.shadow.insert(record.validator_id.clone());}
            self.earned.insert(record.validator_id.clone(),record);self.entries.push(entry);
        }
        self.entries.retain(|e|authority.registry.active_validator(&e.node_address).is_ok()||self.shadow.contains(&e.node_address));
        Ok(self)
    }
    pub(super) fn entry(&self, id: &str) -> Result<&TransportEntry, String> {
        self.entries
            .iter()
            .find(|e| e.node_address == id && !e.revoked)
            .ok_or_else(|| "unknown or revoked current validator transport key".into())
    }
    pub(super) fn context(&self, i: &str, r: &str) -> Result<SessionContext, String> {
        let i = self.entry(i)?;
        let r = self.entry(r)?;
        let mut chain_id = [0; 32];
        chain_id[24..].copy_from_slice(&self.payload.chain_id.to_be_bytes());
        let supplemental=[i,r].into_iter().filter_map(|e|self.earned.get(&e.node_address)).collect::<Vec<_>>();
        let (format,registry)=if supplemental.is_empty(){("synergy-canary-transport-registry-v1-json",self.registry_bytes.clone())}
            else{let mut supplemental=supplemental;supplemental.sort_by(|a,b|a.validator_id.cmp(&b.validator_id));
                ("synergy-native-membership-peer-pair-v1-json",serde_json::to_vec(&(sha256(&self.registry_bytes),supplemental)).map_err(|e|e.to_string())?)};
        Ok(SessionContext {
            chain_id,
            genesis_commitment: artifact_commitment(
                b"SYNERGY/VSESSION/GENESIS/v1",
                "synergy-signed-genesis-v2-json",
                &self.genesis_bytes,
            )?,
            protocol: self.payload.protocol.clone(),
            registry_epoch: self.payload.epoch,
            registry_commitment: artifact_commitment(
                b"SYNERGY/VSESSION/REGISTRY/v1",
                format,
                &registry,
            )?,
            initiator_node: i.node_address.clone(),
            responder_node: r.node_address.clone(),
            initiator_transport_key_id: i.transport_key_id.clone(),
            initiator_key_version: i.transport_key_version,
            responder_transport_key_id: r.transport_key_id.clone(),
            responder_key_version: r.transport_key_version,
            network_id: self.payload.network_id.clone(),
            genesis_format: "synergy-signed-genesis-v2-json".into(),
            registry_format: format.into(),
        })
    }
}
fn cbor_head(out: &mut Vec<u8>, major: u8, n: usize) {
    let prefix = major << 5;
    match n {
        0..=23 => out.push(prefix | n as u8),
        24..=255 => out.extend_from_slice(&[prefix | 24, n as u8]),
        256..=65535 => {
            out.push(prefix | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        _ => {
            out.push(prefix | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
}
pub(super) fn artifact_commitment(
    domain: &[u8],
    format: &str,
    bytes: &[u8],
) -> Result<[u8; 64], String> {
    let mut preimage = vec![0x82];
    cbor_head(&mut preimage, 3, format.len());
    preimage.extend_from_slice(format.as_bytes());
    cbor_head(&mut preimage, 2, bytes.len());
    preimage.extend_from_slice(bytes);
    let mut hash = Primitives
        .hash_stream(HashAlgorithm::Sha3512)
        .map_err(|e| e.to_string())?;
    hash.update(domain);
    hash.update(&preimage);
    hash.finalize()
        .try_into()
        .map_err(|_| "incorrect transport commitment length".into())
}
struct CurrentTrust {
    ingress:Option<super::ingress::AuthenticatedIngress>,
    context: SessionContext,
    i: Vec<u8>,
    r: Vec<u8>,
    stamps: Vec<Stamp>,
    expires: u64,
}
impl CurrentTransportTrust for CurrentTrust {
    fn check(
        &self,
        context: &SessionContext,
        i: &PublicKey<Mldsa65>,
        r: &PublicKey<Mldsa65>,
    ) -> Result<(), SessionError> {
        let roles_current=self.ingress.as_ref().is_none_or(|ingress|ingress.transport_authority().is_ok_and(|authority|authority.is_some_and(|authority|{
            let records=authority.earned_transport_records().unwrap_or_default();
            let root=authority.epoch.root().ok();
            [&context.initiator_node,&context.responder_node].into_iter().all(|id|authority.registry.active_validator(id).is_ok()
                ||records.iter().any(|r|&r.validator_id==id&&Some(&r.frozen_epoch_context_root)==root.as_ref()&&r.effective_epoch==authority.epoch.epoch.saturating_add(1)))
        })));
        if roles_current && context == &self.context
            && Primitives.constant_time_equal(i.as_bytes(), &self.i)
            && Primitives.constant_time_equal(r.as_bytes(), &self.r)
            && clock().is_ok_and(|now| now < self.expires)
            && self.stamps.iter().all(Stamp::unchanged)
        {
            Ok(())
        } else {
            Err(SessionError::Rejected)
        }
    }
}
struct Factory {
    config: NodeConfiguration,
    local: NodeAddress,
    anchors: [String; 2],
    routing: Option<Snapshot>,
    ingress:Option<super::ingress::AuthenticatedIngress>,
    endpoint_verified:Mutex<BTreeSet<String>>,
}
impl Factory {
    fn snapshot(&self) -> Result<Snapshot, String> {
        let snapshot=if let Some(snapshot)=&self.routing{
            if !snapshot.stamps.iter().all(Stamp::unchanged)||clock()? >= snapshot.payload.expires_at_unix{return Err("authenticated transport artifacts changed or expired".into());}
            snapshot.clone()
        }else{Snapshot::load(&self.config,&self.anchors)?};
        self.current(snapshot)
    }
    fn current(&self,snapshot:Snapshot)->Result<Snapshot,String>{
        let Some(authority)=self.ingress.as_ref().map(|i|i.transport_authority()).transpose()?.flatten() else{return Ok(snapshot);};
        let mut snapshot=snapshot.with_current(&authority)?;
        for endpoint in super::transport_endpoint::load(&self.config)?.into_values(){
            if authority.registry.active_validator(&endpoint.validator_id).is_err(){continue;}
            let digest=sha256(&super::transport_endpoint::encode(&endpoint)?);
            let mut cache=self.endpoint_verified.lock().map_err(|_|"endpoint signature cache poisoned")?;
            if !cache.contains(&digest){endpoint.verify(&authority)?;if cache.len()>=self.config.p2p.max_authenticated_peers{cache.pop_first();}cache.insert(digest);}
            if let Some(entry)=snapshot.entries.iter_mut().find(|e|e.node_address==endpoint.validator_id){entry.dial_address=endpoint.dial_address;}
        }
        Ok(snapshot)
    }
}
impl SecureTransportFactory for Factory {
    fn local_node_address(&self) -> &NodeAddress {
        &self.local
    }
    fn contains_peer(&self, id: &str) -> bool {
        id != self.local.as_str()
            && self.routing.as_ref().and_then(|s|self.current(s.clone()).ok()).is_some_and(|snapshot| {
                clock().is_ok_and(|now| now < snapshot.payload.expires_at_unix)
                    && snapshot.stamps.iter().all(Stamp::unchanged)
                    && snapshot.entry(id).is_ok()
            })
    }
    fn dial_peers(&self) -> Result<Vec<(NodeAddress, SocketAddr)>, String> {
        let snapshot = self.current(self.routing.as_ref().ok_or("missing authenticated routing")?.clone())?;
        if clock()? >= snapshot.payload.expires_at_unix
            || !snapshot.stamps.iter().all(Stamp::unchanged)
        {
            return Err("authenticated routing changed or expired; reinitialize transport".into());
        }
        snapshot
            .entries
            .iter()
            .filter(|entry| !entry.revoked && entry.node_address != self.local.as_str())
            .map(|entry| {
                Ok((
                    NodeAddress::parse(entry.node_address.clone()).map_err(|e| e.to_string())?,
                    entry.dial_address,
                ))
            })
            .collect()
    }
    fn endpoint_announcements(&self)->Result<Vec<Vec<u8>>,String>{
        // Each owner announces its own latest record at authentication. Peers
        // learn exact dial hints without a separate discovery authority.
        super::transport_endpoint::load(&self.config)?.get(self.local.as_str()).map(super::transport_endpoint::encode).transpose().map(|v|v.into_iter().collect())
    }
    fn receive_endpoint(&self,bytes:&[u8])->Result<bool,String>{
        let Some(record)=super::transport_endpoint::decode(bytes)? else{return Ok(false);};
        let authority=self.ingress.as_ref().ok_or("native endpoint requires runtime finality")?.transport_authority()?.ok_or("native endpoint requires authenticated authority")?;
        super::transport_endpoint::accept(&self.config,&authority,record)?;Ok(true)
    }
    fn allow_reverse_dial(&self)->bool{super::transport_endpoint::load(&self.config).is_ok_and(|m|m.contains_key(self.local.as_str()))}
    fn peer_is_shadow(&self,id:&str)->bool{self.routing.as_ref().and_then(|s|self.current(s.clone()).ok()).is_some_and(|s|s.shadow.contains(id))}
    fn material(&self, peer_id: &str, inbound: bool) -> Result<SecureConnectionMaterial, String> {
        let snapshot = self.snapshot()?;
        let local = snapshot.entry(self.local.as_str())?;
        let peer = snapshot.entry(peer_id)?;
        let selected = self
            .config
            .apqe_transport
            .as_ref()
            .ok_or("APQE transport not configured")?;
        let request_bytes = read(&selected.enrollment_path, 128 * 1024, false)?;
        if sha256(&request_bytes) != local.enrollment_sha256 {
            return Err("local enrollment differs from authenticated transport registry".into());
        }
        let request: EnrollmentRequest = serde_json::from_slice(&request_bytes)
            .map_err(|_| "invalid APQE validator enrollment")?;
        if request.payload.identity.address != self.local.as_str() {
            return Err("custody identity differs from local admitted validator".into());
        }
        let envelope: EncryptedEnvelope =
            serde_json::from_slice(&read(&selected.custody_path, 256 * 1024, true)?)
                .map_err(|_| "invalid encrypted transport custody")?;
        let pass = synergy_address_engine::apqe::SecretBytes::from_bytes(read(
            &selected.custody_unlock_path,
            4096,
            true,
        )?);
        let pass =
            std::str::from_utf8(pass.as_bytes()).map_err(|_| "custody unlock input is not UTF8")?;
        let provider = self
            .config
            .aegis_provider
            .as_ref()
            .ok_or("missing authenticated APQE provider")?;
        let report_digest = decode_digest(&provider.authenticated_report_sha256)?;
        // Operator configuration pins native code out of band. Registry and
        // membership verification above never authorize a different native library.
        let worker = unsafe {
            load_transport_worker(
                &provider.report_path,
                report_digest,
                &request,
                &snapshot.network,
                &envelope,
                pass,
                &local.transport_public_key,
            )
        }?;
        let (i, r) = if inbound {
            (peer, local)
        } else {
            (local, peer)
        };
        let context = snapshot.context(&i.node_address, &r.node_address)?;
        let peer_public = PublicKey::from_bytes(&peer.transport_public_key)
            .map_err(|e| format!("peer key rejected: {e:?}"))?;
        let trust = Arc::new(CurrentTrust {
            ingress:self.ingress.clone(),
            context: context.clone(),
            i: i.transport_public_key.clone(),
            r: r.transport_public_key.clone(),
            stamps: snapshot.stamps,
            expires: snapshot.payload.expires_at_unix,
        });
        Ok(SecureConnectionMaterial {
            worker,
            context,
            peer_public,
            trust,
        })
    }
}
pub(super) fn decode_digest(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 {
        return Err("invalid digest length".into());
    }
    let mut digest = [0; 32];
    for (i, part) in text.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(part).map_err(|_| "invalid digest")?;
        digest[i] = u8::from_str_radix(s, 16).map_err(|_| "invalid digest")?;
    }
    Ok(digest)
}
pub(super) fn factory(
    config: &NodeConfiguration,
) -> Result<Option<Arc<dyn SecureTransportFactory>>, String> {
    build_factory(config, true, None)
}
pub(super) fn factory_with_ingress(config:&NodeConfiguration,ingress:super::ingress::AuthenticatedIngress)->Result<Option<Arc<dyn SecureTransportFactory>>,String>{build_factory(config,true,Some(ingress))}
pub(crate) fn verify_runtime(config: &NodeConfiguration) -> Result<(), String> {
    factory(config)?.ok_or("missing explicit APQE transport")?;
    Ok(())
}
pub(crate) fn preflight(config: &NodeConfiguration) -> Result<(), String> {
    build_factory(config, false,None)?.ok_or("missing explicit APQE transport")?;
    Ok(())
}
fn build_factory(
    config: &NodeConfiguration,
    unlock: bool,
    ingress:Option<super::ingress::AuthenticatedIngress>,
) -> Result<Option<Arc<dyn SecureTransportFactory>>, String> {
    let Some(selected) = &config.apqe_transport else {
        return Ok(None);
    };
    let request_bytes = read(&selected.enrollment_path, 128 * 1024, false)?;
    let request: EnrollmentRequest =
        serde_json::from_slice(&request_bytes).map_err(|_| "invalid APQE enrollment")?;
    let local = NodeAddress::parse(request.payload.identity.address.clone())
        .map_err(|e| format!("invalid local APQE identity: {e}"))?;
    let mut value = Factory {
        config: config.clone(),
        local,
        routing: None,ingress,endpoint_verified:Mutex::new(BTreeSet::new()),
        anchors: [
            selected.registry_trust_key_sha256.clone(),
            selected.genesis_trust_key_sha256.clone(),
        ],
    };
    let snapshot = value.snapshot()?;
    if request.payload.network.chain_id_hex != snapshot.network.chain_id_hex
        || request.payload.network.genesis_sha256 != snapshot.network.genesis_sha256
    {
        return Err("APQE custody belongs to a different incarnation".into());
    }
    let public: synergy_identity::PublicNodeIdentity =
        serde_json::from_slice(&read(&config.public_identity_path, 65536, false)?)
            .map_err(|_| "invalid local public node identity")?;
    let public = public
        .validate()
        .map_err(|e| format!("local public node identity invalid: {e:?}"))?;
    if public.node_address != value.local {
        return Err("local public identity and APQE enrollment disagree".into());
    }
    let local = snapshot.entry(value.local.as_str())?;
    if sha256(&request_bytes) != local.enrollment_sha256 {
        return Err("local enrollment differs from authenticated transport registry".into());
    }
    // Unlock/preflight once before any service or listener is started. Each
    // accepted connection subsequently owns a fresh independent worker context.
    let engine = super::apqe_provider::load(config)?;
    let guard = engine
        .try_lock()
        .map_err(|_| "preflight provider unavailable")?;
    synergy_address_engine::validator_provisioning::verify_enrollment(
        &guard,
        &request,
        &snapshot.network,
    )?;
    if local.transport_public_key
        != decode_public(&request.payload.identity.node_identity_key.public_key)?
    {
        return Err("registry binds a different transport role key".into());
    }
    drop(guard);
    let other = snapshot
        .entries
        .iter()
        .find(|entry| entry.node_address != value.local.as_str() && !entry.revoked)
        .ok_or("canary requires a peer")?;
    if unlock {
        drop(value.material(&other.node_address, false)?);
    }
    value.routing = Some(snapshot);
    Ok(Some(Arc::new(value)))
}
fn decode_public(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("invalid public key hex".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|v| {
            std::str::from_utf8(v)
                .map_err(|_| "invalid key".to_string())
                .and_then(|s| u8::from_str_radix(s, 16).map_err(|_| "invalid key".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_descriptor_reads_reject_links_and_public_secret_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = std::env::temp_dir().join(format!(
            "apqe-input-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let file = root.join("input");
        fs::write(&file, b"fixture").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&file, 64, true).unwrap_err().contains("accessible"));
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read(&file, 64, true).unwrap(), b"fixture");
        assert!(read(&file, 2, true).unwrap_err().contains("bounded"));
        let link = root.join("link");
        symlink(&file, &link).unwrap();
        assert!(read(&link, 64, false).unwrap_err().contains("regular"));
        let before = Stamp::capture(&file).unwrap();
        fs::rename(&file, root.join("previous")).unwrap();
        fs::write(&file, b"fixture").unwrap();
        assert!(
            !before.unchanged(),
            "same-length replacement must retire trust"
        );
    }
}
