//! Bounded disposable snapshot cache; consensus/state records remain elsewhere.
use super::*;
use std::path::{Path, PathBuf};

const MAX_WORLD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CHUNKS: usize = 64;
const MAX_ENTRIES: usize = 4;
const MAX_INDEX_BYTES: usize = 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 2 * (4 * MAX_WORLD_BYTES + MAX_INDEX_BYTES as u64);
const INDEX: &str = "cache-index-v1.json";

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheIndex {
    entries: Vec<SnapshotManifest>,
}

pub(super) struct SnapshotChunkStore {
    store: AtomicStore,
    index: RefCell<CacheIndex>,
    cleanup_pending: RefCell<bool>,
    leases: RefCell<BTreeMap<String, Instant>>,
}

impl SnapshotChunkStore {
    pub(super) fn new(root: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let store = AtomicStore::new(root.as_ref(), 64 * 1024 * 1024)
            .map_err(|error| format!("open snapshot chunk store: {error}"))?;
        let index: CacheIndex = store
            .inspect_consistent(|reader| {
                reader
                    .with_maximum_bytes(MAX_INDEX_BYTES)
                    .read_optional_bounded(INDEX)
            })
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
            .transpose()?
            .unwrap_or_default();
        if index.entries.len() > MAX_ENTRIES {
            return Err("snapshot cache index exceeds entry budget".into());
        }
        let mut keys = BTreeSet::new();
        let mut total = 0;
        for manifest in &index.entries {
            total += Self::reservation(manifest)?;
            if !keys.insert(Self::key(manifest)) {
                return Err("duplicate snapshot cache index entry".into());
            }
        }
        if total > MAX_CACHE_BYTES {
            return Err("snapshot cache index exceeds byte budget".into());
        }
        let result = Self {
            store,
            index: RefCell::new(index),
            leases: RefCell::new(BTreeMap::new()),
            cleanup_pending: RefCell::new(true),
        };
        // Seed legacy active custody before any orphan cleanup can run.
        if let Some(active) = result.load_active()? {
            if let Some(manifest) = active.manifest {
                if Self::supports(&manifest) && !result.reserve(&manifest)? {
                    return Err("active snapshot cannot fit cache budget".into());
                }
            }
        }
        for manifest in &result.index.borrow().entries {
            result.leases.borrow_mut().insert(
                Self::key(manifest),
                Instant::now() + 2 * SNAPSHOT_RESPONSE_TIMEOUT,
            );
        }
        Ok(result)
    }

    fn read_small(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        self.store
            .inspect_consistent(|reader| {
                reader
                    .with_maximum_bytes(MAX_INDEX_BYTES)
                    .read_optional_bounded(path)
            })
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())
    }

    pub(super) fn can_materialize(&self, request: &SnapshotChunkRequest) -> Result<bool, String> {
        let key = Self::manifest_index_path(request.height, &request.finalized_block_id);
        let active = self
            .load_active()?
            .map(|active| Self::manifest_index_path(active.height, &active.finalized_block_id));
        let index = self.index.borrow();
        if index
            .entries
            .iter()
            .any(|manifest| Self::key(manifest) == key)
        {
            return Ok(true);
        }
        let total = index
            .entries
            .iter()
            .map(Self::reservation)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .sum::<u64>();
        if index.entries.len() < MAX_ENTRIES && total + MAX_CACHE_BYTES / 2 <= MAX_CACHE_BYTES {
            return Ok(true);
        }
        Ok(index.entries.iter().any(|manifest| {
            let key = Self::key(manifest);
            active.as_ref() != Some(&key)
                && self
                    .leases
                    .borrow()
                    .get(&key)
                    .is_none_or(|until| *until <= Instant::now())
        }))
    }

    fn key(manifest: &SnapshotManifest) -> String {
        Self::manifest_index_path(manifest.height, &manifest.finalized_block_id)
    }

    pub(super) fn supports(manifest: &SnapshotManifest) -> bool {
        Self::reservation(manifest).is_ok()
    }

    fn reservation(manifest: &SnapshotManifest) -> Result<u64, String> {
        manifest.validate_shape()?;
        let count = manifest.chunk_hashes.len() as u64;
        let minimum = (count - 1)
            .checked_mul(manifest.chunk_size)
            .ok_or("snapshot size overflow")?;
        if count > MAX_CHUNKS as u64 || minimum >= MAX_WORLD_BYTES {
            return Err("snapshot exceeds local64MiB/64-chunk restore budget".into());
        }
        Ok(4 * (count * manifest.chunk_size).min(MAX_WORLD_BYTES) + MAX_INDEX_BYTES as u64)
    }

    fn paths(manifest: &SnapshotManifest) -> Vec<PathBuf> {
        let mut paths = vec![Self::key(manifest).into()];
        paths.extend((0..manifest.chunk_hashes.len() as u64).map(|index| {
            Self::chunk_path(
                manifest.height,
                &manifest.finalized_block_id,
                &manifest.state_root,
                index,
            )
            .into()
        }));
        paths
    }

    fn persist_index(&self) -> Result<(), String> {
        let bytes = serde_json::to_vec(&*self.index.borrow()).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_INDEX_BYTES {
            return Err("snapshot cache index encoding exceeds budget".into());
        }
        self.store
            .write_atomic(INDEX, &bytes)
            .map_err(|e| e.to_string())
    }

    fn reserve(&self, manifest: &SnapshotManifest) -> Result<bool, String> {
        let required = Self::reservation(manifest)?;
        let key = Self::key(manifest);
        let active = self
            .load_active()?
            .map(|active| Self::manifest_index_path(active.height, &active.finalized_block_id));
        let mut index = self.index.borrow_mut();
        if let Some(existing) = index.entries.iter().find(|old| Self::key(old) == key) {
            if !same_snapshot_content(existing, manifest) {
                return Err("conflicting snapshot content for finalized block".into());
            }
            return Ok(true);
        }
        self.leases
            .borrow_mut()
            .retain(|_, deadline| *deadline > Instant::now());
        let mut survivors = index.entries.clone();
        let mut retired = Vec::new();
        while survivors.len() >= MAX_ENTRIES
            || survivors
                .iter()
                .map(Self::reservation)
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .sum::<u64>()
                + required
                > MAX_CACHE_BYTES
        {
            let Some(victim) = survivors.iter().position(|old| {
                let key = Self::key(old);
                active.as_ref() != Some(&key) && !self.leases.borrow().contains_key(&key)
            }) else {
                return Ok(false);
            };
            // Disposable records only; the active incoming transfer is never a victim.
            retired.extend(Self::paths(&survivors[victim]));
            survivors.remove(victim);
        }
        // Select the whole eviction set before removing any file or index entry.
        self.store
            .remove_cache_records(&retired)
            .map_err(|e| e.to_string())?;
        survivors.push(manifest.clone());
        index.entries = survivors;
        drop(index);
        self.persist_index()?;
        Ok(true)
    }

    pub(super) fn maintain(&self) -> Result<(), String> {
        if !*self.cleanup_pending.borrow() {
            return Ok(());
        }
        let keep: BTreeSet<_> = self
            .index
            .borrow()
            .entries
            .iter()
            .flat_map(Self::paths)
            .collect();
        let manifests = self
            .store
            .prune_cache_directory(Path::new("manifest-index"), &keep)
            .map_err(|e| e.to_string())?;
        let chunks = self
            .store
            .prune_cache_directory(Path::new("chunk"), &keep)
            .map_err(|e| e.to_string())?;
        *self.cleanup_pending.borrow_mut() = !(manifests && chunks);
        Ok(())
    }

    pub(super) fn load_active(&self) -> Result<Option<PersistedSnapshotAcquisition>, String> {
        const PATH: &str = "active-snapshot-request.json";
        let bytes = self
            .store
            .inspect_consistent(|reader| {
                reader
                    .with_maximum_bytes(MAX_INDEX_BYTES)
                    .read_optional_bounded(PATH)
            })
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        let active: Option<PersistedSnapshotAcquisition> = bytes
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
            .transpose()?
            .flatten();
        Ok(active)
    }

    pub(super) fn save_active(&self, active: &PersistedSnapshotAcquisition) -> Result<(), String> {
        if let Some(manifest) = active.manifest.as_ref() {
            Self::reservation(manifest)?;
        }
        if active.received.len() > MAX_CHUNKS {
            return Err("active snapshot exceeds chunk budget".into());
        }
        let bytes = serde_json::to_vec(active)
            .map_err(|error| format!("encode persisted snapshot request: {error}"))?;
        if bytes.len() > MAX_INDEX_BYTES {
            return Err("active snapshot metadata exceeds byte budget".into());
        }
        self.store
            .write_atomic("active-snapshot-request.json", &bytes)
            .map_err(|error| format!("persist snapshot request: {error}"))
    }

    pub(super) fn clear_active(&self) -> Result<(), String> {
        self.store
            .write_atomic("active-snapshot-request.json", b"null")
            .map_err(|error| format!("clear persisted snapshot request: {error}"))
    }

    pub(super) fn manifest_index_path(height: u64, finalized_block_id: &str) -> String {
        format!(
            "manifest-index/{height:020}-{}.json",
            synergy_block::hash_block_bytes(finalized_block_id.as_bytes())
        )
    }

    pub(super) fn chunk_path(
        height: u64,
        block_id: &str,
        state_root: &synergy_crypto::Hash32,
        index: u64,
    ) -> String {
        format!(
            "chunk/{height:020}-{}-{}-{index:020}.json",
            synergy_block::hash_block_bytes(block_id.as_bytes()),
            state_root_hex(state_root)
        )
    }

    pub(super) fn put(&self, response: &SnapshotChunkResponse) -> Result<bool, String> {
        response.validate()?;
        Self::reservation(&response.manifest)?;
        let end = response
            .chunk
            .index
            .checked_mul(response.manifest.chunk_size)
            .and_then(|offset| offset.checked_add(response.chunk.bytes.len() as u64))
            .ok_or("snapshot chunk size overflow")?;
        if end > MAX_WORLD_BYTES {
            return Err("snapshot exceeds finalized world byte budget".into());
        }
        // A snapshot payload can legitimately have independent authenticated
        // signatures from several governed validators. Keep the first proof;
        // content/context equality never means accepting a different snapshot.
        let path = Self::manifest_index_path(
            response.manifest.height,
            &response.manifest.finalized_block_id,
        );
        let bytes = serde_json::to_vec(&response.manifest)
            .map_err(|error| format!("encode snapshot manifest: {error}"))?;
        if let Some(existing) = self.read_small(&path)? {
            let existing: SnapshotManifest =
                serde_json::from_slice(&existing).map_err(|e| e.to_string())?;
            if !same_snapshot_content(&existing, &response.manifest) {
                return Err("conflicting snapshot content for finalized block".into());
            }
        }
        if !self.reserve(&response.manifest)? {
            return Ok(false);
        }
        if !self.store.exists(&path).map_err(|e| e.to_string())? {
            self.store
                .write_atomic(&path, &bytes)
                .map_err(|error| format!("persist snapshot manifest index: {error}"))?;
        }
        let path = Self::chunk_path(
            response.manifest.height,
            &response.manifest.finalized_block_id,
            &response.manifest.state_root,
            response.chunk.index,
        );
        let bytes = serde_json::to_vec(&response.chunk)
            .map_err(|error| format!("encode snapshot chunk: {error}"))?;
        if self
            .store
            .exists(&path)
            .map_err(|error| error.to_string())?
        {
            let existing = self
                .store
                .inspect_consistent(|reader| {
                    reader
                        .with_maximum_bytes(bytes.len())
                        .read_optional_bounded(&path)
                })
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?
                .ok_or("cached snapshot chunk disappeared")?;
            if existing != bytes {
                return Err("conflicting snapshot chunk for finalized block/state root".into());
            }
            return Ok(true);
        }
        self.store
            .write_atomic(path, &bytes)
            .map(|()| true)
            .map_err(|error| format!("persist snapshot chunk: {error}"))
    }

    fn read_chunk(
        &self,
        manifest: &SnapshotManifest,
        index: u64,
    ) -> Result<Option<SnapshotChunk>, String> {
        let offset = index
            .checked_mul(manifest.chunk_size)
            .ok_or("snapshot offset overflow")?;
        let maximum_raw = manifest
            .chunk_size
            .min(MAX_WORLD_BYTES.saturating_sub(offset));
        let path = Self::chunk_path(
            manifest.height,
            &manifest.finalized_block_id,
            &manifest.state_root,
            index,
        );
        let bytes = self
            .store
            .inspect_consistent(|reader| {
                reader
                    .with_maximum_bytes((maximum_raw * 4 + 512) as usize)
                    .read_optional_bounded(path)
            })
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let chunk: SnapshotChunk = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if chunk.index != index || chunk.bytes.len() as u64 > maximum_raw || chunk.bytes.is_empty()
        {
            return Err("cached snapshot chunk exceeds manifest/world budget".into());
        }
        Ok(Some(chunk))
    }

    pub(super) fn get(
        &self,
        request: &SnapshotChunkRequest,
    ) -> Result<Option<SnapshotChunkResponse>, String> {
        if !request.validate() {
            return Err("invalid snapshot chunk request".into());
        }
        let path = Self::manifest_index_path(request.height, &request.finalized_block_id);
        let Some(expected) = self
            .index
            .borrow()
            .entries
            .iter()
            .find(|manifest| Self::key(manifest) == path)
            .cloned()
        else {
            return Ok(None);
        };
        let Some(manifest_bytes) = self.read_small(&path)? else {
            return Ok(None);
        };
        let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| format!("decode snapshot manifest: {error}"))?;
        if !same_snapshot_content(&expected, &manifest) {
            return Err("cached snapshot manifest differs from reserved content".into());
        }
        if manifest.epoch != request.epoch
            || manifest.height != request.height
            || manifest.finalized_block_id != request.finalized_block_id
            || manifest.finality_evidence_id != request.finality_evidence_id
            || request
                .expected_snapshot_root
                .is_some_and(|root| root != manifest.state_root)
        {
            return Ok(None);
        }
        Self::reservation(&manifest)?;
        let Some(chunk) = self.read_chunk(&manifest, request.index)? else {
            return Ok(None);
        };
        let response = SnapshotChunkResponse {
            request: request.clone(),
            manifest,
            chunk,
        };
        response.validate()?;
        self.leases.borrow_mut().insert(
            Self::key(&response.manifest),
            Instant::now() + 2 * SNAPSHOT_RESPONSE_TIMEOUT,
        );
        Ok(Some(response))
    }

    pub(super) fn chunks(
        &self,
        manifest: &SnapshotManifest,
    ) -> Result<Option<Vec<SnapshotChunk>>, String> {
        Self::reservation(manifest)?;
        let mut chunks = Vec::with_capacity(manifest.chunk_hashes.len());
        for index in 0..manifest.chunk_hashes.len() as u64 {
            let Some(chunk) = self.read_chunk(manifest, index)? else {
                return Ok(None);
            };
            chunks.push(chunk);
        }
        Ok(Some(chunks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_pqvm::pqc::signatures::mldsa::mldsa65;
    use pqrust_traits::sign::SecretKey as _;

    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "snapshot-cache-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    fn response(height: u64) -> SnapshotChunkResponse {
        let (_, secret) = mldsa65::keypair();
        let key_id = KeyId::new("snapshot-cache-test").unwrap();
        let signer = LocalSnapshotSigner {
            key_id: key_id.clone(),
            signer: PqvmSigner::from_secret_key_bytes(
                AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                    maximum_message_bytes: 1024 * 1024,
                    maximum_signature_bytes: 16 * 1024,
                },
                key_id,
                secret.as_bytes().to_vec(),
            )
            .unwrap(),
        };
        let (manifest, mut chunks) = build_snapshot(
            &AegisSha3_256,
            &signer,
            1266,
            "snapshot-cache-test",
            1,
            height,
            &format!("block-{height}"),
            &format!("finality-{height}"),
            &"a".repeat(64),
            1024,
            &[7; 1024],
        )
        .unwrap();
        SnapshotChunkResponse {
            request: SnapshotChunkRequest {
                epoch: 1,
                height,
                finalized_block_id: manifest.finalized_block_id.clone(),
                finality_evidence_id: manifest.finality_evidence_id.clone(),
                expected_snapshot_root: Some(manifest.state_root),
                index: 0,
            },
            manifest,
            chunk: chunks.remove(0),
        }
    }
    fn active(response: &SnapshotChunkResponse) -> PersistedSnapshotAcquisition {
        PersistedSnapshotAcquisition {
            epoch: 1,
            height: response.manifest.height,
            finalized_block_id: response.manifest.finalized_block_id.clone(),
            finality_evidence_id: response.manifest.finality_evidence_id.clone(),
            peer_id: "source".into(),
            attempted: BTreeSet::from(["source".into()]),
            manifest: Some(response.manifest.clone()),
            received: BTreeSet::from([0]),
            requested_index: 0,
        }
    }

    #[test]
    fn many_heights_remain_bounded_and_evicted_payload_can_be_rebuilt() {
        let root = root();
        let store = SnapshotChunkStore::new(&root).unwrap();
        let first = response(1);
        assert!(store.put(&first).unwrap());
        for height in 2..=40 {
            assert!(store.put(&response(height)).unwrap());
        }
        assert_eq!(store.index.borrow().entries.len(), MAX_ENTRIES);
        assert_eq!(
            fs::read_dir(root.join("chunk")).unwrap().count(),
            MAX_ENTRIES
        );
        assert_eq!(
            fs::read_dir(root.join("manifest-index")).unwrap().count(),
            MAX_ENTRIES
        );
        assert!(store.get(&first.request).unwrap().is_none());
        assert!(store.put(&first).unwrap());
        assert_eq!(store.get(&first.request).unwrap().unwrap(), first);
        drop(store);
        let restarted = SnapshotChunkStore::new(&root).unwrap();
        assert_eq!(restarted.get(&first.request).unwrap().unwrap(), first);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_custody_and_outgoing_leases_survive_pressure_and_restart() {
        let root = root();
        let store = SnapshotChunkStore::new(&root).unwrap();
        let responses: Vec<_> = (1..=5).map(response).collect();
        for response in &responses[..4] {
            assert!(store.put(response).unwrap());
            assert!(store.get(&response.request).unwrap().is_some());
        }
        store.save_active(&active(&responses[0])).unwrap();
        let index_before = fs::read(root.join(INDEX)).unwrap();
        assert!(!store.put(&responses[4]).unwrap());
        assert!(!store.can_materialize(&responses[4].request).unwrap());
        assert_eq!(fs::read(root.join(INDEX)).unwrap(), index_before);
        drop(store);
        let restarted = SnapshotChunkStore::new(&root).unwrap();
        assert!(!restarted.put(&responses[4]).unwrap());
        restarted.leases.borrow_mut().clear();
        assert!(restarted.put(&responses[4]).unwrap());
        assert!(restarted.get(&responses[0].request).unwrap().is_some());
        assert!(restarted.get(&responses[1].request).unwrap().is_none());
        assert_eq!(
            restarted.load_active().unwrap().unwrap().received,
            BTreeSet::from([0])
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_cleanup_is_incremental_and_preserves_active_transfer() {
        let root = root();
        let first = response(1);
        let store = SnapshotChunkStore::new(&root).unwrap();
        assert!(store.put(&first).unwrap());
        store.save_active(&active(&first)).unwrap();
        drop(store);
        fs::remove_file(root.join(INDEX)).unwrap(); // legacy layout
        for i in 0..150 {
            fs::write(root.join(format!("chunk/legacy-{i}.json")), b"old cache").unwrap();
            fs::write(
                root.join(format!("manifest-index/legacy-{i}.json")),
                b"old cache",
            )
            .unwrap();
        }
        let store = SnapshotChunkStore::new(&root).unwrap();
        store.maintain().unwrap();
        assert_eq!(fs::read_dir(root.join("chunk")).unwrap().count(), 87);
        for _ in 0..3 {
            store.maintain().unwrap();
        }
        assert_eq!(fs::read_dir(root.join("chunk")).unwrap().count(), 1);
        assert_eq!(
            fs::read_dir(root.join("manifest-index")).unwrap().count(),
            1
        );
        assert_eq!(store.get(&first.request).unwrap().unwrap(), first);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn byte_reservations_bound_cache_before_the_entry_limit() {
        let root = root();
        let store = SnapshotChunkStore::new(&root).unwrap();
        // Exercise local reservation accounting without writing maximum-size worlds.
        let mut manifests: Vec<_> = (1..=3).map(|height| response(height).manifest).collect();
        for manifest in &mut manifests {
            manifest.chunk_size = 16 * 1024 * 1024;
            manifest.chunk_hashes.resize(4, manifest.chunk_hashes[0]);
            assert!(store.reserve(manifest).unwrap());
        }
        let index = store.index.borrow();
        assert_eq!(index.entries.len(), 2);
        assert_eq!(
            index
                .entries
                .iter()
                .map(SnapshotChunkStore::reservation)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .into_iter()
                .sum::<u64>(),
            MAX_CACHE_BYTES
        );
        drop(index);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn insufficient_byte_capacity_preserves_unleased_victims_too() {
        let root = root();
        let store = SnapshotChunkStore::new(&root).unwrap();
        let mut full = response(1).manifest;
        full.chunk_size = 16 * 1024 * 1024;
        full.chunk_hashes.resize(4, full.chunk_hashes[0]);
        assert!(store.reserve(&full).unwrap());
        let small: Vec<_> = (2..=4).map(|height| response(height).manifest).collect();
        for manifest in &small {
            assert!(store.reserve(manifest).unwrap());
        }
        for manifest in [&full, &small[0], &small[1]] {
            store.leases.borrow_mut().insert(
                SnapshotChunkStore::key(manifest),
                Instant::now() + Duration::from_secs(10),
            );
        }
        let before = fs::read(root.join(INDEX)).unwrap();
        let mut next = full.clone();
        next.height = 5;
        next.finalized_block_id = "block-5".into();
        assert!(!store.reserve(&next).unwrap());
        assert_eq!(store.index.borrow().entries.len(), 4);
        assert_eq!(fs::read(root.join(INDEX)).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resource_limits_and_corrupt_cached_chunk_fail_before_unbounded_restore() {
        let root = root();
        let store = SnapshotChunkStore::new(&root).unwrap();
        let first = response(1);
        let mut huge = first.clone();
        huge.manifest.chunk_hashes.resize(65, first.chunk.hash);
        assert!(store.put(&huge).is_err());
        assert!(store.index.borrow().entries.is_empty());
        assert!(store.put(&first).unwrap());
        let path = root.join(SnapshotChunkStore::chunk_path(
            1,
            &first.manifest.finalized_block_id,
            &first.manifest.state_root,
            0,
        ));
        fs::write(&path, vec![b' '; 4 * 1024 + 513]).unwrap();
        assert!(store.chunks(&first.manifest).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
