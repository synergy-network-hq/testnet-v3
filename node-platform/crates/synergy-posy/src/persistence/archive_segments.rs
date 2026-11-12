//! Exact-byte, content-addressed cold payloads. This module never decides
//! consensus authority or retirement: callers publish locators only after sync.
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub(super) const SEGMENT_LIMIT: u64 = 64 * 1024 * 1024;
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;
const HEADER: &[u8; 8] = b"SNPARC02";
const FRAME_HEADER: usize = 44;
pub(super) const OPAQUE: u8 = 0;
pub(super) const TEMPLATE: u8 = 1;
pub(super) const BYTE_ARRAY: u8 = 2;
pub(super) const RECORD_BINDING: u8 = 3;
pub(super) const BATCH_COMMIT: u8 = 4;
const SEALED: u8 = 255;

type SegmentState = (u64, u64, bool);
type ArchiveObjects = BTreeMap<[u8; 32], (u8, Vec<u8>)>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Location {
    pub hash: [u8; 32],
    pub kind: u8,
    pub segment: u64,
    pub offset: u64,
    pub length: usize,
}
#[derive(Debug)]
pub(super) struct Segments {
    root: PathBuf,
    id: u64,
    file: File,
    length: u64,
}
pub(super) fn object_hash(kind: u8, bytes: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"SYNERGY_POSY_ARCHIVE_OBJECT_V2");
    hash.update(&[kind]);
    hash.update(bytes);
    *hash.finalize().as_bytes()
}
fn path(root: &Path, id: u64) -> PathBuf {
    root.join(format!("segment-{id:020}.sya"))
}
fn error(message: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string())
}
fn regular(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(error("non-regular consensus segment"));
    }
    Ok(())
}
impl Segments {
    /// Only the current segment and at most one interrupted rollover are
    /// inspected. The cold index is rebuilt explicitly offline if lost.
    /// `committed` is the durable SQLite end offset; a shorter file is corrupt.
    pub fn open(
        root: &Path,
        id: u64,
        committed: u64,
    ) -> std::io::Result<(Self, Vec<Location>, Vec<SegmentState>)> {
        if let Ok(metadata) = fs::symlink_metadata(root) {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(error("non-directory consensus archive"));
            }
        }
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(root)?;
        let mut current = Self::open_one(root, id, committed)?;
        let mut recovered = Vec::new();
        let mut segments = Vec::new();
        for pass in 0..2 {
            let mut offset = if pass == 0 { committed.max(16) } else { 16 };
            let mut sealed = false;
            while offset < current.length {
                current.file.seek(SeekFrom::Start(offset))?;
                match read_frame(&mut current.file, current.id, offset) {
                    Ok((location, _)) => {
                        offset += FRAME_HEADER as u64 + location.length as u64;
                        if location.kind == SEALED {
                            if offset != current.length || location.length != 0 {
                                return Err(error("invalid consensus segment seal"));
                            }
                            sealed = true;
                            break;
                        }
                        recovered.push(location);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        // Unacknowledged active tail only. Indexed offsets are
                        // never truncated: offset starts at the committed end.
                        current.file.set_len(offset)?;
                        current.file.sync_all()?;
                        current.length = offset;
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
            segments.push((current.id, current.length, sealed));
            // Complete unindexed frames can precede process death before the
            // writer's fsync. Make them durable before publishing recovered
            // content locators (record bindings still need a batch footer).
            if !recovered.is_empty() {
                current.file.sync_all()?;
            }
            let next = path(root, current.id + 1);
            if sealed {
                if pass == 1 {
                    return Err(error("archive tail exceeds bounded startup recovery"));
                }
                current = Self::open_one(root, current.id + 1, 0)?;
            } else {
                if next.exists() {
                    return Err(error("unsealed archive has unexpected successor"));
                }
                current.file.seek(SeekFrom::Start(current.length))?;
                return Ok((current, recovered, segments));
            }
        }
        Err(error("archive tail recovery did not reach active segment"))
    }
    fn open_one(root: &Path, id: u64, committed: u64) -> std::io::Result<Self> {
        let name = path(root, id);
        let existed = name.exists();
        if existed {
            regular(&name)?;
        } else if committed > 16 {
            return Err(error("indexed consensus segment is missing"));
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(!existed);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&name)?;
        let mut length = file.metadata()?.len();
        if existed && length < 16 && committed == 0 {
            let expected = [HEADER.as_slice(), &id.to_le_bytes()].concat();
            let mut prefix = vec![0; length as usize];
            file.read_exact(&mut prefix)?;
            if prefix != expected[..length as usize] {
                return Err(error("unpublished segment has invalid partial header"));
            }
            file.seek(SeekFrom::Start(0))?;
        }
        if !existed || (length < 16 && committed == 0) {
            file.write_all(HEADER)?;
            file.write_all(&id.to_le_bytes())?;
            file.sync_all()?;
            File::open(root)?.sync_all()?;
            length = 16;
        }
        if length < committed.max(16) || length > SEGMENT_LIMIT + MAX_PAYLOAD as u64 + 4096 {
            return Err(error("invalid consensus segment length"));
        }
        file.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; 16];
        file.read_exact(&mut header)?;
        if &header[..8] != HEADER || header[8..] != id.to_le_bytes() {
            return Err(error("invalid consensus segment header"));
        }
        Ok(Self {
            root: root.into(),
            id,
            file,
            length,
        })
    }
    /// One call is one bounded publication batch. Sync every touched segment
    /// before returning; callers then atomically publish all index locators.
    pub fn append(
        &mut self,
        objects: &ArchiveObjects,
        bindings: &[[u8; 32]],
    ) -> std::io::Result<(Vec<Location>, Vec<SegmentState>)> {
        let footer = batch_footer(bindings)?;
        let total = objects
            .values()
            .try_fold(0usize, |sum, (_, bytes)| {
                sum.checked_add(bytes.len() + FRAME_HEADER)
            })
            .and_then(|sum| {
                sum.checked_add(if bindings.is_empty() {
                    0
                } else {
                    footer.len() + FRAME_HEADER
                })
            })
            .ok_or_else(|| error("archive batch overflow"))?;
        if total > 32 * 1024 * 1024 {
            return Err(error("archive batch exceeds32MiB"));
        }
        let mut result = Vec::with_capacity(objects.len());
        let mut segments = Vec::new();
        for (hash, (kind, bytes)) in objects {
            if bytes.len() > MAX_PAYLOAD
                || *kind > RECORD_BINDING
                || object_hash(*kind, bytes) != *hash
            {
                return Err(error("invalid archive object"));
            }
            if self.length + FRAME_HEADER as u64 + bytes.len() as u64 > SEGMENT_LIMIT {
                self.write_frame(SEALED, &[])?;
                self.file.sync_all()?;
                segments.push((self.id, self.length, true));
                *self = Self::open_one(&self.root, self.id + 1, 0)?;
            }
            result.push(self.write_frame(*kind, bytes)?);
            #[cfg(test)]
            if *kind == RECORD_BINDING
                && std::env::var("SYNERGY_ARCHIVE_CRASH_POINT").ok().as_deref()
                    == Some("after-one-binding")
            {
                self.file.sync_all()?;
                std::process::exit(91);
            }
        }
        if !bindings.is_empty() {
            if self.length + FRAME_HEADER as u64 + footer.len() as u64 > SEGMENT_LIMIT {
                self.write_frame(SEALED, &[])?;
                self.file.sync_all()?;
                segments.push((self.id, self.length, true));
                *self = Self::open_one(&self.root, self.id + 1, 0)?;
            }
            #[cfg(test)]
            if std::env::var("SYNERGY_ARCHIVE_CRASH_POINT").ok().as_deref()
                == Some("partial-batch-footer")
            {
                self.file.write_all(b"SNFR\x05")?;
                self.file.sync_all()?;
                std::process::exit(91);
            }
            // Local durability record, never a network certificate. It is
            // physically LAST and commits the entire cold binding batch.
            result.push(self.write_frame(BATCH_COMMIT, &footer)?);
        }
        #[cfg(test)]
        if std::env::var("SYNERGY_ARCHIVE_CRASH_POINT").ok().as_deref()
            == Some("before-segment-sync")
        {
            std::process::exit(91);
        }
        self.file.sync_all()?;
        segments.push((self.id, self.length, false));
        Ok((result, segments))
    }
    fn write_frame(&mut self, kind: u8, bytes: &[u8]) -> std::io::Result<Location> {
        let hash = object_hash(kind, bytes);
        let location = Location {
            hash,
            kind,
            segment: self.id,
            offset: self.length,
            length: bytes.len(),
        };
        self.file.seek(SeekFrom::Start(self.length))?;
        self.file.write_all(b"SNFR")?;
        self.file.write_all(&(bytes.len() as u32).to_le_bytes())?;
        self.file.write_all(&[kind, 0, 0, 0])?;
        self.file.write_all(&hash)?;
        self.file.write_all(bytes)?;
        self.length += FRAME_HEADER as u64 + bytes.len() as u64;
        Ok(location)
    }
    pub fn read(&self, expected: &Location) -> std::io::Result<Vec<u8>> {
        read_location(&self.root, expected)
    }
}
pub(super) fn read_location(root: &Path, expected: &Location) -> std::io::Result<Vec<u8>> {
    let name = path(root, expected.segment);
    regular(&name)?;
    let mut file = File::open(name)?;
    file.seek(SeekFrom::Start(expected.offset))?;
    let (actual, bytes) = read_frame(&mut file, expected.segment, expected.offset)?;
    if actual != *expected {
        return Err(error("consensus segment index binding mismatch"));
    }
    Ok(bytes)
}
fn read_frame(file: &mut File, segment: u64, offset: u64) -> std::io::Result<(Location, Vec<u8>)> {
    let mut header = [0u8; FRAME_HEADER];
    file.read_exact(&mut header)?;
    if &header[..4] != b"SNFR" || header[9..12] != [0, 0, 0] {
        return Err(error("invalid archive frame header"));
    }
    let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
    let kind = header[8];
    if length > MAX_PAYLOAD || (kind > BATCH_COMMIT && kind != SEALED) {
        return Err(error("invalid archive frame bounds"));
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)?;
    let hash: [u8; 32] = header[12..44].try_into().unwrap();
    if object_hash(kind, &bytes) != hash {
        return Err(error("consensus archive frame hash mismatch"));
    }
    Ok((
        Location {
            hash,
            kind,
            segment,
            offset,
            length,
        },
        bytes,
    ))
}
pub(super) fn batch_footer(bindings: &[[u8; 32]]) -> std::io::Result<Vec<u8>> {
    if bindings.len() > 256 {
        return Err(error("too many cold bindings in publication batch"));
    }
    let mut bytes = Vec::with_capacity(4 + 32 * bindings.len());
    bytes.extend_from_slice(&(bindings.len() as u32).to_le_bytes());
    for binding in bindings {
        bytes.extend_from_slice(binding);
    }
    Ok(bytes)
}
pub(super) fn batch_bindings(bytes: &[u8]) -> std::io::Result<Vec<[u8; 32]>> {
    let count = u32::from_le_bytes(
        bytes
            .get(..4)
            .ok_or_else(|| error("truncated archive batch footer"))?
            .try_into()
            .unwrap(),
    ) as usize;
    if count == 0 || count > 256 || bytes.len() != 4 + 32 * count {
        return Err(error("invalid archive batch footer"));
    }
    Ok(bytes[4..]
        .chunks_exact(32)
        .map(|hash| hash.try_into().unwrap())
        .collect())
}

/// Explicit offline rebuild only. Frames and segment boundaries are streamed
/// in physical order; no history-wide payload/name list is retained.
pub(super) fn scan(
    root: &Path,
    mut object: impl FnMut(Location, Vec<u8>) -> std::io::Result<()>,
    mut segment: impl FnMut(u64, u64, bool) -> std::io::Result<()>,
) -> std::io::Result<(u64, u64, bool)> {
    let mut id = 1;
    loop {
        let name = path(root, id);
        regular(&name)?;
        let mut file = File::open(&name)?;
        let length = file.metadata()?.len();
        if length < 16 || length > SEGMENT_LIMIT + MAX_PAYLOAD as u64 + 4096 {
            return Err(error("invalid segment length during offline rebuild"));
        }
        let mut header = [0; 16];
        file.read_exact(&mut header)?;
        if &header[..8] != HEADER || header[8..] != id.to_le_bytes() {
            return Err(error("invalid segment header during offline rebuild"));
        }
        let mut offset = 16;
        let mut sealed = false;
        while offset < length {
            let (location, bytes) = read_frame(&mut file, id, offset)?;
            offset += FRAME_HEADER as u64 + location.length as u64;
            if location.kind == SEALED {
                if offset != length || !bytes.is_empty() {
                    return Err(error("invalid offline segment seal"));
                }
                sealed = true;
                break;
            }
            object(location, bytes)?;
        }
        // A complete frame/footer may still have been only in page cache when
        // the previous writer died. Explicit rebuild must establish its own
        // durable data-before-index boundary, even without ordinary open first.
        file.sync_all()?;
        segment(id, length, sealed)?;
        if !path(root, id + 1).exists() {
            return Ok((id, length, sealed));
        }
        if !sealed {
            return Err(error(
                "unsealed segment has successor during offline rebuild",
            ));
        }
        id = id
            .checked_add(1)
            .ok_or_else(|| error("segment index overflow"))?;
    }
}

/// Split only canonical numeric byte arrays outside strings. Literal chunks
/// retain all original JSON punctuation/order/spacing. Noncanonical arrays are
/// left opaque, so old signed bytes are never normalized by this encoding.
pub(super) fn encode(bytes: &[u8]) -> ([u8; 32], ArchiveObjects) {
    let mut objects = BTreeMap::new();
    let mut template = Vec::new();
    let mut at = 0;
    let mut literal = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut parts = 0;
    while at < bytes.len() && parts < 64 {
        let byte = bytes[at];
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            at += 1;
            continue;
        }
        if byte == b'"' {
            quoted = true;
        }
        if byte == b'[' {
            if let Some((end, array)) = byte_array(&bytes[at..]) {
                if at > literal {
                    template.push(0);
                    template.extend_from_slice(&((at - literal) as u32).to_le_bytes());
                    template.extend_from_slice(&bytes[literal..at]);
                }
                let hash = object_hash(BYTE_ARRAY, &array);
                objects.entry(hash).or_insert((BYTE_ARRAY, array));
                template.push(1);
                template.extend_from_slice(&hash);
                at += end;
                literal = at;
                parts += 1;
                continue;
            }
        }
        at += 1;
    }
    let (kind, data) = if parts == 0 {
        (OPAQUE, bytes.to_vec())
    } else {
        if literal < bytes.len() {
            template.push(0);
            template.extend_from_slice(&((bytes.len() - literal) as u32).to_le_bytes());
            template.extend_from_slice(&bytes[literal..]);
        }
        (TEMPLATE, template)
    };
    let hash = object_hash(kind, &data);
    objects.insert(hash, (kind, data));
    (hash, objects)
}
fn byte_array(bytes: &[u8]) -> Option<(usize, Vec<u8>)> {
    let mut at = 1;
    let mut result = Vec::new();
    loop {
        let start = at;
        let mut value = 0u16;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            value = value
                .checked_mul(10)?
                .checked_add((bytes[at] - b'0') as u16)?;
            if value > 255 {
                return None;
            }
            at += 1;
        }
        if at == start || (at - start > 1 && bytes[start] == b'0') {
            return None;
        }
        result.push(value as u8);
        match bytes.get(at)? {
            b',' => at += 1,
            b']' if result.len() >= 64 => return Some((at + 1, result)),
            _ => return None,
        }
    }
}
pub(super) fn decode(
    kind: u8,
    bytes: &[u8],
    mut child: impl FnMut(&[u8; 32]) -> std::io::Result<Vec<u8>>,
) -> std::io::Result<Vec<u8>> {
    if kind == OPAQUE {
        return Ok(bytes.to_vec());
    }
    if kind != TEMPLATE {
        return Err(error("record is not an archive template"));
    }
    let mut result = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let tag = bytes[at];
        at += 1;
        match tag {
            0 => {
                let length = bytes
                    .get(at..at + 4)
                    .ok_or_else(|| error("truncated literal length"))?;
                at += 4;
                let length = u32::from_le_bytes(length.try_into().unwrap()) as usize;
                let literal = bytes
                    .get(at..at + length)
                    .ok_or_else(|| error("truncated literal"))?;
                if result.len() + literal.len() > MAX_PAYLOAD {
                    return Err(error("decoded archive exceeds bound"));
                }
                result.extend_from_slice(literal);
                at += length;
            }
            1 => {
                let hash: [u8; 32] = bytes
                    .get(at..at + 32)
                    .ok_or_else(|| error("truncated byte reference"))?
                    .try_into()
                    .unwrap();
                at += 32;
                let raw = child(&hash)?;
                if object_hash(BYTE_ARRAY, &raw) != hash {
                    return Err(error("archive byte-array binding mismatch"));
                }
                struct Bounded<'a>(&'a mut Vec<u8>);
                impl Write for Bounded<'_> {
                    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                        if self.0.len() + bytes.len() > MAX_PAYLOAD {
                            return Err(error("decoded archive exceeds bound"));
                        }
                        self.0.extend_from_slice(bytes);
                        Ok(bytes.len())
                    }
                    fn flush(&mut self) -> std::io::Result<()> {
                        Ok(())
                    }
                }
                serde_json::to_writer(Bounded(&mut result), &raw).map_err(error)?;
            }
            _ => return Err(error("invalid archive template tag")),
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "posy-segments-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    #[test]
    fn byte_arrays_are_shared_without_changing_exact_json() {
        let signature = (0..3309).map(|n| (n % 256) as u8).collect::<Vec<_>>();
        let array = serde_json::to_string(&signature).unwrap();
        let first = format!("{{\"signature\":{array},\"literal\":\"[1,2,3]\"}}\n");
        let second = format!("[\"other transcript\",{array}]");
        let (a, objects_a) = encode(first.as_bytes());
        let (b, objects_b) = encode(second.as_bytes());
        let shared = objects_a
            .keys()
            .filter(|hash| objects_b.contains_key(*hash))
            .count();
        assert_eq!(shared, 1);
        for (hash, objects, original) in [(a, objects_a, first), (b, objects_b, second)] {
            let (kind, bytes) = &objects[&hash];
            assert_eq!(
                decode(*kind, bytes, |hash| Ok(objects[hash].1.clone())).unwrap(),
                original.as_bytes()
            );
        }
        let legacy = b"{ \"old\": [ 1, 2, 3 ], \"string\":\"escaped\\\"[123]\" }\n";
        let (hash, objects) = encode(legacy);
        let (kind, bytes) = &objects[&hash];
        assert_eq!(*kind, OPAQUE);
        assert_eq!(decode(*kind, bytes, |_| unreachable!()).unwrap(), legacy);
    }
    #[test]
    fn synced_orphan_frames_recover_but_partial_uncommitted_tail_is_truncated() {
        let root = root("tail");
        let (mut archive, orphan, _) = Segments::open(&root, 1, 16).unwrap();
        assert!(orphan.is_empty());
        let (hash, objects) = encode(b"exact original bytes\n");
        let (locations, state) = archive.append(&objects, &[]).unwrap();
        assert_eq!(archive.read(&locations[0]).unwrap(), objects[&hash].1);
        drop(archive);
        // SQLite publication was lost, but the complete frame is self-checking.
        let (archive, orphan, _) = Segments::open(&root, 1, 16).unwrap();
        assert_eq!(orphan, locations);
        drop(archive);
        let end = state[0].1;
        let mut file = OpenOptions::new()
            .append(true)
            .open(path(&root, 1))
            .unwrap();
        file.write_all(b"SNFR\x0a\x00").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let (archive, orphan, _) = Segments::open(&root, 1, end).unwrap();
        assert!(orphan.is_empty());
        assert_eq!(archive.length, end);
        assert_eq!(archive.read(&locations[0]).unwrap(), objects[&hash].1);
        drop(archive);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn committed_truncation_and_corrupt_frame_fail_closed() {
        let root = root("corrupt");
        let (mut archive, _, _) = Segments::open(&root, 1, 16).unwrap();
        let (_, objects) = encode(b"immutable proof");
        let (locations, state) = archive.append(&objects, &[]).unwrap();
        let mut file = OpenOptions::new().write(true).open(path(&root, 1)).unwrap();
        file.seek(SeekFrom::Start(locations[0].offset + FRAME_HEADER as u64))
            .unwrap();
        file.write_all(b"X").unwrap();
        file.sync_all().unwrap();
        assert!(archive.read(&locations[0]).is_err());
        file.set_len(state[0].1 - 1).unwrap();
        drop(file);
        drop(archive);
        assert!(Segments::open(&root, 1, state[0].1).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn only_unpublished_valid_header_prefix_can_be_repaired() {
        for length in [0usize, 1, 8, 12, 15] {
            let root = root("header");
            fs::create_dir(&root).unwrap();
            let header = [HEADER.as_slice(), &1u64.to_le_bytes()].concat();
            fs::write(path(&root, 1), &header[..length]).unwrap();
            assert!(
                Segments::open(&root, 1, 16).is_err(),
                "published partial header"
            );
            let (archive, orphans, _) = Segments::open(&root, 1, 0).unwrap();
            assert_eq!(archive.length, 16);
            assert!(orphans.is_empty());
            drop(archive);
            fs::remove_dir_all(root).unwrap();
        }
        let root = root("bad-header");
        fs::create_dir(&root).unwrap();
        fs::write(path(&root, 1), b"wrong").unwrap();
        assert!(Segments::open(&root, 1, 0).is_err());
        assert_eq!(fs::read(path(&root, 1)).unwrap(), b"wrong");
        fs::remove_dir_all(root).unwrap();
    }
}
