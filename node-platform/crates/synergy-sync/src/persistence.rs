use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha3::{Digest, Sha3_256};

use crate::{ReceivedChunk, ResumeError, ResumeToken};

const MAGIC: &[u8; 8] = b"SYNSYNC1";
const HASH_BYTES: usize = 32;
const HEX_ID_BYTES: usize = 64;
const ENTRY_BYTES: usize = 16 + HEX_ID_BYTES;
const MAX_RESUME_CHUNKS: usize = 1_000_000;
const MAX_RESUME_BYTES: u64 = 128 * 1024 * 1024;

/// Failure while encoding or durably storing a new-format resume token.
#[derive(Debug)]
pub enum PersistenceError {
    Io(std::io::Error),
    Resume(ResumeError),
    InvalidFormat,
    TooLarge,
    IntegrityMismatch,
    LengthOverflow,
}

impl From<std::io::Error> for PersistenceError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Encodes a resume token using the canonical `SYNSYNC1` format.
///
/// # Errors
/// Returns an error if entry counts or encoded lengths exceed format bounds.
pub fn encode_resume_token(token: &ResumeToken) -> Result<Vec<u8>, PersistenceError> {
    if token.chunks().len() > MAX_RESUME_CHUNKS {
        return Err(PersistenceError::TooLarge);
    }
    let entries_bytes = token
        .chunks()
        .len()
        .checked_mul(ENTRY_BYTES)
        .ok_or(PersistenceError::LengthOverflow)?;
    let payload_len = MAGIC
        .len()
        .checked_add(HEX_ID_BYTES + 8)
        .and_then(|length| length.checked_add(entries_bytes))
        .ok_or(PersistenceError::LengthOverflow)?;
    let total_len = payload_len
        .checked_add(HASH_BYTES)
        .ok_or(PersistenceError::LengthOverflow)?;
    if total_len as u64 > MAX_RESUME_BYTES {
        return Err(PersistenceError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(token.checkpoint_id().as_bytes());
    bytes.extend_from_slice(&(token.chunks().len() as u64).to_be_bytes());
    for chunk in token.chunks() {
        bytes.extend_from_slice(&chunk.index.to_be_bytes());
        bytes.extend_from_slice(&chunk.byte_len.to_be_bytes());
        bytes.extend_from_slice(chunk.digest.as_bytes());
    }
    let integrity = integrity_hash(&bytes);
    bytes.extend_from_slice(&integrity);
    Ok(bytes)
}

/// Decodes and integrity-checks the canonical `SYNSYNC1` format.
///
/// # Errors
/// Rejects legacy/unknown formats, malformed lengths, invalid metadata, and
/// integrity mismatches.
pub fn decode_resume_token(bytes: &[u8]) -> Result<ResumeToken, PersistenceError> {
    if bytes.len() as u64 > MAX_RESUME_BYTES
        || bytes.len() < MAGIC.len() + HEX_ID_BYTES + 8 + HASH_BYTES
        || bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice())
    {
        return Err(PersistenceError::InvalidFormat);
    }
    let payload_len = bytes
        .len()
        .checked_sub(HASH_BYTES)
        .ok_or(PersistenceError::InvalidFormat)?;
    let (payload, stored_hash) = bytes.split_at(payload_len);
    if integrity_hash(payload).as_slice() != stored_hash {
        return Err(PersistenceError::IntegrityMismatch);
    }
    let mut cursor = MAGIC.len();
    let checkpoint_id = read_text(payload, &mut cursor, HEX_ID_BYTES)?;
    let count = read_u64(payload, &mut cursor)?;
    let count = usize::try_from(count).map_err(|_| PersistenceError::TooLarge)?;
    if count > MAX_RESUME_CHUNKS {
        return Err(PersistenceError::TooLarge);
    }
    let expected_len = cursor
        .checked_add(
            count
                .checked_mul(ENTRY_BYTES)
                .ok_or(PersistenceError::LengthOverflow)?,
        )
        .ok_or(PersistenceError::LengthOverflow)?;
    if expected_len != payload.len() {
        return Err(PersistenceError::InvalidFormat);
    }
    let mut chunks = Vec::with_capacity(count);
    for _ in 0..count {
        chunks.push(ReceivedChunk {
            index: read_u64(payload, &mut cursor)?,
            byte_len: read_u64(payload, &mut cursor)?,
            digest: read_text(payload, &mut cursor, HEX_ID_BYTES)?,
        });
    }
    ResumeToken::new(checkpoint_id, chunks).map_err(PersistenceError::Resume)
}

/// Atomically writes one bounded resume token and synchronizes it before rename.
///
/// # Errors
/// Returns encoding or filesystem failures. Existing temporary files are not
/// overwritten.
pub fn write_resume_token(path: &Path, token: &ResumeToken) -> Result<(), PersistenceError> {
    let bytes = encode_resume_token(token)?;
    let temporary = temporary_path(path)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(PersistenceError::Io(error));
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(PersistenceError::Io(error));
    }
    Ok(())
}

/// Reads one resume token with a hard file-size limit.
///
/// # Errors
/// Rejects oversized, truncated, unknown, or integrity-invalid files.
pub fn read_resume_token(path: &Path) -> Result<ResumeToken, PersistenceError> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() > MAX_RESUME_BYTES {
        return Err(PersistenceError::TooLarge);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_RESUME_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RESUME_BYTES {
        return Err(PersistenceError::TooLarge);
    }
    decode_resume_token(&bytes)
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, PersistenceError> {
    let end = cursor
        .checked_add(8)
        .ok_or(PersistenceError::LengthOverflow)?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(PersistenceError::InvalidFormat)?;
    let array: [u8; 8] = slice
        .try_into()
        .map_err(|_| PersistenceError::InvalidFormat)?;
    *cursor = end;
    Ok(u64::from_be_bytes(array))
}

fn read_text(bytes: &[u8], cursor: &mut usize, length: usize) -> Result<String, PersistenceError> {
    let end = cursor
        .checked_add(length)
        .ok_or(PersistenceError::LengthOverflow)?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(PersistenceError::InvalidFormat)?;
    let text = std::str::from_utf8(slice).map_err(|_| PersistenceError::InvalidFormat)?;
    *cursor = end;
    Ok(text.to_owned())
}

fn integrity_hash(payload: &[u8]) -> [u8; HASH_BYTES] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"SYNERGY_SYNC_RESUME_INTEGRITY_V1");
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn temporary_path(path: &Path) -> Result<PathBuf, PersistenceError> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(PersistenceError::InvalidFormat);
    };
    Ok(path.with_file_name(format!(".{name}.{}.sync-tmp", std::process::id())))
}
