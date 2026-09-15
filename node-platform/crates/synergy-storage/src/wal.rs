use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{fsync::sync_directory, IntegrityDigest, StorageError};

const WAL_DOMAIN: &str = "SYNERGY_WAL_RECORD_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalRecord {
    pub sequence: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct WriteAheadLog {
    path: PathBuf,
    max_record_bytes: usize,
    next_sequence: u64,
    poisoned: bool,
}

impl WriteAheadLog {
    pub fn open(path: impl AsRef<Path>, max_record_bytes: usize) -> Result<Self, StorageError> {
        if max_record_bytes == 0 {
            return Err(StorageError::RecordTooLarge {
                actual: 1,
                maximum: 0,
            });
        }
        let path = path.as_ref().to_path_buf();
        let records = replay_path(&path, max_record_bytes)?;
        let next_sequence = records
            .last()
            .map(|record| {
                record
                    .sequence
                    .checked_add(1)
                    .ok_or(StorageError::CorruptWal)
            })
            .transpose()?
            .unwrap_or(0);
        Ok(Self {
            path,
            max_record_bytes,
            next_sequence,
            poisoned: false,
        })
    }

    pub fn append(&mut self, payload: &[u8]) -> Result<u64, StorageError> {
        if self.poisoned {
            return Err(StorageError::CorruptWal);
        }
        if payload.len() > self.max_record_bytes {
            return Err(StorageError::RecordTooLarge {
                actual: payload.len(),
                maximum: self.max_record_bytes,
            });
        }
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty());
        if let Some(parent) = parent {
            std::fs::create_dir_all(parent).map_err(io_error)?;
        }
        let sequence = self.next_sequence;
        let next_sequence = sequence.checked_add(1).ok_or(StorageError::CorruptWal)?;
        let digest = IntegrityDigest::of(WAL_DOMAIN, &record_bytes(sequence, payload));
        let new_file = !self.path.exists();
        let result = (|| {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .map_err(io_error)?;
            file.write_all(&sequence.to_be_bytes()).map_err(io_error)?;
            file.write_all(&(payload.len() as u64).to_be_bytes())
                .map_err(io_error)?;
            file.write_all(digest.0.as_bytes()).map_err(io_error)?;
            file.write_all(payload).map_err(io_error)?;
            file.sync_data().map_err(io_error)?;
            if new_file {
                if let Some(parent) = parent {
                    sync_directory(parent)?;
                }
            }
            Ok(())
        })();
        if result.is_err() {
            // A partial record must never be followed by another append in this process.
            // Reopen forces a full replay and rejects a damaged log.
            self.poisoned = true;
        } else {
            self.next_sequence = next_sequence;
        }
        result.map(|()| sequence)
    }

    pub fn replay(&self) -> Result<Vec<WalRecord>, StorageError> {
        replay_path(&self.path, self.max_record_bytes)
    }
}

fn replay_path(path: &Path, maximum: usize) -> Result<Vec<WalRecord>, StorageError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut file = std::fs::File::open(path).map_err(io_error)?;
    let mut records = Vec::new();
    let mut expected_sequence = 0u64;
    loop {
        let Some(sequence) = read_u64(&mut file)? else {
            break;
        };
        let length = read_u64(&mut file)?.ok_or(StorageError::CorruptWal)?;
        let length = usize::try_from(length).map_err(|_| StorageError::RecordTooLarge {
            actual: usize::MAX,
            maximum,
        })?;
        if length > maximum {
            return Err(StorageError::RecordTooLarge {
                actual: length,
                maximum,
            });
        }
        let mut digest = [0u8; 64];
        file.read_exact(&mut digest)
            .map_err(|_| StorageError::CorruptWal)?;
        let digest = std::str::from_utf8(&digest).map_err(|_| StorageError::CorruptWal)?;
        let mut payload = vec![0u8; length];
        file.read_exact(&mut payload)
            .map_err(|_| StorageError::CorruptWal)?;
        if sequence != expected_sequence
            || IntegrityDigest(digest.to_string())
                .verify(WAL_DOMAIN, &record_bytes(sequence, &payload))
                .is_err()
        {
            return Err(StorageError::CorruptWal);
        }
        records.push(WalRecord { sequence, payload });
        expected_sequence = expected_sequence.saturating_add(1);
    }
    Ok(records)
}

fn read_u64(file: &mut std::fs::File) -> Result<Option<u64>, StorageError> {
    let mut bytes = [0u8; 8];
    match file.read(&mut bytes[..1]).map_err(io_error)? {
        0 => Ok(None),
        1 => {
            file.read_exact(&mut bytes[1..])
                .map_err(|_| StorageError::CorruptWal)?;
            Ok(Some(u64::from_be_bytes(bytes)))
        }
        _ => unreachable!(),
    }
}

fn record_bytes(sequence: u64, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16 + payload.len());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn io_error(error: std::io::Error) -> StorageError {
    StorageError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "synergy-wal-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    #[test]
    fn durable_replay_preserves_sequence_and_payload() {
        let path = path("replay");
        let mut log = WriteAheadLog::open(&path, 32).unwrap();
        assert_eq!(log.append(b"first").unwrap(), 0);
        assert_eq!(log.append(b"second").unwrap(), 1);
        let reopened = WriteAheadLog::open(&path, 32).unwrap();
        assert_eq!(
            reopened.replay().unwrap(),
            vec![
                WalRecord {
                    sequence: 0,
                    payload: b"first".to_vec()
                },
                WalRecord {
                    sequence: 1,
                    payload: b"second".to_vec()
                },
            ]
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn truncated_header_fails_closed() {
        let path = path("truncated");
        std::fs::write(&path, [0u8; 3]).unwrap();
        assert!(matches!(
            WriteAheadLog::open(&path, 32),
            Err(StorageError::CorruptWal)
        ));
        std::fs::remove_file(path).unwrap();
    }
}
