//! Exclusive single-writer lock for single-authority durable state.
//!
//! Two writable handles to the same finality log or signing journal would
//! break the sign-once and one-block-per-height guarantees, so writable open
//! must be exclusive. Read-only inspection never takes the writer role.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

static HELD_WRITER_PATHS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

fn held() -> &'static Mutex<HashSet<PathBuf>> {
    HELD_WRITER_PATHS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// RAII writer claim. Dropping it releases the path for reuse.
#[derive(Debug)]
pub struct SingleAuthorityWriterLock {
    path: PathBuf,
}

impl SingleAuthorityWriterLock {
    pub fn acquire(path: &Path) -> Result<Self, String> {
        let canonical = path.to_path_buf();
        let mut guard = held()
            .lock()
            .map_err(|_| "single-authority writer lock poisoned".to_string())?;
        if !guard.insert(canonical.clone()) {
            return Err(format!(
                "single-authority writable state {} is already open for writing; \
                 refusing a second writer",
                canonical.display()
            ));
        }
        Ok(Self { path: canonical })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SingleAuthorityWriterLock {
    fn drop(&mut self) {
        if let Ok(mut guard) = held().lock() {
            guard.remove(&self.path);
        }
    }
}
