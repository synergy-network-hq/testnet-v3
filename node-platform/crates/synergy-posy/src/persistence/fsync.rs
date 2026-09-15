use std::{fs::File, io, path::Path};

/// Explicit durability boundary used by PoSy persistence owners.
pub trait FsyncBarrier: Send + Sync {
    fn sync_file(&self, path: &Path) -> io::Result<()>;
    fn sync_directory(&self, path: &Path) -> io::Result<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OperatingSystemFsync;

impl FsyncBarrier for OperatingSystemFsync {
    fn sync_file(&self, path: &Path) -> io::Result<()> {
        File::open(path)?.sync_all()
    }

    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        File::open(path)?.sync_all()
    }
}
