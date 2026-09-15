use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use crate::verify::verify;

const COPY_BUFFER_BYTES: usize = 1024 * 1024;

pub fn export(source: &Path, destination: &Path) -> Result<(), String> {
    let verified = verify(source)?;
    if destination.exists() {
        return Err("export destination already exists".into());
    }
    fs::create_dir_all(destination).map_err(|error| {
        format!(
            "create export destination {}: {error}",
            destination.display()
        )
    })?;
    for entry in &verified.inventory.entries {
        let source_path = source.join(&entry.relative_path);
        let destination_path = destination.join(&entry.relative_path);
        let parent = destination_path
            .parent()
            .ok_or("export record has no parent")?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create export directory {}: {error}", parent.display()))?;
        let temporary = destination_path.with_extension("export-tmp");
        let mut input = fs::File::open(&source_path)
            .map_err(|error| format!("open source record {}: {error}", source_path.display()))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("create export record {}: {error}", temporary.display()))?;
        let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
        let mut copied = 0u64;
        loop {
            let read = input.read(&mut buffer).map_err(|error| {
                format!("read source record {}: {error}", source_path.display())
            })?;
            if read == 0 {
                break;
            }
            output
                .write_all(&buffer[..read])
                .map_err(|error| format!("write export record {}: {error}", temporary.display()))?;
            copied = copied
                .checked_add(read as u64)
                .ok_or("export byte count overflow")?;
        }
        if copied != entry.bytes {
            return Err(format!(
                "source record changed during export: {}",
                source_path.display()
            ));
        }
        output
            .sync_all()
            .map_err(|error| format!("sync export record: {error}"))?;
        fs::rename(&temporary, &destination_path).map_err(|error| {
            format!(
                "publish export record {}: {error}",
                destination_path.display()
            )
        })?;
    }
    let exported = verify(destination)?;
    if exported.digest != verified.digest {
        return Err("export verification digest differs from source".into());
    }
    Ok(())
}
