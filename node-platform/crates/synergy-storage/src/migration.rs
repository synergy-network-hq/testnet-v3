use crate::{AtomicStore, StorageError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaVersion {
    pub name: String,
    pub version: u32,
}

impl SchemaVersion {
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.name.trim().is_empty() || self.version == 0 {
            Err(StorageError::InvalidSchemaVersion)
        } else {
            Ok(())
        }
    }
}

pub fn write_schema_version(
    store: &AtomicStore,
    schema: &SchemaVersion,
) -> Result<(), StorageError> {
    schema.validate()?;
    store.write_atomic(
        "metadata/schema-version",
        format!("{}:{}", schema.name, schema.version).as_bytes(),
    )
}
