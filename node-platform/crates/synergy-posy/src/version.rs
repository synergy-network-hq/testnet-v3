use crate::{PosyError, PosyResult, POSY_SIMPLIFIED_PROTOCOL_VERSION};

pub const POSY_STORAGE_FORMAT_VERSION: u32 = 1;

pub fn require_supported_protocol_version(version: &str) -> PosyResult<()> {
    if version != POSY_SIMPLIFIED_PROTOCOL_VERSION {
        return Err(PosyError::invalid(format!(
            "unsupported PoSy protocol version: {version}"
        )));
    }
    Ok(())
}

pub fn require_supported_storage_version(version: u32) -> PosyResult<()> {
    if version != POSY_STORAGE_FORMAT_VERSION {
        return Err(PosyError::invalid(format!(
            "unsupported PoSy storage format version: {version}"
        )));
    }
    Ok(())
}
