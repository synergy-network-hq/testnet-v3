use crate::{BlockRequest, BlockResponse};

pub trait ArchiveSyncSource {
    fn archive_id(&self) -> &str;
    fn authenticated(&self) -> bool;
    fn finalized_blocks(&self, request: &BlockRequest) -> Result<BlockResponse, String>;
}

pub fn request_authenticated_archive(
    source: &impl ArchiveSyncSource,
    request: &BlockRequest,
) -> Result<BlockResponse, String> {
    if !source.authenticated() || source.archive_id().trim().is_empty() || !request.validate() {
        return Err("ineligible archive sync source".into());
    }
    source.finalized_blocks(request)
}
