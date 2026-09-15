use crate::{BlockRequest, BlockResponse};

pub trait PeerSyncSource {
    fn peer_id(&self) -> &str;
    fn authenticated(&self) -> bool;
    fn request_blocks(&mut self, request: &BlockRequest) -> Result<BlockResponse, String>;
}

pub fn request_authenticated_peer(
    source: &mut impl PeerSyncSource,
    request: &BlockRequest,
) -> Result<BlockResponse, String> {
    if !source.authenticated() || source.peer_id().trim().is_empty() || !request.validate() {
        return Err("ineligible peer sync source".into());
    }
    source.request_blocks(request)
}
