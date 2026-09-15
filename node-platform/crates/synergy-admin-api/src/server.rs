#[cfg(unix)]
pub use crate::local::LocalAdminServer;

pub trait AuthorizedAdminService: Send + Sync {
    fn handle_authorized(
        &self,
        request: crate::protocol::AdminCommandRequest,
        authorization: &crate::authorization::AuthorizationContext,
    ) -> crate::protocol::AdminCommandResponse;
}
