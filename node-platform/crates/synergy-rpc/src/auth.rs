#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcAccess {
    Public,
    Restricted,
}

pub trait RpcAuthenticator: Send + Sync {
    fn authorize(&self, method: &str, credential: Option<&str>) -> Result<(), crate::RpcError>;
}

#[derive(Debug, Default)]
pub struct PublicOnlyAuthenticator;

impl RpcAuthenticator for PublicOnlyAuthenticator {
    fn authorize(&self, method: &str, _credential: Option<&str>) -> Result<(), crate::RpcError> {
        if crate::methods::method_access(method) == RpcAccess::Public {
            Ok(())
        } else {
            Err(crate::RpcError {
                code: -32001,
                message: "RPC method requires authentication".into(),
            })
        }
    }
}
