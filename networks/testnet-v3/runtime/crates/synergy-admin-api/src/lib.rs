//! Shared, typed contract for the local Synergy node administration surface.
//!
//! The contract intentionally starts with read-only operations. Adding a
//! mutating operation requires explicit authorization, an idempotency model,
//! and a corresponding runtime implementation; clients must never infer
//! authority from their ability to reach this API.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use synergy_node_core::{ManagementOperation, MANAGEMENT_SCHEMA_VERSION};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRequest {
    pub schema_version: u16,
    pub request_id: String,
    pub operation: ManagementOperation,
}

impl AdminRequest {
    pub fn new(request_id: impl Into<String>, operation: ManagementOperation) -> Self {
        Self {
            schema_version: MANAGEMENT_SCHEMA_VERSION,
            request_id: request_id.into(),
            operation,
        }
    }

    pub fn validate(&self) -> Result<(), AdminError> {
        if self.schema_version != MANAGEMENT_SCHEMA_VERSION {
            return Err(AdminError::unsupported_schema(self.schema_version));
        }
        if self.request_id.trim().is_empty() {
            return Err(AdminError::invalid_request("request_id must not be empty"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminResponse {
    pub schema_version: u16,
    pub request_id: String,
    pub result: Result<Value, AdminError>,
}

impl AdminResponse {
    pub fn success(request_id: impl Into<String>, value: Value) -> Self {
        Self {
            schema_version: MANAGEMENT_SCHEMA_VERSION,
            request_id: request_id.into(),
            result: Ok(value),
        }
    }

    pub fn failure(request_id: impl Into<String>, error: AdminError) -> Self {
        Self {
            schema_version: MANAGEMENT_SCHEMA_VERSION,
            request_id: request_id.into(),
            result: Err(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl AdminError {
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            code: "invalid_request".to_string(),
            message: message.into(),
            retryable: false,
        }
    }

    pub fn unsupported_schema(schema_version: u16) -> Self {
        Self {
            code: "unsupported_schema".to_string(),
            message: format!("management schema version {schema_version} is unsupported"),
            retryable: false,
        }
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: "unavailable".to_string(),
            message: message.into(),
            retryable: true,
        }
    }
}

/// Runtime-owned dispatcher implemented once and consumed by every client.
/// CLI and GUI code must not duplicate management decisions around this trait.
pub trait AdminService: Send + Sync {
    fn handle(&self, request: AdminRequest) -> AdminResponse;
}

/// Unix-domain transport for the local Admin API. A filesystem socket is used
/// deliberately: it has no routable address and is permissioned by the host
/// operating system. The server never binds TCP on behalf of administration.
#[cfg(unix)]
pub mod local {
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use super::{AdminError, AdminRequest, AdminResponse, AdminService};

    const MAX_REQUEST_BYTES: usize = 1024 * 1024;

    pub struct LocalAdminServer {
        socket_path: PathBuf,
        running: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl LocalAdminServer {
        pub fn start<S>(socket_path: impl AsRef<Path>, service: Arc<S>) -> Result<Self, AdminError>
        where
            S: AdminService + 'static,
        {
            let socket_path = socket_path.as_ref().to_path_buf();
            let parent = socket_path.parent().ok_or_else(|| {
                AdminError::invalid_request("local Admin API socket must have a parent directory")
            })?;
            if !parent.is_dir() {
                return Err(AdminError::invalid_request(format!(
                    "local Admin API parent directory does not exist: {}",
                    parent.display()
                )));
            }
            remove_stale_socket(&socket_path)?;
            let listener = UnixListener::bind(&socket_path).map_err(|error| {
                AdminError::unavailable(format!(
                    "bind local Admin API socket {}: {error}",
                    socket_path.display()
                ))
            })?;
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).map_err(
                |error| {
                    AdminError::unavailable(format!(
                        "restrict local Admin API socket {}: {error}",
                        socket_path.display()
                    ))
                },
            )?;
            listener.set_nonblocking(true).map_err(|error| {
                AdminError::unavailable(format!("configure local Admin API socket: {error}"))
            })?;

            let running = Arc::new(AtomicBool::new(true));
            let worker_running = Arc::clone(&running);
            let worker = thread::Builder::new()
                .name("synergy-local-admin-api".to_string())
                .spawn(move || {
                    while worker_running.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                // Accepted sockets inherit the listener's
                                // nonblocking mode on macOS. Request framing
                                // is deliberately blocking once admitted so a
                                // peer cannot be rejected merely because its
                                // first bytes have not arrived yet.
                                if stream.set_nonblocking(false).is_ok() {
                                    handle_connection(stream, service.as_ref());
                                }
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(25));
                            }
                            Err(_) => thread::sleep(Duration::from_millis(25)),
                        }
                    }
                })
                .map_err(|error| {
                    AdminError::unavailable(format!("start local Admin API worker: {error}"))
                })?;

            Ok(Self {
                socket_path,
                running,
                worker: Some(worker),
            })
        }

        pub fn socket_path(&self) -> &Path {
            &self.socket_path
        }

        pub fn shutdown(mut self) {
            self.stop();
        }

        fn stop(&mut self) {
            self.running.store(false, Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            let _ = remove_stale_socket(&self.socket_path);
        }
    }

    impl Drop for LocalAdminServer {
        fn drop(&mut self) {
            self.stop();
        }
    }

    pub fn request(
        socket_path: impl AsRef<Path>,
        request: &AdminRequest,
    ) -> Result<AdminResponse, AdminError> {
        request.validate()?;
        let mut stream = UnixStream::connect(socket_path.as_ref()).map_err(|error| {
            AdminError::unavailable(format!(
                "connect local Admin API socket {}: {error}",
                socket_path.as_ref().display()
            ))
        })?;
        let payload = serde_json::to_vec(request).map_err(|error| {
            AdminError::unavailable(format!("serialize local Admin API request: {error}"))
        })?;
        if payload.len() > MAX_REQUEST_BYTES {
            return Err(AdminError::invalid_request(
                "local Admin API request is too large",
            ));
        }
        stream.write_all(&payload).map_err(|error| {
            AdminError::unavailable(format!("write local Admin API request: {error}"))
        })?;
        stream.write_all(b"\n").map_err(|error| {
            AdminError::unavailable(format!("terminate local Admin API request: {error}"))
        })?;
        stream.flush().map_err(|error| {
            AdminError::unavailable(format!("flush local Admin API request: {error}"))
        })?;

        let mut response = String::new();
        let bytes = BufReader::new(stream)
            .read_line(&mut response)
            .map_err(|error| {
                AdminError::unavailable(format!("read local Admin API response: {error}"))
            })?;
        if bytes == 0 || response.len() > MAX_REQUEST_BYTES {
            return Err(AdminError::unavailable(
                "local Admin API returned an empty or oversized response",
            ));
        }
        serde_json::from_str(&response).map_err(|error| {
            AdminError::unavailable(format!("decode local Admin API response: {error}"))
        })
    }

    fn handle_connection(mut stream: UnixStream, service: &dyn AdminService) {
        let mut request_text = String::new();
        let read_result = BufReader::new(&mut stream).read_line(&mut request_text);
        let response = match read_result {
            Ok(bytes) if bytes > 0 && request_text.len() <= MAX_REQUEST_BYTES => {
                match serde_json::from_str::<AdminRequest>(&request_text) {
                    Ok(request) => service.handle(request),
                    Err(error) => AdminResponse::failure(
                        "invalid-request",
                        AdminError::invalid_request(format!(
                            "decode local Admin API request: {error}"
                        )),
                    ),
                }
            }
            Ok(_) => AdminResponse::failure(
                "invalid-request",
                AdminError::invalid_request("local Admin API request is empty or too large"),
            ),
            Err(error) => AdminResponse::failure(
                "invalid-request",
                AdminError::invalid_request(format!("read local Admin API request: {error}")),
            ),
        };
        if let Ok(encoded) = serde_json::to_vec(&response) {
            let _ = stream.write_all(&encoded);
            let _ = stream.write_all(b"\n");
            let _ = stream.flush();
        }
    }

    fn remove_stale_socket(socket_path: &Path) -> Result<(), AdminError> {
        let metadata = match fs::symlink_metadata(socket_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(AdminError::unavailable(format!(
                    "inspect local Admin API socket {}: {error}",
                    socket_path.display()
                )))
            }
        };
        if !metadata.file_type().is_socket() {
            return Err(AdminError::invalid_request(format!(
                "refusing to replace non-socket Admin API path {}",
                socket_path.display()
            )));
        }
        fs::remove_file(socket_path).map_err(|error| {
            AdminError::unavailable(format!(
                "remove stale local Admin API socket {}: {error}",
                socket_path.display()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_request_id() {
        let request = AdminRequest::new("", ManagementOperation::Health);
        assert_eq!(request.validate().unwrap_err().code, "invalid_request");
    }

    #[test]
    fn response_keeps_request_correlation() {
        let response = AdminResponse::success("req-42", serde_json::json!({"ok": true}));
        assert_eq!(response.request_id, "req-42");
        assert!(response.result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn local_transport_preserves_typed_request_and_response() {
        use std::sync::Arc;
        use std::time::{SystemTime, UNIX_EPOCH};

        struct Echo;

        impl AdminService for Echo {
            fn handle(&self, request: AdminRequest) -> AdminResponse {
                AdminResponse::success(
                    request.request_id,
                    serde_json::json!({"operation": request.operation}),
                )
            }
        }

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "synergy-admin-api-{}-{unique}.sock",
            std::process::id()
        ));
        let server = local::LocalAdminServer::start(&path, Arc::new(Echo))
            .expect("local Admin API should bind its Unix socket");
        let response = local::request(
            &path,
            &AdminRequest::new("req-1", ManagementOperation::Health),
        )
        .expect("local Admin API should return a typed response");
        assert_eq!(response.request_id, "req-1", "response: {response:?}");
        assert_eq!(response.result.expect("success")["operation"], "health");
        server.shutdown();
        assert!(!path.exists());
    }
}
