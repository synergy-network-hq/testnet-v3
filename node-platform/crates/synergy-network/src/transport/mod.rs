//! Network endpoint normalization. Endpoints are routing data, not identity.

mod address;
mod connection;
mod dialer;
mod limits;
mod listener;
mod tcp;
mod timeout;
mod transport;

pub use address::parse_dial_address;
pub use connection::TransportConnection;
pub use dialer::TcpDialer;
pub use limits::TransportLimits;
pub use listener::TcpListenerService;
pub use tcp::configure_tcp_stream;
pub use timeout::TransportTimeouts;
pub use transport::{TcpTransport, Transport, TransportError};
