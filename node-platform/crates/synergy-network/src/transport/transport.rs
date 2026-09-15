use std::{fmt, net::ToSocketAddrs};

use super::{TcpDialer, TcpListenerService, TransportConnection, TransportTimeouts};

#[derive(Debug)]
pub enum TransportError {
    InvalidConfiguration(String),
    UnresolvedAddress,
    Capacity,
    Io(std::io::Error),
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => write!(formatter, "{message}"),
            Self::UnresolvedAddress => write!(formatter, "transport address did not resolve"),
            Self::Capacity => write!(formatter, "transport connection capacity reached"),
            Self::Io(error) => write!(formatter, "transport I/O failed: {error}"),
        }
    }
}

impl std::error::Error for TransportError {}

pub trait Transport {
    fn listen(&self, address: impl ToSocketAddrs) -> Result<TcpListenerService, TransportError>;

    fn dial(&self, address: impl ToSocketAddrs) -> Result<TransportConnection, TransportError>;
}

#[derive(Debug, Clone, Copy)]
pub struct TcpTransport {
    timeouts: TransportTimeouts,
}

impl TcpTransport {
    pub fn new(timeouts: TransportTimeouts) -> Result<Self, TransportError> {
        Ok(Self {
            timeouts: timeouts.validate()?,
        })
    }
}

impl Transport for TcpTransport {
    fn listen(&self, address: impl ToSocketAddrs) -> Result<TcpListenerService, TransportError> {
        TcpListenerService::bind(address, self.timeouts)
    }

    fn dial(&self, address: impl ToSocketAddrs) -> Result<TransportConnection, TransportError> {
        TcpDialer::new(self.timeouts)?.dial(address)
    }
}
