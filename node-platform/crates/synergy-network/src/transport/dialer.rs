use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

use super::{configure_tcp_stream, TransportConnection, TransportError, TransportTimeouts};

#[derive(Debug, Clone, Copy)]
pub struct TcpDialer {
    timeouts: TransportTimeouts,
}

impl TcpDialer {
    pub fn new(timeouts: TransportTimeouts) -> Result<Self, TransportError> {
        Ok(Self {
            timeouts: timeouts.validate()?,
        })
    }

    pub fn dial(&self, address: impl ToSocketAddrs) -> Result<TransportConnection, TransportError> {
        let addresses = address
            .to_socket_addrs()
            .map_err(TransportError::Io)?
            .collect::<Vec<SocketAddr>>();
        if addresses.is_empty() {
            return Err(TransportError::UnresolvedAddress);
        }
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect_timeout(&address, self.timeouts.connect) {
                Ok(stream) => {
                    configure_tcp_stream(&stream, self.timeouts).map_err(TransportError::Io)?;
                    return Ok(TransportConnection::new(stream, address, false));
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error
            .map(TransportError::Io)
            .unwrap_or(TransportError::UnresolvedAddress))
    }
}
