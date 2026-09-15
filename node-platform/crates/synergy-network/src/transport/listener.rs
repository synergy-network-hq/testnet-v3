use std::net::{SocketAddr, TcpListener, ToSocketAddrs};

use super::{configure_tcp_stream, TransportConnection, TransportError, TransportTimeouts};

#[derive(Debug)]
pub struct TcpListenerService {
    listener: TcpListener,
    timeouts: TransportTimeouts,
}

impl TcpListenerService {
    pub fn bind(
        address: impl ToSocketAddrs,
        timeouts: TransportTimeouts,
    ) -> Result<Self, TransportError> {
        let timeouts = timeouts.validate()?;
        let listener = TcpListener::bind(address).map_err(TransportError::Io)?;
        listener.set_nonblocking(true).map_err(TransportError::Io)?;
        Ok(Self { listener, timeouts })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.listener.local_addr().map_err(TransportError::Io)
    }

    pub fn accept(&self) -> Result<Option<TransportConnection>, TransportError> {
        match self.listener.accept() {
            Ok((stream, address)) => {
                configure_tcp_stream(&stream, self.timeouts).map_err(TransportError::Io)?;
                Ok(Some(TransportConnection::new(stream, address, true)))
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(TransportError::Io(error)),
        }
    }
}
