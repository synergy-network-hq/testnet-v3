use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    time::Duration,
};

use super::TransportError;

#[derive(Debug)]
pub struct TransportConnection {
    stream: TcpStream,
    peer_addr: SocketAddr,
    inbound: bool,
}

impl TransportConnection {
    pub(crate) fn new(stream: TcpStream, peer_addr: SocketAddr, inbound: bool) -> Self {
        Self {
            stream,
            peer_addr,
            inbound,
        }
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn is_inbound(&self) -> bool {
        self.inbound
    }

    pub fn read_exact(&mut self, bytes: &mut [u8]) -> Result<(), TransportError> {
        self.stream.read_exact(bytes).map_err(TransportError::Io)
    }

    pub fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.stream.write_all(bytes).map_err(TransportError::Io)
    }

    pub fn flush(&mut self) -> Result<(), TransportError> {
        self.stream.flush().map_err(TransportError::Io)
    }

    pub fn set_read_timeout(&self, timeout: Duration) -> Result<(), TransportError> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(TransportError::Io)
    }

    pub fn try_clone(&self) -> Result<Self, TransportError> {
        let stream = self.stream.try_clone().map_err(TransportError::Io)?;
        Ok(Self::new(stream, self.peer_addr, self.inbound))
    }

    pub fn shutdown(&self) -> Result<(), TransportError> {
        self.stream
            .shutdown(Shutdown::Both)
            .map_err(TransportError::Io)
    }
}
