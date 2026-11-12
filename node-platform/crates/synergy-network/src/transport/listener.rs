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
        self.accept_configured(configure_tcp_stream)
    }

    fn accept_configured(
        &self,
        configure: impl FnOnce(&std::net::TcpStream, TransportTimeouts) -> std::io::Result<()>,
    ) -> Result<Option<TransportConnection>, TransportError> {
        match self.listener.accept() {
            Ok((stream, address)) => {
                configure(&stream, self.timeouts)
                    .map_err(TransportError::AcceptedStreamConfiguration)?;
                Ok(Some(TransportConnection::new(stream, address, true)))
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(TransportError::Io(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    #[test]
    fn failed_accepted_stream_configuration_preserves_listener() {
        let timeouts = TransportTimeouts {
            connect: Duration::from_secs(2),
            handshake: Duration::from_secs(2),
            read: Duration::from_secs(2),
            write: Duration::from_secs(2),
        };
        let listener = TcpListenerService::bind("127.0.0.1:0", timeouts).unwrap();
        let address = listener.local_addr().unwrap();
        let _first = TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let error = loop {
            match listener.accept_configured(|_, _| Err(std::io::Error::from_raw_os_error(22))) {
                Err(error) => break error,
                Ok(None) => {
                    assert!(Instant::now() < deadline, "first connection was not queued");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(Some(_)) => panic!("injected stream configuration unexpectedly succeeded"),
            }
        };
        assert!(matches!(
            error,
            TransportError::AcceptedStreamConfiguration(_)
        ));
        let _second = TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if listener.accept().unwrap().is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "healthy connection was not queued"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(listener.accept().unwrap().is_none());
    }
}
