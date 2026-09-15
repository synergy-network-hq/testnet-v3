use std::{io, net::TcpStream};

use super::TransportTimeouts;

pub fn configure_tcp_stream(stream: &TcpStream, timeouts: TransportTimeouts) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(timeouts.read))?;
    stream.set_write_timeout(Some(timeouts.write))?;
    Ok(())
}
