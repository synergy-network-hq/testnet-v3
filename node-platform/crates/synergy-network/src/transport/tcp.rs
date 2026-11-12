use std::{io, net::TcpStream};

use super::TransportTimeouts;

pub fn configure_tcp_stream(stream: &TcpStream, timeouts: TransportTimeouts) -> io::Result<()> {
    // Accepted sockets can inherit the listener's nonblocking mode. Session
    // workers perform blocking I/O with deadlines on their dedicated threads.
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(timeouts.read))?;
    stream.set_write_timeout(Some(timeouts.write))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn session_stream_waits_for_delayed_handshake_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        configure_tcp_stream(
            &stream,
            TransportTimeouts {
                connect: Duration::from_secs(2),
                read: Duration::from_secs(2),
                write: Duration::from_secs(2),
                handshake: Duration::from_secs(2),
            },
        )
        .unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            client.write_all(b"hello").unwrap();
        });
        let mut bytes = [0; 5];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"hello");
        writer.join().unwrap();
    }
}
