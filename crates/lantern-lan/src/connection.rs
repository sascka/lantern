// SPDX-License-Identifier: MPL-2.0

use core::{fmt, time::Duration};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
};

use crate::{
    BindAddress, LAN_PROTOCOL_VERSION, LanError, PeerAddress,
    hello::{HELLO_BYTES, decode_hello, encode_hello},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// A TCP connection that completed the fixed version handshake.
pub struct LanConnection {
    stream: TcpStream,
}

impl LanConnection {
    pub const fn protocol_version(&self) -> u8 {
        LAN_PROTOCOL_VERSION
    }

    pub fn shutdown(self) -> Result<(), LanError> {
        self.stream
            .shutdown(std::net::Shutdown::Both)
            .map_err(|_| LanError::ShutdownFailed)
    }
}

impl fmt::Debug for LanConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LanConnection")
            .field("protocol_version", &LAN_PROTOCOL_VERSION)
            .finish_non_exhaustive()
    }
}

/// One blocking listener for a manually selected private or loopback address.
pub struct LanListener {
    listener: TcpListener,
}

impl LanListener {
    pub fn bind(address: BindAddress) -> Result<Self, LanError> {
        let listener =
            TcpListener::bind(address.socket_addr()).map_err(|_| LanError::BindFailed)?;
        Ok(Self { listener })
    }

    pub fn local_address(&self) -> Result<BindAddress, LanError> {
        let address = self
            .listener
            .local_addr()
            .map_err(|_| LanError::ConnectionSetupFailed)?;
        BindAddress::try_new(address).map_err(|_| LanError::ConnectionSetupFailed)
    }

    pub fn accept(&self) -> Result<LanConnection, LanError> {
        self.accept_with_timeout(HANDSHAKE_TIMEOUT)
    }

    fn accept_with_timeout(&self, timeout: Duration) -> Result<LanConnection, LanError> {
        let (stream, _) = self.listener.accept().map_err(|_| LanError::AcceptFailed)?;
        finish_connection(stream, timeout)
    }
}

impl fmt::Debug for LanListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LanListener")
            .finish_non_exhaustive()
    }
}

pub fn connect(address: PeerAddress) -> Result<LanConnection, LanError> {
    let stream = TcpStream::connect_timeout(&address.socket_addr(), CONNECT_TIMEOUT)
        .map_err(|_| LanError::ConnectFailed)?;
    finish_connection(stream, HANDSHAKE_TIMEOUT)
}

fn finish_connection(stream: TcpStream, timeout: Duration) -> Result<LanConnection, LanError> {
    configure_stream(&stream, timeout)?;
    exchange_hello(&stream)?;
    Ok(LanConnection { stream })
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> Result<(), LanError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| LanError::ConnectionSetupFailed)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| LanError::ConnectionSetupFailed)?;
    stream
        .set_nodelay(true)
        .map_err(|_| LanError::ConnectionSetupFailed)
}

fn exchange_hello(mut stream: &TcpStream) -> Result<(), LanError> {
    stream
        .write_all(&encode_hello())
        .map_err(map_handshake_io)?;
    stream.flush().map_err(map_handshake_io)?;

    let mut incoming = [0_u8; HELLO_BYTES];
    stream.read_exact(&mut incoming).map_err(map_handshake_io)?;
    decode_hello(incoming)
}

fn map_handshake_io(error: io::Error) -> LanError {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => LanError::HandshakeTimedOut,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe => LanError::ConnectionClosed,
        _ => LanError::HandshakeIoFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::{LanListener, connect, encode_hello};
    use crate::{BindAddress, LAN_PROTOCOL_VERSION, LanError, PeerAddress};
    use core::time::Duration;
    use std::{
        io::{Read, Write},
        net::{SocketAddr, TcpStream},
        thread,
    };

    fn loopback_listener() -> LanListener {
        let address: SocketAddr = match "127.0.0.1:0".parse() {
            Ok(address) => address,
            Err(_) => panic!("loopback test address should parse"),
        };
        let address = match BindAddress::try_new(address) {
            Ok(address) => address,
            Err(_) => panic!("loopback test address should be allowed"),
        };
        match LanListener::bind(address) {
            Ok(listener) => listener,
            Err(_) => panic!("loopback listener should bind"),
        }
    }

    fn peer_address(listener: &LanListener) -> PeerAddress {
        let address = match listener.local_address() {
            Ok(address) => address.socket_addr(),
            Err(_) => panic!("bound listener should have a local address"),
        };
        match PeerAddress::try_new(address) {
            Ok(address) => address,
            Err(_) => panic!("bound loopback address should be a peer address"),
        }
    }

    #[test]
    fn two_tcp_sides_negotiate_the_same_version() {
        let listener = loopback_listener();
        let peer = peer_address(&listener);
        let server = thread::spawn(move || listener.accept());

        let client = connect(peer);
        let Ok(client) = client else {
            panic!("client handshake should succeed");
        };
        let server = match server.join() {
            Ok(result) => result,
            Err(_) => panic!("server thread should not panic"),
        };
        let Ok(server) = server else {
            panic!("server handshake should succeed");
        };

        assert_eq!(client.protocol_version(), LAN_PROTOCOL_VERSION);
        assert_eq!(server.protocol_version(), LAN_PROTOCOL_VERSION);
    }

    #[test]
    fn fragmented_hello_is_read_without_allocating_a_body() {
        let listener = loopback_listener();
        let peer = peer_address(&listener);
        let server = thread::spawn(move || listener.accept());

        let mut raw = match TcpStream::connect(peer.socket_addr()) {
            Ok(stream) => stream,
            Err(_) => panic!("raw loopback client should connect"),
        };
        let mut server_hello = [0_u8; 8];
        if raw.read_exact(&mut server_hello).is_err() {
            panic!("raw client should receive the server hello");
        }
        for byte in encode_hello() {
            if raw.write_all(&[byte]).is_err() {
                panic!("fragmented test hello should be written");
            }
        }

        let result = match server.join() {
            Ok(result) => result,
            Err(_) => panic!("server thread should not panic"),
        };
        assert!(result.is_ok());
    }

    #[test]
    fn unsupported_version_is_rejected_before_application_data() {
        let listener = loopback_listener();
        let peer = peer_address(&listener);
        let server = thread::spawn(move || listener.accept());

        let mut raw = match TcpStream::connect(peer.socket_addr()) {
            Ok(stream) => stream,
            Err(_) => panic!("raw loopback client should connect"),
        };
        let mut server_hello = [0_u8; 8];
        if raw.read_exact(&mut server_hello).is_err() {
            panic!("raw client should receive the server hello");
        }
        let mut unsupported = encode_hello();
        unsupported[5] = LAN_PROTOCOL_VERSION + 1;
        if raw.write_all(&unsupported).is_err() {
            panic!("unsupported test hello should be written");
        }

        let result = match server.join() {
            Ok(result) => result,
            Err(_) => panic!("server thread should not panic"),
        };
        assert!(matches!(result, Err(LanError::UnsupportedVersion)));
    }

    #[test]
    fn connection_closed_during_hello_is_rejected() {
        let listener = loopback_listener();
        let peer = peer_address(&listener);
        let server = thread::spawn(move || listener.accept());

        let mut raw = match TcpStream::connect(peer.socket_addr()) {
            Ok(stream) => stream,
            Err(_) => panic!("raw loopback client should connect"),
        };
        let mut server_hello = [0_u8; 8];
        if raw.read_exact(&mut server_hello).is_err() {
            panic!("raw client should receive the server hello");
        }
        if raw.write_all(&encode_hello()[..3]).is_err() {
            panic!("partial test hello should be written");
        }
        if raw.shutdown(std::net::Shutdown::Write).is_err() {
            panic!("raw client should close its write side");
        }

        let result = match server.join() {
            Ok(result) => result,
            Err(_) => panic!("server thread should not panic"),
        };
        assert!(matches!(result, Err(LanError::ConnectionClosed)));
    }

    #[test]
    fn stalled_peer_is_stopped_by_the_handshake_timeout() {
        let listener = loopback_listener();
        let peer = peer_address(&listener);
        let server = thread::spawn(move || listener.accept_with_timeout(Duration::from_millis(25)));

        let _raw = match TcpStream::connect(peer.socket_addr()) {
            Ok(stream) => stream,
            Err(_) => panic!("raw loopback client should connect"),
        };
        let result = match server.join() {
            Ok(result) => result,
            Err(_) => panic!("server thread should not panic"),
        };
        assert!(matches!(result, Err(LanError::HandshakeTimedOut)));
    }

    #[test]
    fn debug_output_contains_no_socket_addresses() {
        let listener = loopback_listener();
        let marker = match listener.local_address() {
            Ok(address) => format!("{}", address.socket_addr()),
            Err(_) => panic!("bound listener should have a local address"),
        };
        assert!(!format!("{listener:?}").contains(&marker));
    }
}
