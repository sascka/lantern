// SPDX-License-Identifier: MPL-2.0

use core::{fmt, time::Duration};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    time::Instant,
};

use lantern_transport::{FrameReceive, FrameTransport, TransportFailureKind};

use crate::{
    BindAddress, LAN_PROTOCOL_VERSION, LanError, PeerAddress,
    framing::{receive_wire_frame, send_wire_frame},
    hello::{HELLO_BYTES, decode_hello, encode_hello},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const FRAME_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// A TCP connection that completed the fixed version handshake.
pub struct LanConnection {
    stream: TcpStream,
    terminated: bool,
}

impl LanConnection {
    pub const fn protocol_version(&self) -> u8 {
        LAN_PROTOCOL_VERSION
    }

    pub const fn is_terminated(&self) -> bool {
        self.terminated
    }

    pub fn shutdown(self) -> Result<(), LanError> {
        self.stream
            .shutdown(std::net::Shutdown::Both)
            .map_err(|_| LanError::ShutdownFailed)
    }

    fn receive_frame_with_timeout(
        &mut self,
        destination: &mut [u8],
        timeout: Duration,
    ) -> Result<FrameReceive, TransportFailureKind> {
        if self.terminated {
            return Err(TransportFailureKind::Unavailable);
        }
        let result = receive_wire_frame(&mut self.stream, destination, timeout);
        if !matches!(result, Ok(FrameReceive::Complete(_))) {
            self.terminated = true;
        }
        result
    }
}

impl fmt::Debug for LanConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LanConnection")
            .field("protocol_version", &LAN_PROTOCOL_VERSION)
            .field("terminated", &self.terminated)
            .finish_non_exhaustive()
    }
}

impl FrameTransport for LanConnection {
    fn receive_frame(
        &mut self,
        destination: &mut [u8],
    ) -> Result<FrameReceive, TransportFailureKind> {
        self.receive_frame_with_timeout(destination, FRAME_IO_TIMEOUT)
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportFailureKind> {
        if self.terminated {
            return Err(TransportFailureKind::Unavailable);
        }
        let result = send_wire_frame(&mut self.stream, frame, FRAME_IO_TIMEOUT);
        if result.is_err() {
            self.terminated = true;
        }
        result
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
    exchange_hello(&stream, timeout)?;
    Ok(LanConnection {
        stream,
        terminated: false,
    })
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

fn exchange_hello(stream: &TcpStream, timeout: Duration) -> Result<(), LanError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(LanError::HandshakeTimedOut)?;
    write_all_before_handshake_deadline(stream, &encode_hello(), deadline)?;
    let mut incoming = [0_u8; HELLO_BYTES];
    read_exact_before_handshake_deadline(stream, &mut incoming, deadline)?;
    decode_hello(incoming)
}

fn write_all_before_handshake_deadline(
    stream: &TcpStream,
    mut source: &[u8],
    deadline: Instant,
) -> Result<(), LanError> {
    let mut stream = stream;
    while !source.is_empty() {
        stream
            .set_write_timeout(Some(handshake_time_left(deadline)?))
            .map_err(map_handshake_io)?;
        match stream.write(source) {
            Ok(0) => return Err(LanError::ConnectionClosed),
            Ok(written_bytes) => source = &source[written_bytes..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(map_handshake_io(error)),
        }
    }
    Ok(())
}

fn read_exact_before_handshake_deadline(
    stream: &TcpStream,
    mut destination: &mut [u8],
    deadline: Instant,
) -> Result<(), LanError> {
    let mut stream = stream;
    while !destination.is_empty() {
        stream
            .set_read_timeout(Some(handshake_time_left(deadline)?))
            .map_err(map_handshake_io)?;
        match stream.read(destination) {
            Ok(0) => return Err(LanError::ConnectionClosed),
            Ok(read_bytes) => destination = &mut destination[read_bytes..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(map_handshake_io(error)),
        }
    }
    Ok(())
}

fn handshake_time_left(deadline: Instant) -> Result<Duration, LanError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(LanError::HandshakeTimedOut);
    }
    Ok(remaining)
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
    use super::{LanConnection, LanListener, connect, encode_hello};
    use crate::{BindAddress, LAN_PROTOCOL_VERSION, LanError, PeerAddress};
    use core::time::Duration;
    use lantern_transport::{FrameReceive, FrameTransport, MAX_FRAME_BYTES, TransportFailureKind};
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

    fn connection_pair() -> (LanConnection, LanConnection) {
        let listener = loopback_listener();
        let peer = peer_address(&listener);
        let accepting = thread::spawn(move || listener.accept());
        let client = match connect(peer) {
            Ok(connection) => connection,
            Err(_) => panic!("client connection should complete"),
        };
        let server = match accepting.join() {
            Ok(Ok(connection)) => connection,
            Ok(Err(_)) => panic!("server connection should complete"),
            Err(_) => panic!("server thread should not panic"),
        };
        (client, server)
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

    #[test]
    fn outgoing_frame_uses_one_exact_big_endian_wire_vector() {
        let (mut client, mut server) = connection_pair();
        assert!(FrameTransport::send_frame(&mut client, &[0xa1, 0xb2]).is_ok());

        let mut wire = [0_u8; 6];
        if server.stream.read_exact(&mut wire).is_err() {
            panic!("server should read one complete wire frame");
        }
        assert_eq!(wire, [0, 0, 0, 2, 0xa1, 0xb2]);
    }

    #[test]
    fn fragmented_prefix_and_body_form_one_complete_frame() {
        let (mut client, mut server) = connection_pair();
        for byte in [0_u8, 0, 0, 3, 0x31, 0x32, 0x33] {
            if server.stream.write_all(&[byte]).is_err() {
                panic!("fragmented wire byte should be written");
            }
        }

        let mut destination = [0_u8; 3];
        assert_eq!(
            client.receive_frame(&mut destination),
            Ok(FrameReceive::Complete(3))
        );
        assert_eq!(destination, [0x31, 0x32, 0x33]);
    }

    #[test]
    fn invalid_wire_lengths_terminate_before_body_read() {
        for prefix in [[0_u8; 4], [0, 1, 0, 1]] {
            let (mut client, mut server) = connection_pair();
            if server.stream.write_all(&prefix).is_err() {
                panic!("invalid test prefix should be written");
            }
            let mut destination = [0_u8; MAX_FRAME_BYTES];
            assert_eq!(
                client.receive_frame(&mut destination),
                Err(TransportFailureKind::ProtocolViolation)
            );
            assert!(client.is_terminated());
            assert_eq!(
                client.receive_frame(&mut destination),
                Err(TransportFailureKind::Unavailable)
            );
        }
    }

    #[test]
    fn destination_capacity_is_checked_before_body_read() {
        let (mut client, mut server) = connection_pair();
        if server.stream.write_all(&[0, 0, 0, 2]).is_err() {
            panic!("capacity test prefix should be written");
        }
        let mut destination = [0_u8; 1];
        assert_eq!(
            client.receive_frame(&mut destination),
            Err(TransportFailureKind::ResourceExhausted)
        );
        assert!(client.is_terminated());
    }

    #[test]
    fn partial_body_and_clean_boundary_close_are_distinct() {
        let (mut truncated_client, mut truncated_server) = connection_pair();
        if truncated_server
            .stream
            .write_all(&[0, 0, 0, 3, 0x41])
            .is_err()
        {
            panic!("truncated frame prefix and body should be written");
        }
        if truncated_server
            .stream
            .shutdown(std::net::Shutdown::Write)
            .is_err()
        {
            panic!("truncated frame writer should close");
        }
        let mut destination = [0_u8; 3];
        assert_eq!(
            truncated_client.receive_frame(&mut destination),
            Err(TransportFailureKind::Unavailable)
        );

        let (mut closed_client, closed_server) = connection_pair();
        if closed_server
            .stream
            .shutdown(std::net::Shutdown::Write)
            .is_err()
        {
            panic!("clean frame writer should close");
        }
        assert_eq!(
            closed_client.receive_frame(&mut destination),
            Ok(FrameReceive::ConnectionClosed)
        );
        assert!(closed_client.is_terminated());
    }

    #[test]
    fn one_deadline_covers_the_prefix_and_the_whole_body() {
        let (mut client, mut server) = connection_pair();
        if server.stream.write_all(&[0, 0, 0, 3, 0x41]).is_err() {
            panic!("slow frame prefix and first body byte should be written");
        }
        let mut destination = [0_u8; 3];
        assert_eq!(
            client.receive_frame_with_timeout(&mut destination, Duration::from_millis(25)),
            Err(TransportFailureKind::Interrupted)
        );
        assert!(client.is_terminated());
    }

    #[test]
    fn direct_invalid_send_fails_before_writing_and_terminates() {
        let (mut client, _server) = connection_pair();
        assert_eq!(
            client.send_frame(&[]),
            Err(TransportFailureKind::ProtocolViolation)
        );
        assert!(client.is_terminated());
        assert_eq!(
            client.send_frame(&[0x51]),
            Err(TransportFailureKind::Unavailable)
        );
    }
}
