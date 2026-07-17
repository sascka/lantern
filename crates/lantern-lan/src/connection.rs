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

