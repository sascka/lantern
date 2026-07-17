// SPDX-License-Identifier: MPL-2.0

use core::fmt;

/// Closed LAN error vocabulary without peer addresses or operating system text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LanError {
    BindFailed,
    AcceptFailed,
    ConnectFailed,
    ConnectionSetupFailed,
    ConnectionClosed,
    HandshakeTimedOut,
    InvalidHello,
    UnsupportedVersion,
    HandshakeIoFailed,
    PeerLimitReached,
    PeerLimitUnavailable,
    ShutdownFailed,
}

impl fmt::Display for LanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BindFailed => formatter.write_str("LAN listener could not bind"),
            Self::AcceptFailed => formatter.write_str("LAN listener could not accept a connection"),
            Self::ConnectFailed => formatter.write_str("LAN peer connection failed"),
            Self::ConnectionSetupFailed => {
                formatter.write_str("LAN connection limits could not be applied")
            }
            Self::ConnectionClosed => formatter.write_str("LAN peer closed during handshake"),
            Self::HandshakeTimedOut => formatter.write_str("LAN version handshake timed out"),
            Self::InvalidHello => formatter.write_str("LAN peer sent an invalid hello"),
            Self::UnsupportedVersion => {
                formatter.write_str("LAN peer uses an unsupported protocol version")
            }
            Self::HandshakeIoFailed => formatter.write_str("LAN version handshake failed"),
            Self::PeerLimitReached => formatter.write_str("LAN peer connection limit reached"),
            Self::PeerLimitUnavailable => {
                formatter.write_str("LAN peer connection limiter is unavailable")
            }
            Self::ShutdownFailed => formatter.write_str("LAN connection could not close cleanly"),
        }
    }
}

impl std::error::Error for LanError {}
