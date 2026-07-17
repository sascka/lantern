// SPDX-License-Identifier: MPL-2.0

use core::{fmt, str::FromStr};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

const MAX_ADDRESS_TEXT_BYTES: usize = 64;

/// A concrete local address used for `TcpListener::bind`.
///
/// Port zero is accepted so tests and local tools can request an ephemeral
/// port. Wildcard and public addresses are rejected.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BindAddress(SocketAddr);

impl BindAddress {
    pub fn try_new(address: SocketAddr) -> Result<Self, AddressError> {
        if !is_lan_ip(address.ip()) {
            return Err(AddressError::OutsideLan);
        }
        Ok(Self(address))
    }

    pub(crate) const fn socket_addr(self) -> SocketAddr {
        self.0
    }

    /// Returns only the selected port, mainly for an ephemeral loopback bind.
    pub const fn port(self) -> u16 {
        self.0.port()
    }
}

impl FromStr for BindAddress {
    type Err = AddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_new(parse_socket_address(value)?)
    }
}

impl fmt::Debug for BindAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindAddress")
            .finish_non_exhaustive()
    }
}

/// A concrete LAN peer address used for an outgoing connection.
///
/// DNS names, public addresses, wildcard addresses and port zero are rejected.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PeerAddress(SocketAddr);

impl PeerAddress {
    pub fn try_new(address: SocketAddr) -> Result<Self, AddressError> {
        if address.port() == 0 {
            return Err(AddressError::MissingPort);
        }
        if !is_lan_ip(address.ip()) {
            return Err(AddressError::OutsideLan);
        }
        Ok(Self(address))
    }

    pub(crate) const fn socket_addr(self) -> SocketAddr {
        self.0
    }
}

impl FromStr for PeerAddress {
    type Err = AddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_new(parse_socket_address(value)?)
    }
}

impl fmt::Debug for PeerAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerAddress")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    Empty,
    TooLong,
    Invalid,
    MissingPort,
    OutsideLan,
}

impl fmt::Display for AddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("LAN address is empty"),
            Self::TooLong => formatter.write_str("LAN address is too long"),
            Self::Invalid => formatter.write_str("LAN address is invalid"),
            Self::MissingPort => formatter.write_str("LAN peer port is missing"),
            Self::OutsideLan => formatter.write_str("address is outside the allowed LAN ranges"),
        }
    }
}

impl std::error::Error for AddressError {}

fn parse_socket_address(value: &str) -> Result<SocketAddr, AddressError> {
    if value.is_empty() {
        return Err(AddressError::Empty);
    }
    if value.len() > MAX_ADDRESS_TEXT_BYTES {
        return Err(AddressError::TooLong);
    }
    value.parse().map_err(|_| AddressError::Invalid)
}

fn is_lan_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private() || address.is_link_local() || address.is_loopback()
        }
        IpAddr::V6(address) => {
            address.is_loopback() || is_unique_local_v6(address) || is_link_local_v6(address)
        }
    }
}

fn is_unique_local_v6(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

fn is_link_local_v6(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

