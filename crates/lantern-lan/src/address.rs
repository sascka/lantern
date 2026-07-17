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

#[cfg(test)]
mod tests {
    use super::{AddressError, BindAddress, PeerAddress};
    use core::str::FromStr;
    use std::net::SocketAddr;

    fn socket(value: &str) -> SocketAddr {
        match value.parse() {
            Ok(address) => address,
            Err(_) => panic!("test socket address should be valid"),
        }
    }

    #[test]
    fn accepts_loopback_private_link_local_and_unique_local_addresses() {
        for value in [
            "127.0.0.1:38383",
            "10.20.30.40:38383",
            "169.254.20.1:38383",
            "[::1]:38383",
            "[fd12:3456::1]:38383",
            "[fe80::1]:38383",
        ] {
            assert!(PeerAddress::from_str(value).is_ok(), "rejected {value}");
        }
    }

    #[test]
    fn rejects_public_multicast_wildcard_dns_and_missing_port() {
        for value in [
            "8.8.8.8:53",
            "224.0.0.1:38383",
            "0.0.0.0:38383",
            "[::]:38383",
            "example.com:38383",
            "127.0.0.1:0",
        ] {
            assert!(PeerAddress::from_str(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn bind_allows_an_ephemeral_port_but_not_a_wildcard() {
        assert!(BindAddress::try_new(socket("127.0.0.1:0")).is_ok());
        assert_eq!(
            BindAddress::try_new(socket("0.0.0.0:0")),
            Err(AddressError::OutsideLan)
        );
    }

    #[test]
    fn text_input_is_bounded_before_parsing() {
        assert_eq!(PeerAddress::from_str(""), Err(AddressError::Empty));
        assert_eq!(
            PeerAddress::from_str(&"1".repeat(65)),
            Err(AddressError::TooLong)
        );
    }

    #[test]
    fn debug_output_does_not_disclose_the_address() {
        let marker = "10.81.82.83:38383";
        let address = PeerAddress::from_str(marker);
        let Ok(address) = address else {
            panic!("private test address should be accepted");
        };
        assert!(!format!("{address:?}").contains(marker));
    }
}
