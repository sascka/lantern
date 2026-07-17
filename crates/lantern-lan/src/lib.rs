// SPDX-License-Identifier: MPL-2.0

//! Manual LAN addresses and the first fixed Lantern version handshake.
//!
//! This crate does not transfer `Envelope` values yet. It establishes one TCP
//! connection, exchanges a fixed-size hello, and rejects unsupported versions
//! before any application frame can be accepted.

#![forbid(unsafe_code)]

mod address;
mod connection;
mod error;
mod hello;

pub use address::{AddressError, BindAddress, PeerAddress};
pub use connection::{LanConnection, LanListener, connect};
pub use error::LanError;
pub use hello::LAN_PROTOCOL_VERSION;
