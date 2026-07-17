// SPDX-License-Identifier: MPL-2.0

//! Manual LAN addresses, bounded peer admission and versioned frames.
//!
//! This crate keeps application frames opaque. It establishes one TCP
//! connection, applies a bounded listener policy, exchanges a fixed-size hello,
//! and rejects unsupported versions before any application frame is accepted.

#![forbid(unsafe_code)]

mod address;
mod connection;
mod error;
mod framing;
mod hello;
mod peer_limit;

pub use address::{AddressError, BindAddress, PeerAddress};
pub use connection::{LanConnection, LanListener, connect};
pub use error::LanError;
pub use framing::FRAME_LENGTH_PREFIX_BYTES;
pub use hello::LAN_PROTOCOL_VERSION;
pub use peer_limit::{
    MAX_ACTIVE_CONNECTIONS_PER_PEER, MAX_CONNECTION_ATTEMPTS_PER_PEER_WINDOW, MAX_TRACKED_PEERS,
    PEER_ATTEMPT_WINDOW_SECONDS,
};
