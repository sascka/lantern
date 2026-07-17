// SPDX-License-Identifier: MPL-2.0

//! Bounded, transport-independent sessions for opaque Lantern frames.
//!
//! This crate defines no wire framing, socket, peer discovery, cryptography, or
//! application message format. A concrete adapter must separate one complete
//! frame without allocating from an untrusted length before calling this API.

#![forbid(unsafe_code)]

mod adapter;
mod limits;
mod session;

pub use adapter::{FrameReceive, FrameTransport, TransportFailureKind};
pub use limits::{LimitsError, SessionLimits};
pub use session::{BoundedSession, SessionError, SessionUsage};

/// Maximum size of one opaque transport frame.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Largest number of frames allowed in one direction during one session.
pub const MAX_SESSION_FRAMES: u32 = 1_024;
/// Largest number of frame bytes allowed in one direction during one session.
pub const MAX_SESSION_BYTES: usize = 64 * 1024 * 1024;
