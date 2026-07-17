// SPDX-License-Identifier: MPL-2.0

//! Bounded synchronization of opaque Lantern Envelopes.
//!
//! The protocol is independent from TCP and cryptography. A caller supplies a
//! bounded transport session and decides which active Envelopes may be offered.

#![forbid(unsafe_code)]

mod error;
mod exchange;
mod frame;

pub use error::{SyncError, SyncSinkError};
pub use exchange::{EnvelopeSink, SyncSummary, receive_batch, send_batch};
pub use frame::{
    MAX_OFFERED_IDS, MAX_TRANSFER_ENVELOPE_BYTES, SYNC_PROTOCOL_VERSION, SyncFrame,
    decode_sync_frame, encode_sync_frame,
};
