// SPDX-License-Identifier: MPL-2.0

//! Bounded, transport-independent domain types and strict CBOR serialization
//! for Lantern.
//!
//! This crate does not implement networking, persistent storage, or cryptography.
//! `protected_payload` is opaque test data until the separate cryptographic
//! milestone is completed.

#![forbid(unsafe_code)]

mod cbor;
mod envelope;
mod error;
mod queue;
mod route;

pub use cbor::{CborError, CborField, decode_envelope, encode_envelope, encoded_envelope_size};
pub use envelope::{
    Envelope, MaxHops, MessageId, Priority, ProtectedPayload, RecipientHint, TtlSeconds,
};
pub use error::{CoreError, Field};
pub use queue::{
    DeduplicationStatus, EnqueueOutcome, EnqueueResult, EnvelopeQueue, QueueEffects, QueueEntry,
    QueueError, QueueField, QueueLimits, TombstoneEntry,
};
pub use route::{ContainerState, ForwardingReservation, LocalRouteRecord};

/// Only protocol version accepted by the v0.1 domain model.
pub const PROTOCOL_VERSION: u64 = 1;
/// Exact byte length of a message identifier.
pub const MESSAGE_ID_LENGTH: usize = 16;
/// Exact byte length of an opaque recipient hint.
pub const RECIPIENT_HINT_LENGTH: usize = 16;
/// Minimum lifetime accepted for an Envelope.
pub const MIN_TTL_SECONDS: u64 = 60;
/// Maximum lifetime accepted for an Envelope: seven days.
pub const MAX_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
/// Minimum hop limit accepted for an Envelope.
pub const MIN_MAX_HOPS: u64 = 1;
/// Maximum hop limit accepted for an Envelope.
pub const MAX_MAX_HOPS: u64 = 16;
/// Only priority supported by protocol version 1.
pub const NORMAL_PRIORITY: u64 = 0;
/// Smallest useful opaque protected payload.
pub const MIN_PROTECTED_PAYLOAD_SIZE: usize = 1;
/// Largest protected payload allowed by the logical v0.1 schema.
pub const MAX_PROTECTED_PAYLOAD_SIZE: usize = 63 * 1024;
/// Largest serialized Envelope accepted by the strict decoder.
pub const MAX_ENVELOPE_SIZE: usize = 64 * 1024;
/// Initial Binary Spray-and-Wait copy budget selected in Stage 1.
pub const INITIAL_COPY_BUDGET: u8 = 32;
/// Maximum number of Envelopes in the default foreign-container queue.
pub const MAX_QUEUE_ENTRIES: usize = 1_000;
/// Maximum deterministic CBOR bytes in the default foreign-container queue.
pub const MAX_QUEUE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum number of recently removed identifiers retained for deduplication.
pub const MAX_TOMBSTONES: usize = 2_000;
/// Maximum local tombstone retention: seven days.
pub const MAX_TOMBSTONE_RETENTION_SECONDS: u64 = MAX_TTL_SECONDS;
