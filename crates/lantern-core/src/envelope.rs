// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use crate::{
    CoreError, Field, MAX_MAX_HOPS, MAX_PROTECTED_PAYLOAD_SIZE, MAX_TTL_SECONDS, MESSAGE_ID_LENGTH,
    MIN_MAX_HOPS, MIN_PROTECTED_PAYLOAD_SIZE, MIN_TTL_SECONDS, NORMAL_PRIORITY, PROTOCOL_VERSION,
    RECIPIENT_HINT_LENGTH,
};

/// A random fixed-size identifier supplied by a future cryptographic boundary.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct MessageId([u8; MESSAGE_ID_LENGTH]);

impl MessageId {
    pub const fn from_bytes(bytes: [u8; MESSAGE_ID_LENGTH]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; MESSAGE_ID_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageId")
            .field("length", &MESSAGE_ID_LENGTH)
            .finish_non_exhaustive()
    }
}

/// An opaque fixed-size routing hint created by a future E2EE implementation.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RecipientHint([u8; RECIPIENT_HINT_LENGTH]);

impl RecipientHint {
    pub const fn from_bytes(bytes: [u8; RECIPIENT_HINT_LENGTH]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; RECIPIENT_HINT_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for RecipientHint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecipientHint")
            .field("length", &RECIPIENT_HINT_LENGTH)
            .finish_non_exhaustive()
    }
}

/// Validated lifetime requested by the Envelope creator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TtlSeconds(u32);

impl TtlSeconds {
    pub fn try_from_raw(value: u64) -> Result<Self, CoreError> {
        if value < MIN_TTL_SECONDS {
            return Err(CoreError::ValueBelowMinimum {
                field: Field::TtlSeconds,
            });
        }
        if value > MAX_TTL_SECONDS {
            return Err(CoreError::ValueAboveMaximum {
                field: Field::TtlSeconds,
            });
        }

        let bounded = u32::try_from(value).map_err(|_| CoreError::ValueAboveMaximum {
            field: Field::TtlSeconds,
        })?;
        Ok(Self(bounded))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Validated maximum number of sequential transmissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaxHops(u8);

impl MaxHops {
    pub fn try_from_raw(value: u64) -> Result<Self, CoreError> {
        if value < MIN_MAX_HOPS {
            return Err(CoreError::ValueBelowMinimum {
                field: Field::MaxHops,
            });
        }
        if value > MAX_MAX_HOPS {
            return Err(CoreError::ValueAboveMaximum {
                field: Field::MaxHops,
            });
        }

        let bounded = u8::try_from(value).map_err(|_| CoreError::ValueAboveMaximum {
            field: Field::MaxHops,
        })?;
        Ok(Self(bounded))
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Priority accepted by protocol version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Priority {
    Normal,
}

impl Priority {
    pub fn try_from_raw(value: u64) -> Result<Self, CoreError> {
        if value == NORMAL_PRIORITY {
            Ok(Self::Normal)
        } else {
            Err(CoreError::UnsupportedValue {
                field: Field::Priority,
            })
        }
    }

    pub const fn as_raw(self) -> u64 {
        match self {
            Self::Normal => NORMAL_PRIORITY,
        }
    }
}

/// Opaque E2EE output represented by obvious test bytes in the current stage.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedPayload(Box<[u8]>);

impl ProtectedPayload {
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, CoreError> {
        if bytes.len() < MIN_PROTECTED_PAYLOAD_SIZE {
            return Err(CoreError::ValueBelowMinimum {
                field: Field::ProtectedPayload,
            });
        }
        if bytes.len() > MAX_PROTECTED_PAYLOAD_SIZE {
            return Err(CoreError::ValueAboveMaximum {
                field: Field::ProtectedPayload,
            });
        }

        Ok(Self(bytes.into_boxed_slice()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ProtectedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedPayload")
            .field("length", &self.len())
            .finish_non_exhaustive()
    }
}

/// Immutable logical Envelope version 1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    protocol_version: u64,
    message_id: MessageId,
    recipient_hint: RecipientHint,
    ttl_seconds: TtlSeconds,
    max_hops: MaxHops,
    priority: Priority,
    protected_payload: ProtectedPayload,
}

impl Envelope {
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_fields(
        protocol_version: u64,
        message_id: [u8; MESSAGE_ID_LENGTH],
        recipient_hint: [u8; RECIPIENT_HINT_LENGTH],
        ttl_seconds: u64,
        max_hops: u64,
        priority: u64,
        protected_payload: Vec<u8>,
    ) -> Result<Self, CoreError> {
        if protocol_version != PROTOCOL_VERSION {
            return Err(CoreError::UnsupportedValue {
                field: Field::ProtocolVersion,
            });
        }

        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            message_id: MessageId::from_bytes(message_id),
            recipient_hint: RecipientHint::from_bytes(recipient_hint),
            ttl_seconds: TtlSeconds::try_from_raw(ttl_seconds)?,
            max_hops: MaxHops::try_from_raw(max_hops)?,
            priority: Priority::try_from_raw(priority)?,
            protected_payload: ProtectedPayload::try_from_bytes(protected_payload)?,
        })
    }

    pub const fn protocol_version(&self) -> u64 {
        self.protocol_version
    }

    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    pub const fn recipient_hint(&self) -> RecipientHint {
        self.recipient_hint
    }

    pub const fn ttl_seconds(&self) -> TtlSeconds {
        self.ttl_seconds
    }

    pub const fn max_hops(&self) -> MaxHops {
        self.max_hops
    }

    pub const fn priority(&self) -> Priority {
        self.priority
    }

    pub const fn protected_payload(&self) -> &ProtectedPayload {
        &self.protected_payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MESSAGE_ID: [u8; MESSAGE_ID_LENGTH] = [0x11; MESSAGE_ID_LENGTH];
    const TEST_RECIPIENT_HINT: [u8; RECIPIENT_HINT_LENGTH] = [0x22; RECIPIENT_HINT_LENGTH];

    fn envelope_with(
        protocol_version: u64,
        ttl_seconds: u64,
        max_hops: u64,
        priority: u64,
        payload_size: usize,
    ) -> Result<Envelope, CoreError> {
        Envelope::try_from_fields(
            protocol_version,
            TEST_MESSAGE_ID,
            TEST_RECIPIENT_HINT,
            ttl_seconds,
            max_hops,
            priority,
            vec![0x54; payload_size],
        )
    }

    #[test]
    fn accepts_minimum_and_maximum_field_values() {
        assert!(
            envelope_with(
                PROTOCOL_VERSION,
                MIN_TTL_SECONDS,
                MIN_MAX_HOPS,
                NORMAL_PRIORITY,
                MIN_PROTECTED_PAYLOAD_SIZE,
            )
            .is_ok()
        );
        assert!(
            envelope_with(
                PROTOCOL_VERSION,
                MAX_TTL_SECONDS,
                MAX_MAX_HOPS,
                NORMAL_PRIORITY,
                MAX_PROTECTED_PAYLOAD_SIZE,
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_unknown_version_and_priority() {
        assert_eq!(
            envelope_with(2, MIN_TTL_SECONDS, MIN_MAX_HOPS, NORMAL_PRIORITY, 1),
            Err(CoreError::UnsupportedValue {
                field: Field::ProtocolVersion,
            })
        );
        assert_eq!(
            envelope_with(PROTOCOL_VERSION, MIN_TTL_SECONDS, MIN_MAX_HOPS, 1, 1),
            Err(CoreError::UnsupportedValue {
                field: Field::Priority,
            })
        );
    }

    #[test]
    fn rejects_ttl_outside_protocol_range() {
        assert_eq!(
            envelope_with(
                PROTOCOL_VERSION,
                MIN_TTL_SECONDS - 1,
                MIN_MAX_HOPS,
                NORMAL_PRIORITY,
                1,
            ),
            Err(CoreError::ValueBelowMinimum {
                field: Field::TtlSeconds,
            })
        );
        assert_eq!(
            envelope_with(
                PROTOCOL_VERSION,
                MAX_TTL_SECONDS + 1,
                MIN_MAX_HOPS,
                NORMAL_PRIORITY,
                1,
            ),
            Err(CoreError::ValueAboveMaximum {
                field: Field::TtlSeconds,
            })
        );
    }

    #[test]
    fn rejects_hop_limit_outside_protocol_range() {
        assert_eq!(
            envelope_with(
                PROTOCOL_VERSION,
                MIN_TTL_SECONDS,
                MIN_MAX_HOPS - 1,
                NORMAL_PRIORITY,
                1,
            ),
            Err(CoreError::ValueBelowMinimum {
                field: Field::MaxHops,
            })
        );
        assert_eq!(
            envelope_with(
                PROTOCOL_VERSION,
                MIN_TTL_SECONDS,
                MAX_MAX_HOPS + 1,
                NORMAL_PRIORITY,
                1,
            ),
            Err(CoreError::ValueAboveMaximum {
                field: Field::MaxHops,
            })
        );
    }

    #[test]
    fn rejects_empty_and_oversized_payloads() {
        assert_eq!(
            envelope_with(
                PROTOCOL_VERSION,
                MIN_TTL_SECONDS,
                MIN_MAX_HOPS,
                NORMAL_PRIORITY,
                0,
            ),
            Err(CoreError::ValueBelowMinimum {
                field: Field::ProtectedPayload,
            })
        );
        assert_eq!(
            envelope_with(
                PROTOCOL_VERSION,
                MIN_TTL_SECONDS,
                MIN_MAX_HOPS,
                NORMAL_PRIORITY,
                MAX_PROTECTED_PAYLOAD_SIZE + 1,
            ),
            Err(CoreError::ValueAboveMaximum {
                field: Field::ProtectedPayload,
            })
        );
    }

    #[test]
    fn debug_output_redacts_identifier_hint_and_payload() {
        let result = envelope_with(
            PROTOCOL_VERSION,
            MIN_TTL_SECONDS,
            MIN_MAX_HOPS,
            NORMAL_PRIORITY,
            4,
        );
        let Ok(envelope) = result else {
            panic!("valid test Envelope was rejected");
        };

        let output = format!("{envelope:?}");
        assert!(!output.contains("17, 17"));
        assert!(!output.contains("34, 34"));
        assert!(!output.contains("84, 84"));
        assert!(output.contains("length"));
    }
}
