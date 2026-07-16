// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use crate::{CoreError, Envelope, Field, INITIAL_COPY_BUDGET, MessageId};

/// Lifecycle state defined by the v0.1 protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerState {
    Draft,
    Sealed,
    Stored,
    Opened,
    Expired,
    Evicted,
    Rejected,
}

impl ContainerState {
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Draft, Self::Sealed)
                | (Self::Sealed, Self::Stored)
                | (Self::Stored, Self::Opened | Self::Expired | Self::Evicted)
        )
    }
}

/// Local routing metadata that is never part of the immutable Envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct LocalRouteRecord {
    message_id: MessageId,
    first_seen_at: u64,
    local_deadline: u64,
    remaining_ttl: u32,
    hops_taken: u8,
    copies_left: u8,
    state: ContainerState,
}

impl fmt::Debug for LocalRouteRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalRouteRecord")
            .field("message_id", &self.message_id)
            .field("timing", &"redacted")
            .field("remaining_ttl", &self.remaining_ttl)
            .field("hops_taken", &self.hops_taken)
            .field("copies_left", &self.copies_left)
            .field("state", &self.state)
            .finish()
    }
}

impl LocalRouteRecord {
    pub fn for_origin(envelope: &Envelope, first_seen_at: u64) -> Result<Self, CoreError> {
        Self::from_bounded_values(
            envelope,
            first_seen_at,
            envelope.ttl_seconds().get(),
            0,
            INITIAL_COPY_BUDGET,
        )
    }

    pub fn from_received(
        envelope: &Envelope,
        first_seen_at: u64,
        advertised_remaining_ttl: u64,
        advertised_hops_taken: u64,
        advertised_copies_left: u64,
    ) -> Result<Self, CoreError> {
        if advertised_remaining_ttl == 0 {
            return Err(CoreError::ValueBelowMinimum {
                field: Field::RemainingTtl,
            });
        }
        if advertised_copies_left == 0 {
            return Err(CoreError::ValueBelowMinimum {
                field: Field::CopiesLeft,
            });
        }

        let bounded_remaining_ttl =
            advertised_remaining_ttl.min(u64::from(envelope.ttl_seconds().get()));
        let bounded_hops_taken = advertised_hops_taken.min(u64::from(envelope.max_hops().get()));
        let bounded_copies_left = advertised_copies_left.min(u64::from(INITIAL_COPY_BUDGET));

        let remaining_ttl =
            u32::try_from(bounded_remaining_ttl).map_err(|_| CoreError::ValueAboveMaximum {
                field: Field::RemainingTtl,
            })?;
        let hops_taken =
            u8::try_from(bounded_hops_taken).map_err(|_| CoreError::ValueAboveMaximum {
                field: Field::HopsTaken,
            })?;
        let copies_left =
            u8::try_from(bounded_copies_left).map_err(|_| CoreError::ValueAboveMaximum {
                field: Field::CopiesLeft,
            })?;

        Self::from_bounded_values(
            envelope,
            first_seen_at,
            remaining_ttl,
            hops_taken,
            copies_left,
        )
    }

    /// Restore one strictly validated active route from persistent fields.
    pub fn try_restore_stored(
        envelope: &Envelope,
        first_seen_at: u64,
        local_deadline: u64,
        remaining_ttl: u64,
        hops_taken: u64,
        copies_left: u64,
    ) -> Result<Self, CoreError> {
        if remaining_ttl == 0 {
            return Err(CoreError::ValueBelowMinimum {
                field: Field::RemainingTtl,
            });
        }
        if remaining_ttl > u64::from(envelope.ttl_seconds().get()) {
            return Err(CoreError::ValueAboveMaximum {
                field: Field::RemainingTtl,
            });
        }
        if hops_taken > u64::from(envelope.max_hops().get()) {
            return Err(CoreError::ValueAboveMaximum {
                field: Field::HopsTaken,
            });
        }
        if copies_left == 0 {
            return Err(CoreError::ValueBelowMinimum {
                field: Field::CopiesLeft,
            });
        }
        if copies_left > u64::from(INITIAL_COPY_BUDGET) {
            return Err(CoreError::ValueAboveMaximum {
                field: Field::CopiesLeft,
            });
        }

        let expected_deadline =
            first_seen_at
                .checked_add(remaining_ttl)
                .ok_or(CoreError::ArithmeticOverflow {
                    field: Field::LocalDeadline,
                })?;
        if local_deadline != expected_deadline {
            return Err(CoreError::UnsupportedValue {
                field: Field::LocalDeadline,
            });
        }

        let remaining_ttl =
            u32::try_from(remaining_ttl).map_err(|_| CoreError::ValueAboveMaximum {
                field: Field::RemainingTtl,
            })?;
        let hops_taken = u8::try_from(hops_taken).map_err(|_| CoreError::ValueAboveMaximum {
            field: Field::HopsTaken,
        })?;
        let copies_left = u8::try_from(copies_left).map_err(|_| CoreError::ValueAboveMaximum {
            field: Field::CopiesLeft,
        })?;

        Ok(Self {
            message_id: envelope.message_id(),
            first_seen_at,
            local_deadline,
            remaining_ttl,
            hops_taken,
            copies_left,
            state: ContainerState::Stored,
        })
    }

    fn from_bounded_values(
        envelope: &Envelope,
        first_seen_at: u64,
        remaining_ttl: u32,
        hops_taken: u8,
        copies_left: u8,
    ) -> Result<Self, CoreError> {
        let local_deadline = first_seen_at.checked_add(u64::from(remaining_ttl)).ok_or(
            CoreError::ArithmeticOverflow {
                field: Field::LocalDeadline,
            },
        )?;

        Ok(Self {
            message_id: envelope.message_id(),
            first_seen_at,
            local_deadline,
            remaining_ttl,
            hops_taken,
            copies_left,
            state: ContainerState::Stored,
        })
    }

    pub fn transition_to(&mut self, next: ContainerState) -> Result<(), CoreError> {
        if !self.state.can_transition_to(next) {
            return Err(CoreError::InvalidStateTransition);
        }
        self.state = next;
        Ok(())
    }

    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    pub const fn first_seen_at(&self) -> u64 {
        self.first_seen_at
    }

    pub const fn local_deadline(&self) -> u64 {
        self.local_deadline
    }

    pub const fn remaining_ttl(&self) -> u32 {
        self.remaining_ttl
    }

    pub const fn hops_taken(&self) -> u8 {
        self.hops_taken
    }

    pub const fn copies_left(&self) -> u8 {
        self.copies_left
    }

    pub const fn state(&self) -> ContainerState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MAX_TTL_SECONDS, NORMAL_PRIORITY, PROTOCOL_VERSION};

    fn test_envelope() -> Envelope {
        let result = Envelope::try_from_fields(
            PROTOCOL_VERSION,
            [0x11; 16],
            [0x22; 16],
            MAX_TTL_SECONDS,
            16,
            NORMAL_PRIORITY,
            vec![0x54],
        );
        let Ok(envelope) = result else {
            panic!("valid test Envelope was rejected");
        };
        envelope
    }

    #[test]
    fn origin_starts_with_full_local_limits() {
        let result = LocalRouteRecord::for_origin(&test_envelope(), 100);
        let Ok(record) = result else {
            panic!("valid origin route was rejected");
        };

        assert_eq!(record.first_seen_at(), 100);
        assert_eq!(u64::from(record.remaining_ttl()), MAX_TTL_SECONDS);
        assert_eq!(record.hops_taken(), 0);
        assert_eq!(record.copies_left(), INITIAL_COPY_BUDGET);
        assert_eq!(record.state(), ContainerState::Stored);
    }

    #[test]
    fn received_route_values_are_capped_by_local_limits() {
        let result =
            LocalRouteRecord::from_received(&test_envelope(), 100, u64::MAX, u64::MAX, u64::MAX);
        let Ok(record) = result else {
            panic!("bounded received route was rejected");
        };

        assert_eq!(u64::from(record.remaining_ttl()), MAX_TTL_SECONDS);
        assert_eq!(record.hops_taken(), 16);
        assert_eq!(record.copies_left(), INITIAL_COPY_BUDGET);
    }

    #[test]
    fn zero_remaining_ttl_and_copy_budget_are_rejected() {
        assert_eq!(
            LocalRouteRecord::from_received(&test_envelope(), 100, 0, 1, 1),
            Err(CoreError::ValueBelowMinimum {
                field: Field::RemainingTtl,
            })
        );
        assert_eq!(
            LocalRouteRecord::from_received(&test_envelope(), 100, 60, 1, 0),
            Err(CoreError::ValueBelowMinimum {
                field: Field::CopiesLeft,
            })
        );
    }

    #[test]
    fn deadline_overflow_is_rejected() {
        assert_eq!(
            LocalRouteRecord::for_origin(&test_envelope(), u64::MAX),
            Err(CoreError::ArithmeticOverflow {
                field: Field::LocalDeadline,
            })
        );
    }

    #[test]
    fn only_documented_state_transitions_are_accepted() {
        assert!(ContainerState::Draft.can_transition_to(ContainerState::Sealed));
        assert!(ContainerState::Sealed.can_transition_to(ContainerState::Stored));
        assert!(ContainerState::Stored.can_transition_to(ContainerState::Opened));
        assert!(ContainerState::Stored.can_transition_to(ContainerState::Expired));
        assert!(ContainerState::Stored.can_transition_to(ContainerState::Evicted));
        assert!(!ContainerState::Opened.can_transition_to(ContainerState::Stored));
        assert!(!ContainerState::Rejected.can_transition_to(ContainerState::Stored));
    }

    #[test]
    fn route_record_rejects_a_second_terminal_transition() {
        let result = LocalRouteRecord::for_origin(&test_envelope(), 100);
        let Ok(mut record) = result else {
            panic!("valid origin route was rejected");
        };

        assert_eq!(record.transition_to(ContainerState::Expired), Ok(()));
        assert_eq!(
            record.transition_to(ContainerState::Opened),
            Err(CoreError::InvalidStateTransition)
        );
        assert_eq!(record.state(), ContainerState::Expired);
    }

    #[test]
    fn route_debug_output_redacts_exact_timing() {
        let result = LocalRouteRecord::for_origin(&test_envelope(), 123_456_789);
        let Ok(record) = result else {
            panic!("valid origin route was rejected");
        };

        let output = format!("{record:?}");
        assert!(!output.contains("123456789"));
        assert!(!output.contains(&record.local_deadline().to_string()));
        assert!(output.contains("redacted"));
    }

    #[test]
    fn persistent_restore_rejects_inconsistent_or_unbounded_fields() {
        let envelope = test_envelope();
        assert!(LocalRouteRecord::try_restore_stored(&envelope, 100, 160, 60, 1, 1).is_ok());
        assert_eq!(
            LocalRouteRecord::try_restore_stored(&envelope, 100, 161, 60, 1, 1),
            Err(CoreError::UnsupportedValue {
                field: Field::LocalDeadline,
            })
        );
        assert_eq!(
            LocalRouteRecord::try_restore_stored(&envelope, 100, 100, 0, 1, 1),
            Err(CoreError::ValueBelowMinimum {
                field: Field::RemainingTtl,
            })
        );
        assert_eq!(
            LocalRouteRecord::try_restore_stored(&envelope, 100, 160, 60, 17, 1),
            Err(CoreError::ValueAboveMaximum {
                field: Field::HopsTaken,
            })
        );
        assert_eq!(
            LocalRouteRecord::try_restore_stored(&envelope, 100, 160, 60, 1, 33),
            Err(CoreError::ValueAboveMaximum {
                field: Field::CopiesLeft,
            })
        );
    }
}
