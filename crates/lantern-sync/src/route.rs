// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use lantern_core::{Envelope, INITIAL_COPY_BUDGET, MAX_MAX_HOPS, MAX_TTL_SECONDS, MessageId};

use crate::SyncError;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RouteGrant {
    remaining_ttl_seconds: u32,
    hops_taken: u8,
    copies_left: u8,
}

impl RouteGrant {
    pub fn try_new(
        remaining_ttl_seconds: u32,
        hops_taken: u8,
        copies_left: u8,
    ) -> Result<Self, SyncError> {
        if remaining_ttl_seconds == 0
            || u64::from(remaining_ttl_seconds) > MAX_TTL_SECONDS
            || hops_taken == 0
            || u64::from(hops_taken) > MAX_MAX_HOPS
            || copies_left == 0
            || copies_left > INITIAL_COPY_BUDGET
        {
            return Err(SyncError::InvalidRouteGrant);
        }
        Ok(Self {
            remaining_ttl_seconds,
            hops_taken,
            copies_left,
        })
    }

    pub const fn remaining_ttl_seconds(self) -> u32 {
        self.remaining_ttl_seconds
    }

    pub const fn hops_taken(self) -> u8 {
        self.hops_taken
    }

    pub const fn copies_left(self) -> u8 {
        self.copies_left
    }
}

impl fmt::Debug for RouteGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteGrant")
            .field("values", &"redacted")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TransferredEnvelope {
    envelope: Envelope,
    route: RouteGrant,
}

impl TransferredEnvelope {
    pub fn try_new(envelope: Envelope, route: RouteGrant) -> Result<Self, SyncError> {
        if u64::from(route.remaining_ttl_seconds()) > u64::from(envelope.ttl_seconds().get())
            || u64::from(route.hops_taken()) > u64::from(envelope.max_hops().get())
        {
            return Err(SyncError::InvalidRouteGrant);
        }
        Ok(Self { envelope, route })
    }

    pub const fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    pub const fn route(&self) -> RouteGrant {
        self.route
    }

    pub const fn message_id(&self) -> MessageId {
        self.envelope.message_id()
    }

    pub fn into_parts(self) -> (Envelope, RouteGrant) {
        (self.envelope, self.route)
    }
}

impl fmt::Debug for TransferredEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransferredEnvelope")
            .field("contents", &"redacted")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use lantern_core::{MESSAGE_ID_LENGTH, NORMAL_PRIORITY, PROTOCOL_VERSION};

    use super::*;

    fn envelope() -> Envelope {
        Envelope::try_from_fields(
            PROTOCOL_VERSION,
            [0x11; MESSAGE_ID_LENGTH],
            [0x22; 16],
            300,
            4,
            NORMAL_PRIORITY,
            b"SYNTHETIC ROUTE PAYLOAD".to_vec(),
        )
        .unwrap_or_else(|_| panic!("route fixture should be valid"))
    }

    #[test]
    fn grant_has_strict_nonzero_protocol_limits() {
        assert!(RouteGrant::try_new(1, 1, 1).is_ok());
        assert!(RouteGrant::try_new(0, 1, 1).is_err());
        assert!(RouteGrant::try_new(1, 0, 1).is_err());
        assert!(RouteGrant::try_new(1, 1, 0).is_err());
        assert!(RouteGrant::try_new(1, 1, INITIAL_COPY_BUDGET + 1).is_err());
    }

    #[test]
    fn grant_cannot_exceed_its_envelope_and_debug_is_redacted() {
        let route = RouteGrant::try_new(301, 1, 1)
            .unwrap_or_else(|_| panic!("route fixture should be valid"));
        assert_eq!(
            TransferredEnvelope::try_new(envelope(), route),
            Err(SyncError::InvalidRouteGrant)
        );

        let route = RouteGrant::try_new(300, 4, 1)
            .unwrap_or_else(|_| panic!("route fixture should be valid"));
        let item = TransferredEnvelope::try_new(envelope(), route)
            .unwrap_or_else(|_| panic!("transferred fixture should be valid"));
        let output = format!("{item:?} {route:?}");
        assert!(!output.contains("SYNTHETIC"));
        assert!(!output.contains("300"));
    }
}
