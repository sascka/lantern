// SPDX-License-Identifier: MPL-2.0

use core::fmt;

/// Field associated with a validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Field {
    ProtocolVersion,
    TtlSeconds,
    MaxHops,
    Priority,
    ProtectedPayload,
    RemainingTtl,
    HopsTaken,
    CopiesLeft,
    LocalDeadline,
    State,
}

/// A bounded validation failure that never contains untrusted input bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreError {
    UnsupportedValue { field: Field },
    ValueBelowMinimum { field: Field },
    ValueAboveMaximum { field: Field },
    ArithmeticOverflow { field: Field },
    InvalidStateTransition,
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedValue { field } => {
                write!(formatter, "unsupported value for {field:?}")
            }
            Self::ValueBelowMinimum { field } => {
                write!(formatter, "value below minimum for {field:?}")
            }
            Self::ValueAboveMaximum { field } => {
                write!(formatter, "value above maximum for {field:?}")
            }
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "arithmetic overflow for {field:?}")
            }
            Self::InvalidStateTransition => formatter.write_str("invalid state transition"),
        }
    }
}

impl std::error::Error for CoreError {}
