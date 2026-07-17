// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use crate::{MAX_SESSION_BYTES, MAX_SESSION_FRAMES};

/// Validated per-direction limits for one transport session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLimits {
    max_frames: u32,
    max_bytes: usize,
}

impl SessionLimits {
    pub const fn standard() -> Self {
        Self {
            max_frames: MAX_SESSION_FRAMES,
            max_bytes: MAX_SESSION_BYTES,
        }
    }

    pub const fn try_new(max_frames: u32, max_bytes: usize) -> Result<Self, LimitsError> {
        if max_frames == 0 || max_frames > MAX_SESSION_FRAMES {
            return Err(LimitsError::InvalidFrameLimit);
        }
        if max_bytes == 0 || max_bytes > MAX_SESSION_BYTES {
            return Err(LimitsError::InvalidByteLimit);
        }
        Ok(Self {
            max_frames,
            max_bytes,
        })
    }

    pub const fn max_frames(self) -> u32 {
        self.max_frames
    }

    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self::standard()
    }
}

/// Safe configuration error without rejected values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitsError {
    InvalidFrameLimit,
    InvalidByteLimit,
}

impl fmt::Display for LimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFrameLimit => formatter.write_str("invalid session frame limit"),
            Self::InvalidByteLimit => formatter.write_str("invalid session byte limit"),
        }
    }
}

impl std::error::Error for LimitsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_and_smaller_limits_are_accepted() {
        assert_eq!(
            SessionLimits::standard(),
            SessionLimits::try_new(MAX_SESSION_FRAMES, MAX_SESSION_BYTES)
                .unwrap_or_else(|_| panic!("standard limits were rejected"))
        );
        assert!(SessionLimits::try_new(1, 1).is_ok());
    }

    #[test]
    fn zero_and_protocol_excess_are_rejected() {
        assert_eq!(
            SessionLimits::try_new(0, 1),
            Err(LimitsError::InvalidFrameLimit)
        );
        assert_eq!(
            SessionLimits::try_new(MAX_SESSION_FRAMES + 1, 1),
            Err(LimitsError::InvalidFrameLimit)
        );
        assert_eq!(
            SessionLimits::try_new(1, 0),
            Err(LimitsError::InvalidByteLimit)
        );
        assert_eq!(
            SessionLimits::try_new(1, MAX_SESSION_BYTES + 1),
            Err(LimitsError::InvalidByteLimit)
        );
    }
}
