// SPDX-License-Identifier: MPL-2.0

//! Monotonic runtime time policy with explicit wall-clock rollback reporting.

#![forbid(unsafe_code)]

use core::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Largest wall-clock value accepted by storage-backed Lantern components.
pub const MAX_SUPPORTED_WALL_SECONDS: u64 = i64::MAX as u64;

/// Condition observed while producing one logical reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockStatus {
    Normal,
    WallClockRollbackDetected,
}

impl ClockStatus {
    /// A rollback makes remaining lifetime ambiguous and requires fail-closed handling.
    pub const fn requires_conservative_cleanup(self) -> bool {
        matches!(self, Self::WallClockRollbackDetected)
    }
}

/// One nondecreasing logical second suitable for queue and journal maintenance.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ClockReading {
    wall_seconds: u64,
    status: ClockStatus,
}

impl ClockReading {
    pub const fn wall_seconds(self) -> u64 {
        self.wall_seconds
    }

    pub const fn status(self) -> ClockStatus {
        self.status
    }
}

impl fmt::Debug for ClockReading {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClockReading")
            .field("time", &"redacted")
            .field("status", &self.status)
            .finish()
    }
}

/// Safe clock error without exact times or platform error details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    WallClockBeforeUnixEpoch,
    WallClockOutOfRange,
    MonotonicRegression,
    ArithmeticOverflow,
}

impl fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WallClockBeforeUnixEpoch => {
                formatter.write_str("wall clock is before the Unix epoch")
            }
            Self::WallClockOutOfRange => formatter.write_str("wall clock is outside range"),
            Self::MonotonicRegression => formatter.write_str("monotonic clock moved backwards"),
            Self::ArithmeticOverflow => formatter.write_str("clock arithmetic overflow"),
        }
    }
}

impl std::error::Error for ClockError {}

/// Deterministic policy core fed by an elapsed duration and an observed wall clock.
pub struct ClockTracker {
    monotonic_anchor_wall_seconds: u64,
    monotonic_anchor_elapsed: Duration,
    last_elapsed: Duration,
    last_observed_wall_seconds: u64,
    last_logical_wall_seconds: u64,
}

impl ClockTracker {
    pub fn try_new(anchor_wall_seconds: u64) -> Result<Self, ClockError> {
        validate_wall_seconds(anchor_wall_seconds)?;
        Ok(Self {
            monotonic_anchor_wall_seconds: anchor_wall_seconds,
            monotonic_anchor_elapsed: Duration::ZERO,
            last_elapsed: Duration::ZERO,
            last_observed_wall_seconds: anchor_wall_seconds,
            last_logical_wall_seconds: anchor_wall_seconds,
        })
    }

    pub fn observe(
        &mut self,
        elapsed: Duration,
        observed_wall_seconds: u64,
    ) -> Result<ClockReading, ClockError> {
        validate_wall_seconds(observed_wall_seconds)?;
        if elapsed < self.last_elapsed {
            return Err(ClockError::MonotonicRegression);
        }

        let elapsed_since_anchor = elapsed
            .checked_sub(self.monotonic_anchor_elapsed)
            .ok_or(ClockError::MonotonicRegression)?;
        let monotonic_wall_seconds = self
            .monotonic_anchor_wall_seconds
            .checked_add(elapsed_since_anchor.as_secs())
            .ok_or(ClockError::ArithmeticOverflow)?;
        validate_wall_seconds(monotonic_wall_seconds)?;

        let status = if observed_wall_seconds < self.last_observed_wall_seconds {
            ClockStatus::WallClockRollbackDetected
        } else {
            ClockStatus::Normal
        };
        let logical_wall_seconds = monotonic_wall_seconds
            .max(observed_wall_seconds)
            .max(self.last_logical_wall_seconds);
        validate_wall_seconds(logical_wall_seconds)?;

        if logical_wall_seconds > monotonic_wall_seconds {
            self.monotonic_anchor_wall_seconds = logical_wall_seconds;
            self.monotonic_anchor_elapsed = elapsed;
        }
        self.last_elapsed = elapsed;
        self.last_observed_wall_seconds = observed_wall_seconds;
        self.last_logical_wall_seconds = logical_wall_seconds;
        Ok(ClockReading {
            wall_seconds: logical_wall_seconds,
            status,
        })
    }

    pub const fn last_logical_wall_seconds(&self) -> u64 {
        self.last_logical_wall_seconds
    }
}

impl fmt::Debug for ClockTracker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClockTracker")
            .field("time", &"redacted")
            .finish_non_exhaustive()
    }
}

/// Production clock backed by `Instant` and `SystemTime` from the standard library.
pub struct SystemRuntimeClock {
    monotonic_anchor: Instant,
    tracker: ClockTracker,
}

impl SystemRuntimeClock {
    pub fn start() -> Result<Self, ClockError> {
        let monotonic_anchor = Instant::now();
        let wall_seconds = system_wall_seconds(SystemTime::now())?;
        Ok(Self {
            monotonic_anchor,
            tracker: ClockTracker::try_new(wall_seconds)?,
        })
    }

    pub fn now(&mut self) -> Result<ClockReading, ClockError> {
        let monotonic_now = Instant::now();
        let elapsed = monotonic_now
            .checked_duration_since(self.monotonic_anchor)
            .ok_or(ClockError::MonotonicRegression)?;
        let observed_wall_seconds = system_wall_seconds(SystemTime::now())?;
        self.tracker.observe(elapsed, observed_wall_seconds)
    }
}

impl fmt::Debug for SystemRuntimeClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemRuntimeClock")
            .field("time", &"redacted")
            .finish_non_exhaustive()
    }
}

fn system_wall_seconds(system_time: SystemTime) -> Result<u64, ClockError> {
    let duration = system_time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClockError::WallClockBeforeUnixEpoch)?;
    let seconds = duration.as_secs();
    validate_wall_seconds(seconds)?;
    Ok(seconds)
}

fn validate_wall_seconds(seconds: u64) -> Result<(), ClockError> {
    if seconds > MAX_SUPPORTED_WALL_SECONDS {
        return Err(ClockError::WallClockOutOfRange);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_progress_uses_monotonic_seconds_and_floors_subseconds() {
        let tracker = ClockTracker::try_new(1_000);
        let Ok(mut tracker) = tracker else {
            panic!("valid clock anchor was rejected");
        };
        let first = tracker.observe(Duration::from_millis(999), 1_000);
        let second = tracker.observe(Duration::from_secs(1), 1_001);
        let (Ok(first), Ok(second)) = (first, second) else {
            panic!("valid clock observations were rejected");
        };
        assert_eq!(first.wall_seconds(), 1_000);
        assert_eq!(second.wall_seconds(), 1_001);
        assert_eq!(second.status(), ClockStatus::Normal);
    }

    #[test]
    fn forward_wall_jump_advances_logical_time_without_later_regression() {
        let tracker = ClockTracker::try_new(1_000);
        let Ok(mut tracker) = tracker else {
            panic!("valid clock anchor was rejected");
        };
        let forward = tracker.observe(Duration::from_secs(10), 2_000);
        let Ok(forward) = forward else {
            panic!("forward wall observation was rejected");
        };
        assert_eq!(forward.wall_seconds(), 2_000);

        let rollback = tracker.observe(Duration::from_secs(20), 1_020);
        let Ok(rollback) = rollback else {
            panic!("wall rollback observation was rejected");
        };
        assert_eq!(rollback.wall_seconds(), 2_010);
        assert_eq!(rollback.status(), ClockStatus::WallClockRollbackDetected);
        assert!(rollback.status().requires_conservative_cleanup());
    }

    #[test]
    fn wall_rollback_does_not_reduce_logical_time() {
        let tracker = ClockTracker::try_new(100);
        let Ok(mut tracker) = tracker else {
            panic!("valid clock anchor was rejected");
        };
        let first = tracker.observe(Duration::from_secs(10), 110);
        assert!(first.is_ok());
        let rollback = tracker.observe(Duration::from_secs(20), 90);
        let Ok(rollback) = rollback else {
            panic!("wall rollback observation was rejected");
        };
        assert_eq!(rollback.wall_seconds(), 120);
        assert_eq!(rollback.status(), ClockStatus::WallClockRollbackDetected);
    }

    #[test]
    fn monotonic_regression_is_rejected_without_state_change() {
        let tracker = ClockTracker::try_new(100);
        let Ok(mut tracker) = tracker else {
            panic!("valid clock anchor was rejected");
        };
        assert!(tracker.observe(Duration::from_secs(10), 110).is_ok());
        assert_eq!(
            tracker.observe(Duration::from_secs(9), 111),
            Err(ClockError::MonotonicRegression)
        );
        let recovered = tracker.observe(Duration::from_secs(11), 111);
        let Ok(recovered) = recovered else {
            panic!("tracker state changed after rejected observation");
        };
        assert_eq!(recovered.wall_seconds(), 111);
        assert_eq!(recovered.status(), ClockStatus::Normal);
    }

    #[test]
    fn overflow_and_out_of_range_values_do_not_mutate_tracker() {
        assert!(ClockTracker::try_new(MAX_SUPPORTED_WALL_SECONDS).is_ok());
        assert!(matches!(
            ClockTracker::try_new(MAX_SUPPORTED_WALL_SECONDS + 1),
            Err(ClockError::WallClockOutOfRange)
        ));
        let tracker = ClockTracker::try_new(MAX_SUPPORTED_WALL_SECONDS);
        let Ok(mut tracker) = tracker else {
            panic!("maximum clock anchor was rejected");
        };
        assert_eq!(
            tracker.observe(Duration::from_secs(1), MAX_SUPPORTED_WALL_SECONDS),
            Err(ClockError::WallClockOutOfRange)
        );
        assert_eq!(
            tracker.last_logical_wall_seconds(),
            MAX_SUPPORTED_WALL_SECONDS
        );
    }

    #[test]
    fn observed_wall_out_of_range_is_rejected_without_state_change() {
        let tracker = ClockTracker::try_new(100);
        let Ok(mut tracker) = tracker else {
            panic!("valid clock anchor was rejected");
        };
        assert_eq!(
            tracker.observe(Duration::from_secs(1), MAX_SUPPORTED_WALL_SECONDS + 1),
            Err(ClockError::WallClockOutOfRange)
        );
        assert_eq!(tracker.last_logical_wall_seconds(), 100);
    }

    #[test]
    fn arithmetic_overflow_is_rejected_without_state_change() {
        let tracker = ClockTracker::try_new(100);
        let Ok(mut tracker) = tracker else {
            panic!("valid clock anchor was rejected");
        };
        assert_eq!(
            tracker.observe(Duration::from_secs(u64::MAX), 100),
            Err(ClockError::ArithmeticOverflow)
        );
        assert_eq!(tracker.last_logical_wall_seconds(), 100);
    }

    #[test]
    fn system_time_before_unix_epoch_is_rejected() {
        let Some(before_epoch) = UNIX_EPOCH.checked_sub(Duration::from_secs(1)) else {
            panic!("test platform cannot represent a time before Unix epoch");
        };
        assert_eq!(
            system_wall_seconds(before_epoch),
            Err(ClockError::WallClockBeforeUnixEpoch)
        );
    }

    #[test]
    fn debug_and_errors_do_not_disclose_exact_time() {
        let tracker = ClockTracker::try_new(123_456_789);
        let Ok(mut tracker) = tracker else {
            panic!("valid clock anchor was rejected");
        };
        let reading = tracker.observe(Duration::from_secs(1), 123_456_790);
        let Ok(reading) = reading else {
            panic!("valid clock observation was rejected");
        };
        let output = format!("{tracker:?} {reading:?} {}", ClockError::ArithmeticOverflow);
        assert!(!output.contains("123456789"));
        assert!(!output.contains("123456790"));
        assert!(output.contains("redacted"));
    }

    #[test]
    fn deterministic_varied_observations_never_move_logical_time_backwards() {
        let tracker = ClockTracker::try_new(10_000);
        let Ok(mut tracker) = tracker else {
            panic!("valid clock anchor was rejected");
        };
        let mut previous = 10_000;
        for step in 0..1_000_u64 {
            let observed = if step % 17 == 0 {
                9_000 + step
            } else {
                10_000 + step
            };
            let reading = tracker.observe(Duration::from_secs(step), observed);
            let Ok(reading) = reading else {
                panic!("bounded deterministic observation was rejected");
            };
            assert!(reading.wall_seconds() >= previous);
            previous = reading.wall_seconds();
        }
    }

    #[test]
    fn production_clock_returns_a_bounded_non_decreasing_reading() {
        let clock = SystemRuntimeClock::start();
        let Ok(mut clock) = clock else {
            panic!("system runtime clock could not start");
        };
        let first = clock.now();
        let second = clock.now();
        let (Ok(first), Ok(second)) = (first, second) else {
            panic!("system runtime clock could not be read");
        };
        assert!(second.wall_seconds() >= first.wall_seconds());
        assert!(second.wall_seconds() <= MAX_SUPPORTED_WALL_SECONDS);
    }
}
