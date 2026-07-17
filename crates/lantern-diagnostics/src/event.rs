// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use crate::MAX_EVENT_OBJECT_COUNT;

/// Closed technical event vocabulary. It intentionally has no text variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EventCode {
    NodeStarted,
    NodeStopped,
    StorageOpened,
    QueueRecovered,
    QueueSaved,
    EnvelopeAccepted,
    EnvelopeRejected,
    DuplicateIgnored,
    EnvelopeExpired,
    EnvelopeEvicted,
    TransferOffered,
    TransferCompleted,
    TransferRejected,
    ClockRollbackDetected,
    OperationFailed,
}

/// Closed outcome vocabulary with no underlying error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EventOutcome {
    Success,
    InvalidInput,
    Duplicate,
    Expired,
    QuotaReached,
    UnsupportedVersion,
    StorageFailure,
    ClockRollback,
}

/// Coarse object-size category. Exact bytes are discarded at construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SizeBucket {
    NotRecorded,
    UpTo1KiB,
    UpTo4KiB,
    UpTo16KiB,
    UpTo64KiB,
    Over64KiB,
}

impl SizeBucket {
    pub const fn from_bytes(bytes: Option<usize>) -> Self {
        match bytes {
            None => Self::NotRecorded,
            Some(0..=1024) => Self::UpTo1KiB,
            Some(1025..=4096) => Self::UpTo4KiB,
            Some(4097..=16_384) => Self::UpTo16KiB,
            Some(16_385..=65_536) => Self::UpTo64KiB,
            Some(65_537..) => Self::Over64KiB,
        }
    }
}

/// Coarse operation-duration category. Exact duration is discarded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurationBucket {
    NotRecorded,
    Under10Milliseconds,
    Under100Milliseconds,
    Under1Second,
    Under10Seconds,
    TenSecondsOrMore,
}

impl DurationBucket {
    pub const fn from_milliseconds(milliseconds: Option<u64>) -> Self {
        match milliseconds {
            None => Self::NotRecorded,
            Some(0..=9) => Self::Under10Milliseconds,
            Some(10..=99) => Self::Under100Milliseconds,
            Some(100..=999) => Self::Under1Second,
            Some(1000..=9999) => Self::Under10Seconds,
            Some(10_000..) => Self::TenSecondsOrMore,
        }
    }
}

/// One validated event before the journal assigns local ordering and expiry.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DiagnosticEvent {
    code: EventCode,
    outcome: EventOutcome,
    object_count: u16,
    size_bucket: SizeBucket,
    duration_bucket: DurationBucket,
}

impl DiagnosticEvent {
    pub fn try_new(
        code: EventCode,
        outcome: EventOutcome,
        object_count: u16,
        size_bytes: Option<usize>,
        duration_milliseconds: Option<u64>,
    ) -> Result<Self, DiagnosticError> {
        if object_count > MAX_EVENT_OBJECT_COUNT {
            return Err(DiagnosticError::ObjectCountTooLarge);
        }
        Ok(Self {
            code,
            outcome,
            object_count,
            size_bucket: SizeBucket::from_bytes(size_bytes),
            duration_bucket: DurationBucket::from_milliseconds(duration_milliseconds),
        })
    }

    pub const fn code(self) -> EventCode {
        self.code
    }

    pub const fn outcome(self) -> EventOutcome {
        self.outcome
    }

    pub const fn object_count(self) -> u16 {
        self.object_count
    }

    pub const fn size_bucket(self) -> SizeBucket {
        self.size_bucket
    }

    pub const fn duration_bucket(self) -> DurationBucket {
        self.duration_bucket
    }
}

impl fmt::Debug for DiagnosticEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticEvent")
            .field("code", &self.code)
            .field("outcome", &self.outcome)
            .field("object_count", &self.object_count)
            .field("size_bucket", &self.size_bucket)
            .field("duration_bucket", &self.duration_bucket)
            .finish()
    }
}

/// Safe diagnostic error category without input values or external errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticError {
    InvalidRecordLimit,
    InvalidByteLimit,
    InvalidRetention,
    ObjectCountTooLarge,
    ArithmeticOverflow,
}

impl fmt::Display for DiagnosticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRecordLimit => formatter.write_str("invalid diagnostic record limit"),
            Self::InvalidByteLimit => formatter.write_str("invalid diagnostic byte limit"),
            Self::InvalidRetention => formatter.write_str("invalid diagnostic retention"),
            Self::ObjectCountTooLarge => {
                formatter.write_str("diagnostic object count exceeds limit")
            }
            Self::ArithmeticOverflow => formatter.write_str("diagnostic arithmetic overflow"),
        }
    }
}

impl std::error::Error for DiagnosticError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_buckets_cover_exact_boundaries() {
        assert_eq!(SizeBucket::from_bytes(None), SizeBucket::NotRecorded);
        assert_eq!(SizeBucket::from_bytes(Some(0)), SizeBucket::UpTo1KiB);
        assert_eq!(SizeBucket::from_bytes(Some(1024)), SizeBucket::UpTo1KiB);
        assert_eq!(SizeBucket::from_bytes(Some(1025)), SizeBucket::UpTo4KiB);
        assert_eq!(SizeBucket::from_bytes(Some(4096)), SizeBucket::UpTo4KiB);
        assert_eq!(SizeBucket::from_bytes(Some(4097)), SizeBucket::UpTo16KiB);
        assert_eq!(SizeBucket::from_bytes(Some(16_384)), SizeBucket::UpTo16KiB);
        assert_eq!(SizeBucket::from_bytes(Some(16_385)), SizeBucket::UpTo64KiB);
        assert_eq!(SizeBucket::from_bytes(Some(65_536)), SizeBucket::UpTo64KiB);
        assert_eq!(SizeBucket::from_bytes(Some(65_537)), SizeBucket::Over64KiB);
    }

    #[test]
    fn duration_buckets_cover_exact_boundaries() {
        assert_eq!(
            DurationBucket::from_milliseconds(None),
            DurationBucket::NotRecorded
        );
        assert_eq!(
            DurationBucket::from_milliseconds(Some(9)),
            DurationBucket::Under10Milliseconds
        );
        assert_eq!(
            DurationBucket::from_milliseconds(Some(10)),
            DurationBucket::Under100Milliseconds
        );
        assert_eq!(
            DurationBucket::from_milliseconds(Some(100)),
            DurationBucket::Under1Second
        );
        assert_eq!(
            DurationBucket::from_milliseconds(Some(1000)),
            DurationBucket::Under10Seconds
        );
        assert_eq!(
            DurationBucket::from_milliseconds(Some(10_000)),
            DurationBucket::TenSecondsOrMore
        );
    }

    #[test]
    fn exact_size_and_duration_are_discarded() {
        let event = DiagnosticEvent::try_new(
            EventCode::QueueSaved,
            EventOutcome::Success,
            7,
            Some(12_345),
            Some(8_765),
        );
        let Ok(event) = event else {
            panic!("valid diagnostic event was rejected");
        };
        let output = format!("{event:?}");
        assert!(!output.contains("12345"));
        assert!(!output.contains("8765"));
        assert_eq!(event.size_bucket(), SizeBucket::UpTo16KiB);
        assert_eq!(event.duration_bucket(), DurationBucket::Under10Seconds);
    }

    #[test]
    fn object_count_is_bounded() {
        assert!(
            DiagnosticEvent::try_new(
                EventCode::QueueRecovered,
                EventOutcome::Success,
                MAX_EVENT_OBJECT_COUNT,
                None,
                None,
            )
            .is_ok()
        );
        assert_eq!(
            DiagnosticEvent::try_new(
                EventCode::QueueRecovered,
                EventOutcome::Success,
                MAX_EVENT_OBJECT_COUNT + 1,
                None,
                None,
            ),
            Err(DiagnosticError::ObjectCountTooLarge)
        );
    }
}
