// SPDX-License-Identifier: MPL-2.0

//! Bounded diagnostics that cannot accept messages, identifiers or free text.

#![forbid(unsafe_code)]

mod event;
mod journal;

pub use event::{
    DiagnosticError, DiagnosticEvent, DurationBucket, EventCode, EventOutcome, SizeBucket,
};
pub use journal::{
    DEFAULT_JOURNAL_LOGICAL_BYTES, DEFAULT_JOURNAL_RECORDS, DiagnosticJournal, DiagnosticRecord,
    JournalLimits, JournalMaintenance, JournalView, RecordResult,
};

/// Maximum number of records accepted by one journal configuration.
pub const MAX_JOURNAL_RECORDS: usize = 10_000;
/// Maximum logical bytes accepted by one in-memory journal configuration.
pub const MAX_JOURNAL_LOGICAL_BYTES: usize = MAX_JOURNAL_RECORDS * DIAGNOSTIC_RECORD_LOGICAL_BYTES;
/// Maximum time a record may remain in memory: seven days.
pub const MAX_JOURNAL_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
/// Smallest configurable retention, used to reject accidental zero retention.
pub const MIN_JOURNAL_RETENTION_SECONDS: u64 = 60;
/// Maximum exact object counter accepted in one aggregate event.
pub const MAX_EVENT_OBJECT_COUNT: u16 = 10_000;
/// Logical accounting size of one record.
pub const DIAGNOSTIC_RECORD_LOGICAL_BYTES: usize = 32;
