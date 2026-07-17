// SPDX-License-Identifier: MPL-2.0

use core::fmt;
use std::collections::VecDeque;

use crate::{
    DIAGNOSTIC_RECORD_LOGICAL_BYTES, DiagnosticError, DiagnosticEvent, DurationBucket, EventCode,
    EventOutcome, MAX_JOURNAL_LOGICAL_BYTES, MAX_JOURNAL_RECORDS, MAX_JOURNAL_RETENTION_SECONDS,
    MIN_JOURNAL_RETENTION_SECONDS, SizeBucket,
};

pub const DEFAULT_JOURNAL_RECORDS: usize = 2_048;
pub const DEFAULT_JOURNAL_LOGICAL_BYTES: usize =
    DEFAULT_JOURNAL_RECORDS * DIAGNOSTIC_RECORD_LOGICAL_BYTES;

/// Hard limits for one in-memory journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalLimits {
    max_records: usize,
    max_logical_bytes: usize,
    retention_seconds: u64,
}

impl JournalLimits {
    pub fn try_new(
        max_records: usize,
        max_logical_bytes: usize,
        retention_seconds: u64,
    ) -> Result<Self, DiagnosticError> {
        if max_records == 0 || max_records > MAX_JOURNAL_RECORDS {
            return Err(DiagnosticError::InvalidRecordLimit);
        }
        if !(DIAGNOSTIC_RECORD_LOGICAL_BYTES..=MAX_JOURNAL_LOGICAL_BYTES)
            .contains(&max_logical_bytes)
        {
            return Err(DiagnosticError::InvalidByteLimit);
        }
        if !(MIN_JOURNAL_RETENTION_SECONDS..=MAX_JOURNAL_RETENTION_SECONDS)
            .contains(&retention_seconds)
        {
            return Err(DiagnosticError::InvalidRetention);
        }
        Ok(Self {
            max_records,
            max_logical_bytes,
            retention_seconds,
        })
    }

    pub const fn max_records(self) -> usize {
        self.max_records
    }

    pub const fn max_logical_bytes(self) -> usize {
        self.max_logical_bytes
    }

    pub const fn retention_seconds(self) -> u64 {
        self.retention_seconds
    }
}

impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            max_records: DEFAULT_JOURNAL_RECORDS,
            max_logical_bytes: DEFAULT_JOURNAL_LOGICAL_BYTES,
            retention_seconds: MAX_JOURNAL_RETENTION_SECONDS,
        }
    }
}

/// Safe record visible to diagnostic consumers. It has no timestamp or text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticRecord {
    sequence: u64,
    code: EventCode,
    outcome: EventOutcome,
    object_count: u16,
    size_bucket: SizeBucket,
    duration_bucket: DurationBucket,
}

impl DiagnosticRecord {
    pub const fn sequence(self) -> u64 {
        self.sequence
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

impl From<(u64, DiagnosticEvent)> for DiagnosticRecord {
    fn from((sequence, event): (u64, DiagnosticEvent)) -> Self {
        Self {
            sequence,
            code: event.code(),
            outcome: event.outcome(),
            object_count: event.object_count(),
            size_bucket: event.size_bucket(),
            duration_bucket: event.duration_bucket(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JournalMaintenance {
    expired_records: usize,
    evicted_records: usize,
    rollback_cleared_records: usize,
    clock_rollback_detected: bool,
}

impl JournalMaintenance {
    pub const fn expired_records(self) -> usize {
        self.expired_records
    }

    pub const fn evicted_records(self) -> usize {
        self.evicted_records
    }

    pub const fn rollback_cleared_records(self) -> usize {
        self.rollback_cleared_records
    }

    pub const fn clock_rollback_detected(self) -> bool {
        self.clock_rollback_detected
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordResult {
    record: DiagnosticRecord,
    maintenance: JournalMaintenance,
}

impl RecordResult {
    pub const fn record(self) -> DiagnosticRecord {
        self.record
    }

    pub const fn maintenance(self) -> JournalMaintenance {
        self.maintenance
    }
}

struct StoredRecord {
    record: DiagnosticRecord,
    expires_at: u64,
}

/// Maintained read-only view. Creating it always applies time maintenance.
pub struct JournalView<'a> {
    maintenance: JournalMaintenance,
    records: &'a VecDeque<StoredRecord>,
}

impl JournalView<'_> {
    pub const fn maintenance(&self) -> JournalMaintenance {
        self.maintenance
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn logical_bytes(&self) -> usize {
        self.records.len() * DIAGNOSTIC_RECORD_LOGICAL_BYTES
    }

    pub fn records(&self) -> impl Iterator<Item = &DiagnosticRecord> {
        self.records.iter().map(|stored| &stored.record)
    }
}

impl fmt::Debug for JournalView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JournalView")
            .field("maintenance", &self.maintenance)
            .field("record_count", &self.records.len())
            .finish_non_exhaustive()
    }
}

/// Explicit, in-memory, bounded journal with no global logger or file output.
pub struct DiagnosticJournal {
    limits: JournalLimits,
    records: VecDeque<StoredRecord>,
    next_sequence: u64,
    last_observed_wall_seconds: Option<u64>,
}

impl DiagnosticJournal {
    pub fn new(limits: JournalLimits) -> Self {
        Self {
            limits,
            records: VecDeque::new(),
            next_sequence: 1,
            last_observed_wall_seconds: None,
        }
    }

    pub const fn limits(&self) -> JournalLimits {
        self.limits
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn logical_bytes(&self) -> usize {
        self.records.len() * DIAGNOSTIC_RECORD_LOGICAL_BYTES
    }

    pub fn record(
        &mut self,
        event: DiagnosticEvent,
        observed_wall_seconds: u64,
    ) -> Result<RecordResult, DiagnosticError> {
        let expires_at = observed_wall_seconds
            .checked_add(self.limits.retention_seconds)
            .ok_or(DiagnosticError::ArithmeticOverflow)?;
        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(DiagnosticError::ArithmeticOverflow)?;
        let mut maintenance = self.maintain_internal(observed_wall_seconds);

        while self.records.len() >= self.limits.max_records
            || self
                .logical_bytes()
                .checked_add(DIAGNOSTIC_RECORD_LOGICAL_BYTES)
                .is_none_or(|bytes| bytes > self.limits.max_logical_bytes)
        {
            if self.records.pop_front().is_none() {
                return Err(DiagnosticError::InvalidByteLimit);
            }
            maintenance.evicted_records = maintenance
                .evicted_records
                .checked_add(1)
                .ok_or(DiagnosticError::ArithmeticOverflow)?;
        }

        let record = DiagnosticRecord::from((sequence, event));
        self.records.push_back(StoredRecord { record, expires_at });
        self.next_sequence = next_sequence;
        self.last_observed_wall_seconds = Some(observed_wall_seconds);
        Ok(RecordResult {
            record,
            maintenance,
        })
    }

    pub fn maintain(&mut self, observed_wall_seconds: u64) -> JournalMaintenance {
        let maintenance = self.maintain_internal(observed_wall_seconds);
        self.last_observed_wall_seconds = Some(observed_wall_seconds);
        maintenance
    }

    pub fn view(&mut self, observed_wall_seconds: u64) -> JournalView<'_> {
        let maintenance = self.maintain(observed_wall_seconds);
        JournalView {
            maintenance,
            records: &self.records,
        }
    }

    pub fn clear(&mut self) -> usize {
        let removed = self.records.len();
        self.records.clear();
        removed
    }

    fn maintain_internal(&mut self, observed_wall_seconds: u64) -> JournalMaintenance {
        if self
            .last_observed_wall_seconds
            .is_some_and(|last| observed_wall_seconds < last)
        {
            let rollback_cleared_records = self.clear();
            return JournalMaintenance {
                rollback_cleared_records,
                clock_rollback_detected: true,
                ..JournalMaintenance::default()
            };
        }

        let mut expired_records = 0_usize;
        while self
            .records
            .front()
            .is_some_and(|record| record.expires_at <= observed_wall_seconds)
        {
            self.records.pop_front();
            expired_records += 1;
        }
        JournalMaintenance {
            expired_records,
            ..JournalMaintenance::default()
        }
    }
}

impl Default for DiagnosticJournal {
    fn default() -> Self {
        Self::new(JournalLimits::default())
    }
}

impl fmt::Debug for DiagnosticJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticJournal")
            .field("limits", &self.limits)
            .field("record_count", &self.records.len())
            .field("logical_bytes", &self.logical_bytes())
            .field("timing", &"redacted")
            .finish_non_exhaustive()
    }
}

