// SPDX-License-Identifier: MPL-2.0

use core::fmt;
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, TransactionBehavior, limits::Limit, params,
};

use super::{
    DiagnosticJournal, DiagnosticRecord, JournalLimits, JournalMaintenance, JournalView,
    RecordResult, StoredRecord,
};
use crate::{
    DIAGNOSTIC_RECORD_LOGICAL_BYTES, DiagnosticError, DiagnosticEvent, DurationBucket, EventCode,
    EventOutcome, SizeBucket,
};

const APPLICATION_ID: i64 = 0x4c44_4941;
const SCHEMA_VERSION: i64 = 1;
const SQLITE_VALUE_LIMIT: i32 = 1024 * 1024;
const SQLITE_SQL_LIMIT: i32 = 64 * 1024;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

pub const MAX_DIAGNOSTIC_FILE_BYTES: u64 = 10 * 1024 * 1024;

const CREATE_SCHEMA: &str = r#"
CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    max_records INTEGER NOT NULL CHECK (max_records BETWEEN 1 AND 10000),
    max_logical_bytes INTEGER NOT NULL
        CHECK (max_logical_bytes BETWEEN 32 AND 320000),
    retention_seconds INTEGER NOT NULL
        CHECK (retention_seconds BETWEEN 60 AND 604800),
    next_sequence INTEGER NOT NULL CHECK (next_sequence >= 1),
    last_observed_wall_seconds INTEGER NOT NULL
        CHECK (last_observed_wall_seconds >= 0)
) STRICT;

CREATE TABLE diagnostic_records (
    sequence INTEGER PRIMARY KEY CHECK (sequence >= 1),
    code INTEGER NOT NULL CHECK (code BETWEEN 0 AND 14),
    outcome INTEGER NOT NULL CHECK (outcome BETWEEN 0 AND 8),
    object_count INTEGER NOT NULL CHECK (object_count BETWEEN 0 AND 10000),
    size_bucket INTEGER NOT NULL CHECK (size_bucket BETWEEN 0 AND 5),
    duration_bucket INTEGER NOT NULL CHECK (duration_bucket BETWEEN 0 AND 5),
    expires_at_wall_seconds INTEGER NOT NULL
        CHECK (expires_at_wall_seconds >= 0)
) STRICT;
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentDiagnosticError {
    Database,
    Io,
    FileTooLarge,
    UnsupportedSchema,
    WrongApplication,
    LimitMismatch,
    CorruptData,
    ClockOutOfRange,
    Journal(DiagnosticError),
}

impl fmt::Display for PersistentDiagnosticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database => formatter.write_str("persistent diagnostics database failed"),
            Self::Io => formatter.write_str("persistent diagnostics I/O operation failed"),
            Self::FileTooLarge => formatter.write_str("persistent diagnostics file exceeds limit"),
            Self::UnsupportedSchema => {
                formatter.write_str("unsupported persistent diagnostics schema")
            }
            Self::WrongApplication => {
                formatter.write_str("database does not contain Lantern diagnostics")
            }
            Self::LimitMismatch => {
                formatter.write_str("persistent diagnostics limits do not match")
            }
            Self::CorruptData => formatter.write_str("invalid persistent diagnostics data"),
            Self::ClockOutOfRange => formatter.write_str("diagnostic clock is outside range"),
            Self::Journal(error) => write!(formatter, "diagnostic journal failed: {error}"),
        }
    }
}

impl std::error::Error for PersistentDiagnosticError {}

impl From<DiagnosticError> for PersistentDiagnosticError {
    fn from(error: DiagnosticError) -> Self {
        Self::Journal(error)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PersistentDiagnosticRecovery {
    expired_records: usize,
    cleared_records: usize,
    clock_rollback_detected: bool,
}

impl PersistentDiagnosticRecovery {
    pub const fn expired_records(self) -> usize {
        self.expired_records
    }

    pub const fn cleared_records(self) -> usize {
        self.cleared_records
    }

    pub const fn clock_rollback_detected(self) -> bool {
        self.clock_rollback_detected
    }
}

pub struct PersistentDiagnosticJournal {
    connection: Connection,
    journal: DiagnosticJournal,
}

impl PersistentDiagnosticJournal {
    pub fn open(
        path: &Path,
        limits: JournalLimits,
        observed_wall_seconds: u64,
    ) -> Result<(Self, PersistentDiagnosticRecovery), PersistentDiagnosticError> {
        let new_database = preflight_files(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_EXRESCODE;
        let mut connection = Connection::open_with_flags(path, flags).map_err(database_error)?;
        restrict_file_permissions(path)?;
        configure_runtime_limits(&connection)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(database_error)?;

        let application_id = read_pragma_i64(&connection, "application_id")?;
        let schema_version = read_pragma_i64(&connection, "user_version")?;
        if new_database {
            if application_id != 0 || schema_version != 0 {
                return Err(PersistentDiagnosticError::WrongApplication);
            }
            initialize_database(&mut connection, limits, observed_wall_seconds)?;
        } else {
            if application_id != APPLICATION_ID {
                return Err(PersistentDiagnosticError::WrongApplication);
            }
            if schema_version != SCHEMA_VERSION {
                return Err(PersistentDiagnosticError::UnsupportedSchema);
            }
        }

        configure_connection(&connection)?;
        check_database_size(&connection)?;
        check_integrity(&connection)?;
        let mut journal = read_journal(&connection, limits)?;
        let maintenance = journal.maintain(observed_wall_seconds);
        save_snapshot(&mut connection, &journal)?;
        let recovery = PersistentDiagnosticRecovery {
            expired_records: maintenance.expired_records(),
            cleared_records: maintenance.rollback_cleared_records(),
            clock_rollback_detected: maintenance.clock_rollback_detected(),
        };
        Ok((
            Self {
                connection,
                journal,
            },
            recovery,
        ))
    }

    pub const fn limits(&self) -> JournalLimits {
        self.journal.limits
    }

    pub fn len(&self) -> usize {
        self.journal.len()
    }

    pub fn is_empty(&self) -> bool {
        self.journal.is_empty()
    }

    pub fn logical_bytes(&self) -> usize {
        self.journal.logical_bytes()
    }

    pub fn record(
        &mut self,
        event: DiagnosticEvent,
        observed_wall_seconds: u64,
    ) -> Result<RecordResult, PersistentDiagnosticError> {
        let mut candidate = clone_journal(&self.journal);
        let result = candidate.record(event, observed_wall_seconds)?;
        save_snapshot(&mut self.connection, &candidate)?;
        self.journal = candidate;
        Ok(result)
    }

    pub fn maintain(
        &mut self,
        observed_wall_seconds: u64,
    ) -> Result<JournalMaintenance, PersistentDiagnosticError> {
        let mut candidate = clone_journal(&self.journal);
        let maintenance = candidate.maintain(observed_wall_seconds);
        save_snapshot(&mut self.connection, &candidate)?;
        self.journal = candidate;
        Ok(maintenance)
    }

    pub fn view(
        &mut self,
        observed_wall_seconds: u64,
    ) -> Result<JournalView<'_>, PersistentDiagnosticError> {
        let maintenance = self.maintain(observed_wall_seconds)?;
        Ok(JournalView {
            maintenance,
            records: &self.journal.records,
        })
    }

    pub fn clear(
        &mut self,
        observed_wall_seconds: u64,
    ) -> Result<usize, PersistentDiagnosticError> {
        let mut candidate = clone_journal(&self.journal);
        let removed = candidate.clear();
        candidate.last_observed_wall_seconds = Some(observed_wall_seconds);
        save_snapshot(&mut self.connection, &candidate)?;
        self.journal = candidate;
        Ok(removed)
    }
}

impl fmt::Debug for PersistentDiagnosticJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentDiagnosticJournal")
            .field("limits", &self.journal.limits)
            .field("record_count", &self.journal.len())
            .field("file", &"redacted")
            .field("timing", &"redacted")
            .finish_non_exhaustive()
    }
}

fn clone_journal(journal: &DiagnosticJournal) -> DiagnosticJournal {
    DiagnosticJournal {
        limits: journal.limits,
        records: journal.records.clone(),
        next_sequence: journal.next_sequence,
        last_observed_wall_seconds: journal.last_observed_wall_seconds,
    }
}

fn preflight_files(path: &Path) -> Result<bool, PersistentDiagnosticError> {
    let main_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(PersistentDiagnosticError::Io),
    };
    if let Some(metadata) = &main_metadata {
        validate_file_metadata(metadata)?;
    }
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = path_with_suffix(path, suffix);
        match fs::symlink_metadata(sidecar) {
            Ok(metadata) => validate_file_metadata(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PersistentDiagnosticError::Io),
        }
    }
    Ok(main_metadata.is_none() || main_metadata.is_some_and(|metadata| metadata.len() == 0))
}

fn validate_file_metadata(metadata: &fs::Metadata) -> Result<(), PersistentDiagnosticError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PersistentDiagnosticError::Io);
    }
    if metadata.len() > MAX_DIAGNOSTIC_FILE_BYTES {
        return Err(PersistentDiagnosticError::FileTooLarge);
    }
    validate_unix_link_count(metadata)?;
    Ok(())
}

#[cfg(unix)]
fn validate_unix_link_count(metadata: &fs::Metadata) -> Result<(), PersistentDiagnosticError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.nlink() != 1 {
        return Err(PersistentDiagnosticError::Io);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_unix_link_count(_metadata: &fs::Metadata) -> Result<(), PersistentDiagnosticError> {
    Ok(())
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<(), PersistentDiagnosticError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| PersistentDiagnosticError::Io)
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<(), PersistentDiagnosticError> {
    Ok(())
}

fn configure_runtime_limits(connection: &Connection) -> Result<(), PersistentDiagnosticError> {
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, SQLITE_VALUE_LIMIT),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, SQLITE_SQL_LIMIT),
        (Limit::SQLITE_LIMIT_COLUMN, 16),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 16),
        (Limit::SQLITE_LIMIT_TRIGGER_DEPTH, 0),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
    ] {
        connection.set_limit(limit, value).map_err(database_error)?;
    }
    Ok(())
}

fn initialize_database(
    connection: &mut Connection,
    limits: JournalLimits,
    observed_wall_seconds: u64,
) -> Result<(), PersistentDiagnosticError> {
    connection
        .pragma_update(None, "page_size", 4096_i64)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "auto_vacuum", "FULL")
        .map_err(database_error)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(database_error)?;
    transaction
        .execute_batch(CREATE_SCHEMA)
        .map_err(database_error)?;
    let updated = transaction
        .execute(
            "INSERT INTO metadata (
                singleton,
                schema_version,
                max_records,
                max_logical_bytes,
                retention_seconds,
                next_sequence,
                last_observed_wall_seconds
            ) VALUES (1, ?1, ?2, ?3, ?4, 1, ?5)",
            params![
                SCHEMA_VERSION,
                usize_to_i64(limits.max_records())?,
                usize_to_i64(limits.max_logical_bytes())?,
                to_sql_integer(limits.retention_seconds())?,
                to_sql_integer(observed_wall_seconds)?,
            ],
        )
        .map_err(database_error)?;
    if updated != 1 {
        return Err(PersistentDiagnosticError::CorruptData);
    }
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(database_error)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(database_error)?;
    transaction.commit().map_err(database_error)
}

fn configure_connection(connection: &Connection) -> Result<(), PersistentDiagnosticError> {
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "cell_size_check", true)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "secure_delete", true)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "temp_store", "MEMORY")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "synchronous", "EXTRA")
        .map_err(database_error)?;
    let journal_mode: String = connection
        .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
        .map_err(database_error)?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        return Err(PersistentDiagnosticError::Database);
    }
    Ok(())
}

fn check_database_size(connection: &Connection) -> Result<(), PersistentDiagnosticError> {
    let page_size = read_pragma_i64(connection, "page_size")?;
    let page_count = read_pragma_i64(connection, "page_count")?;
    if page_size <= 0 || page_count < 0 {
        return Err(PersistentDiagnosticError::CorruptData);
    }
    let total_bytes = page_size
        .checked_mul(page_count)
        .ok_or(PersistentDiagnosticError::FileTooLarge)?;
    if u64::try_from(total_bytes).map_err(|_| PersistentDiagnosticError::FileTooLarge)?
        > MAX_DIAGNOSTIC_FILE_BYTES
    {
        return Err(PersistentDiagnosticError::FileTooLarge);
    }
    let max_pages = i64::try_from(MAX_DIAGNOSTIC_FILE_BYTES)
        .map_err(|_| PersistentDiagnosticError::FileTooLarge)?
        .checked_add(page_size - 1)
        .ok_or(PersistentDiagnosticError::FileTooLarge)?
        / page_size;
    connection
        .pragma_update(None, "max_page_count", max_pages)
        .map_err(database_error)?;
    Ok(())
}

fn check_integrity(connection: &Connection) -> Result<(), PersistentDiagnosticError> {
    let result: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(database_error)?;
    if result != "ok" {
        return Err(PersistentDiagnosticError::CorruptData);
    }
    Ok(())
}

fn read_journal(
    connection: &Connection,
    expected_limits: JournalLimits,
) -> Result<DiagnosticJournal, PersistentDiagnosticError> {
    let metadata = connection
        .query_row(
            "SELECT
                schema_version,
                max_records,
                max_logical_bytes,
                retention_seconds,
                next_sequence,
                last_observed_wall_seconds
             FROM metadata
             WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?
        .ok_or(PersistentDiagnosticError::CorruptData)?;
    if metadata.0 != SCHEMA_VERSION {
        return Err(PersistentDiagnosticError::UnsupportedSchema);
    }
    let stored_limits = JournalLimits::try_new(
        positive_i64_to_usize(metadata.1)?,
        positive_i64_to_usize(metadata.2)?,
        nonnegative_i64_to_u64(metadata.3)?,
    )
    .map_err(|_| PersistentDiagnosticError::CorruptData)?;
    if stored_limits != expected_limits {
        return Err(PersistentDiagnosticError::LimitMismatch);
    }
    let next_sequence = positive_i64_to_u64(metadata.4)?;
    let last_observed_wall_seconds = nonnegative_i64_to_u64(metadata.5)?;
    let latest_allowed_expiry = last_observed_wall_seconds
        .checked_add(expected_limits.retention_seconds())
        .ok_or(PersistentDiagnosticError::CorruptData)?;

    let record_count: i64 = connection
        .query_row("SELECT count(*) FROM diagnostic_records", [], |row| {
            row.get(0)
        })
        .map_err(database_error)?;
    let record_count = nonnegative_i64_to_usize(record_count)?;
    let logical_bytes = record_count
        .checked_mul(DIAGNOSTIC_RECORD_LOGICAL_BYTES)
        .ok_or(PersistentDiagnosticError::CorruptData)?;
    if record_count > expected_limits.max_records()
        || logical_bytes > expected_limits.max_logical_bytes()
    {
        return Err(PersistentDiagnosticError::CorruptData);
    }

    let mut statement = connection
        .prepare(
            "SELECT
                sequence,
                code,
                outcome,
                object_count,
                size_bucket,
                duration_bucket,
                expires_at_wall_seconds
             FROM diagnostic_records
             ORDER BY sequence",
        )
        .map_err(database_error)?;
    let mut rows = statement.query([]).map_err(database_error)?;
    let mut records = std::collections::VecDeque::with_capacity(record_count);
    let mut previous_sequence = None;
    let mut previous_expiry = None;
    while let Some(row) = rows.next().map_err(database_error)? {
        let sequence = positive_i64_to_u64(row.get(0).map_err(database_error)?)?;
        let expires_at = nonnegative_i64_to_u64(row.get(6).map_err(database_error)?)?;
        if previous_sequence.is_some_and(|previous| sequence <= previous)
            || previous_expiry.is_some_and(|previous| expires_at < previous)
            || expires_at <= last_observed_wall_seconds
            || expires_at > latest_allowed_expiry
        {
            return Err(PersistentDiagnosticError::CorruptData);
        }
        let object_count_value: i64 = row.get(3).map_err(database_error)?;
        let object_count = u16::try_from(object_count_value)
            .map_err(|_| PersistentDiagnosticError::CorruptData)?;
        let record = DiagnosticRecord {
            sequence,
            code: decode_event_code(row.get(1).map_err(database_error)?)?,
            outcome: decode_event_outcome(row.get(2).map_err(database_error)?)?,
            object_count,
            size_bucket: decode_size_bucket(row.get(4).map_err(database_error)?)?,
            duration_bucket: decode_duration_bucket(row.get(5).map_err(database_error)?)?,
        };
        records.push_back(StoredRecord { record, expires_at });
        previous_sequence = Some(sequence);
        previous_expiry = Some(expires_at);
    }
    if records.len() != record_count
        || previous_sequence.is_some_and(|sequence| next_sequence <= sequence)
    {
        return Err(PersistentDiagnosticError::CorruptData);
    }
    Ok(DiagnosticJournal {
        limits: expected_limits,
        records,
        next_sequence,
        last_observed_wall_seconds: Some(last_observed_wall_seconds),
    })
}

fn save_snapshot(
    connection: &mut Connection,
    journal: &DiagnosticJournal,
) -> Result<(), PersistentDiagnosticError> {
    let last_observed = journal
        .last_observed_wall_seconds
        .ok_or(PersistentDiagnosticError::CorruptData)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(database_error)?;
    transaction
        .execute("DELETE FROM diagnostic_records", [])
        .map_err(database_error)?;
    {
        let mut insert = transaction
            .prepare(
                "INSERT INTO diagnostic_records (
                    sequence,
                    code,
                    outcome,
                    object_count,
                    size_bucket,
                    duration_bucket,
                    expires_at_wall_seconds
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .map_err(database_error)?;
        for stored in &journal.records {
            insert
                .execute(params![
                    to_sql_integer(stored.record.sequence)?,
                    encode_event_code(stored.record.code),
                    encode_event_outcome(stored.record.outcome),
                    i64::from(stored.record.object_count),
                    encode_size_bucket(stored.record.size_bucket),
                    encode_duration_bucket(stored.record.duration_bucket),
                    to_sql_integer(stored.expires_at)?,
                ])
                .map_err(database_error)?;
        }
    }
    let updated = transaction
        .execute(
            "UPDATE metadata
             SET next_sequence = ?1, last_observed_wall_seconds = ?2
             WHERE singleton = 1",
            params![
                to_sql_integer(journal.next_sequence)?,
                to_sql_integer(last_observed)?,
            ],
        )
        .map_err(database_error)?;
    if updated != 1 {
        return Err(PersistentDiagnosticError::CorruptData);
    }
    transaction.commit().map_err(database_error)
}

fn read_pragma_i64(
    connection: &Connection,
    pragma: &str,
) -> Result<i64, PersistentDiagnosticError> {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .map_err(database_error)
}

const fn encode_event_code(code: EventCode) -> i64 {
    match code {
        EventCode::NodeStarted => 0,
        EventCode::NodeStopped => 1,
        EventCode::StorageOpened => 2,
        EventCode::QueueRecovered => 3,
        EventCode::QueueSaved => 4,
        EventCode::EnvelopeAccepted => 5,
        EventCode::EnvelopeRejected => 6,
        EventCode::DuplicateIgnored => 7,
        EventCode::EnvelopeExpired => 8,
        EventCode::EnvelopeEvicted => 9,
        EventCode::TransferOffered => 10,
        EventCode::TransferCompleted => 11,
        EventCode::TransferRejected => 12,
        EventCode::ClockRollbackDetected => 13,
        EventCode::OperationFailed => 14,
    }
}

fn decode_event_code(value: i64) -> Result<EventCode, PersistentDiagnosticError> {
    match value {
        0 => Ok(EventCode::NodeStarted),
        1 => Ok(EventCode::NodeStopped),
        2 => Ok(EventCode::StorageOpened),
        3 => Ok(EventCode::QueueRecovered),
        4 => Ok(EventCode::QueueSaved),
        5 => Ok(EventCode::EnvelopeAccepted),
        6 => Ok(EventCode::EnvelopeRejected),
        7 => Ok(EventCode::DuplicateIgnored),
        8 => Ok(EventCode::EnvelopeExpired),
        9 => Ok(EventCode::EnvelopeEvicted),
        10 => Ok(EventCode::TransferOffered),
        11 => Ok(EventCode::TransferCompleted),
        12 => Ok(EventCode::TransferRejected),
        13 => Ok(EventCode::ClockRollbackDetected),
        14 => Ok(EventCode::OperationFailed),
        _ => Err(PersistentDiagnosticError::CorruptData),
    }
}

const fn encode_event_outcome(outcome: EventOutcome) -> i64 {
    match outcome {
        EventOutcome::Success => 0,
        EventOutcome::InvalidInput => 1,
        EventOutcome::Duplicate => 2,
        EventOutcome::Expired => 3,
        EventOutcome::QuotaReached => 4,
        EventOutcome::UnsupportedVersion => 5,
        EventOutcome::StorageFailure => 6,
        EventOutcome::TransportFailure => 7,
        EventOutcome::ClockRollback => 8,
    }
}

fn decode_event_outcome(value: i64) -> Result<EventOutcome, PersistentDiagnosticError> {
    match value {
        0 => Ok(EventOutcome::Success),
        1 => Ok(EventOutcome::InvalidInput),
        2 => Ok(EventOutcome::Duplicate),
        3 => Ok(EventOutcome::Expired),
        4 => Ok(EventOutcome::QuotaReached),
        5 => Ok(EventOutcome::UnsupportedVersion),
        6 => Ok(EventOutcome::StorageFailure),
        7 => Ok(EventOutcome::TransportFailure),
        8 => Ok(EventOutcome::ClockRollback),
        _ => Err(PersistentDiagnosticError::CorruptData),
    }
}

const fn encode_size_bucket(bucket: SizeBucket) -> i64 {
    match bucket {
        SizeBucket::NotRecorded => 0,
        SizeBucket::UpTo1KiB => 1,
        SizeBucket::UpTo4KiB => 2,
        SizeBucket::UpTo16KiB => 3,
        SizeBucket::UpTo64KiB => 4,
        SizeBucket::Over64KiB => 5,
    }
}

fn decode_size_bucket(value: i64) -> Result<SizeBucket, PersistentDiagnosticError> {
    match value {
        0 => Ok(SizeBucket::NotRecorded),
        1 => Ok(SizeBucket::UpTo1KiB),
        2 => Ok(SizeBucket::UpTo4KiB),
        3 => Ok(SizeBucket::UpTo16KiB),
        4 => Ok(SizeBucket::UpTo64KiB),
        5 => Ok(SizeBucket::Over64KiB),
        _ => Err(PersistentDiagnosticError::CorruptData),
    }
}

const fn encode_duration_bucket(bucket: DurationBucket) -> i64 {
    match bucket {
        DurationBucket::NotRecorded => 0,
        DurationBucket::Under10Milliseconds => 1,
        DurationBucket::Under100Milliseconds => 2,
        DurationBucket::Under1Second => 3,
        DurationBucket::Under10Seconds => 4,
        DurationBucket::TenSecondsOrMore => 5,
    }
}

fn decode_duration_bucket(value: i64) -> Result<DurationBucket, PersistentDiagnosticError> {
    match value {
        0 => Ok(DurationBucket::NotRecorded),
        1 => Ok(DurationBucket::Under10Milliseconds),
        2 => Ok(DurationBucket::Under100Milliseconds),
        3 => Ok(DurationBucket::Under1Second),
        4 => Ok(DurationBucket::Under10Seconds),
        5 => Ok(DurationBucket::TenSecondsOrMore),
        _ => Err(PersistentDiagnosticError::CorruptData),
    }
}

fn to_sql_integer(value: u64) -> Result<i64, PersistentDiagnosticError> {
    i64::try_from(value).map_err(|_| PersistentDiagnosticError::ClockOutOfRange)
}

fn usize_to_i64(value: usize) -> Result<i64, PersistentDiagnosticError> {
    i64::try_from(value).map_err(|_| PersistentDiagnosticError::CorruptData)
}

fn nonnegative_i64_to_u64(value: i64) -> Result<u64, PersistentDiagnosticError> {
    u64::try_from(value).map_err(|_| PersistentDiagnosticError::CorruptData)
}

fn positive_i64_to_u64(value: i64) -> Result<u64, PersistentDiagnosticError> {
    if value <= 0 {
        return Err(PersistentDiagnosticError::CorruptData);
    }
    u64::try_from(value).map_err(|_| PersistentDiagnosticError::CorruptData)
}

fn positive_i64_to_usize(value: i64) -> Result<usize, PersistentDiagnosticError> {
    if value <= 0 {
        return Err(PersistentDiagnosticError::CorruptData);
    }
    usize::try_from(value).map_err(|_| PersistentDiagnosticError::CorruptData)
}

fn nonnegative_i64_to_usize(value: i64) -> Result<usize, PersistentDiagnosticError> {
    if value < 0 {
        return Err(PersistentDiagnosticError::CorruptData);
    }
    usize::try_from(value).map_err(|_| PersistentDiagnosticError::CorruptData)
}

fn database_error(_error: rusqlite::Error) -> PersistentDiagnosticError {
    PersistentDiagnosticError::Database
}

