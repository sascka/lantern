// SPDX-License-Identifier: MPL-2.0

//! Bounded SQLite persistence for Lantern queues.

#![forbid(unsafe_code)]

use core::fmt;
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use lantern_core::{
    CborError, EnvelopeQueue, LocalRouteRecord, MAX_ENVELOPE_SIZE, MessageId, QueueEntry,
    QueueError, QueueLimits, TombstoneEntry, decode_envelope, encode_envelope,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, limits::Limit,
    params,
};

const APPLICATION_ID: i64 = 0x4c41_4e54;
const SCHEMA_VERSION: i64 = 1;
const MAX_DATABASE_FILE_BYTES: u64 = 128 * 1024 * 1024;
const SQLITE_VALUE_LIMIT: i32 = 128 * 1024;
const SQLITE_SQL_LIMIT: i32 = 64 * 1024;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const CREATE_SCHEMA: &str = r#"
CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    max_entries INTEGER NOT NULL CHECK (max_entries BETWEEN 1 AND 1000),
    max_bytes INTEGER NOT NULL CHECK (max_bytes BETWEEN 1 AND 67108864),
    max_tombstones INTEGER NOT NULL CHECK (max_tombstones BETWEEN 1 AND 2000),
    tombstone_retention_seconds INTEGER NOT NULL
        CHECK (tombstone_retention_seconds BETWEEN 60 AND 604800),
    last_observed_wall_seconds INTEGER NOT NULL
        CHECK (last_observed_wall_seconds >= 0)
) STRICT;

CREATE TABLE queue_entries (
    message_id BLOB PRIMARY KEY CHECK (length(message_id) = 16),
    envelope_cbor BLOB NOT NULL
        CHECK (length(envelope_cbor) BETWEEN 1 AND 65536),
    first_seen_wall_seconds INTEGER NOT NULL
        CHECK (first_seen_wall_seconds >= 0),
    local_deadline_wall_seconds INTEGER NOT NULL
        CHECK (local_deadline_wall_seconds >= first_seen_wall_seconds),
    remaining_ttl_seconds INTEGER NOT NULL
        CHECK (remaining_ttl_seconds BETWEEN 1 AND 604800),
    hops_taken INTEGER NOT NULL CHECK (hops_taken BETWEEN 0 AND 16),
    copies_left INTEGER NOT NULL CHECK (copies_left BETWEEN 1 AND 32)
) STRICT;

CREATE TABLE tombstones (
    message_id BLOB PRIMARY KEY CHECK (length(message_id) = 16),
    recorded_at_wall_seconds INTEGER NOT NULL
        CHECK (recorded_at_wall_seconds >= 0),
    expires_at_wall_seconds INTEGER NOT NULL
        CHECK (expires_at_wall_seconds > recorded_at_wall_seconds)
) STRICT;
"#;

/// Safe storage error category that omits paths, SQL and stored bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    Database,
    Io,
    FileTooLarge,
    UnsupportedSchema,
    WrongApplication,
    LimitMismatch,
    CorruptData,
    ClockOutOfRange,
    ClockRollback,
    Cbor(CborError),
    Queue(QueueError),
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database => formatter.write_str("persistent database operation failed"),
            Self::Io => formatter.write_str("persistent storage I/O operation failed"),
            Self::FileTooLarge => formatter.write_str("persistent database file exceeds limit"),
            Self::UnsupportedSchema => {
                formatter.write_str("unsupported persistent database schema")
            }
            Self::WrongApplication => formatter.write_str("database does not belong to Lantern"),
            Self::LimitMismatch => {
                formatter.write_str("database queue limits do not match requested limits")
            }
            Self::CorruptData => formatter.write_str("invalid persistent queue data"),
            Self::ClockOutOfRange => formatter.write_str("wall clock is outside storage range"),
            Self::ClockRollback => formatter.write_str("wall clock moved backwards"),
            Self::Cbor(error) => write!(formatter, "invalid stored Envelope: {error}"),
            Self::Queue(error) => write!(formatter, "invalid stored queue: {error}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<CborError> for StorageError {
    fn from(error: CborError) -> Self {
        Self::Cbor(error)
    }
}

impl From<QueueError> for StorageError {
    fn from(error: QueueError) -> Self {
        Self::Queue(error)
    }
}

/// Clock condition observed while reopening a persistent queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockRecovery {
    Normal,
    RollbackDetected,
}

/// Bounded counters describing changes made during recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    clock_recovery: ClockRecovery,
    expired_entries: usize,
    expired_tombstones: usize,
    evicted_tombstones: usize,
}

impl RecoveryReport {
    pub const fn clock_recovery(self) -> ClockRecovery {
        self.clock_recovery
    }

    pub const fn expired_entries(self) -> usize {
        self.expired_entries
    }

    pub const fn expired_tombstones(self) -> usize {
        self.expired_tombstones
    }

    pub const fn evicted_tombstones(self) -> usize {
        self.evicted_tombstones
    }
}

/// Queue and safe recovery counters returned after opening a database.
pub struct RecoveredQueue {
    queue: EnvelopeQueue,
    report: RecoveryReport,
}

impl RecoveredQueue {
    pub const fn queue(&self) -> &EnvelopeQueue {
        &self.queue
    }

    pub fn into_queue(self) -> EnvelopeQueue {
        self.queue
    }

    pub const fn report(&self) -> RecoveryReport {
        self.report
    }
}

impl fmt::Debug for RecoveredQueue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredQueue")
            .field("queue", &self.queue)
            .field("report", &self.report)
            .finish()
    }
}

/// One SQLite database containing a complete bounded queue snapshot.
pub struct SqliteQueueStore {
    connection: Connection,
    limits: QueueLimits,
    last_observed_wall_seconds: u64,
}

impl SqliteQueueStore {
    pub fn open(path: &Path, limits: QueueLimits) -> Result<Self, StorageError> {
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
                return Err(StorageError::WrongApplication);
            }
            initialize_database(&mut connection, limits)?;
        } else {
            if application_id != APPLICATION_ID {
                return Err(StorageError::WrongApplication);
            }
            if schema_version != SCHEMA_VERSION {
                return Err(StorageError::UnsupportedSchema);
            }
        }

        configure_connection(&connection)?;
        check_database_size(&connection)?;
        check_integrity(&connection)?;
        let (stored_limits, last_observed_wall_seconds) = read_metadata(&connection)?;
        if stored_limits != limits {
            return Err(StorageError::LimitMismatch);
        }

        Ok(Self {
            connection,
            limits,
            last_observed_wall_seconds,
        })
    }

    pub const fn limits(&self) -> QueueLimits {
        self.limits
    }

    pub const fn last_observed_wall_seconds(&self) -> u64 {
        self.last_observed_wall_seconds
    }

    pub fn load(&mut self, now_wall_seconds: u64) -> Result<RecoveredQueue, StorageError> {
        to_sql_integer(now_wall_seconds)?;
        check_integrity(&self.connection)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(database_error)?;
        let (stored_limits, stored_last_observed) = read_metadata(&transaction)?;
        if stored_limits != self.limits {
            return Err(StorageError::LimitMismatch);
        }
        let entries = read_queue_entries(&transaction, self.limits)?;
        let stored_tombstones = read_tombstones(&transaction, self.limits)?;
        transaction.commit().map_err(database_error)?;

        let clock_recovery = if now_wall_seconds < stored_last_observed {
            ClockRecovery::RollbackDetected
        } else {
            ClockRecovery::Normal
        };
        let (tombstones, rebased_expired_tombstones) = match clock_recovery {
            ClockRecovery::Normal => (stored_tombstones, 0),
            ClockRecovery::RollbackDetected => rebase_tombstones_after_clock_rollback(
                stored_tombstones,
                stored_last_observed,
                now_wall_seconds,
            )?,
        };
        let mut queue = EnvelopeQueue::try_restore(self.limits, entries, tombstones)?;
        let effects = match clock_recovery {
            ClockRecovery::Normal => queue.expire_due(now_wall_seconds)?,
            ClockRecovery::RollbackDetected => queue.expire_all(now_wall_seconds)?,
        };
        let report = RecoveryReport {
            clock_recovery,
            expired_entries: effects.removed_entries().len(),
            expired_tombstones: effects
                .expired_tombstones()
                .len()
                .checked_add(rebased_expired_tombstones)
                .ok_or(StorageError::CorruptData)?,
            evicted_tombstones: effects.evicted_tombstones().len(),
        };

        self.persist_snapshot(&queue, now_wall_seconds, true)?;
        Ok(RecoveredQueue { queue, report })
    }

    pub fn save(
        &mut self,
        queue: &EnvelopeQueue,
        now_wall_seconds: u64,
    ) -> Result<(), StorageError> {
        self.persist_snapshot(queue, now_wall_seconds, false)
    }

    fn persist_snapshot(
        &mut self,
        queue: &EnvelopeQueue,
        now_wall_seconds: u64,
        allow_clock_rollback: bool,
    ) -> Result<(), StorageError> {
        if queue.limits() != self.limits {
            return Err(StorageError::LimitMismatch);
        }
        let now_sql = to_sql_integer(now_wall_seconds)?;
        if !allow_clock_rollback && now_wall_seconds < self.last_observed_wall_seconds {
            return Err(StorageError::ClockRollback);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        transaction
            .execute("DELETE FROM queue_entries", [])
            .map_err(database_error)?;
        transaction
            .execute("DELETE FROM tombstones", [])
            .map_err(database_error)?;

        {
            let mut statement = transaction
                .prepare(
                    "INSERT INTO queue_entries (
                        message_id,
                        envelope_cbor,
                        first_seen_wall_seconds,
                        local_deadline_wall_seconds,
                        remaining_ttl_seconds,
                        hops_taken,
                        copies_left
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )
                .map_err(database_error)?;
            for entry in queue.entries() {
                let encoded = encode_envelope(entry.envelope())?;
                if encoded.len() != entry.encoded_size() {
                    return Err(StorageError::CorruptData);
                }
                let route = entry.route();
                statement
                    .execute(params![
                        entry.envelope().message_id().as_bytes().as_slice(),
                        encoded,
                        to_sql_integer(route.first_seen_at())?,
                        to_sql_integer(route.local_deadline())?,
                        i64::from(route.remaining_ttl()),
                        i64::from(route.hops_taken()),
                        i64::from(route.copies_left()),
                    ])
                    .map_err(database_error)?;
            }
        }

        {
            let mut statement = transaction
                .prepare(
                    "INSERT INTO tombstones (
                        message_id,
                        recorded_at_wall_seconds,
                        expires_at_wall_seconds
                    ) VALUES (?1, ?2, ?3)",
                )
                .map_err(database_error)?;
            for tombstone in queue.tombstones() {
                statement
                    .execute(params![
                        tombstone.message_id().as_bytes().as_slice(),
                        to_sql_integer(tombstone.recorded_at())?,
                        to_sql_integer(tombstone.expires_at())?,
                    ])
                    .map_err(database_error)?;
            }
        }

        let updated = transaction
            .execute(
                "UPDATE metadata
                 SET last_observed_wall_seconds = ?1
                 WHERE singleton = 1",
                [now_sql],
            )
            .map_err(database_error)?;
        if updated != 1 {
            return Err(StorageError::CorruptData);
        }
        transaction.commit().map_err(database_error)?;
        self.last_observed_wall_seconds = now_wall_seconds;
        Ok(())
    }
}

impl fmt::Debug for SqliteQueueStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteQueueStore")
            .field("limits", &self.limits)
            .field("clock", &"redacted")
            .finish_non_exhaustive()
    }
}

fn preflight_files(path: &Path) -> Result<bool, StorageError> {
    let main_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(StorageError::Io),
    };
    if let Some(metadata) = &main_metadata {
        validate_file_metadata(metadata)?;
    }
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = path_with_suffix(path, suffix);
        match fs::symlink_metadata(sidecar) {
            Ok(metadata) => validate_file_metadata(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StorageError::Io),
        }
    }
    Ok(main_metadata.is_none() || main_metadata.is_some_and(|metadata| metadata.len() == 0))
}

fn validate_file_metadata(metadata: &fs::Metadata) -> Result<(), StorageError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StorageError::Io);
    }
    if metadata.len() > MAX_DATABASE_FILE_BYTES {
        return Err(StorageError::FileTooLarge);
    }
    Ok(())
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, permissions).map_err(|_| StorageError::Io)
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}

fn configure_runtime_limits(connection: &Connection) -> Result<(), StorageError> {
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, SQLITE_VALUE_LIMIT),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, SQLITE_SQL_LIMIT),
        (Limit::SQLITE_LIMIT_COLUMN, 32),
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
    limits: QueueLimits,
) -> Result<(), StorageError> {
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
    transaction
        .execute(
            "INSERT INTO metadata (
                singleton,
                schema_version,
                max_entries,
                max_bytes,
                max_tombstones,
                tombstone_retention_seconds,
                last_observed_wall_seconds
            ) VALUES (1, ?1, ?2, ?3, ?4, ?5, 0)",
            params![
                SCHEMA_VERSION,
                usize_to_i64(limits.max_entries())?,
                usize_to_i64(limits.max_bytes())?,
                usize_to_i64(limits.max_tombstones())?,
                to_sql_integer(limits.tombstone_retention_seconds())?,
            ],
        )
        .map_err(database_error)?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(database_error)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(database_error)?;
    transaction.commit().map_err(database_error)
}

fn configure_connection(connection: &Connection) -> Result<(), StorageError> {
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
        return Err(StorageError::Database);
    }
    Ok(())
}

fn check_database_size(connection: &Connection) -> Result<(), StorageError> {
    let page_size = read_pragma_i64(connection, "page_size")?;
    let page_count = read_pragma_i64(connection, "page_count")?;
    if page_size <= 0 || page_count < 0 {
        return Err(StorageError::CorruptData);
    }
    let total_bytes = page_size
        .checked_mul(page_count)
        .ok_or(StorageError::FileTooLarge)?;
    if u64::try_from(total_bytes).map_err(|_| StorageError::FileTooLarge)? > MAX_DATABASE_FILE_BYTES
    {
        return Err(StorageError::FileTooLarge);
    }
    let max_pages = i64::try_from(MAX_DATABASE_FILE_BYTES)
        .map_err(|_| StorageError::FileTooLarge)?
        .checked_add(page_size - 1)
        .ok_or(StorageError::FileTooLarge)?
        / page_size;
    connection
        .pragma_update(None, "max_page_count", max_pages)
        .map_err(database_error)?;
    Ok(())
}

fn check_integrity(connection: &Connection) -> Result<(), StorageError> {
    let result: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(database_error)?;
    if result != "ok" {
        return Err(StorageError::CorruptData);
    }
    Ok(())
}

fn read_metadata(connection: &Connection) -> Result<(QueueLimits, u64), StorageError> {
    let row = connection
        .query_row(
            "SELECT
                schema_version,
                max_entries,
                max_bytes,
                max_tombstones,
                tombstone_retention_seconds,
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
        .ok_or(StorageError::CorruptData)?;
    if row.0 != SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchema);
    }
    let limits = QueueLimits::try_new(
        positive_i64_to_usize(row.1)?,
        positive_i64_to_usize(row.2)?,
        positive_i64_to_usize(row.3)?,
        nonnegative_i64_to_u64(row.4)?,
    )?;
    Ok((limits, nonnegative_i64_to_u64(row.5)?))
}

fn read_queue_entries(
    transaction: &Transaction<'_>,
    limits: QueueLimits,
) -> Result<Vec<QueueEntry>, StorageError> {
    let count = query_nonnegative_count(transaction, "SELECT count(*) FROM queue_entries")?;
    if count > limits.max_entries() {
        return Err(StorageError::CorruptData);
    }
    let total_bytes = transaction
        .query_row(
            "SELECT coalesce(sum(length(envelope_cbor)), 0) FROM queue_entries",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(database_error)?;
    if positive_or_zero_i64_to_usize(total_bytes)? > limits.max_bytes() {
        return Err(StorageError::CorruptData);
    }

    let mut statement = transaction
        .prepare(
            "SELECT
                length(message_id),
                length(envelope_cbor),
                message_id,
                envelope_cbor,
                first_seen_wall_seconds,
                local_deadline_wall_seconds,
                remaining_ttl_seconds,
                hops_taken,
                copies_left
             FROM queue_entries
             ORDER BY message_id",
        )
        .map_err(database_error)?;
    let mut rows = statement.query([]).map_err(database_error)?;
    let mut entries = Vec::with_capacity(count);
    while let Some(row) = rows.next().map_err(database_error)? {
        let message_id_length = row.get::<_, i64>(0).map_err(database_error)?;
        let envelope_length = row.get::<_, i64>(1).map_err(database_error)?;
        if message_id_length != 16
            || !(1..=i64::try_from(MAX_ENVELOPE_SIZE).map_err(|_| StorageError::CorruptData)?)
                .contains(&envelope_length)
        {
            return Err(StorageError::CorruptData);
        }
        let message_id = fixed_message_id(row.get::<_, Vec<u8>>(2).map_err(database_error)?)?;
        let encoded = row.get::<_, Vec<u8>>(3).map_err(database_error)?;
        if encoded.len() != positive_i64_to_usize(envelope_length)? {
            return Err(StorageError::CorruptData);
        }
        let envelope = decode_envelope(&encoded)?;
        if envelope.message_id() != message_id {
            return Err(StorageError::CorruptData);
        }
        let route = LocalRouteRecord::try_restore_stored(
            &envelope,
            nonnegative_i64_to_u64(row.get::<_, i64>(4).map_err(database_error)?)?,
            nonnegative_i64_to_u64(row.get::<_, i64>(5).map_err(database_error)?)?,
            nonnegative_i64_to_u64(row.get::<_, i64>(6).map_err(database_error)?)?,
            nonnegative_i64_to_u64(row.get::<_, i64>(7).map_err(database_error)?)?,
            nonnegative_i64_to_u64(row.get::<_, i64>(8).map_err(database_error)?)?,
        )
        .map_err(|_| StorageError::CorruptData)?;
        entries.push(QueueEntry::try_from_parts(envelope, route)?);
    }
    Ok(entries)
}

fn read_tombstones(
    transaction: &Transaction<'_>,
    limits: QueueLimits,
) -> Result<Vec<TombstoneEntry>, StorageError> {
    let count = query_nonnegative_count(transaction, "SELECT count(*) FROM tombstones")?;
    if count > limits.max_tombstones() {
        return Err(StorageError::CorruptData);
    }
    let mut statement = transaction
        .prepare(
            "SELECT
                length(message_id),
                message_id,
                recorded_at_wall_seconds,
                expires_at_wall_seconds
             FROM tombstones
             ORDER BY message_id",
        )
        .map_err(database_error)?;
    let mut rows = statement.query([]).map_err(database_error)?;
    let mut tombstones = Vec::with_capacity(count);
    while let Some(row) = rows.next().map_err(database_error)? {
        if row.get::<_, i64>(0).map_err(database_error)? != 16 {
            return Err(StorageError::CorruptData);
        }
        let message_id = fixed_message_id(row.get::<_, Vec<u8>>(1).map_err(database_error)?)?;
        tombstones.push(TombstoneEntry::try_from_parts(
            message_id,
            nonnegative_i64_to_u64(row.get::<_, i64>(2).map_err(database_error)?)?,
            nonnegative_i64_to_u64(row.get::<_, i64>(3).map_err(database_error)?)?,
        )?);
    }
    Ok(tombstones)
}

fn rebase_tombstones_after_clock_rollback(
    tombstones: Vec<TombstoneEntry>,
    stored_last_observed: u64,
    now_wall_seconds: u64,
) -> Result<(Vec<TombstoneEntry>, usize), StorageError> {
    let mut rebased = Vec::with_capacity(tombstones.len());
    let mut expired = 0_usize;
    for tombstone in tombstones {
        let expiry_anchor = stored_last_observed.max(tombstone.recorded_at());
        if tombstone.expires_at() <= expiry_anchor {
            expired = expired.checked_add(1).ok_or(StorageError::CorruptData)?;
            continue;
        }
        let remaining = tombstone
            .expires_at()
            .checked_sub(expiry_anchor)
            .ok_or(StorageError::CorruptData)?;
        let duration = tombstone
            .expires_at()
            .checked_sub(tombstone.recorded_at())
            .ok_or(StorageError::CorruptData)?;
        let expires_at = now_wall_seconds
            .checked_add(remaining)
            .ok_or(StorageError::ClockOutOfRange)?;
        to_sql_integer(expires_at)?;
        let recorded_at = expires_at.saturating_sub(duration);
        rebased.push(TombstoneEntry::try_from_parts(
            tombstone.message_id(),
            recorded_at,
            expires_at,
        )?);
    }
    Ok((rebased, expired))
}

fn fixed_message_id(bytes: Vec<u8>) -> Result<MessageId, StorageError> {
    let fixed = <[u8; 16]>::try_from(bytes).map_err(|_| StorageError::CorruptData)?;
    Ok(MessageId::from_bytes(fixed))
}

fn query_nonnegative_count(connection: &Connection, sql: &str) -> Result<usize, StorageError> {
    let count = connection
        .query_row(sql, [], |row| row.get::<_, i64>(0))
        .map_err(database_error)?;
    positive_or_zero_i64_to_usize(count)
}

fn read_pragma_i64(connection: &Connection, name: &str) -> Result<i64, StorageError> {
    let sql = match name {
        "application_id" => "PRAGMA application_id",
        "user_version" => "PRAGMA user_version",
        "page_size" => "PRAGMA page_size",
        "page_count" => "PRAGMA page_count",
        _ => return Err(StorageError::Database),
    };
    connection
        .query_row(sql, [], |row| row.get(0))
        .map_err(database_error)
}

fn to_sql_integer(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::ClockOutOfRange)
}

fn usize_to_i64(value: usize) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::CorruptData)
}

fn nonnegative_i64_to_u64(value: i64) -> Result<u64, StorageError> {
    u64::try_from(value).map_err(|_| StorageError::CorruptData)
}

fn positive_i64_to_usize(value: i64) -> Result<usize, StorageError> {
    if value <= 0 {
        return Err(StorageError::CorruptData);
    }
    usize::try_from(value).map_err(|_| StorageError::CorruptData)
}

fn positive_or_zero_i64_to_usize(value: i64) -> Result<usize, StorageError> {
    if value < 0 {
        return Err(StorageError::CorruptData);
    }
    usize::try_from(value).map_err(|_| StorageError::CorruptData)
}

fn database_error(_error: rusqlite::Error) -> StorageError {
    StorageError::Database
}

