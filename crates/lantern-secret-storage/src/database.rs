// SPDX-License-Identifier: MPL-2.0

use core::fmt;
use std::{
    ffi::OsString,
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, TransactionBehavior, limits::Limit, params, types::Value};
use vodozemac::olm::{Account, AccountPickle};
use zeroize::{Zeroize, Zeroizing};

use crate::state::LimiterRuntime;
use crate::{DATABASE_KEY_LENGTH, DatabaseKey, SecretStorageError};

const APPLICATION_ID: i64 = 0x4c53_4543;
const SCHEMA_VERSION: i64 = 1;
const EXPECTED_SQLCIPHER_VERSION: &str = "4.17.0 community";
const PROFILE_ID_LENGTH: usize = 16;
const PICKLE_KEY_LENGTH: usize = 32;
const MAX_PICKLE_BYTES: usize = 64 * 1024;
const MAX_DATABASE_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_DATABASE_PAGES: i64 = 32_768;
const SQLITE_VALUE_LIMIT: i32 = 128 * 1024;
const SQLITE_SQL_LIMIT: i32 = 64 * 1024;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const CREATE_SCHEMA: &str = r#"
CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    profile_id BLOB NOT NULL UNIQUE CHECK (length(profile_id) = 16),
    pickle_key BLOB NOT NULL CHECK (length(pickle_key) = 32),
    profile_tokens INTEGER NOT NULL CHECK (profile_tokens BETWEEN 0 AND 32),
    pending_contact_tokens INTEGER NOT NULL
        CHECK (pending_contact_tokens BETWEEN 0 AND 4),
    max_contacts INTEGER NOT NULL CHECK (max_contacts = 128),
    max_attempts INTEGER NOT NULL CHECK (max_attempts = 2000),
    max_outbox_entries INTEGER NOT NULL CHECK (max_outbox_entries = 1000),
    max_history_entries INTEGER NOT NULL CHECK (max_history_entries = 8192)
) STRICT;

CREATE TABLE account_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    encrypted_pickle TEXT NOT NULL
        CHECK (length(encrypted_pickle) BETWEEN 1 AND 65536)
) STRICT;

CREATE TABLE contacts (
    contact_id BLOB PRIMARY KEY CHECK (length(contact_id) = 16),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
    signing_identity_key BLOB NOT NULL UNIQUE
        CHECK (length(signing_identity_key) = 32),
    curve_identity_key BLOB NOT NULL UNIQUE
        CHECK (length(curve_identity_key) = 32),
    inbound_current_hint BLOB NOT NULL UNIQUE
        CHECK (length(inbound_current_hint) = 16),
    inbound_proposed_hint BLOB UNIQUE
        CHECK (inbound_proposed_hint IS NULL OR length(inbound_proposed_hint) = 16),
    inbound_retiring_hint BLOB UNIQUE
        CHECK (inbound_retiring_hint IS NULL OR length(inbound_retiring_hint) = 16),
    outbound_current_hint BLOB NOT NULL
        CHECK (length(outbound_current_hint) = 16),
    outbound_proposed_hint BLOB
        CHECK (outbound_proposed_hint IS NULL OR length(outbound_proposed_hint) = 16),
    inbound_generation INTEGER NOT NULL
        CHECK (inbound_generation BETWEEN 0 AND 4294967295),
    outbound_generation INTEGER NOT NULL
        CHECK (outbound_generation BETWEEN 0 AND 4294967295),
    inbound_message_count INTEGER NOT NULL
        CHECK (inbound_message_count BETWEEN 0 AND 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 0 AND 3),
    contact_tokens INTEGER NOT NULL CHECK (contact_tokens BETWEEN 0 AND 8),
    CHECK (inbound_proposed_hint IS NULL OR inbound_proposed_hint != inbound_current_hint),
    CHECK (inbound_retiring_hint IS NULL OR inbound_retiring_hint != inbound_current_hint),
    CHECK (inbound_proposed_hint IS NULL OR inbound_retiring_hint IS NULL
           OR inbound_proposed_hint != inbound_retiring_hint)
) STRICT;

CREATE TABLE session_state (
    contact_id BLOB PRIMARY KEY REFERENCES contacts(contact_id) ON DELETE CASCADE,
    encrypted_pickle TEXT NOT NULL
        CHECK (length(encrypted_pickle) BETWEEN 1 AND 65536)
) STRICT;

CREATE TABLE contact_exchange (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    role INTEGER NOT NULL CHECK (role BETWEEN 0 AND 1),
    state INTEGER NOT NULL CHECK (state BETWEEN 0 AND 4),
    exchange_data BLOB NOT NULL CHECK (length(exchange_data) BETWEEN 1 AND 2048)
) STRICT;

CREATE TABLE crypto_attempts (
    message_id BLOB PRIMARY KEY CHECK (length(message_id) = 16),
    contact_id BLOB REFERENCES contacts(contact_id) ON DELETE CASCADE,
    attempt_kind INTEGER NOT NULL CHECK (attempt_kind BETWEEN 0 AND 1),
    attempt_state INTEGER NOT NULL CHECK (attempt_state BETWEEN 0 AND 1),
    sequence INTEGER NOT NULL UNIQUE CHECK (sequence >= 1)
) STRICT;

CREATE TABLE pending_outbox (
    message_id BLOB PRIMARY KEY CHECK (length(message_id) = 16),
    envelope_cbor BLOB NOT NULL CHECK (length(envelope_cbor) BETWEEN 1 AND 65536),
    sequence INTEGER NOT NULL UNIQUE CHECK (sequence >= 1)
) STRICT;

CREATE TABLE messages (
    message_id BLOB PRIMARY KEY CHECK (length(message_id) = 16),
    contact_id BLOB NOT NULL REFERENCES contacts(contact_id) ON DELETE CASCADE,
    direction INTEGER NOT NULL CHECK (direction BETWEEN 0 AND 1),
    text TEXT NOT NULL CHECK (length(CAST(text AS BLOB)) BETWEEN 1 AND 4096),
    sequence INTEGER NOT NULL UNIQUE CHECK (sequence >= 1)
) STRICT;
"#;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ProfileId([u8; PROFILE_ID_LENGTH]);

impl ProfileId {
    pub const fn as_bytes(&self) -> &[u8; PROFILE_ID_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for ProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileId")
            .field("length", &PROFILE_ID_LENGTH)
            .finish_non_exhaustive()
    }
}

pub(crate) struct PickleKey(pub(crate) [u8; PICKLE_KEY_LENGTH]);

impl Drop for PickleKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct SecretStore {
    pub(crate) connection: Connection,
    profile_id: ProfileId,
    pub(crate) pickle_key: PickleKey,
    pub(crate) limiter: LimiterRuntime,
}

impl SecretStore {
    pub fn create(path: &Path, database_key: &DatabaseKey) -> Result<Self, SecretStorageError> {
        preflight_new_database(path)?;
        let mut connection = open_connection(path, true)?;
        restrict_file_permissions(path)?;
        configure_limits(&connection)?;
        configure_sqlcipher(&connection, database_key).map_err(|_| SecretStorageError::Io)?;

        let mut profile_id = [0_u8; PROFILE_ID_LENGTH];
        getrandom::fill(&mut profile_id).map_err(|_| SecretStorageError::Entropy)?;
        let mut pickle_key = [0_u8; PICKLE_KEY_LENGTH];
        getrandom::fill(&mut pickle_key).map_err(|_| SecretStorageError::Entropy)?;
        let account = Account::new();
        let encrypted_account = Zeroizing::new(account.pickle().encrypt(&pickle_key));
        if encrypted_account.is_empty() || encrypted_account.len() > MAX_PICKLE_BYTES {
            pickle_key.zeroize();
            return Err(SecretStorageError::CorruptStorage);
        }

        let initialization = initialize_database(
            &mut connection,
            &profile_id,
            &pickle_key,
            encrypted_account.as_str(),
        );
        if let Err(error) = initialization {
            pickle_key.zeroize();
            return Err(error);
        }
        connection.close().map_err(|_| SecretStorageError::Io)?;
        sync_database_file(path)?;

        Self::open(path, database_key)
    }

    pub fn open(path: &Path, database_key: &DatabaseKey) -> Result<Self, SecretStorageError> {
        preflight_existing_database(path)?;
        let connection = open_connection(path, false)?;
        configure_limits(&connection)?;
        configure_sqlcipher(&connection, database_key)
            .map_err(|_| SecretStorageError::UnlockFailed)?;
        validate_database(&connection)?;
        check_database_size(&connection, path)?;
        let (profile_id, pickle_key) = read_metadata(&connection)?;
        validate_account(&connection, &pickle_key)?;
        validate_quotas(&connection)?;

        Ok(Self {
            connection,
            profile_id,
            pickle_key: PickleKey(pickle_key),
            limiter: LimiterRuntime::new(),
        })
    }

    pub const fn profile_id(&self) -> ProfileId {
        self.profile_id
    }

    pub fn load_account(&self) -> Result<Account, SecretStorageError> {
        let encrypted: String = self
            .connection
            .query_row(
                "SELECT encrypted_pickle FROM account_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if encrypted.is_empty() || encrypted.len() > MAX_PICKLE_BYTES {
            return Err(SecretStorageError::CorruptStorage);
        }
        let encrypted = Zeroizing::new(encrypted);
        let pickle = AccountPickle::from_encrypted(&encrypted, &self.pickle_key.0)
            .map_err(|_| SecretStorageError::CorruptStorage)?;
        Ok(Account::from_pickle(pickle))
    }

    pub fn replace_account(&mut self, account: &Account) -> Result<(), SecretStorageError> {
        let encrypted = Zeroizing::new(account.pickle().encrypt(&self.pickle_key.0));
        if encrypted.is_empty() || encrypted.len() > MAX_PICKLE_BYTES {
            return Err(SecretStorageError::QuotaExceeded);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let changed = transaction
            .execute(
                "UPDATE account_state SET encrypted_pickle = ?1 WHERE singleton = 1",
                params![encrypted.as_str()],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(SecretStorageError::CorruptStorage);
        }
        transaction.commit().map_err(database_error)
    }
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretStore")
            .field("profile", &"redacted")
            .field("database", &"redacted")
            .finish_non_exhaustive()
    }
}

fn open_connection(path: &Path, create: bool) -> Result<Connection, SecretStorageError> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_EXRESCODE;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection = Connection::open_with_flags(path, flags).map_err(database_error)?;
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(database_error)?;
    Ok(connection)
}

fn configure_limits(connection: &Connection) -> Result<(), SecretStorageError> {
    connection
        .set_limit(Limit::SQLITE_LIMIT_LENGTH, SQLITE_VALUE_LIMIT)
        .map_err(database_error)?;
    connection
        .set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, SQLITE_SQL_LIMIT)
        .map_err(database_error)?;
    connection
        .set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)
        .map_err(database_error)?;
    connection
        .set_limit(Limit::SQLITE_LIMIT_WORKER_THREADS, 0)
        .map_err(database_error)?;
    Ok(())
}

fn configure_sqlcipher(
    connection: &Connection,
    database_key: &DatabaseKey,
) -> Result<(), SecretStorageError> {
    let literal = raw_key_literal(database_key.as_bytes())?;
    connection
        .pragma_update(None, "key", literal.as_str())
        .map_err(database_error)?;
    connection
        .pragma_update(None, "cipher_page_size", 4096_i64)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "cipher_memory_security", "ON")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "cipher_log_level", "NONE")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "temp_store", "MEMORY")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "mmap_size", 0_i64)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "secure_delete", "ON")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "max_page_count", MAX_DATABASE_PAGES)
        .map_err(database_error)?;
    Ok(())
}

fn raw_key_literal(
    key: &[u8; DATABASE_KEY_LENGTH],
) -> Result<Zeroizing<String>, SecretStorageError> {
    let mut literal = Zeroizing::new(String::with_capacity(67));
    literal.push_str("x'");
    for byte in key {
        write!(literal, "{byte:02x}").map_err(|_| SecretStorageError::Io)?;
    }
    literal.push('\'');
    Ok(literal)
}

fn initialize_database(
    connection: &mut Connection,
    profile_id: &[u8; PROFILE_ID_LENGTH],
    pickle_key: &[u8; PICKLE_KEY_LENGTH],
    encrypted_account: &str,
) -> Result<(), SecretStorageError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(database_error)?;
    transaction
        .execute_batch(CREATE_SCHEMA)
        .map_err(database_error)?;
    transaction
        .execute(
            "INSERT INTO metadata (
                singleton, schema_version, profile_id, pickle_key,
                profile_tokens, pending_contact_tokens, max_contacts,
                max_attempts, max_outbox_entries, max_history_entries
             ) VALUES (1, 1, ?1, ?2, 32, 4, 128, 2000, 1000, 8192)",
            params![profile_id.as_slice(), pickle_key.as_slice()],
        )
        .map_err(database_error)?;
    transaction
        .execute(
            "INSERT INTO account_state(singleton, encrypted_pickle) VALUES (1, ?1)",
            params![encrypted_account],
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

fn validate_database(connection: &Connection) -> Result<(), SecretStorageError> {
    let version: String = connection
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .map_err(|_| SecretStorageError::UnlockFailed)?;
    if version != EXPECTED_SQLCIPHER_VERSION {
        return Err(SecretStorageError::UnsupportedSchema);
    }
    let cipher_status: String = connection
        .query_row("PRAGMA cipher_status", [], |row| row.get(0))
        .map_err(database_error)?;
    let cipher_page_size: String = connection
        .query_row("PRAGMA cipher_page_size", [], |row| row.get(0))
        .map_err(database_error)?;
    if cipher_status != "1"
        || cipher_page_size != "4096"
        || read_pragma_i64(connection, "page_size")? != 4096
        || read_pragma_i64(connection, "application_id")? != APPLICATION_ID
    {
        return Err(SecretStorageError::CorruptStorage);
    }
    if read_pragma_i64(connection, "user_version")? != SCHEMA_VERSION {
        return Err(SecretStorageError::UnsupportedSchema);
    }
    let integrity: String = connection
        .query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))
        .map_err(database_error)?;
    if integrity != "ok" {
        return Err(SecretStorageError::CorruptStorage);
    }
    let foreign_key_errors: i64 = connection
        .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(database_error)?;
    if foreign_key_errors != 0 {
        return Err(SecretStorageError::CorruptStorage);
    }
    let table_names: String = connection
        .query_row(
            "SELECT group_concat(name, ',') FROM (
                 SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name
             )",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if table_names
        != "account_state,contact_exchange,contacts,crypto_attempts,messages,metadata,pending_outbox,session_state"
    {
        return Err(SecretStorageError::CorruptStorage);
    }
    Ok(())
}

fn read_metadata(
    connection: &Connection,
) -> Result<(ProfileId, [u8; PICKLE_KEY_LENGTH]), SecretStorageError> {
    let row = connection
        .query_row(
            "SELECT profile_id, pickle_key, profile_tokens, pending_contact_tokens,
                    max_contacts, max_attempts, max_outbox_entries, max_history_entries
             FROM metadata WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .map_err(database_error)?;
    if !(0..=32).contains(&row.2)
        || !(0..=4).contains(&row.3)
        || row.4 != 128
        || row.5 != 2000
        || row.6 != 1000
        || row.7 != 8192
    {
        return Err(SecretStorageError::CorruptStorage);
    }
    let profile_id = <[u8; PROFILE_ID_LENGTH]>::try_from(row.0)
        .map_err(|_| SecretStorageError::CorruptStorage)?;
    let mut stored_key = row.1;
    if stored_key.len() != PICKLE_KEY_LENGTH {
        stored_key.zeroize();
        return Err(SecretStorageError::CorruptStorage);
    }
    let mut pickle_key = [0_u8; PICKLE_KEY_LENGTH];
    pickle_key.copy_from_slice(&stored_key);
    stored_key.zeroize();
    Ok((ProfileId(profile_id), pickle_key))
}

fn validate_account(
    connection: &Connection,
    pickle_key: &[u8; PICKLE_KEY_LENGTH],
) -> Result<(), SecretStorageError> {
    let encrypted: String = connection
        .query_row(
            "SELECT encrypted_pickle FROM account_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if encrypted.is_empty() || encrypted.len() > MAX_PICKLE_BYTES {
        return Err(SecretStorageError::CorruptStorage);
    }
    let encrypted = Zeroizing::new(encrypted);
    AccountPickle::from_encrypted(&encrypted, pickle_key)
        .map_err(|_| SecretStorageError::CorruptStorage)?;
    Ok(())
}

fn validate_quotas(connection: &Connection) -> Result<(), SecretStorageError> {
    check_count(connection, "contacts", 128)?;
    check_count(connection, "session_state", 128)?;
    check_count(connection, "contact_exchange", 1)?;
    check_count(connection, "crypto_attempts", 2000)?;
    check_count(connection, "pending_outbox", 1000)?;
    check_count(connection, "messages", 8192)?;

    let outbox_bytes: i64 = connection
        .query_row(
            "SELECT coalesce(sum(length(envelope_cbor)), 0) FROM pending_outbox",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    let history_bytes: i64 = connection
        .query_row(
            "SELECT coalesce(sum(length(CAST(text AS BLOB))), 0) FROM messages",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if !(0..=67_108_864).contains(&outbox_bytes) || !(0..=33_554_432).contains(&history_bytes) {
        return Err(SecretStorageError::CorruptStorage);
    }
    Ok(())
}

fn check_count(
    connection: &Connection,
    table: &str,
    maximum: i64,
) -> Result<(), SecretStorageError> {
    let sql = format!("SELECT count(*) FROM {table}");
    let count: i64 = connection
        .query_row(&sql, [], |row| row.get(0))
        .map_err(database_error)?;
    if !(0..=maximum).contains(&count) {
        return Err(SecretStorageError::CorruptStorage);
    }
    Ok(())
}

fn read_pragma_i64(connection: &Connection, name: &str) -> Result<i64, SecretStorageError> {
    let value: Value = connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(database_error)?;
    match value {
        Value::Integer(value) => Ok(value),
        Value::Text(value) => value
            .parse::<i64>()
            .map_err(|_| SecretStorageError::CorruptStorage),
        _ => Err(SecretStorageError::CorruptStorage),
    }
}

fn preflight_new_database(path: &Path) -> Result<(), SecretStorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(SecretStorageError::AlreadyExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => ensure_journal_absent(path),
        Err(_) => Err(SecretStorageError::Io),
    }
}

fn ensure_journal_absent(path: &Path) -> Result<(), SecretStorageError> {
    match fs::symlink_metadata(journal_path(path)) {
        Ok(_) => Err(SecretStorageError::AlreadyExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SecretStorageError::Io),
    }
}

fn preflight_existing_database(path: &Path) -> Result<(), SecretStorageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| SecretStorageError::Io)?;
    validate_file_metadata(&metadata, false)?;
    match fs::symlink_metadata(journal_path(path)) {
        Ok(journal) => validate_file_metadata(&journal, true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SecretStorageError::Io),
    }
}

fn journal_path(path: &Path) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push("-journal");
    PathBuf::from(value)
}

fn sync_database_file(path: &Path) -> Result<(), SecretStorageError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| SecretStorageError::Io)?;
    file.sync_all().map_err(|_| SecretStorageError::Io)
}

#[cfg(unix)]
fn validate_file_metadata(
    metadata: &fs::Metadata,
    allow_empty: bool,
) -> Result<(), SecretStorageError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || (!allow_empty && metadata.len() == 0)
        || metadata.len() > MAX_DATABASE_FILE_BYTES
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(SecretStorageError::UnsafeFile);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_file_metadata(
    _metadata: &fs::Metadata,
    _allow_empty: bool,
) -> Result<(), SecretStorageError> {
    Err(SecretStorageError::UnsupportedPlatform)
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<(), SecretStorageError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|_| SecretStorageError::Io)
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<(), SecretStorageError> {
    Err(SecretStorageError::UnsupportedPlatform)
}

fn check_database_size(connection: &Connection, path: &Path) -> Result<(), SecretStorageError> {
    let page_count = read_pragma_i64(connection, "page_count")?;
    if !(1..=MAX_DATABASE_PAGES).contains(&page_count) {
        return Err(SecretStorageError::CorruptStorage);
    }
    let metadata = fs::metadata(path).map_err(|_| SecretStorageError::Io)?;
    if metadata.len() > MAX_DATABASE_FILE_BYTES {
        return Err(SecretStorageError::UnsafeFile);
    }
    Ok(())
}

pub(crate) fn database_error(_error: rusqlite::Error) -> SecretStorageError {
    SecretStorageError::Io
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    use vodozemac::olm::Account;

    use super::SecretStore;
    use crate::{DatabaseKey, SecretStorageError};

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn key() -> DatabaseKey {
        DatabaseKey::from_bytes([0x25; 32])
    }

    fn wrong_key() -> DatabaseKey {
        DatabaseKey::from_bytes([0xa6; 32])
    }

    struct TemporaryPath(PathBuf);

    impl TemporaryPath {
        fn new(label: &str) -> Self {
            let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "lantern-secret-database-{}-{sequence}-{label}.sqlite3",
                std::process::id()
            )))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TemporaryPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let mut journal = self.0.as_os_str().to_os_string();
            journal.push("-journal");
            let _ = fs::remove_file(PathBuf::from(journal));
        }
    }

    #[test]
    fn encrypted_database_round_trips_account_without_plaintext_header() {
        let temporary = TemporaryPath::new("round-trip");
        let store = SecretStore::create(temporary.path(), &key());
        let Ok(mut store) = store else {
            panic!("encrypted database could not be created");
        };
        let first_profile = store.profile_id();
        assert!(store.load_account().is_ok());

        let replacement = Account::new();
        let replacement_keys = replacement.identity_keys();
        assert!(store.replace_account(&replacement).is_ok());
        drop(store);

        let reopened = SecretStore::open(temporary.path(), &key());
        let Ok(reopened) = reopened else {
            panic!("encrypted database could not be reopened");
        };
        assert_eq!(reopened.profile_id(), first_profile);
        let account = reopened.load_account();
        let Ok(account) = account else {
            panic!("stored account could not be restored");
        };
        assert_eq!(account.identity_keys(), replacement_keys);

        let bytes = fs::read(temporary.path());
        let Ok(bytes) = bytes else {
            panic!("encrypted database bytes could not be read");
        };
        assert_ne!(bytes.get(..16), Some(b"SQLite format 3\0".as_slice()));
    }

    #[test]
    fn wrong_key_and_changed_first_page_fail_closed() {
        let temporary = TemporaryPath::new("wrong-key");
        let store = SecretStore::create(temporary.path(), &key());
        assert!(store.is_ok());
        drop(store);
        assert!(matches!(
            SecretStore::open(temporary.path(), &wrong_key()),
            Err(SecretStorageError::UnlockFailed)
        ));

        let bytes = fs::read(temporary.path());
        let Ok(mut bytes) = bytes else {
            panic!("encrypted database could not be read for mutation");
        };
        if let Some(byte) = bytes.first_mut() {
            *byte ^= 1;
        } else {
            panic!("encrypted database was empty");
        }
        assert!(fs::write(temporary.path(), bytes).is_ok());
        assert!(matches!(
            SecretStore::open(temporary.path(), &key()),
            Err(SecretStorageError::UnlockFailed)
        ));
    }

    #[test]
    fn unknown_schema_and_existing_file_are_rejected() {
        let temporary = TemporaryPath::new("schema");
        let store = SecretStore::create(temporary.path(), &key());
        let Ok(store) = store else {
            panic!("encrypted database could not be created for schema test");
        };
        assert_eq!(
            SecretStore::create(temporary.path(), &key()).err(),
            Some(SecretStorageError::AlreadyExists)
        );
        assert!(store.connection.execute("DROP TABLE messages", []).is_ok());
        drop(store);
        assert!(matches!(
            SecretStore::open(temporary.path(), &key()),
            Err(SecretStorageError::CorruptStorage)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_paths_and_permissions_are_rejected() {
        let original = TemporaryPath::new("original");
        let link = TemporaryPath::new("link");
        let hardlink = TemporaryPath::new("hardlink");
        let store = SecretStore::create(original.path(), &key());
        assert!(store.is_ok());
        drop(store);

        assert!(symlink(original.path(), link.path()).is_ok());
        assert!(matches!(
            SecretStore::open(link.path(), &key()),
            Err(SecretStorageError::UnsafeFile)
        ));

        assert!(fs::hard_link(original.path(), hardlink.path()).is_ok());
        assert!(matches!(
            SecretStore::open(original.path(), &key()),
            Err(SecretStorageError::UnsafeFile)
        ));
        assert!(fs::remove_file(hardlink.path()).is_ok());

        assert!(fs::set_permissions(original.path(), fs::Permissions::from_mode(0o644)).is_ok());
        assert!(matches!(
            SecretStore::open(original.path(), &key()),
            Err(SecretStorageError::UnsafeFile)
        ));
    }

    #[test]
    fn debug_and_errors_do_not_disclose_path_or_key() {
        let marker = "secret-database-path-marker";
        let temporary = TemporaryPath::new(marker);
        let store = SecretStore::create(temporary.path(), &key());
        let Ok(store) = store else {
            panic!("encrypted database could not be created for debug test");
        };
        let debug = format!("{store:?}");
        assert!(!debug.contains(marker));
        assert!(!debug.contains("25252525"));
        drop(store);

        let error = SecretStore::open(temporary.path(), &wrong_key());
        let Err(error) = error else {
            panic!("wrong key unexpectedly opened the database");
        };
        let text = format!("{error:?} {error}");
        assert!(!text.contains(marker));
        assert!(!text.contains("a6a6a6a6"));
    }
}
