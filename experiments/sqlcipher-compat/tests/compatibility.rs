// SPDX-License-Identifier: MPL-2.0

use std::{
    error::Error,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use rusqlite::{Connection, OpenFlags, params};
use zeroize::Zeroizing;

const KEY: [u8; 32] = [0x31; 32];
const WRONG_KEY: [u8; 32] = [0x72; 32];
const PLAINTEXT_MARKER: &str = "sqlcipher-plaintext-sentinel-6d18";

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

struct TemporaryDatabase {
    path: PathBuf,
}

impl TemporaryDatabase {
    fn new(label: &str) -> Self {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lantern-sqlcipher-compat-{}-{sequence}-{label}.sqlite3",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let mut journal = self.path.as_os_str().to_os_string();
        journal.push("-journal");
        let _ = fs::remove_file(PathBuf::from(journal));
    }
}

fn raw_key_literal(key: &[u8; 32]) -> TestResult<Zeroizing<String>> {
    let mut literal = Zeroizing::new(String::with_capacity(67));
    literal.push_str("x'");
    for byte in key {
        write!(literal, "{byte:02x}")?;
    }
    literal.push('\'');
    Ok(literal)
}

fn apply_key(connection: &Connection, key: &[u8; 32]) -> TestResult {
    let literal = raw_key_literal(key)?;
    connection.pragma_update(None, "key", literal.as_str())?;
    Ok(())
}

fn open_with_key(path: &Path, key: &[u8; 32]) -> TestResult<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(path, flags)?;
    apply_key(&connection, key)?;
    Ok(connection)
}

fn configure_encrypted(connection: &Connection) -> TestResult {
    connection.pragma_update(None, "cipher_memory_security", "ON")?;
    connection.pragma_update(None, "cipher_log_level", "NONE")?;
    connection.pragma_update(None, "journal_mode", "DELETE")?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.pragma_update(None, "mmap_size", 0_i64)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "secure_delete", "ON")?;
    Ok(())
}

fn open_encrypted(path: &Path, key: &[u8; 32]) -> TestResult<Connection> {
    let connection = open_with_key(path, key)?;
    configure_encrypted(&connection)?;
    Ok(connection)
}

#[test]
fn reports_the_pinned_sqlcipher_release() -> TestResult {
    let connection = Connection::open_in_memory()?;
    let version: String = connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
    assert_eq!(version, "4.17.0 community");

    let status: String = connection.query_row("PRAGMA cipher_status", [], |row| row.get(0))?;
    assert_eq!(status, "0");

    let database = TemporaryDatabase::new("status");
    let encrypted = open_encrypted(database.path(), &KEY)?;
    encrypted.execute("CREATE TABLE sample(value INTEGER NOT NULL) STRICT", [])?;
    let status: String = encrypted.query_row("PRAGMA cipher_status", [], |row| row.get(0))?;
    assert_eq!(status, "1");
    Ok(())
}

#[test]
fn raw_key_encrypts_and_reopens_the_database() -> TestResult {
    let database = TemporaryDatabase::new("round-trip");
    {
        let connection = open_encrypted(database.path(), &KEY)?;
        connection.execute_batch(
            "CREATE TABLE sample(value TEXT NOT NULL) STRICT;
             INSERT INTO sample(value) VALUES ('sqlcipher-plaintext-sentinel-6d18');",
        )?;
    }

    let bytes = fs::read(database.path())?;
    assert!(
        !bytes
            .windows(PLAINTEXT_MARKER.len())
            .any(|window| window == PLAINTEXT_MARKER.as_bytes())
    );
    assert_ne!(bytes.get(..16), Some(b"SQLite format 3\0".as_slice()));

    let connection = open_encrypted(database.path(), &KEY)?;
    let value: String = connection.query_row("SELECT value FROM sample", [], |row| row.get(0))?;
    assert_eq!(value, PLAINTEXT_MARKER);
    Ok(())
}

#[test]
fn wrong_key_cannot_read_or_modify_the_schema() -> TestResult {
    let database = TemporaryDatabase::new("wrong-key");
    {
        let connection = open_encrypted(database.path(), &KEY)?;
        connection.execute("CREATE TABLE sample(value INTEGER NOT NULL) STRICT", [])?;
    }

    let wrong = open_with_key(database.path(), &WRONG_KEY)?;
    assert!(
        wrong
            .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row
                .get::<_, i64>(0))
            .is_err()
    );
    assert!(
        wrong
            .execute("CREATE TABLE attacker(value INTEGER)", [])
            .is_err()
    );

    let correct = open_encrypted(database.path(), &KEY)?;
    let count: i64 = correct.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name = ?1",
        params!["attacker"],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn plaintext_connection_stays_available_for_the_transport_queue() -> TestResult {
    let database = TemporaryDatabase::new("plaintext");
    let connection = Connection::open(database.path())?;
    connection.execute("CREATE TABLE queue(value BLOB NOT NULL) STRICT", [])?;
    connection.execute("INSERT INTO queue(value) VALUES (?1)", params![b"opaque"])?;
    let value: Vec<u8> = connection.query_row("SELECT value FROM queue", [], |row| row.get(0))?;
    assert_eq!(value, b"opaque");
    Ok(())
}
