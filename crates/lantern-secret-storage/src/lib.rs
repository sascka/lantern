// SPDX-License-Identifier: MPL-2.0

//! Password KDF boundary for the future Lantern secret database.

mod database;
mod error;
mod file;
mod header;
mod profile;
mod state;

pub use database::{ProfileId, SecretStore};
pub use error::SecretStorageError;
pub use file::{create_kdf_header_file, read_kdf_header_file};
pub use header::{
    ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_PASSES, DATABASE_KEY_LENGTH, DatabaseKey,
    KDF_HEADER_MAX_BYTES, KDF_SALT_LENGTH, KdfHeader, Passphrase,
};
pub use profile::SecretProfile;
pub use state::{ContactId, NewContact, PendingEnvelope};
