// SPDX-License-Identifier: MPL-2.0

use core::fmt;
use std::{ffi::OsStr, fs, io, path::Path};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use vodozemac::olm::Account;

use crate::{
    KdfHeader, Passphrase, ProfileId, SecretStorageError, SecretStore, file::write_kdf_header_file,
    read_kdf_header_file,
};

const KDF_FILENAME: &str = "secrets.kdf";
const DATABASE_FILENAME: &str = "secrets.sqlite3";
const JOURNAL_FILENAME: &str = "secrets.sqlite3-journal";

pub struct SecretProfile {
    store: SecretStore,
}

impl SecretProfile {
    pub fn create(directory: &Path, passphrase: &Passphrase) -> Result<Self, SecretStorageError> {
        create_private_directory(directory)?;

        let header = KdfHeader::generate()?;
        write_kdf_header_file(&directory.join(KDF_FILENAME), &header)?;
        let database_key = header.derive_database_key(passphrase)?;
        let store = SecretStore::create(&directory.join(DATABASE_FILENAME), &database_key)?;
        sync_directory(directory)?;

        Ok(Self { store })
    }

    pub fn open(directory: &Path, passphrase: &Passphrase) -> Result<Self, SecretStorageError> {
        validate_profile_directory(directory)?;
        validate_directory_entries(directory)?;

        let header = read_kdf_header_file(&directory.join(KDF_FILENAME))?;
        let database_key = header.derive_database_key(passphrase)?;
        let store = SecretStore::open(&directory.join(DATABASE_FILENAME), &database_key)?;

        Ok(Self { store })
    }

    pub const fn profile_id(&self) -> ProfileId {
        self.store.profile_id()
    }

    pub fn load_account(&self) -> Result<Account, SecretStorageError> {
        self.store.load_account()
    }

    pub fn replace_account(&mut self, account: &Account) -> Result<(), SecretStorageError> {
        self.store.replace_account(account)
    }

    pub const fn secret_store(&self) -> &SecretStore {
        &self.store
    }

    pub const fn secret_store_mut(&mut self) -> &mut SecretStore {
        &mut self.store
    }
}

impl fmt::Debug for SecretProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretProfile")
            .field("directory", &"redacted")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), SecretStorageError> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(|error| match error.kind() {
        io::ErrorKind::AlreadyExists => SecretStorageError::AlreadyExists,
        _ => SecretStorageError::Io,
    })?;
    validate_profile_directory(path)
}

#[cfg(not(unix))]
fn create_private_directory(_path: &Path) -> Result<(), SecretStorageError> {
    Err(SecretStorageError::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_profile_directory(path: &Path) -> Result<(), SecretStorageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| SecretStorageError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(SecretStorageError::UnsafeFile);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_profile_directory(_path: &Path) -> Result<(), SecretStorageError> {
    Err(SecretStorageError::UnsupportedPlatform)
}

fn validate_directory_entries(directory: &Path) -> Result<(), SecretStorageError> {
    let mut has_header = false;
    let mut has_database = false;
    for entry in fs::read_dir(directory).map_err(|_| SecretStorageError::Io)? {
        let entry = entry.map_err(|_| SecretStorageError::Io)?;
        match entry.file_name().as_os_str() {
            name if name == OsStr::new(KDF_FILENAME) => has_header = true,
            name if name == OsStr::new(DATABASE_FILENAME) => has_database = true,
            name if name == OsStr::new(JOURNAL_FILENAME) => {}
            _ => {}
        }
    }
    if !has_header || !has_database {
        return Err(SecretStorageError::IncompleteProfile);
    }
    Ok(())
}

fn sync_directory(directory: &Path) -> Result<(), SecretStorageError> {
    let handle = fs::File::open(directory).map_err(|_| SecretStorageError::Io)?;
    handle.sync_all().map_err(|_| SecretStorageError::Io)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(unix)]
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};

    use super::SecretProfile;
    use crate::{Passphrase, SecretStorageError};

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "lantern-secret-profile-{}-{sequence}-{label}",
                std::process::id()
            )))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
            let _ = fs::remove_file(&self.0);
        }
    }

    fn passphrase() -> Passphrase {
        let value = Passphrase::new("correct horse battery staple".to_owned());
        let Ok(value) = value else {
            panic!("test passphrase was rejected");
        };
        value
    }

    #[test]
    fn profile_round_trips_through_password_unlock() {
        let temporary = TemporaryDirectory::new("round-trip");
        let profile = SecretProfile::create(temporary.path(), &passphrase());
        let Ok(profile) = profile else {
            panic!("profile could not be created");
        };
        let id = profile.profile_id();
        let keys = profile
            .load_account()
            .map(|account| account.identity_keys());
        assert!(keys.is_ok());
        drop(profile);

        let reopened = SecretProfile::open(temporary.path(), &passphrase());
        let Ok(reopened) = reopened else {
            panic!("profile could not be reopened");
        };
        assert_eq!(reopened.profile_id(), id);
        assert_eq!(
            reopened
                .load_account()
                .map(|account| account.identity_keys()),
            keys
        );

        #[cfg(unix)]
        {
            let metadata = fs::metadata(temporary.path());
            let Ok(metadata) = metadata else {
                panic!("profile directory metadata could not be read");
            };
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }
    }

    #[cfg(unix)]
    #[test]
    fn incomplete_and_unsafe_profile_directories_are_rejected() {
        let incomplete = TemporaryDirectory::new("incomplete");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        assert!(builder.create(incomplete.path()).is_ok());
        assert_eq!(
            SecretProfile::open(incomplete.path(), &passphrase()).err(),
            Some(SecretStorageError::IncompleteProfile)
        );

        let permissive = TemporaryDirectory::new("permissive");
        assert!(fs::create_dir(permissive.path()).is_ok());
        assert_eq!(
            SecretProfile::open(permissive.path(), &passphrase()).err(),
            Some(SecretStorageError::UnsafeFile)
        );

        let target = TemporaryDirectory::new("target");
        let link = TemporaryDirectory::new("link");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        assert!(builder.create(target.path()).is_ok());
        assert!(symlink(target.path(), link.path()).is_ok());
        assert_eq!(
            SecretProfile::open(link.path(), &passphrase()).err(),
            Some(SecretStorageError::UnsafeFile)
        );
    }

    #[test]
    fn existing_profile_directory_is_never_reused() {
        let temporary = TemporaryDirectory::new("existing");
        assert!(fs::create_dir(temporary.path()).is_ok());
        assert_eq!(
            SecretProfile::create(temporary.path(), &passphrase()).err(),
            Some(SecretStorageError::AlreadyExists)
        );
    }
}
