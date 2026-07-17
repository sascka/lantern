// SPDX-License-Identifier: MPL-2.0

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use crate::{KDF_HEADER_MAX_BYTES, KdfHeader, SecretStorageError};

pub fn create_kdf_header_file(path: &Path) -> Result<KdfHeader, SecretStorageError> {
    let header = KdfHeader::generate()?;
    let encoded = header.encode()?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    configure_secure_open(&mut options)?;

    let mut file = options.open(path).map_err(map_create_error)?;
    write_and_sync(&mut file, &encoded)?;

    Ok(header)
}

pub fn read_kdf_header_file(path: &Path) -> Result<KdfHeader, SecretStorageError> {
    let mut options = OpenOptions::new();
    options.read(true);
    configure_secure_open(&mut options)?;

    let mut file = options.open(path).map_err(map_open_error)?;
    validate_open_file(&file)?;

    let read_limit =
        u64::try_from(KDF_HEADER_MAX_BYTES + 1).map_err(|_| SecretStorageError::HeaderSize)?;
    let mut encoded = Vec::with_capacity(KDF_HEADER_MAX_BYTES + 1);
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut encoded)
        .map_err(|_| SecretStorageError::Io)?;

    if encoded.is_empty() || encoded.len() > KDF_HEADER_MAX_BYTES {
        return Err(SecretStorageError::HeaderSize);
    }

    KdfHeader::decode(&encoded)
}

fn write_and_sync(file: &mut File, encoded: &[u8]) -> Result<(), SecretStorageError> {
    file.write_all(encoded)
        .and_then(|()| file.sync_all())
        .map_err(|_| SecretStorageError::Io)?;
    validate_open_file(file)
}

fn map_create_error(error: std::io::Error) -> SecretStorageError {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        SecretStorageError::AlreadyExists
    } else {
        SecretStorageError::Io
    }
}

fn map_open_error(error: std::io::Error) -> SecretStorageError {
    if error.raw_os_error() == Some(libc::ELOOP) {
        SecretStorageError::UnsafeFile
    } else {
        SecretStorageError::Io
    }
}

#[cfg(unix)]
fn configure_secure_open(options: &mut OpenOptions) -> Result<(), SecretStorageError> {
    options
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    Ok(())
}

#[cfg(not(unix))]
fn configure_secure_open(_options: &mut OpenOptions) -> Result<(), SecretStorageError> {
    Err(SecretStorageError::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_open_file(file: &File) -> Result<(), SecretStorageError> {
    let metadata = file.metadata().map_err(|_| SecretStorageError::Io)?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > KDF_HEADER_MAX_BYTES as u64
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(SecretStorageError::UnsafeFile);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_open_file(_file: &File) -> Result<(), SecretStorageError> {
    Err(SecretStorageError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::{create_kdf_header_file, read_kdf_header_file};
    use crate::{KDF_HEADER_MAX_BYTES, SecretStorageError};

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TemporaryPath {
        path: PathBuf,
    }

    impl TemporaryPath {
        fn new(label: &str) -> Self {
            let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            let filename = format!(
                "lantern-secret-storage-{}-{sequence}-{label}",
                std::process::id()
            );
            let path = std::env::temp_dir().join(filename);
            let _ = fs::remove_file(&path);
            let _ = fs::remove_dir_all(&path);
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TemporaryPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn created_header_is_restricted_and_round_trips() {
        let temporary = TemporaryPath::new("round-trip");
        let created = create_kdf_header_file(temporary.path());
        let Ok(created) = created else {
            panic!("KDF header could not be created");
        };
        let reopened = read_kdf_header_file(temporary.path());
        assert_eq!(reopened, Ok(created));

        #[cfg(unix)]
        {
            let metadata = fs::metadata(temporary.path());
            let Ok(metadata) = metadata else {
                panic!("KDF header metadata could not be read");
            };
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
    }

    #[test]
    fn existing_file_is_never_replaced() {
        let temporary = TemporaryPath::new("existing");
        assert!(fs::write(temporary.path(), b"owner data").is_ok());
        assert_eq!(
            create_kdf_header_file(temporary.path()),
            Err(SecretStorageError::AlreadyExists)
        );
        let contents = fs::read(temporary.path());
        let Ok(contents) = contents else {
            panic!("existing test file could not be read");
        };
        assert_eq!(contents, b"owner data");
    }

    #[test]
    fn empty_and_oversized_files_are_rejected() {
        let empty = TemporaryPath::new("empty");
        assert!(fs::write(empty.path(), []).is_ok());
        assert_eq!(
            read_kdf_header_file(empty.path()),
            Err(SecretStorageError::UnsafeFile)
        );

        let oversized = TemporaryPath::new("oversized");
        assert!(fs::write(oversized.path(), vec![0_u8; KDF_HEADER_MAX_BYTES + 1]).is_ok());
        assert_eq!(
            read_kdf_header_file(oversized.path()),
            Err(SecretStorageError::UnsafeFile)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_hardlink_and_open_permissions_are_rejected() {
        let original = TemporaryPath::new("original");
        let link = TemporaryPath::new("symlink");
        let hardlink = TemporaryPath::new("hardlink");
        let created = create_kdf_header_file(original.path());
        assert!(created.is_ok());

        assert!(symlink(original.path(), link.path()).is_ok());
        assert_eq!(
            read_kdf_header_file(link.path()),
            Err(SecretStorageError::UnsafeFile)
        );

        assert!(fs::hard_link(original.path(), hardlink.path()).is_ok());
        assert_eq!(
            read_kdf_header_file(original.path()),
            Err(SecretStorageError::UnsafeFile)
        );
        assert_eq!(
            read_kdf_header_file(hardlink.path()),
            Err(SecretStorageError::UnsafeFile)
        );

        assert!(fs::remove_file(hardlink.path()).is_ok());
        let permissions = fs::Permissions::from_mode(0o644);
        assert!(fs::set_permissions(original.path(), permissions).is_ok());
        assert_eq!(
            read_kdf_header_file(original.path()),
            Err(SecretStorageError::UnsafeFile)
        );
    }

    #[test]
    fn directory_is_rejected_without_reading_it() {
        let temporary = TemporaryPath::new("directory");
        assert!(fs::create_dir(temporary.path()).is_ok());
        assert_eq!(
            read_kdf_header_file(temporary.path()),
            Err(SecretStorageError::UnsafeFile)
        );
    }

    #[test]
    fn file_errors_never_include_the_path() {
        let marker = "private-path-marker";
        let temporary = TemporaryPath::new(marker);
        let error = read_kdf_header_file(temporary.path());
        let Err(error) = error else {
            panic!("missing file was unexpectedly accepted");
        };
        assert!(!format!("{error}").contains(marker));
        assert!(!format!("{error:?}").contains(marker));
    }
}
