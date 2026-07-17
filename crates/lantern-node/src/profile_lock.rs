// SPDX-License-Identifier: MPL-2.0

use core::fmt;
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileLockError {
    AlreadyInUse,
    InvalidLockFile,
    Io,
}

impl fmt::Display for ProfileLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInUse => formatter.write_str("node profile is already in use"),
            Self::InvalidLockFile => formatter.write_str("node profile lock file is invalid"),
            Self::Io => formatter.write_str("node profile lock operation failed"),
        }
    }
}

impl std::error::Error for ProfileLockError {}

pub(crate) struct ProfileLock {
    file: File,
}

impl ProfileLock {
    pub(crate) fn acquire(database_path: &Path) -> Result<Self, ProfileLockError> {
        let path = lock_path(database_path);
        validate_existing_path(&path)?;
        let (file, created) = open_lock_file(&path)?;
        if created {
            restrict_created_permissions(&path)?;
        }
        validate_open_file(&path, &file)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { file }),
            Err(fs::TryLockError::WouldBlock) => Err(ProfileLockError::AlreadyInUse),
            Err(fs::TryLockError::Error(_)) => Err(ProfileLockError::Io),
        }
    }
}

impl fmt::Debug for ProfileLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.file;
        formatter
            .debug_struct("ProfileLock")
            .field("path", &"redacted")
            .finish_non_exhaustive()
    }
}

fn lock_path(database_path: &Path) -> PathBuf {
    let mut value = OsString::from(database_path.as_os_str());
    value.push(".lock");
    PathBuf::from(value)
}

fn validate_existing_path(path: &Path) -> Result<(), ProfileLockError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_metadata(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ProfileLockError::Io),
    }
}

fn open_lock_file(path: &Path) -> Result<(File, bool), ProfileLockError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    configure_create_mode(&mut options);
    match options.create_new(true).open(path) {
        Ok(file) => Ok((file, true)),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => options
            .create_new(false)
            .create(false)
            .open(path)
            .map(|file| (file, false))
            .map_err(|_| ProfileLockError::Io),
        Err(_) => Err(ProfileLockError::Io),
    }
}

#[cfg(unix)]
fn configure_create_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn configure_create_mode(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn restrict_created_permissions(path: &Path) -> Result<(), ProfileLockError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|_| ProfileLockError::Io)
}

#[cfg(not(unix))]
fn restrict_created_permissions(_path: &Path) -> Result<(), ProfileLockError> {
    Ok(())
}

fn validate_open_file(path: &Path, file: &File) -> Result<(), ProfileLockError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| ProfileLockError::Io)?;
    let file_metadata = file.metadata().map_err(|_| ProfileLockError::Io)?;
    validate_metadata(&path_metadata)?;
    validate_metadata(&file_metadata)?;
    same_opened_file(&path_metadata, &file_metadata)
}

fn validate_metadata(metadata: &fs::Metadata) -> Result<(), ProfileLockError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 0 {
        return Err(ProfileLockError::InvalidLockFile);
    }
    validate_unix_metadata(metadata)
}

#[cfg(unix)]
fn validate_unix_metadata(metadata: &fs::Metadata) -> Result<(), ProfileLockError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.permissions().mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
        return Err(ProfileLockError::InvalidLockFile);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_unix_metadata(_metadata: &fs::Metadata) -> Result<(), ProfileLockError> {
    Ok(())
}

#[cfg(unix)]
fn same_opened_file(
    path_metadata: &fs::Metadata,
    file_metadata: &fs::Metadata,
) -> Result<(), ProfileLockError> {
    use std::os::unix::fs::MetadataExt;

    if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino() {
        return Err(ProfileLockError::InvalidLockFile);
    }
    Ok(())
}

#[cfg(not(unix))]
fn same_opened_file(
    _path_metadata: &fs::Metadata,
    _file_metadata: &fs::Metadata,
) -> Result<(), ProfileLockError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct TestPath(PathBuf);

    impl TestPath {
        fn new(label: &str) -> Self {
            let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "lantern-profile-lock-{label}-{}-{sequence}.sqlite3",
                std::process::id()
            )))
        }

        fn database(&self) -> &Path {
            &self.0
        }

        fn lock(&self) -> PathBuf {
            lock_path(&self.0)
        }
    }

    impl Drop for TestPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(lock_path(&self.0));
        }
    }

    #[test]
    fn second_lock_fails_and_drop_releases_the_profile() {
        let path = TestPath::new("exclusive");
        let first = ProfileLock::acquire(path.database());
        let Ok(first) = first else {
            panic!("first profile lock could not be acquired");
        };
        assert!(matches!(
            ProfileLock::acquire(path.database()),
            Err(ProfileLockError::AlreadyInUse)
        ));
        drop(first);
        assert!(ProfileLock::acquire(path.database()).is_ok());
    }

    #[test]
    fn lock_file_is_empty_restricted_and_redacted() {
        let path = TestPath::new("private-marker");
        let lock = ProfileLock::acquire(path.database());
        let Ok(lock) = lock else {
            panic!("profile lock could not be acquired for metadata test");
        };
        let metadata = fs::metadata(path.lock());
        let Ok(metadata) = metadata else {
            panic!("profile lock metadata could not be read");
        };
        assert_eq!(metadata.len(), 0);
        assert!(!format!("{lock:?}").contains("private-marker"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_hardlink_and_nonempty_lock_files_are_rejected() {
        use std::os::unix::fs::symlink;

        let target = TestPath::new("target");
        let target_lock = target.lock();
        assert!(fs::File::create(&target_lock).is_ok());
        let metadata = fs::metadata(&target_lock);
        let Ok(metadata) = metadata else {
            panic!("target lock metadata could not be read");
        };
        let mut permissions = metadata.permissions();
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o600);
        assert!(fs::set_permissions(&target_lock, permissions).is_ok());

        let symlink_path = TestPath::new("symlink");
        assert!(symlink(&target_lock, symlink_path.lock()).is_ok());
        assert!(matches!(
            ProfileLock::acquire(symlink_path.database()),
            Err(ProfileLockError::InvalidLockFile)
        ));

        let hardlink_path = TestPath::new("hardlink");
        assert!(fs::hard_link(&target_lock, hardlink_path.lock()).is_ok());
        assert!(matches!(
            ProfileLock::acquire(hardlink_path.database()),
            Err(ProfileLockError::InvalidLockFile)
        ));

        let nonempty = TestPath::new("nonempty");
        assert!(fs::write(nonempty.lock(), b"unexpected").is_ok());
        assert!(matches!(
            ProfileLock::acquire(nonempty.database()),
            Err(ProfileLockError::InvalidLockFile)
        ));
    }
}
