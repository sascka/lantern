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

