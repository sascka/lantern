// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use lantern_secret_storage::Passphrase;
use zeroize::Zeroizing;

use crate::error::CliError;

const MAX_SECRET_TEXT_BYTES: u64 = 4096;
const CONTACT_WAIT: Duration = Duration::from_secs(120);
const CONTACT_POLL: Duration = Duration::from_millis(50);
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

pub fn create_private_directory(path: &Path) -> Result<(), CliError> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(|_| CliError::Io)?;
    validate_private_directory(path)
}

pub fn validate_private_directory(path: &Path) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CliError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(CliError::UnsafeFile);
    }
    Ok(())
}

pub fn read_passphrase(path: &Path) -> Result<Passphrase, CliError> {
    let mut text = read_private_text(path, MAX_SECRET_TEXT_BYTES)?;
    strip_final_newline(&mut text);
    if text.chars().any(char::is_control) {
        return Err(CliError::InvalidText);
    }
    Passphrase::new(text.to_string()).map_err(|_| CliError::Profile)
}

pub fn read_message(path: &Path, max_bytes: usize) -> Result<String, CliError> {
    let limit = u64::try_from(max_bytes).map_err(|_| CliError::InvalidText)?;
    let mut text = read_private_text(path, limit)?;
    strip_final_newline(&mut text);
    if text.is_empty() || text.len() > max_bytes || text.chars().any(char::is_control) {
        return Err(CliError::InvalidText);
    }
    Ok(text.to_string())
}

fn read_private_text(path: &Path, limit: u64) -> Result<Zeroizing<String>, CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CliError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > limit
    {
        return Err(CliError::UnsafeFile);
    }
    let file = File::open(path).map_err(|_| CliError::Io)?;
    let mut text = Zeroizing::new(String::new());
    file.take(limit.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(|_| CliError::InvalidText)?;
    if u64::try_from(text.len()).map_err(|_| CliError::InvalidText)? > limit {
        return Err(CliError::InvalidText);
    }
    Ok(text)
}

fn strip_final_newline(text: &mut String) {
    if text.ends_with("\r\n") {
        text.truncate(text.len().saturating_sub(2));
    } else if text.ends_with('\n') {
        text.pop();
    }
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    if bytes.is_empty() {
        return Err(CliError::InvalidText);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or(CliError::Io)?;
    let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let mut temporary_name = OsString::from(file_name);
    temporary_name.push(format!(".lantern-{}-{sequence}.tmp", std::process::id()));
    let temporary_path = parent.join(temporary_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary_path)
        .map_err(|_| CliError::Io)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary_path);
        let _ = error;
        return Err(CliError::Io);
    }
    drop(file);
    if fs::hard_link(&temporary_path, path).is_err() {
        let _ = fs::remove_file(&temporary_path);
        return Err(CliError::Io);
    }
    fs::remove_file(&temporary_path).map_err(|_| CliError::Io)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CliError::Io)?;
    Ok(())
}

pub fn wait_and_read(path: &Path, limit: usize) -> Result<Vec<u8>, CliError> {
    let started = Instant::now();
    loop {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.permissions().mode() & 0o777 != 0o600
                    || metadata.len() > u64::try_from(limit).map_err(|_| CliError::InvalidText)?
                {
                    return Err(CliError::UnsafeFile);
                }
                if metadata.nlink() != 1 {
                    if started.elapsed() >= CONTACT_WAIT {
                        return Err(CliError::Timeout);
                    }
                    thread::sleep(CONTACT_POLL);
                    continue;
                }
                let file = File::open(path).map_err(|_| CliError::Io)?;
                let mut bytes = Vec::with_capacity(
                    usize::try_from(metadata.len()).map_err(|_| CliError::InvalidText)?,
                );
                file.take(
                    u64::try_from(limit)
                        .map_err(|_| CliError::InvalidText)?
                        .saturating_add(1),
                )
                .read_to_end(&mut bytes)
                .map_err(|_| CliError::Io)?;
                if bytes.is_empty() || bytes.len() > limit {
                    return Err(CliError::InvalidText);
                }
                return Ok(bytes);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if started.elapsed() >= CONTACT_WAIT {
                    return Err(CliError::Timeout);
                }
                thread::sleep(CONTACT_POLL);
            }
            Err(_) => return Err(CliError::Io),
        }
    }
}
