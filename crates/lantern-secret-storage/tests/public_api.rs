// SPDX-License-Identifier: MPL-2.0

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use lantern_secret_storage::{
    KDF_HEADER_MAX_BYTES, Passphrase, SecretStorageError, create_kdf_header_file,
    read_kdf_header_file,
};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn temporary_path() -> PathBuf {
    let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "lantern-secret-storage-public-{}-{sequence}",
        std::process::id()
    ))
}

#[test]
fn public_api_creates_and_reopens_one_strict_header() {
    let path = temporary_path();
    let _ = fs::remove_file(&path);

    let created = create_kdf_header_file(&path);
    let Ok(created) = created else {
        panic!("public KDF header creation failed");
    };
    assert_eq!(read_kdf_header_file(&path), Ok(created));
    assert_eq!(
        create_kdf_header_file(&path),
        Err(SecretStorageError::AlreadyExists)
    );

    let _ = fs::remove_file(path);
}

#[test]
fn public_decoder_rejects_unbounded_input_before_parsing() {
    let oversized = vec![0_u8; KDF_HEADER_MAX_BYTES + 1];
    assert_eq!(
        lantern_secret_storage::KdfHeader::decode(&oversized),
        Err(SecretStorageError::HeaderSize)
    );
}

#[test]
fn public_secret_types_have_redacted_debug_output() {
    let marker = "public-passphrase-marker";
    let passphrase = Passphrase::new(marker.to_owned());
    let Ok(passphrase) = passphrase else {
        panic!("public test passphrase was rejected");
    };
    assert!(!format!("{passphrase:?}").contains(marker));
}
