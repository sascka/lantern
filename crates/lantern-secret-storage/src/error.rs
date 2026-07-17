// SPDX-License-Identifier: MPL-2.0

use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretStorageError {
    HeaderSize,
    MalformedHeader,
    UnsupportedHeader,
    PassphraseLength,
    Entropy,
    Derivation,
    AlreadyExists,
    UnsafeFile,
    Io,
    UnsupportedPlatform,
}

impl fmt::Display for SecretStorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderSize => formatter.write_str("KDF header size is outside the limit"),
            Self::MalformedHeader => formatter.write_str("KDF header is malformed"),
            Self::UnsupportedHeader => formatter.write_str("KDF header version is unsupported"),
            Self::PassphraseLength => {
                formatter.write_str("passphrase length is outside the allowed range")
            }
            Self::Entropy => formatter.write_str("operating system entropy is unavailable"),
            Self::Derivation => formatter.write_str("database key derivation failed"),
            Self::AlreadyExists => formatter.write_str("KDF header already exists"),
            Self::UnsafeFile => formatter.write_str("KDF header file is unsafe"),
            Self::Io => formatter.write_str("KDF header file operation failed"),
            Self::UnsupportedPlatform => formatter.write_str("platform is not supported by v0.1"),
        }
    }
}

impl Error for SecretStorageError {}
