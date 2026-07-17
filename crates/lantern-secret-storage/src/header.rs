// SPDX-License-Identifier: MPL-2.0

use std::fmt;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use crate::SecretStorageError;

const KDF_FORMAT_VERSION: u8 = 1;
const KDF_ALGORITHM_ARGON2ID_13: u8 = 1;
const KDF_MAP_FIELDS: u64 = 7;

pub const KDF_HEADER_MAX_BYTES: usize = 128;
pub const KDF_SALT_LENGTH: usize = 16;
pub const DATABASE_KEY_LENGTH: usize = 32;
const DATABASE_KEY_LENGTH_U32: u32 = 32;
pub const ARGON2_MEMORY_KIB: u32 = 65_536;
pub const ARGON2_PASSES: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 4;

const MIN_PASSPHRASE_CHARS: usize = 16;
const MAX_PASSPHRASE_CHARS: usize = 128;
const MAX_PASSPHRASE_BYTES: usize = 1024;

#[derive(Clone, Eq, PartialEq)]
pub struct KdfHeader {
    salt: [u8; KDF_SALT_LENGTH],
}

impl KdfHeader {
    pub fn generate() -> Result<Self, SecretStorageError> {
        let mut salt = [0_u8; KDF_SALT_LENGTH];
        getrandom::fill(&mut salt).map_err(|_| SecretStorageError::Entropy)?;
        Ok(Self { salt })
    }

    pub fn decode(input: &[u8]) -> Result<Self, SecretStorageError> {
        if input.is_empty() || input.len() > KDF_HEADER_MAX_BYTES {
            return Err(SecretStorageError::HeaderSize);
        }

        let mut decoder = Decoder::new(input);
        let field_count = decoder
            .map()
            .map_err(|_| SecretStorageError::MalformedHeader)?;
        if field_count != Some(KDF_MAP_FIELDS) {
            return Err(SecretStorageError::MalformedHeader);
        }

        let version = decode_u8_field(&mut decoder, 0)?;
        let algorithm = decode_u8_field(&mut decoder, 1)?;

        if decoder
            .u8()
            .map_err(|_| SecretStorageError::MalformedHeader)?
            != 2
        {
            return Err(SecretStorageError::MalformedHeader);
        }
        let salt_bytes = decoder
            .bytes()
            .map_err(|_| SecretStorageError::MalformedHeader)?;
        let salt = <[u8; KDF_SALT_LENGTH]>::try_from(salt_bytes)
            .map_err(|_| SecretStorageError::MalformedHeader)?;

        let memory_kib = decode_u32_field(&mut decoder, 3)?;
        let passes = decode_u32_field(&mut decoder, 4)?;
        let parallelism = decode_u32_field(&mut decoder, 5)?;
        let output_length = decode_u32_field(&mut decoder, 6)?;

        if decoder.position() != input.len() {
            return Err(SecretStorageError::MalformedHeader);
        }

        if version != KDF_FORMAT_VERSION
            || algorithm != KDF_ALGORITHM_ARGON2ID_13
            || memory_kib != ARGON2_MEMORY_KIB
            || passes != ARGON2_PASSES
            || parallelism != ARGON2_PARALLELISM
            || output_length != DATABASE_KEY_LENGTH_U32
        {
            return Err(SecretStorageError::UnsupportedHeader);
        }

        let header = Self { salt };
        if header.encode()?.as_slice() != input {
            return Err(SecretStorageError::MalformedHeader);
        }

        Ok(header)
    }

    pub fn encode(&self) -> Result<Vec<u8>, SecretStorageError> {
        let mut encoded = Vec::with_capacity(40);
        let mut encoder = Encoder::new(&mut encoded);

        encoder
            .map(KDF_MAP_FIELDS)
            .and_then(|value| value.u8(0))
            .and_then(|value| value.u8(KDF_FORMAT_VERSION))
            .and_then(|value| value.u8(1))
            .and_then(|value| value.u8(KDF_ALGORITHM_ARGON2ID_13))
            .and_then(|value| value.u8(2))
            .and_then(|value| value.bytes(&self.salt))
            .and_then(|value| value.u8(3))
            .and_then(|value| value.u32(ARGON2_MEMORY_KIB))
            .and_then(|value| value.u8(4))
            .and_then(|value| value.u32(ARGON2_PASSES))
            .and_then(|value| value.u8(5))
            .and_then(|value| value.u32(ARGON2_PARALLELISM))
            .and_then(|value| value.u8(6))
            .and_then(|value| value.u32(DATABASE_KEY_LENGTH_U32))
            .map_err(|_| SecretStorageError::MalformedHeader)?;

        if encoded.len() > KDF_HEADER_MAX_BYTES {
            return Err(SecretStorageError::HeaderSize);
        }

        Ok(encoded)
    }

    pub fn derive_database_key(
        &self,
        passphrase: &Passphrase,
    ) -> Result<DatabaseKey, SecretStorageError> {
        let params = production_params()?;
        let block_count = params.block_count();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut memory = vec![Block::default(); block_count];
        let mut bytes = [0_u8; DATABASE_KEY_LENGTH];

        let result = argon2.hash_password_into_with_memory(
            passphrase.as_bytes(),
            &self.salt,
            &mut bytes,
            &mut memory,
        );
        for block in &mut memory {
            block.zeroize();
        }

        match result {
            Ok(()) => Ok(DatabaseKey { bytes }),
            Err(_) => {
                bytes.zeroize();
                Err(SecretStorageError::Derivation)
            }
        }
    }
}

impl fmt::Debug for KdfHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KdfHeader")
            .field("version", &KDF_FORMAT_VERSION)
            .field("algorithm", &"Argon2id")
            .field("salt", &"[REDACTED]")
            .finish()
    }
}

pub struct Passphrase {
    bytes: Vec<u8>,
}

impl Passphrase {
    pub fn new(value: String) -> Result<Self, SecretStorageError> {
        let character_count = value.chars().count();
        let mut bytes = value.into_bytes();
        if !(MIN_PASSPHRASE_CHARS..=MAX_PASSPHRASE_CHARS).contains(&character_count)
            || bytes.len() > MAX_PASSPHRASE_BYTES
        {
            bytes.as_mut_slice().zeroize();
            return Err(SecretStorageError::PassphraseLength);
        }

        Ok(Self { bytes })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Passphrase([REDACTED])")
    }
}

pub struct DatabaseKey {
    bytes: [u8; DATABASE_KEY_LENGTH],
}

impl Drop for DatabaseKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for DatabaseKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DatabaseKey([REDACTED])")
    }
}

fn production_params() -> Result<Params, SecretStorageError> {
    Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_PASSES,
        ARGON2_PARALLELISM,
        Some(DATABASE_KEY_LENGTH),
    )
    .map_err(|_| SecretStorageError::Derivation)
}

fn decode_u8_field(decoder: &mut Decoder<'_>, expected_key: u8) -> Result<u8, SecretStorageError> {
    if decoder
        .u8()
        .map_err(|_| SecretStorageError::MalformedHeader)?
        != expected_key
    {
        return Err(SecretStorageError::MalformedHeader);
    }
    decoder
        .u8()
        .map_err(|_| SecretStorageError::MalformedHeader)
}

fn decode_u32_field(
    decoder: &mut Decoder<'_>,
    expected_key: u8,
) -> Result<u32, SecretStorageError> {
    if decoder
        .u8()
        .map_err(|_| SecretStorageError::MalformedHeader)?
        != expected_key
    {
        return Err(SecretStorageError::MalformedHeader);
    }
    decoder
        .u32()
        .map_err(|_| SecretStorageError::MalformedHeader)
}

