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

impl DatabaseKey {
    #[cfg(test)]
    pub(crate) const fn from_bytes(bytes: [u8; DATABASE_KEY_LENGTH]) -> Self {
        Self { bytes }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; DATABASE_KEY_LENGTH] {
        &self.bytes
    }
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

#[cfg(test)]
mod tests {
    use argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};
    use zeroize::Zeroize;

    use super::{
        ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_PASSES, DATABASE_KEY_LENGTH, KdfHeader,
        Passphrase,
    };
    use crate::SecretStorageError;

    const SALT: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    fn header() -> KdfHeader {
        KdfHeader { salt: SALT }
    }

    #[test]
    fn header_has_one_canonical_encoding() {
        let encoded = header().encode();
        let Ok(encoded) = encoded else {
            panic!("test header could not be encoded");
        };
        let expected = [
            0xa7, 0x00, 0x01, 0x01, 0x01, 0x02, 0x50, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x03, 0x1a, 0x00, 0x01, 0x00,
            0x00, 0x04, 0x03, 0x05, 0x04, 0x06, 0x18, 0x20,
        ];
        assert_eq!(encoded, expected);
        assert_eq!(KdfHeader::decode(&encoded), Ok(header()));
    }

    #[test]
    fn malformed_and_noncanonical_headers_are_rejected() {
        let encoded = header().encode();
        let Ok(encoded) = encoded else {
            panic!("test header could not be encoded");
        };

        for prefix_length in 0..encoded.len() {
            assert!(KdfHeader::decode(&encoded[..prefix_length]).is_err());
        }

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            KdfHeader::decode(&trailing),
            Err(SecretStorageError::MalformedHeader)
        );

        let mut noncanonical_map = encoded.clone();
        noncanonical_map.splice(0..1, [0xb8, 0x07]);
        assert_eq!(
            KdfHeader::decode(&noncanonical_map),
            Err(SecretStorageError::MalformedHeader)
        );
    }

    #[test]
    fn changed_parameters_are_not_accepted() {
        let encoded = header().encode();
        let Ok(encoded) = encoded else {
            panic!("test header could not be encoded");
        };

        for (index, replacement) in [(2, 2), (4, 2), (28, 1), (30, 2), (32, 3), (35, 31)] {
            let mut changed = encoded.clone();
            changed[index] = replacement;
            assert_eq!(
                KdfHeader::decode(&changed),
                Err(SecretStorageError::UnsupportedHeader)
            );
        }
    }

    #[test]
    fn wrong_keys_and_indefinite_values_are_rejected() {
        let encoded = header().encode();
        let Ok(encoded) = encoded else {
            panic!("test header could not be encoded");
        };

        for (index, replacement) in [(0, 0xbf), (3, 0), (3, 7), (6, 0x5f), (6, 0x4f)] {
            let mut changed = encoded.clone();
            changed[index] = replacement;
            assert_eq!(
                KdfHeader::decode(&changed),
                Err(SecretStorageError::MalformedHeader)
            );
        }

        for byte in 0_u8..=u8::MAX {
            assert!(KdfHeader::decode(&[byte]).is_err());
        }
    }

    #[test]
    fn passphrase_boundaries_count_unicode_scalars() {
        assert!(Passphrase::new("a".repeat(15)).is_err());
        assert!(Passphrase::new("a".repeat(16)).is_ok());
        assert!(Passphrase::new("я".repeat(128)).is_ok());
        assert!(Passphrase::new("я".repeat(129)).is_err());
    }

    #[test]
    fn production_parameters_derive_a_stable_nonzero_key() {
        assert_eq!(ARGON2_MEMORY_KIB, 65_536);
        assert_eq!(ARGON2_PASSES, 3);
        assert_eq!(ARGON2_PARALLELISM, 4);
        assert_eq!(DATABASE_KEY_LENGTH, 32);

        let passphrase = Passphrase::new("correct horse battery staple".to_owned());
        let Ok(passphrase) = passphrase else {
            panic!("test passphrase was rejected");
        };
        let first = header().derive_database_key(&passphrase);
        let second = header().derive_database_key(&passphrase);
        let (Ok(first), Ok(second)) = (first, second) else {
            panic!("test key could not be derived");
        };
        assert_eq!(first.bytes, second.bytes);
        assert_ne!(first.bytes, [0_u8; DATABASE_KEY_LENGTH]);
    }

    #[test]
    fn rfc_9106_argon2id_vector_matches() {
        let data = AssociatedData::new(&[0x04; 12]);
        let Ok(data) = data else {
            panic!("RFC associated data was rejected");
        };
        let mut builder = ParamsBuilder::new();
        builder
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .output_len(32)
            .data(data);
        let params = builder.build();
        let Ok(params) = params else {
            panic!("RFC parameters were rejected");
        };
        let argon2 =
            Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params);
        let Ok(argon2) = argon2 else {
            panic!("RFC secret was rejected");
        };
        let mut output = [0_u8; 32];
        let mut memory = vec![Block::default(); 32];
        assert!(
            argon2
                .hash_password_into_with_memory(&[0x01; 32], &[0x02; 16], &mut output, &mut memory,)
                .is_ok()
        );
        for block in &mut memory {
            block.zeroize();
        }
        assert_eq!(
            output,
            [
                0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
                0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
                0x6b, 0x01, 0xe6, 0x59,
            ]
        );
    }

    #[test]
    fn debug_output_redacts_all_secret_values() {
        let secret = "passphrase-marker-1234";
        let passphrase = Passphrase::new(secret.to_owned());
        let Ok(passphrase) = passphrase else {
            panic!("test passphrase was rejected");
        };
        let key = header().derive_database_key(&passphrase);
        let Ok(key) = key else {
            panic!("test key could not be derived");
        };
        let header_debug = format!("{:?}", header());
        let passphrase_debug = format!("{passphrase:?}");
        let key_debug = format!("{key:?}");

        assert!(!header_debug.contains("00010203"));
        assert!(!passphrase_debug.contains(secret));
        assert!(!key_debug.contains("bytes"));
    }
}
