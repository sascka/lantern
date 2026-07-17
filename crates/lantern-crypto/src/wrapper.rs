// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use minicbor::{Decoder, Encoder, data::Type};
use vodozemac::olm::OlmMessage;

use crate::CryptoError;

const PROTECTED_PAYLOAD_VERSION: u8 = 1;
const WRAPPER_FIELDS: u64 = 3;

pub const PROTECTED_PAYLOAD_MAX_BYTES: usize = 8192;
pub const OLM_MESSAGE_MAX_BYTES: usize = 8183;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OlmMessageType {
    PreKey,
    Normal,
}

impl OlmMessageType {
    pub const fn as_raw(self) -> u8 {
        match self {
            Self::PreKey => 0,
            Self::Normal => 1,
        }
    }

    fn from_raw(value: u64) -> Result<Self, CryptoError> {
        match value {
            0 => Ok(Self::PreKey),
            1 => Ok(Self::Normal),
            _ => Err(CryptoError::UnsupportedType),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedOlmMessage {
    message_type: OlmMessageType,
    message: Box<[u8]>,
}

impl ProtectedOlmMessage {
    pub fn try_from_parts(
        message_type: OlmMessageType,
        message: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        if message.is_empty() || message.len() > OLM_MESSAGE_MAX_BYTES {
            return Err(CryptoError::WrongLength);
        }
        OlmMessage::from_parts(usize::from(message_type.as_raw()), &message)
            .map_err(|_| CryptoError::OlmRejected)?;
        Ok(Self {
            message_type,
            message: message.into_boxed_slice(),
        })
    }

    pub fn from_olm(message: &OlmMessage) -> Result<Self, CryptoError> {
        let (message_type, bytes) = message.to_parts();
        let message_type = match message_type {
            0 => OlmMessageType::PreKey,
            1 => OlmMessageType::Normal,
            _ => return Err(CryptoError::UnsupportedType),
        };
        Self::try_from_parts(message_type, bytes)
    }

    pub fn to_olm(&self) -> Result<OlmMessage, CryptoError> {
        OlmMessage::from_parts(usize::from(self.message_type.as_raw()), &self.message)
            .map_err(|_| CryptoError::OlmRejected)
    }

    pub const fn message_type(&self) -> OlmMessageType {
        self.message_type
    }

    pub fn message_bytes(&self) -> &[u8] {
        &self.message
    }
}

impl fmt::Debug for ProtectedOlmMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedOlmMessage")
            .field("message_type", &self.message_type)
            .field("message_length", &self.message.len())
            .finish_non_exhaustive()
    }
}

pub fn encode_protected_payload(message: &ProtectedOlmMessage) -> Result<Vec<u8>, CryptoError> {
    let mut encoder = Encoder::new(Vec::with_capacity(message.message.len().saturating_add(9)));
    encoder
        .map(WRAPPER_FIELDS)
        .and_then(|value| value.u8(0))
        .and_then(|value| value.u8(PROTECTED_PAYLOAD_VERSION))
        .and_then(|value| value.u8(1))
        .and_then(|value| value.u8(message.message_type.as_raw()))
        .and_then(|value| value.u8(2))
        .and_then(|value| value.bytes(&message.message))
        .map_err(|_| CryptoError::Malformed)?;
    let encoded = encoder.into_writer();
    if encoded.len() > PROTECTED_PAYLOAD_MAX_BYTES {
        return Err(CryptoError::InputTooLarge);
    }
    Ok(encoded)
}

pub fn decode_protected_payload(input: &[u8]) -> Result<ProtectedOlmMessage, CryptoError> {
    if input.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    if input.len() > PROTECTED_PAYLOAD_MAX_BYTES {
        return Err(CryptoError::InputTooLarge);
    }

    let mut decoder = Decoder::new(input);
    expect_map(&mut decoder, WRAPPER_FIELDS)?;
    expect_key(&mut decoder, 0)?;
    if decode_unsigned(&mut decoder)? != u64::from(PROTECTED_PAYLOAD_VERSION) {
        return Err(CryptoError::UnsupportedVersion);
    }
    expect_key(&mut decoder, 1)?;
    let message_type = OlmMessageType::from_raw(decode_unsigned(&mut decoder)?)?;
    expect_key(&mut decoder, 2)?;
    let message = decode_bytes(&mut decoder)?;
    if message.is_empty() || message.len() > OLM_MESSAGE_MAX_BYTES {
        return Err(CryptoError::WrongLength);
    }
    if decoder.position() != input.len() {
        return Err(CryptoError::Malformed);
    }

    let decoded = ProtectedOlmMessage::try_from_parts(message_type, message.to_vec())?;
    if encode_protected_payload(&decoded)?.as_slice() != input {
        return Err(CryptoError::NonCanonical);
    }
    Ok(decoded)
}

fn expect_map(decoder: &mut Decoder<'_>, fields: u64) -> Result<(), CryptoError> {
    if decoder.datatype().map_err(|_| CryptoError::Malformed)? != Type::Map {
        return Err(CryptoError::Malformed);
    }
    if decoder.map().map_err(|_| CryptoError::Malformed)? != Some(fields) {
        return Err(CryptoError::Malformed);
    }
    Ok(())
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), CryptoError> {
    if decode_unsigned(decoder)? != u64::from(expected) {
        return Err(CryptoError::Malformed);
    }
    Ok(())
}

fn decode_unsigned(decoder: &mut Decoder<'_>) -> Result<u64, CryptoError> {
    match decoder.datatype().map_err(|_| CryptoError::Malformed)? {
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
            decoder.u64().map_err(|_| CryptoError::Malformed)
        }
        _ => Err(CryptoError::Malformed),
    }
}

fn decode_bytes<'a>(decoder: &mut Decoder<'a>) -> Result<&'a [u8], CryptoError> {
    if decoder.datatype().map_err(|_| CryptoError::Malformed)? != Type::Bytes {
        return Err(CryptoError::Malformed);
    }
    decoder.bytes().map_err(|_| CryptoError::Malformed)
}

#[cfg(test)]
mod tests {
    use vodozemac::olm::{Account, OlmMessage, SessionConfig};

    use super::{
        OlmMessageType, ProtectedOlmMessage, decode_protected_payload, encode_protected_payload,
    };
    use crate::CryptoError;

    fn to_hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;

        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            assert!(write!(output, "{byte:02x}").is_ok());
        }
        output
    }

    fn from_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = core::str::from_utf8(pair);
                let Ok(text) = text else {
                    panic!("test hex vector was not UTF-8");
                };
                let value = u8::from_str_radix(text, 16);
                let Ok(value) = value else {
                    panic!("test hex vector was malformed");
                };
                value
            })
            .collect()
    }

    fn first_message(plaintext: &[u8]) -> OlmMessage {
        let alice = Account::new();
        let mut bob = Account::new();
        bob.generate_one_time_keys(1);
        let key = bob.one_time_keys().values().next().copied();
        let Some(key) = key else {
            panic!("test one-time key was not generated");
        };
        let session =
            alice.create_outbound_session(SessionConfig::version_1(), bob.curve25519_key(), key);
        let Ok(mut session) = session else {
            panic!("test session could not be created");
        };
        let message = session.encrypt(plaintext);
        let Ok(message) = message else {
            panic!("test plaintext could not be encrypted");
        };
        message
    }

    #[test]
    fn pre_key_wrapper_has_a_fixed_vector_and_round_trips() {
        let message = first_message(b"wrapper vector");
        let protected = ProtectedOlmMessage::from_olm(&message);
        let Ok(protected) = protected else {
            panic!("Olm message could not enter the wrapper");
        };
        assert_eq!(protected.message_type(), OlmMessageType::PreKey);
        let encoded = encode_protected_payload(&protected);
        let Ok(encoded) = encoded else {
            panic!("Olm wrapper could not be encoded");
        };
        assert_eq!(decode_protected_payload(&encoded), Ok(protected));
    }

    #[test]
    fn pre_key_and_normal_wrapper_bytes_have_fixed_vectors() {
        let vectors = [
            "a3000101000258b8030a20a497c6104efdd5f6e03be88fcc1582c13b44f2bc2ac5cad461037e5b826bf1791220fab44d725266c999b65743f376a14ace3771e89515437993c890691eea2112001a203e416d6314421ee215879e710ad37dd566ae39b5ef4f6a4a26f87d029bfaeb3f224f030a206b2866960bfb65d0f72a389dd7a44067548b4fe219fb9cf56c81d7791300d43410002220a9624c769b2371d381ac50c76496074b2afa5363d826da3af00b70905c324310a123cc749bb409f3",
            "a30001010102584f030a2034f6a010dc80c19783ded28abff3e50ba70f317de15681753131f728297a7f64100022209e93ad01f446c701ce33de4b43c1a27e360ced1fe8ffe4829f95edac0bfddca7d6dcd8c8d2f6700b",
        ];
        for (index, vector) in vectors.iter().enumerate() {
            let bytes = from_hex(vector);
            let decoded = decode_protected_payload(&bytes);
            let Ok(decoded) = decoded else {
                panic!("fixed test wrapper was rejected");
            };
            assert_eq!(
                decoded.message_type().as_raw(),
                u8::try_from(index).unwrap_or(0)
            );
            let encoded = encode_protected_payload(&decoded);
            assert_eq!(encoded.as_deref(), Ok(bytes.as_slice()));
            assert_eq!(to_hex(&bytes), *vector);
        }
    }

    #[test]
    fn wrapper_rejects_all_truncated_prefixes_and_noncanonical_fields() {
        let message = first_message(b"truncation vector");
        let protected = ProtectedOlmMessage::from_olm(&message);
        let Ok(protected) = protected else {
            panic!("Olm message could not enter the wrapper");
        };
        let encoded = encode_protected_payload(&protected);
        let Ok(encoded) = encoded else {
            panic!("Olm wrapper could not be encoded");
        };
        for length in 0..encoded.len() {
            assert!(decode_protected_payload(&encoded[..length]).is_err());
        }
        let mut noncanonical = encoded;
        noncanonical.splice(1..2, [0x18, 0x00]);
        assert_eq!(
            decode_protected_payload(&noncanonical),
            Err(CryptoError::NonCanonical)
        );
    }

    #[test]
    fn maximum_inner_plaintext_stays_inside_the_payload_limit() {
        let message = first_message(&vec![0x41; 4155]);
        let protected = ProtectedOlmMessage::from_olm(&message);
        let Ok(protected) = protected else {
            panic!("maximum Olm message did not fit the wrapper");
        };
        let encoded = encode_protected_payload(&protected);
        let Ok(encoded) = encoded else {
            panic!("maximum protected payload did not fit its limit");
        };
        assert!(encoded.len() <= 8192);
        assert!(protected.message_bytes().len() <= 8183);
    }

    #[test]
    fn debug_output_does_not_include_ciphertext() {
        let marker = b"wrapper-debug-marker";
        let message = first_message(marker);
        let protected = ProtectedOlmMessage::from_olm(&message);
        let Ok(protected) = protected else {
            panic!("Olm message could not enter the wrapper");
        };
        let debug = format!("{protected:?}");
        assert!(!debug.contains("wrapper-debug-marker"));
        assert!(!debug.contains(&format!("{:?}", protected.message_bytes())));
    }
}
