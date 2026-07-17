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

