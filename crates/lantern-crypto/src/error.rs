// SPDX-License-Identifier: MPL-2.0

use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    EmptyInput,
    InputTooLarge,
    Malformed,
    NonCanonical,
    UnsupportedVersion,
    UnsupportedType,
    WrongLength,
    InvalidValue,
    EnvelopeMismatch,
    OlmRejected,
    SignatureRejected,
    Entropy,
    StateRejected,
    RateLimited,
    StorageFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => formatter.write_str("cryptographic input is empty"),
            Self::InputTooLarge => formatter.write_str("cryptographic input exceeds its limit"),
            Self::Malformed => formatter.write_str("cryptographic input is malformed"),
            Self::NonCanonical => formatter.write_str("cryptographic input is not canonical"),
            Self::UnsupportedVersion => formatter.write_str("cryptographic version is unsupported"),
            Self::UnsupportedType => {
                formatter.write_str("cryptographic message type is unsupported")
            }
            Self::WrongLength => formatter.write_str("cryptographic field has the wrong length"),
            Self::InvalidValue => formatter.write_str("cryptographic field is invalid"),
            Self::EnvelopeMismatch => {
                formatter.write_str("protected and envelope fields do not match")
            }
            Self::OlmRejected => formatter.write_str("encrypted message was rejected"),
            Self::SignatureRejected => formatter.write_str("contact signature was rejected"),
            Self::Entropy => formatter.write_str("operating system entropy is unavailable"),
            Self::StateRejected => {
                formatter.write_str("cryptographic state does not allow this operation")
            }
            Self::RateLimited => {
                formatter.write_str("cryptographic processing is temporarily limited")
            }
            Self::StorageFailed => formatter.write_str("cryptographic state could not be stored"),
        }
    }
}

impl std::error::Error for CryptoError {}
