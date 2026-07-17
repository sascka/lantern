// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use lantern_core::CborError;
use lantern_crypto::CryptoError;
use lantern_node::NodeError;
use lantern_secret_storage::SecretStorageError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeError {
    Cbor(CborError),
    Crypto(CryptoError),
    Node(NodeError),
    SecretStorage(SecretStorageError),
    OutboxIdentifierMismatch,
    QueueConflict,
    OutboxAcknowledgementLost,
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => write!(formatter, "stored Envelope is invalid: {error}"),
            Self::Crypto(error) => write!(formatter, "cryptographic processing failed: {error}"),
            Self::Node(error) => write!(formatter, "node operation failed: {error}"),
            Self::SecretStorage(error) => {
                write!(formatter, "secret storage operation failed: {error}")
            }
            Self::OutboxIdentifierMismatch => {
                formatter.write_str("outbox identifier does not match its Envelope")
            }
            Self::QueueConflict => {
                formatter.write_str("queue contains a different Envelope with the same identifier")
            }
            Self::OutboxAcknowledgementLost => {
                formatter.write_str("exported outbox item could not be acknowledged")
            }
        }
    }
}

impl std::error::Error for BridgeError {}

impl From<CborError> for BridgeError {
    fn from(error: CborError) -> Self {
        Self::Cbor(error)
    }
}

impl From<CryptoError> for BridgeError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<NodeError> for BridgeError {
    fn from(error: NodeError) -> Self {
        Self::Node(error)
    }
}

impl From<SecretStorageError> for BridgeError {
    fn from(error: SecretStorageError) -> Self {
        Self::SecretStorage(error)
    }
}
