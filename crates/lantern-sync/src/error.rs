// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use lantern_transport::SessionError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncSinkError {
    Unavailable,
    Rejected,
    ResourceExhausted,
}

impl fmt::Display for SyncSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("Envelope sink is unavailable"),
            Self::Rejected => formatter.write_str("Envelope sink rejected the item"),
            Self::ResourceExhausted => {
                formatter.write_str("Envelope sink reached a resource limit")
            }
        }
    }
}

impl std::error::Error for SyncSinkError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncError {
    FrameTooSmall,
    FrameTooLarge,
    UnsupportedVersion,
    UnsupportedFrameType,
    InvalidFrameLength,
    InvalidIdentifierCount,
    IdentifiersNotCanonical,
    EnvelopeRejected,
    EnvelopeIdentifierMismatch,
    InvalidRouteGrant,
    TooManyOfferedEnvelopes,
    DuplicateOfferedEnvelope,
    UnexpectedFrame,
    RequestNotOffered,
    TransferNotRequested,
    Transport(SessionError),
    Sink(SyncSinkError),
}

impl fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooSmall => formatter.write_str("sync frame is too small"),
            Self::FrameTooLarge => formatter.write_str("sync frame exceeds the size limit"),
            Self::UnsupportedVersion => formatter.write_str("unsupported sync protocol version"),
            Self::UnsupportedFrameType => formatter.write_str("unsupported sync frame type"),
            Self::InvalidFrameLength => formatter.write_str("invalid sync frame length"),
            Self::InvalidIdentifierCount => formatter.write_str("invalid sync identifier count"),
            Self::IdentifiersNotCanonical => {
                formatter.write_str("sync identifiers are not canonical")
            }
            Self::EnvelopeRejected => formatter.write_str("transferred Envelope was rejected"),
            Self::EnvelopeIdentifierMismatch => {
                formatter.write_str("transferred Envelope identifier does not match")
            }
            Self::InvalidRouteGrant => formatter.write_str("invalid sync route grant"),
            Self::TooManyOfferedEnvelopes => {
                formatter.write_str("sync offer exceeds the batch limit")
            }
            Self::DuplicateOfferedEnvelope => {
                formatter.write_str("sync offer contains a duplicate")
            }
            Self::UnexpectedFrame => {
                formatter.write_str("unexpected sync frame for the current state")
            }
            Self::RequestNotOffered => formatter.write_str("sync request was not offered"),
            Self::TransferNotRequested => {
                formatter.write_str("Envelope transfer was not requested")
            }
            Self::Transport(_) => formatter.write_str("sync transport operation failed"),
            Self::Sink(_) => formatter.write_str("sync Envelope sink failed"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<SessionError> for SyncError {
    fn from(error: SessionError) -> Self {
        Self::Transport(error)
    }
}

impl From<SyncSinkError> for SyncError {
    fn from(error: SyncSinkError) -> Self {
        Self::Sink(error)
    }
}
