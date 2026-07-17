// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use lantern_core::{
    Envelope, MAX_ENVELOPE_SIZE, MESSAGE_ID_LENGTH, MessageId, decode_envelope, encode_envelope,
};
use lantern_transport::MAX_FRAME_BYTES;

use crate::SyncError;

pub const SYNC_PROTOCOL_VERSION: u8 = 1;
pub const MAX_OFFERED_IDS: usize = 32;

const HEADER_BYTES: usize = 4;
const TRANSFER_HEADER_BYTES: usize = HEADER_BYTES + MESSAGE_ID_LENGTH;
pub const MAX_TRANSFER_ENVELOPE_BYTES: usize = MAX_FRAME_BYTES - TRANSFER_HEADER_BYTES;

const OFFER_TYPE: u8 = 1;
const REQUEST_TYPE: u8 = 2;
const TRANSFER_TYPE: u8 = 3;
const DONE_TYPE: u8 = 4;

#[derive(Eq, PartialEq)]
pub enum SyncFrame {
    Offer(Box<[MessageId]>),
    Request(Box<[MessageId]>),
    Transfer(Envelope),
    Done,
}

impl SyncFrame {
    pub fn offer(identifiers: Vec<MessageId>) -> Result<Self, SyncError> {
        validate_identifiers(&identifiers)?;
        Ok(Self::Offer(identifiers.into_boxed_slice()))
    }

    pub fn request(identifiers: Vec<MessageId>) -> Result<Self, SyncError> {
        validate_identifiers(&identifiers)?;
        Ok(Self::Request(identifiers.into_boxed_slice()))
    }

    pub fn transfer(envelope: Envelope) -> Self {
        Self::Transfer(envelope)
    }

    pub const fn done() -> Self {
        Self::Done
    }

    pub fn identifiers(&self) -> Option<&[MessageId]> {
        match self {
            Self::Offer(identifiers) | Self::Request(identifiers) => Some(identifiers),
            Self::Transfer(_) | Self::Done => None,
        }
    }

    pub const fn transferred_envelope(&self) -> Option<&Envelope> {
        match self {
            Self::Transfer(envelope) => Some(envelope),
            Self::Offer(_) | Self::Request(_) | Self::Done => None,
        }
    }
}

impl fmt::Debug for SyncFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offer(identifiers) => formatter
                .debug_struct("Offer")
                .field("identifier_count", &identifiers.len())
                .finish(),
            Self::Request(identifiers) => formatter
                .debug_struct("Request")
                .field("identifier_count", &identifiers.len())
                .finish(),
            Self::Transfer(_) => formatter.debug_struct("Transfer").finish_non_exhaustive(),
            Self::Done => formatter.debug_struct("Done").finish(),
        }
    }
}

pub fn encode_sync_frame(frame: &SyncFrame) -> Result<Vec<u8>, SyncError> {
    match frame {
        SyncFrame::Offer(identifiers) => encode_identifiers(OFFER_TYPE, identifiers),
        SyncFrame::Request(identifiers) => encode_identifiers(REQUEST_TYPE, identifiers),
        SyncFrame::Transfer(envelope) => encode_transfer_envelope(envelope),
        SyncFrame::Done => Ok(vec![SYNC_PROTOCOL_VERSION, DONE_TYPE, 0, 0]),
    }
}

pub fn decode_sync_frame(input: &[u8]) -> Result<SyncFrame, SyncError> {
    if input.len() < HEADER_BYTES {
        return Err(SyncError::FrameTooSmall);
    }
    if input.len() > MAX_FRAME_BYTES {
        return Err(SyncError::FrameTooLarge);
    }
    if input[0] != SYNC_PROTOCOL_VERSION {
        return Err(SyncError::UnsupportedVersion);
    }
    match input[1] {
        OFFER_TYPE => decode_identifiers(input, true),
        REQUEST_TYPE => decode_identifiers(input, false),
        TRANSFER_TYPE => decode_transfer(input),
        DONE_TYPE => {
            if input.len() != HEADER_BYTES || input[2] != 0 || input[3] != 0 {
                return Err(SyncError::InvalidFrameLength);
            }
            Ok(SyncFrame::Done)
        }
        _ => Err(SyncError::UnsupportedFrameType),
    }
}

fn encode_identifiers(frame_type: u8, identifiers: &[MessageId]) -> Result<Vec<u8>, SyncError> {
    validate_identifiers(identifiers)?;
    let count = u16::try_from(identifiers.len()).map_err(|_| SyncError::InvalidIdentifierCount)?;
    let body_bytes = identifiers
        .len()
        .checked_mul(MESSAGE_ID_LENGTH)
        .and_then(|bytes| bytes.checked_add(HEADER_BYTES))
        .ok_or(SyncError::FrameTooLarge)?;
    let mut encoded = Vec::with_capacity(body_bytes);
    encoded.push(SYNC_PROTOCOL_VERSION);
    encoded.push(frame_type);
    encoded.extend_from_slice(&count.to_be_bytes());
    for identifier in identifiers {
        encoded.extend_from_slice(identifier.as_bytes());
    }
    Ok(encoded)
}

fn decode_identifiers(input: &[u8], offer: bool) -> Result<SyncFrame, SyncError> {
    let count = usize::from(u16::from_be_bytes([input[2], input[3]]));
    if count > MAX_OFFERED_IDS {
        return Err(SyncError::InvalidIdentifierCount);
    }
    let expected = count
        .checked_mul(MESSAGE_ID_LENGTH)
        .and_then(|bytes| bytes.checked_add(HEADER_BYTES))
        .ok_or(SyncError::FrameTooLarge)?;
    if input.len() != expected {
        return Err(SyncError::InvalidFrameLength);
    }
    let mut identifiers = Vec::with_capacity(count);
    for bytes in input[HEADER_BYTES..].chunks_exact(MESSAGE_ID_LENGTH) {
        let array = <[u8; MESSAGE_ID_LENGTH]>::try_from(bytes)
            .map_err(|_| SyncError::InvalidFrameLength)?;
        identifiers.push(MessageId::from_bytes(array));
    }
    validate_identifiers(&identifiers)?;
    if offer {
        Ok(SyncFrame::Offer(identifiers.into_boxed_slice()))
    } else {
        Ok(SyncFrame::Request(identifiers.into_boxed_slice()))
    }
}

pub(crate) fn encode_transfer_envelope(envelope: &Envelope) -> Result<Vec<u8>, SyncError> {
    let encoded_envelope = encode_envelope(envelope).map_err(|_| SyncError::EnvelopeRejected)?;
    if encoded_envelope.len() > MAX_TRANSFER_ENVELOPE_BYTES {
        return Err(SyncError::FrameTooLarge);
    }
    let capacity = TRANSFER_HEADER_BYTES
        .checked_add(encoded_envelope.len())
        .ok_or(SyncError::FrameTooLarge)?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(&[SYNC_PROTOCOL_VERSION, TRANSFER_TYPE, 0, 0]);
    encoded.extend_from_slice(envelope.message_id().as_bytes());
    encoded.extend_from_slice(&encoded_envelope);
    Ok(encoded)
}

fn decode_transfer(input: &[u8]) -> Result<SyncFrame, SyncError> {
    if input[2] != 0 || input[3] != 0 || input.len() <= TRANSFER_HEADER_BYTES {
        return Err(SyncError::InvalidFrameLength);
    }
    if input.len() - TRANSFER_HEADER_BYTES > MAX_ENVELOPE_SIZE {
        return Err(SyncError::FrameTooLarge);
    }
    let id_bytes = <[u8; MESSAGE_ID_LENGTH]>::try_from(&input[HEADER_BYTES..TRANSFER_HEADER_BYTES])
        .map_err(|_| SyncError::InvalidFrameLength)?;
    let expected_id = MessageId::from_bytes(id_bytes);
    let envelope = decode_envelope(&input[TRANSFER_HEADER_BYTES..])
        .map_err(|_| SyncError::EnvelopeRejected)?;
    if envelope.message_id() != expected_id {
        return Err(SyncError::EnvelopeIdentifierMismatch);
    }
    Ok(SyncFrame::Transfer(envelope))
}

fn validate_identifiers(identifiers: &[MessageId]) -> Result<(), SyncError> {
    if identifiers.len() > MAX_OFFERED_IDS {
        return Err(SyncError::InvalidIdentifierCount);
    }
    if identifiers.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SyncError::IdentifiersNotCanonical);
    }
    Ok(())
}

