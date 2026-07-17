// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use lantern_core::{
    MAX_ENVELOPE_SIZE, MESSAGE_ID_LENGTH, MessageId, decode_envelope, encode_envelope,
};
use lantern_transport::MAX_FRAME_BYTES;

use crate::{RouteGrant, SyncError, TransferredEnvelope};

pub const SYNC_PROTOCOL_VERSION: u8 = 1;
pub const MAX_OFFERED_IDS: usize = 32;

const HEADER_BYTES: usize = 4;
const TRANSFER_ROUTE_BYTES: usize = 6;
const TRANSFER_ID_END: usize = HEADER_BYTES + MESSAGE_ID_LENGTH;
const TRANSFER_HEADER_BYTES: usize = TRANSFER_ID_END + TRANSFER_ROUTE_BYTES;
pub const MAX_TRANSFER_ENVELOPE_BYTES: usize = MAX_FRAME_BYTES - TRANSFER_HEADER_BYTES;

const OFFER_TYPE: u8 = 1;
const REQUEST_TYPE: u8 = 2;
const TRANSFER_TYPE: u8 = 3;
const DONE_TYPE: u8 = 4;

#[derive(Eq, PartialEq)]
pub enum SyncFrame {
    Offer(Box<[MessageId]>),
    Request(Box<[MessageId]>),
    Transfer(TransferredEnvelope),
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

    pub fn transfer(item: TransferredEnvelope) -> Self {
        Self::Transfer(item)
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

    pub const fn transferred_envelope(&self) -> Option<&TransferredEnvelope> {
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

pub(crate) fn encode_transfer_envelope(item: &TransferredEnvelope) -> Result<Vec<u8>, SyncError> {
    let encoded_envelope =
        encode_envelope(item.envelope()).map_err(|_| SyncError::EnvelopeRejected)?;
    if encoded_envelope.len() > MAX_TRANSFER_ENVELOPE_BYTES {
        return Err(SyncError::FrameTooLarge);
    }
    let capacity = TRANSFER_HEADER_BYTES
        .checked_add(encoded_envelope.len())
        .ok_or(SyncError::FrameTooLarge)?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(&[SYNC_PROTOCOL_VERSION, TRANSFER_TYPE, 0, 0]);
    encoded.extend_from_slice(item.message_id().as_bytes());
    encoded.extend_from_slice(&item.route().remaining_ttl_seconds().to_be_bytes());
    encoded.push(item.route().hops_taken());
    encoded.push(item.route().copies_left());
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
    let id_bytes = <[u8; MESSAGE_ID_LENGTH]>::try_from(&input[HEADER_BYTES..TRANSFER_ID_END])
        .map_err(|_| SyncError::InvalidFrameLength)?;
    let expected_id = MessageId::from_bytes(id_bytes);
    let remaining_ttl_seconds = u32::from_be_bytes([
        input[TRANSFER_ID_END],
        input[TRANSFER_ID_END + 1],
        input[TRANSFER_ID_END + 2],
        input[TRANSFER_ID_END + 3],
    ]);
    let hops_taken = input[TRANSFER_ID_END + 4];
    let copies_left = input[TRANSFER_ID_END + 5];
    let route = RouteGrant::try_new(remaining_ttl_seconds, hops_taken, copies_left)?;
    let envelope = decode_envelope(&input[TRANSFER_HEADER_BYTES..])
        .map_err(|_| SyncError::EnvelopeRejected)?;
    if envelope.message_id() != expected_id {
        return Err(SyncError::EnvelopeIdentifierMismatch);
    }
    let item = TransferredEnvelope::try_new(envelope, route)?;
    Ok(SyncFrame::Transfer(item))
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

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_core::{Envelope, MAX_PROTECTED_PAYLOAD_SIZE, NORMAL_PRIORITY, PROTOCOL_VERSION};

    fn envelope(id: u8) -> Envelope {
        match Envelope::try_from_fields(
            PROTOCOL_VERSION,
            [id; MESSAGE_ID_LENGTH],
            [0x22; 16],
            300,
            4,
            NORMAL_PRIORITY,
            b"SYNTHETIC SYNC PAYLOAD".to_vec(),
        ) {
            Ok(envelope) => envelope,
            Err(_) => panic!("sync test Envelope should be valid"),
        }
    }

    fn transferred(id: u8) -> TransferredEnvelope {
        let route = RouteGrant::try_new(300, 1, 16)
            .unwrap_or_else(|_| panic!("sync test route should be valid"));
        TransferredEnvelope::try_new(envelope(id), route)
            .unwrap_or_else(|_| panic!("sync test transfer should be valid"))
    }

    #[test]
    fn all_frame_types_have_fixed_vectors_or_canonical_round_trips() {
        let offer = SyncFrame::offer(vec![MessageId::from_bytes([0x11; 16])]);
        let Ok(offer) = offer else {
            panic!("one identifier should form an offer");
        };
        let encoded = encode_sync_frame(&offer);
        let Ok(encoded) = encoded else {
            panic!("offer should encode");
        };
        let mut expected = vec![1, 1, 0, 1];
        expected.extend_from_slice(&[0x11; 16]);
        assert_eq!(encoded, expected);

        assert_eq!(
            encode_sync_frame(
                &SyncFrame::request(Vec::new())
                    .unwrap_or_else(|_| panic!("empty request should be valid"))
            ),
            Ok(vec![1, 2, 0, 0])
        );
        assert_eq!(encode_sync_frame(&SyncFrame::Done), Ok(vec![1, 4, 0, 0]));

        let transfer = SyncFrame::transfer(transferred(0x31));
        let encoded = encode_sync_frame(&transfer);
        let Ok(encoded) = encoded else {
            panic!("transfer should encode");
        };
        assert_eq!(
            &encoded[TRANSFER_ID_END..TRANSFER_HEADER_BYTES],
            &[0, 0, 1, 44, 1, 16]
        );
        let decoded = decode_sync_frame(&encoded);
        let Ok(SyncFrame::Transfer(decoded)) = decoded else {
            panic!("transfer should decode");
        };
        assert_eq!(decoded, transferred(0x31));
    }

    #[test]
    fn identifiers_must_be_sorted_unique_and_bounded() {
        let duplicate = vec![MessageId::from_bytes([0x11; 16]); 2];
        assert!(matches!(
            SyncFrame::offer(duplicate),
            Err(SyncError::IdentifiersNotCanonical)
        ));
        let descending = vec![
            MessageId::from_bytes([0x22; 16]),
            MessageId::from_bytes([0x11; 16]),
        ];
        assert!(matches!(
            SyncFrame::request(descending),
            Err(SyncError::IdentifiersNotCanonical)
        ));
        let excessive = vec![MessageId::from_bytes([0x11; 16]); MAX_OFFERED_IDS + 1];
        assert!(matches!(
            SyncFrame::offer(excessive),
            Err(SyncError::InvalidIdentifierCount)
        ));
    }

    #[test]
    fn malformed_lengths_versions_types_and_transfer_ids_are_rejected() {
        assert_eq!(decode_sync_frame(&[]), Err(SyncError::FrameTooSmall));
        assert_eq!(
            decode_sync_frame(&[2, 4, 0, 0]),
            Err(SyncError::UnsupportedVersion)
        );
        assert_eq!(
            decode_sync_frame(&[1, 9, 0, 0]),
            Err(SyncError::UnsupportedFrameType)
        );
        assert_eq!(
            decode_sync_frame(&[1, 1, 0, 1]),
            Err(SyncError::InvalidFrameLength)
        );
        assert_eq!(
            decode_sync_frame(&[1, 4, 0, 1]),
            Err(SyncError::InvalidFrameLength)
        );

        let transfer = SyncFrame::transfer(transferred(0x41));
        let encoded = encode_sync_frame(&transfer);
        let Ok(mut encoded) = encoded else {
            panic!("transfer should encode");
        };
        encoded[HEADER_BYTES] ^= 1;
        assert_eq!(
            decode_sync_frame(&encoded),
            Err(SyncError::EnvelopeIdentifierMismatch)
        );
    }

    #[test]
    fn debug_output_contains_no_identifiers_or_envelope_bytes() {
        let marker = "85, 85, 85";
        let offer = SyncFrame::offer(vec![MessageId::from_bytes([0x55; 16])]);
        let Ok(offer) = offer else {
            panic!("one identifier should form an offer");
        };
        assert!(!format!("{offer:?}").contains(marker));
        assert!(!format!("{:?}", SyncFrame::transfer(transferred(0x55))).contains("SYNTHETIC"));
    }

    #[test]
    fn every_truncated_canonical_frame_is_rejected() {
        let frames = [
            encode_sync_frame(
                &SyncFrame::offer(vec![MessageId::from_bytes([0x11; MESSAGE_ID_LENGTH])])
                    .unwrap_or_else(|_| panic!("offer fixture should be valid")),
            )
            .unwrap_or_else(|_| panic!("offer fixture should encode")),
            encode_sync_frame(&SyncFrame::transfer(transferred(0x21)))
                .unwrap_or_else(|_| panic!("transfer fixture should encode")),
            encode_sync_frame(&SyncFrame::done())
                .unwrap_or_else(|_| panic!("done fixture should encode")),
        ];

        for frame in frames {
            for truncated_length in 0..frame.len() {
                assert!(decode_sync_frame(&frame[..truncated_length]).is_err());
            }
        }
    }

    #[test]
    fn exact_batch_and_payload_limits_fit_one_transport_frame() {
        let identifiers = (0_u8..32)
            .map(|value| MessageId::from_bytes([value; MESSAGE_ID_LENGTH]))
            .collect::<Vec<_>>();
        assert_eq!(identifiers.len(), MAX_OFFERED_IDS);
        let offer = SyncFrame::offer(identifiers)
            .unwrap_or_else(|_| panic!("maximum offer should be valid"));
        let encoded_offer =
            encode_sync_frame(&offer).unwrap_or_else(|_| panic!("maximum offer should encode"));
        assert_eq!(
            encoded_offer.len(),
            HEADER_BYTES + MAX_OFFERED_IDS * MESSAGE_ID_LENGTH
        );

        let maximum = Envelope::try_from_fields(
            PROTOCOL_VERSION,
            [0x71; MESSAGE_ID_LENGTH],
            [0x72; 16],
            300,
            4,
            NORMAL_PRIORITY,
            vec![0x73; MAX_PROTECTED_PAYLOAD_SIZE],
        )
        .unwrap_or_else(|_| panic!("maximum Envelope should be valid"));
        let maximum = TransferredEnvelope::try_new(
            maximum,
            RouteGrant::try_new(300, 1, 16)
                .unwrap_or_else(|_| panic!("maximum transfer route should be valid")),
        )
        .unwrap_or_else(|_| panic!("maximum transfer should be valid"));
        let encoded_transfer = encode_sync_frame(&SyncFrame::transfer(maximum))
            .unwrap_or_else(|_| panic!("maximum transfer should encode"));
        assert!(encoded_transfer.len() <= MAX_FRAME_BYTES);
    }

    #[test]
    fn invalid_route_grant_bytes_are_rejected_before_envelope_use() {
        let encoded = encode_sync_frame(&SyncFrame::transfer(transferred(0x61)))
            .unwrap_or_else(|_| panic!("transfer fixture should encode"));
        let route_start = HEADER_BYTES + MESSAGE_ID_LENGTH;

        let mut zero_ttl = encoded.clone();
        zero_ttl[route_start..route_start + 4].fill(0);
        assert_eq!(
            decode_sync_frame(&zero_ttl),
            Err(SyncError::InvalidRouteGrant)
        );

        let mut zero_hops = encoded.clone();
        zero_hops[route_start + 4] = 0;
        assert_eq!(
            decode_sync_frame(&zero_hops),
            Err(SyncError::InvalidRouteGrant)
        );

        let mut zero_copies = encoded;
        zero_copies[route_start + 5] = 0;
        assert_eq!(
            decode_sync_frame(&zero_copies),
            Err(SyncError::InvalidRouteGrant)
        );
    }
}
