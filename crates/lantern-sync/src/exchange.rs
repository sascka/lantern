// SPDX-License-Identifier: MPL-2.0

use lantern_core::{Envelope, MessageId};
use lantern_transport::{BoundedSession, FrameTransport, MAX_FRAME_BYTES};

use crate::frame::encode_transfer_envelope;
use crate::{
    MAX_OFFERED_IDS, SyncError, SyncFrame, SyncSinkError, decode_sync_frame, encode_sync_frame,
};

pub trait EnvelopeSink {
    fn wants(&mut self, message_id: MessageId) -> Result<bool, SyncSinkError>;
    fn accept(&mut self, envelope: Envelope) -> Result<(), SyncSinkError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncSummary {
    offered: u8,
    requested: u8,
    transferred: u8,
}

impl SyncSummary {
    pub const fn offered(self) -> u8 {
        self.offered
    }

    pub const fn requested(self) -> u8 {
        self.requested
    }

    pub const fn transferred(self) -> u8 {
        self.transferred
    }
}

pub fn send_batch<T: FrameTransport>(
    mut session: BoundedSession<T>,
    offered: &[Envelope],
) -> Result<(BoundedSession<T>, SyncSummary), SyncError> {
    let sorted = sorted_offers(offered)?;
    let identifiers = sorted
        .iter()
        .map(|envelope| envelope.message_id())
        .collect::<Vec<_>>();
    send_frame(&mut session, &SyncFrame::offer(identifiers)?)?;

    let request = receive_frame(&mut session)?;
    let SyncFrame::Request(requested) = request else {
        return Err(SyncError::UnexpectedFrame);
    };
    for requested_id in &requested {
        let envelope = sorted
            .iter()
            .find(|envelope| envelope.message_id() == *requested_id)
            .ok_or(SyncError::RequestNotOffered)?;
        let encoded = encode_transfer_envelope(envelope)?;
        session.send_frame(&encoded)?;
    }
    send_frame(&mut session, &SyncFrame::done())?;

    Ok((
        session,
        SyncSummary {
            offered: count_u8(sorted.len())?,
            requested: count_u8(requested.len())?,
            transferred: count_u8(requested.len())?,
        },
    ))
}

pub fn receive_batch<T: FrameTransport, S: EnvelopeSink>(
    mut session: BoundedSession<T>,
    sink: &mut S,
) -> Result<(BoundedSession<T>, SyncSummary), SyncError> {
    let offer = receive_frame(&mut session)?;
    let SyncFrame::Offer(offered) = offer else {
        return Err(SyncError::UnexpectedFrame);
    };

    let mut requested = Vec::with_capacity(offered.len());
    for identifier in &offered {
        if sink.wants(*identifier)? {
            requested.push(*identifier);
        }
    }
    send_frame(&mut session, &SyncFrame::request(requested.clone())?)?;

    for expected_id in &requested {
        let transfer = receive_frame(&mut session)?;
        let SyncFrame::Transfer(envelope) = transfer else {
            return Err(SyncError::UnexpectedFrame);
        };
        if envelope.message_id() != *expected_id {
            return Err(SyncError::TransferNotRequested);
        }
        sink.accept(envelope)?;
    }

    if !matches!(receive_frame(&mut session)?, SyncFrame::Done) {
        return Err(SyncError::UnexpectedFrame);
    }

    Ok((
        session,
        SyncSummary {
            offered: count_u8(offered.len())?,
            requested: count_u8(requested.len())?,
            transferred: count_u8(requested.len())?,
        },
    ))
}

fn send_frame<T: FrameTransport>(
    session: &mut BoundedSession<T>,
    frame: &SyncFrame,
) -> Result<(), SyncError> {
    let encoded = encode_sync_frame(frame)?;
    session.send_frame(&encoded)?;
    Ok(())
}

fn receive_frame<T: FrameTransport>(
    session: &mut BoundedSession<T>,
) -> Result<SyncFrame, SyncError> {
    let mut buffer = [0_u8; MAX_FRAME_BYTES];
    let frame = session
        .receive_frame(&mut buffer)?
        .ok_or(SyncError::UnexpectedFrame)?;
    decode_sync_frame(frame)
}

fn sorted_offers(offered: &[Envelope]) -> Result<Vec<&Envelope>, SyncError> {
    if offered.len() > MAX_OFFERED_IDS {
        return Err(SyncError::TooManyOfferedEnvelopes);
    }
    let mut sorted = offered.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|envelope| envelope.message_id());
    if sorted
        .windows(2)
        .any(|pair| pair[0].message_id() == pair[1].message_id())
    {
        return Err(SyncError::DuplicateOfferedEnvelope);
    }
    Ok(sorted)
}

fn count_u8(count: usize) -> Result<u8, SyncError> {
    u8::try_from(count).map_err(|_| SyncError::InvalidIdentifierCount)
}

