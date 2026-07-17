// SPDX-License-Identifier: MPL-2.0

use lantern_core::MessageId;
use lantern_transport::{BoundedSession, FrameTransport, MAX_FRAME_BYTES};

use crate::frame::encode_transfer_envelope;
use crate::{
    MAX_OFFERED_IDS, SyncError, SyncFrame, SyncSinkError, SyncSourceError, TransferredEnvelope,
    decode_sync_frame, encode_sync_frame,
};

pub trait EnvelopeSink {
    fn wants(&mut self, message_id: MessageId) -> Result<bool, SyncSinkError>;
    fn accept(&mut self, item: TransferredEnvelope) -> Result<(), SyncSinkError>;
}

pub trait EnvelopeSource {
    fn prepare_transfer(
        &mut self,
        message_id: MessageId,
    ) -> Result<TransferredEnvelope, SyncSourceError>;
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
    offered: &[TransferredEnvelope],
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
        let item = sorted
            .iter()
            .find(|item| item.message_id() == *requested_id)
            .ok_or(SyncError::RequestNotOffered)?;
        let encoded = encode_transfer_envelope(item)?;
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

pub fn send_batch_from_source<T: FrameTransport, S: EnvelopeSource>(
    mut session: BoundedSession<T>,
    offered: &[MessageId],
    source: &mut S,
) -> Result<(BoundedSession<T>, SyncSummary), SyncError> {
    send_frame(&mut session, &SyncFrame::offer(offered.to_vec())?)?;

    let request = receive_frame(&mut session)?;
    let SyncFrame::Request(requested) = request else {
        return Err(SyncError::UnexpectedFrame);
    };
    for requested_id in &requested {
        if offered.binary_search(requested_id).is_err() {
            return Err(SyncError::RequestNotOffered);
        }
        let item = source.prepare_transfer(*requested_id)?;
        if item.message_id() != *requested_id {
            return Err(SyncError::SourceIdentifierMismatch);
        }
        let encoded = encode_transfer_envelope(&item)?;
        session.send_frame(&encoded)?;
    }
    send_frame(&mut session, &SyncFrame::done())?;

    Ok((
        session,
        SyncSummary {
            offered: count_u8(offered.len())?,
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
        let SyncFrame::Transfer(item) = transfer else {
            return Err(SyncError::UnexpectedFrame);
        };
        if item.message_id() != *expected_id {
            return Err(SyncError::TransferNotRequested);
        }
        sink.accept(item)?;
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

fn sorted_offers(offered: &[TransferredEnvelope]) -> Result<Vec<&TransferredEnvelope>, SyncError> {
    if offered.len() > MAX_OFFERED_IDS {
        return Err(SyncError::TooManyOfferedEnvelopes);
    }
    let mut sorted = offered.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|item| item.message_id());
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use lantern_core::{Envelope, MESSAGE_ID_LENGTH, NORMAL_PRIORITY, PROTOCOL_VERSION};
    use lantern_transport::{FrameReceive, SessionLimits, TransportFailureKind};

    use super::*;

    #[derive(Default)]
    struct MemoryTransport {
        incoming: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl FrameTransport for MemoryTransport {
        fn receive_frame(
            &mut self,
            destination: &mut [u8],
        ) -> Result<FrameReceive, TransportFailureKind> {
            let Some(frame) = self.incoming.pop_front() else {
                return Ok(FrameReceive::ConnectionClosed);
            };
            if frame.len() > destination.len() {
                return Err(TransportFailureKind::ResourceExhausted);
            }
            destination[..frame.len()].copy_from_slice(&frame);
            Ok(FrameReceive::Complete(frame.len()))
        }

        fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportFailureKind> {
            self.sent.push(frame.to_vec());
            Ok(())
        }
    }

    fn envelope(id: u8) -> Envelope {
        match Envelope::try_from_fields(
            PROTOCOL_VERSION,
            [id; MESSAGE_ID_LENGTH],
            [0x33; 16],
            300,
            4,
            NORMAL_PRIORITY,
            b"SYNTHETIC EXCHANGE PAYLOAD".to_vec(),
        ) {
            Ok(envelope) => envelope,
            Err(_) => panic!("exchange test Envelope should be valid"),
        }
    }

    fn transferred(id: u8) -> TransferredEnvelope {
        let route = crate::RouteGrant::try_new(300, 1, 16)
            .unwrap_or_else(|_| panic!("exchange route fixture should be valid"));
        TransferredEnvelope::try_new(envelope(id), route)
            .unwrap_or_else(|_| panic!("exchange transfer fixture should be valid"))
    }

    fn encoded(frame: &SyncFrame) -> Vec<u8> {
        encode_sync_frame(frame).unwrap_or_else(|_| panic!("sync frame fixture should encode"))
    }

    #[derive(Default)]
    struct TestSink {
        known: Vec<MessageId>,
        accepted: Vec<TransferredEnvelope>,
    }

    impl EnvelopeSink for TestSink {
        fn wants(&mut self, message_id: MessageId) -> Result<bool, SyncSinkError> {
            Ok(!self.known.contains(&message_id))
        }

        fn accept(&mut self, item: TransferredEnvelope) -> Result<(), SyncSinkError> {
            self.accepted.push(item);
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestSource {
        items: Vec<TransferredEnvelope>,
        prepared: Vec<MessageId>,
    }

    impl EnvelopeSource for TestSource {
        fn prepare_transfer(
            &mut self,
            message_id: MessageId,
        ) -> Result<TransferredEnvelope, SyncSourceError> {
            self.prepared.push(message_id);
            self.items
                .iter()
                .find(|item| item.message_id() == message_id)
                .cloned()
                .ok_or(SyncSourceError::Rejected)
        }
    }

    #[test]
    fn sender_rejects_unoffered_request_and_consumes_the_session() {
        let request = SyncFrame::request(vec![MessageId::from_bytes([0x77; 16])]);
        let Ok(request) = request else {
            panic!("request fixture should be valid");
        };
        let encoded = encode_sync_frame(&request);
        let Ok(encoded) = encoded else {
            panic!("request fixture should encode");
        };
        let transport = MemoryTransport {
            incoming: VecDeque::from([encoded]),
            sent: Vec::new(),
        };
        let session = BoundedSession::new(transport, SessionLimits::default());
        assert!(matches!(
            send_batch(session, &[transferred(0x11)]),
            Err(SyncError::RequestNotOffered)
        ));
    }

    #[test]
    fn sender_canonicalizes_offer_and_follows_request_order() {
        let first = transferred(0x11);
        let second = transferred(0x22);
        let request = SyncFrame::request(vec![second.message_id()])
            .unwrap_or_else(|_| panic!("request fixture should be valid"));
        let transport = MemoryTransport {
            incoming: VecDeque::from([encoded(&request)]),
            sent: Vec::new(),
        };
        let session = BoundedSession::new(transport, SessionLimits::default());

        let (session, summary) = send_batch(session, &[second.clone(), first.clone()])
            .unwrap_or_else(|_| panic!("sender batch should complete"));
        let sent = session.into_inner().sent;
        let offer = SyncFrame::offer(vec![first.message_id(), second.message_id()])
            .unwrap_or_else(|_| panic!("offer fixture should be valid"));

        assert_eq!(summary.offered(), 2);
        assert_eq!(summary.requested(), 1);
        assert_eq!(summary.transferred(), 1);
        assert_eq!(sent[0], encoded(&offer));
        assert_eq!(decode_sync_frame(&sent[1]), Ok(SyncFrame::transfer(second)));
        assert_eq!(sent[2], encoded(&SyncFrame::done()));
    }

    #[test]
    fn source_prepares_only_identifiers_requested_by_receiver() {
        let first = transferred(0x11);
        let second = transferred(0x22);
        let offered = [first.message_id(), second.message_id()];
        let request = SyncFrame::request(vec![second.message_id()])
            .unwrap_or_else(|_| panic!("request fixture should be valid"));
        let transport = MemoryTransport {
            incoming: VecDeque::from([encoded(&request)]),
            sent: Vec::new(),
        };
        let session = BoundedSession::new(transport, SessionLimits::default());
        let mut source = TestSource {
            items: vec![first, second.clone()],
            prepared: Vec::new(),
        };

        let (session, summary) = send_batch_from_source(session, &offered, &mut source)
            .unwrap_or_else(|_| panic!("source batch should complete"));

        assert_eq!(source.prepared, [second.message_id()]);
        assert_eq!(summary.offered(), 2);
        assert_eq!(summary.transferred(), 1);
        let sent = session.into_inner().sent;
        assert_eq!(sent.len(), 3);
        assert_eq!(decode_sync_frame(&sent[1]), Ok(SyncFrame::transfer(second)));
    }

    #[test]
    fn source_rejection_stops_before_transfer_send() {
        let offered = [MessageId::from_bytes([0x11; MESSAGE_ID_LENGTH])];
        let request = SyncFrame::request(offered.to_vec())
            .unwrap_or_else(|_| panic!("request fixture should be valid"));
        let transport = MemoryTransport {
            incoming: VecDeque::from([encoded(&request)]),
            sent: Vec::new(),
        };
        let session = BoundedSession::new(transport, SessionLimits::default());
        let mut source = TestSource {
            items: vec![transferred(0x22)],
            prepared: Vec::new(),
        };

        assert_eq!(
            send_batch_from_source(session, &offered, &mut source).map(|_| ()),
            Err(SyncError::Source(SyncSourceError::Rejected))
        );
    }

    #[test]
    fn duplicate_local_offer_is_rejected_before_transport_use() {
        let session = BoundedSession::new(MemoryTransport::default(), SessionLimits::default());
        assert!(matches!(
            send_batch(session, &[transferred(0x11), transferred(0x11)]),
            Err(SyncError::DuplicateOfferedEnvelope)
        ));
    }

    #[test]
    fn receiver_does_not_request_an_envelope_it_already_has() {
        let identifier = MessageId::from_bytes([0x31; MESSAGE_ID_LENGTH]);
        let offer = SyncFrame::offer(vec![identifier])
            .unwrap_or_else(|_| panic!("offer fixture should be valid"));
        let transport = MemoryTransport {
            incoming: VecDeque::from([encoded(&offer), encoded(&SyncFrame::done())]),
            sent: Vec::new(),
        };
        let session = BoundedSession::new(transport, SessionLimits::default());
        let mut sink = TestSink {
            known: vec![identifier],
            accepted: Vec::new(),
        };

        let (session, summary) = receive_batch(session, &mut sink)
            .unwrap_or_else(|_| panic!("known item exchange should complete"));

        assert_eq!(summary.offered(), 1);
        assert_eq!(summary.requested(), 0);
        assert_eq!(summary.transferred(), 0);
        assert!(sink.accepted.is_empty());
        assert_eq!(
            session.into_inner().sent,
            [encoded(&SyncFrame::request(Vec::new()).unwrap_or_else(
                |_| panic!("empty request should be valid")
            ))]
        );
    }

    #[test]
    fn receiver_rejects_a_transfer_that_was_not_requested() {
        let requested_id = MessageId::from_bytes([0x41; MESSAGE_ID_LENGTH]);
        let offer = SyncFrame::offer(vec![requested_id])
            .unwrap_or_else(|_| panic!("offer fixture should be valid"));
        let wrong_transfer = SyncFrame::transfer(transferred(0x42));
        let transport = MemoryTransport {
            incoming: VecDeque::from([encoded(&offer), encoded(&wrong_transfer)]),
            sent: Vec::new(),
        };
        let session = BoundedSession::new(transport, SessionLimits::default());
        let mut sink = TestSink::default();

        assert!(matches!(
            receive_batch(session, &mut sink),
            Err(SyncError::TransferNotRequested)
        ));
        assert!(sink.accepted.is_empty());
    }
}
