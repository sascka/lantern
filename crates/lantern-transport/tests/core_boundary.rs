// SPDX-License-Identifier: MPL-2.0

use std::collections::VecDeque;

use lantern_core::{
    Envelope, MAX_ENVELOPE_SIZE, NORMAL_PRIORITY, PROTOCOL_VERSION, decode_envelope,
    encode_envelope,
};
use lantern_transport::{
    BoundedSession, FrameReceive, FrameTransport, MAX_FRAME_BYTES, SessionLimits,
    TransportFailureKind,
};

struct MemoryTransport {
    incoming: VecDeque<Vec<u8>>,
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
            return Err(TransportFailureKind::ProtocolViolation);
        }
        destination[..frame.len()].copy_from_slice(&frame);
        Ok(FrameReceive::Complete(frame.len()))
    }

    fn send_frame(&mut self, _frame: &[u8]) -> Result<(), TransportFailureKind> {
        Ok(())
    }
}

fn test_envelope() -> Envelope {
    let result = Envelope::try_from_fields(
        PROTOCOL_VERSION,
        [0x11; 16],
        [0x22; 16],
        60,
        4,
        NORMAL_PRIORITY,
        vec![0x33; 32],
    );
    let Ok(envelope) = result else {
        panic!("valid integration Envelope was rejected");
    };
    envelope
}

#[test]
fn transport_limit_matches_core_and_delivers_only_opaque_bytes() {
    assert_eq!(MAX_FRAME_BYTES, MAX_ENVELOPE_SIZE);
    let expected = test_envelope();
    let encoded = encode_envelope(&expected);
    let Ok(encoded) = encoded else {
        panic!("valid integration Envelope could not be encoded");
    };
    let transport = MemoryTransport {
        incoming: VecDeque::from([encoded]),
    };
    let mut session = BoundedSession::new(transport, SessionLimits::standard());
    let mut buffer = vec![0_u8; MAX_FRAME_BYTES];
    let received = session.receive_frame(&mut buffer);
    let Ok(Some(frame)) = received else {
        panic!("bounded integration frame was not received");
    };
    let decoded = decode_envelope(frame);
    assert_eq!(decoded, Ok(expected));
}

#[test]
fn malformed_frame_reaches_strict_core_decoder_without_transport_interpretation() {
    let malformed = vec![0xff, 0x00, 0x11];
    let transport = MemoryTransport {
        incoming: VecDeque::from([malformed]),
    };
    let mut session = BoundedSession::new(transport, SessionLimits::standard());
    let mut buffer = vec![0_u8; MAX_FRAME_BYTES];
    let received = session.receive_frame(&mut buffer);
    let Ok(Some(frame)) = received else {
        panic!("bounded malformed frame was not received");
    };
    assert!(decode_envelope(frame).is_err());
}
