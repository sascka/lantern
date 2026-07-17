// SPDX-License-Identifier: MPL-2.0

use core::str::FromStr;
use std::thread;

use lantern_core::{Envelope, MESSAGE_ID_LENGTH, MessageId, NORMAL_PRIORITY, PROTOCOL_VERSION};
use lantern_lan::{BindAddress, LanListener, PeerAddress, connect};
use lantern_sync::{EnvelopeSink, SyncSinkError, receive_batch, send_batch};
use lantern_transport::{BoundedSession, SessionLimits};

#[derive(Default)]
struct MemorySink {
    accepted: Vec<Envelope>,
}

impl EnvelopeSink for MemorySink {
    fn wants(&mut self, message_id: MessageId) -> Result<bool, SyncSinkError> {
        Ok(self
            .accepted
            .iter()
            .all(|envelope| envelope.message_id() != message_id))
    }

    fn accept(&mut self, envelope: Envelope) -> Result<(), SyncSinkError> {
        self.accepted.push(envelope);
        Ok(())
    }
}

fn envelope(id: u8) -> Envelope {
    match Envelope::try_from_fields(
        PROTOCOL_VERSION,
        [id; MESSAGE_ID_LENGTH],
        [0x44; 16],
        300,
        4,
        NORMAL_PRIORITY,
        b"SYNTHETIC PUBLIC SYNC PAYLOAD".to_vec(),
    ) {
        Ok(envelope) => envelope,
        Err(_) => panic!("public sync Envelope should be valid"),
    }
}

#[test]
fn two_public_lan_sessions_offer_request_and_transfer_one_envelope() {
    let bind = BindAddress::from_str("127.0.0.1:0");
    let Ok(bind) = bind else {
        panic!("sync listener address should be valid");
    };
    let listener = match LanListener::bind(bind) {
        Ok(listener) => listener,
        Err(_) => panic!("sync listener should bind"),
    };
    let local = match listener.local_address() {
        Ok(address) => address,
        Err(_) => panic!("sync listener should report its port"),
    };
    let peer = PeerAddress::from_str(&format!("127.0.0.1:{}", local.port()));
    let Ok(peer) = peer else {
        panic!("sync peer address should be valid");
    };

    let receiver = thread::spawn(move || {
        let connection = listener.accept().map_err(|_| ())?;
        let session = BoundedSession::new(connection, SessionLimits::default());
        let mut sink = MemorySink::default();
        let (session, summary) = receive_batch(session, &mut sink).map_err(|_| ())?;
        Ok::<_, ()>((session, summary, sink))
    });

    let connection = match connect(peer) {
        Ok(connection) => connection,
        Err(_) => panic!("sync sender should connect"),
    };
    let session = BoundedSession::new(connection, SessionLimits::default());
    let offered = envelope(0x21);
    let sent = send_batch(session, std::slice::from_ref(&offered));
    let Ok((_session, sent_summary)) = sent else {
        panic!("public sync sender should complete one batch");
    };

    let received = match receiver.join() {
        Ok(Ok(result)) => result,
        Ok(Err(())) => panic!("public sync receiver should complete one batch"),
        Err(_) => panic!("public sync receiver thread should not panic"),
    };
    let (_session, received_summary, sink) = received;

    assert_eq!(sent_summary.offered(), 1);
    assert_eq!(sent_summary.requested(), 1);
    assert_eq!(sent_summary.transferred(), 1);
    assert_eq!(sent_summary, received_summary);
    assert_eq!(sink.accepted, [offered]);
}

#[test]
fn public_debug_output_does_not_contain_sync_identifiers_or_payload() {
    let frame = lantern_sync::SyncFrame::offer(vec![MessageId::from_bytes([0x55; 16])]);
    let Ok(frame) = frame else {
        panic!("public offer should be valid");
    };
    let output = format!("{frame:?}");
    assert!(!output.contains("85, 85"));
    assert!(!output.contains("SYNTHETIC"));
}
