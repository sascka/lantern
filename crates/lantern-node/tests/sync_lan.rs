// SPDX-License-Identifier: MPL-2.0

use core::str::FromStr;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use lantern_core::{Envelope, MESSAGE_ID_LENGTH, NORMAL_PRIORITY, PROTOCOL_VERSION, QueueLimits};
use lantern_diagnostics::JournalLimits;
use lantern_lan::{BindAddress, LanListener, PeerAddress, connect};
use lantern_node::{EncounterRole, NodeRuntime};
use lantern_sync::{
    RouteGrant, SyncFrame, TransferredEnvelope, decode_sync_frame, encode_sync_frame, send_batch,
};
use lantern_transport::{BoundedSession, MAX_FRAME_BYTES, SessionLimits};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new() -> Self {
        let number = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "lantern-node-sync-lan-{}-{number}.sqlite3",
            std::process::id()
        )))
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        for suffix in ["-journal", "-wal", "-shm", ".lock"] {
            let _ = fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

fn transferred() -> TransferredEnvelope {
    let envelope = Envelope::try_from_fields(
        PROTOCOL_VERSION,
        [0xa1; MESSAGE_ID_LENGTH],
        [0xa2; 16],
        300,
        4,
        NORMAL_PRIORITY,
        b"SYNTHETIC NODE LAN PAYLOAD".to_vec(),
    )
    .unwrap_or_else(|_| panic!("LAN sync Envelope fixture should be valid"));
    let route = RouteGrant::try_new(250, 1, 16)
        .unwrap_or_else(|_| panic!("LAN sync route fixture should be valid"));
    TransferredEnvelope::try_new(envelope, route)
        .unwrap_or_else(|_| panic!("LAN sync transfer fixture should be valid"))
}

#[test]
fn lan_sync_reaches_sqlite_and_survives_receiver_restart() {
    let database = TestDatabase::new();
    let mut receiver = NodeRuntime::start(
        &database.0,
        QueueLimits::default(),
        JournalLimits::default(),
    )
    .unwrap_or_else(|_| panic!("receiver node should start"));
    let bind = BindAddress::from_str("127.0.0.1:0")
        .unwrap_or_else(|_| panic!("loopback bind address should be valid"));
    let listener =
        LanListener::bind(bind).unwrap_or_else(|_| panic!("loopback sync listener should bind"));
    let local = listener
        .local_address()
        .unwrap_or_else(|_| panic!("loopback sync listener should report its port"));
    let peer = PeerAddress::from_str(&format!("127.0.0.1:{}", local.port()))
        .unwrap_or_else(|_| panic!("loopback peer address should be valid"));
    let offered = transferred();
    let expected = offered.clone();

    let sender = thread::spawn(move || {
        let connection = connect(peer).map_err(|_| ())?;
        let session = BoundedSession::new(connection, SessionLimits::standard());
        let (_session, summary) = send_batch(session, &[offered]).map_err(|_| ())?;
        if summary.transferred() != 1 {
            return Err(());
        }
        Ok::<(), ()>(())
    });

    let connection = listener
        .accept()
        .unwrap_or_else(|_| panic!("receiver should accept the sync connection"));
    let session = receiver
        .begin_session(connection, SessionLimits::standard())
        .unwrap_or_else(|_| panic!("receiver should create a bounded session"));
    let (_session, summary) = receiver
        .receive_sync_batch(session)
        .unwrap_or_else(|_| panic!("receiver should persist the LAN sync batch"));
    match sender.join() {
        Ok(Ok(())) => {}
        Ok(Err(())) => panic!("sender did not complete the LAN sync batch"),
        Err(_) => panic!("sender thread should not panic"),
    }

    assert_eq!(summary.transferred(), 1);
    assert_eq!(
        receiver
            .queue()
            .get(expected.message_id())
            .map(|entry| entry.envelope()),
        Some(expected.envelope())
    );
    drop(receiver);

    let recovered = NodeRuntime::start(
        &database.0,
        QueueLimits::default(),
        JournalLimits::default(),
    )
    .unwrap_or_else(|_| panic!("receiver should reopen its persistent queue"));
    let entry = recovered
        .queue()
        .get(expected.message_id())
        .unwrap_or_else(|| panic!("LAN sync Envelope should survive receiver restart"));
    assert_eq!(entry.envelope(), expected.envelope());
    assert_eq!(entry.route().remaining_ttl(), 250);
    assert_eq!(entry.route().hops_taken(), 1);
    assert_eq!(entry.route().copies_left(), 16);
}

#[test]
fn two_nodes_split_and_persist_copy_budget_over_lan() {
    let sender_database = TestDatabase::new();
    let receiver_database = TestDatabase::new();
    let mut receiver = NodeRuntime::start(
        &receiver_database.0,
        QueueLimits::default(),
        JournalLimits::default(),
    )
    .unwrap_or_else(|_| panic!("receiver node should start"));
    let bind = BindAddress::from_str("127.0.0.1:0")
        .unwrap_or_else(|_| panic!("loopback bind address should be valid"));
    let listener =
        LanListener::bind(bind).unwrap_or_else(|_| panic!("loopback sync listener should bind"));
    let local = listener
        .local_address()
        .unwrap_or_else(|_| panic!("loopback sync listener should report its port"));
    let peer = PeerAddress::from_str(&format!("127.0.0.1:{}", local.port()))
        .unwrap_or_else(|_| panic!("loopback peer address should be valid"));
    let item = transferred();
    let envelope = item.envelope().clone();
    let identifier = envelope.message_id();
    let sender_path = sender_database.0.clone();

    let sender = thread::spawn(move || {
        let mut node = NodeRuntime::start(
            &sender_path,
            QueueLimits::default(),
            JournalLimits::default(),
        )
        .map_err(|_| ())?;
        node.enqueue_origin(envelope).map_err(|_| ())?;
        let connection = connect(peer).map_err(|_| ())?;
        let session = node
            .begin_session(connection, SessionLimits::standard())
            .map_err(|_| ())?;
        let (_session, summary) = node.send_sync_batch(session).map_err(|_| ())?;
        let copies = node
            .queue()
            .get(identifier)
            .map(|entry| entry.route().copies_left())
            .ok_or(())?;
        Ok::<_, ()>((summary, copies))
    });

    let connection = listener
        .accept()
        .unwrap_or_else(|_| panic!("receiver should accept the node connection"));
    let session = receiver
        .begin_session(connection, SessionLimits::standard())
        .unwrap_or_else(|_| panic!("receiver should create a bounded session"));
    let (_session, received) = receiver
        .receive_sync_batch(session)
        .unwrap_or_else(|_| panic!("receiver should persist the node batch"));
    let (sent, sender_copies) = match sender.join() {
        Ok(Ok(result)) => result,
        Ok(Err(())) => panic!("sender node did not complete the LAN batch"),
        Err(_) => panic!("sender node thread should not panic"),
    };

    assert_eq!(sent.transferred(), 1);
    assert_eq!(received.transferred(), 1);
    assert_eq!(sender_copies, 16);
    assert_eq!(
        receiver
            .queue()
            .get(identifier)
            .map(|entry| entry.route().copies_left()),
        Some(16)
    );
    drop(receiver);

    let sender_recovered = NodeRuntime::start(
        &sender_database.0,
        QueueLimits::default(),
        JournalLimits::default(),
    )
    .unwrap_or_else(|_| panic!("sender should recover its reserved budget"));
    let receiver_recovered = NodeRuntime::start(
        &receiver_database.0,
        QueueLimits::default(),
        JournalLimits::default(),
    )
    .unwrap_or_else(|_| panic!("receiver should recover its granted budget"));
    assert_eq!(
        sender_recovered
            .queue()
            .get(identifier)
            .map(|entry| entry.route().copies_left()),
        Some(16)
    );
    assert_eq!(
        receiver_recovered
            .queue()
            .get(identifier)
            .map(|entry| entry.route().copies_left()),
        Some(16)
    );
}

#[test]
fn two_nodes_exchange_both_directions_in_one_encounter() {
    let initiator_database = TestDatabase::new();
    let responder_database = TestDatabase::new();
    let mut responder = NodeRuntime::start(
        &responder_database.0,
        QueueLimits::default(),
        JournalLimits::default(),
    )
    .unwrap_or_else(|_| panic!("responder node should start"));
    let responder_envelope = Envelope::try_from_fields(
        PROTOCOL_VERSION,
        [0xb1; MESSAGE_ID_LENGTH],
        [0xb2; 16],
        300,
        4,
        NORMAL_PRIORITY,
        b"SYNTHETIC RESPONDER PAYLOAD".to_vec(),
    )
    .unwrap_or_else(|_| panic!("responder Envelope fixture should be valid"));
    let responder_id = responder_envelope.message_id();
    responder
        .enqueue_origin(responder_envelope)
        .unwrap_or_else(|_| panic!("responder should store its origin Envelope"));

    let bind = BindAddress::from_str("127.0.0.1:0")
        .unwrap_or_else(|_| panic!("loopback bind address should be valid"));
    let listener =
        LanListener::bind(bind).unwrap_or_else(|_| panic!("encounter listener should bind"));
    let local = listener
        .local_address()
        .unwrap_or_else(|_| panic!("encounter listener should report its port"));
    let peer = PeerAddress::from_str(&format!("127.0.0.1:{}", local.port()))
        .unwrap_or_else(|_| panic!("loopback peer address should be valid"));
    let initiator_path = initiator_database.0.clone();
    let initiator_envelope = transferred().envelope().clone();
    let initiator_id = initiator_envelope.message_id();

    let initiator = thread::spawn(move || {
        let mut node = NodeRuntime::start(
            &initiator_path,
            QueueLimits::default(),
            JournalLimits::default(),
        )
        .map_err(|_| ())?;
        node.enqueue_origin(initiator_envelope).map_err(|_| ())?;
        let connection = connect(peer).map_err(|_| ())?;
        let session = node
            .begin_session(connection, SessionLimits::standard())
            .map_err(|_| ())?;
        let (_session, summary) = node
            .run_encounter(session, EncounterRole::Initiator)
            .map_err(|_| ())?;
        let received = node.queue().get(responder_id).is_some();
        Ok::<_, ()>((summary, received))
    });

    let connection = listener
        .accept()
        .unwrap_or_else(|_| panic!("responder should accept the encounter"));
    let session = responder
        .begin_session(connection, SessionLimits::standard())
        .unwrap_or_else(|_| panic!("responder should create a bounded session"));
    let (_session, responder_summary) = responder
        .run_encounter(session, EncounterRole::Responder)
        .unwrap_or_else(|_| panic!("responder should complete the encounter"));
    let (initiator_summary, initiator_received) = match initiator.join() {
        Ok(Ok(result)) => result,
        Ok(Err(())) => panic!("initiator did not complete the encounter"),
        Err(_) => panic!("initiator thread should not panic"),
    };

    assert_eq!(initiator_summary.sent().transferred(), 1);
    assert_eq!(initiator_summary.received().transferred(), 1);
    assert_eq!(responder_summary.sent().transferred(), 1);
    assert_eq!(responder_summary.received().transferred(), 1);
    assert!(initiator_received);
    assert!(responder.queue().get(initiator_id).is_some());
}

#[test]
fn interrupted_transfer_completes_after_bounded_reconnect() {
    let sender_database = TestDatabase::new();
    let receiver_database = TestDatabase::new();
    let mut receiver = NodeRuntime::start(
        &receiver_database.0,
        QueueLimits::default(),
        JournalLimits::default(),
    )
    .unwrap_or_else(|_| panic!("reconnect receiver should start"));
    let bind = BindAddress::from_str("127.0.0.1:0")
        .unwrap_or_else(|_| panic!("loopback bind address should be valid"));
    let listener =
        LanListener::bind(bind).unwrap_or_else(|_| panic!("reconnect listener should bind"));
    let local = listener
        .local_address()
        .unwrap_or_else(|_| panic!("reconnect listener should report its port"));
    let peer = PeerAddress::from_str(&format!("127.0.0.1:{}", local.port()))
        .unwrap_or_else(|_| panic!("loopback peer address should be valid"));
    let sender_path = sender_database.0.clone();
    let envelope = transferred().envelope().clone();
    let identifier = envelope.message_id();

    let sender = thread::spawn(move || {
        let mut node = NodeRuntime::start(
            &sender_path,
            QueueLimits::default(),
            JournalLimits::default(),
        )
        .map_err(|_| ())?;
        node.enqueue_origin(envelope).map_err(|_| ())?;

        let first = connect(peer).map_err(|_| ())?;
        let first = node
            .begin_session(first, SessionLimits::standard())
            .map_err(|_| ())?;
        if let Ok((session, _)) = node.send_sync_batch(first) {
            let _ = session.into_inner().shutdown();
        }

        let second = connect(peer).map_err(|_| ())?;
        let second = node
            .begin_session(second, SessionLimits::standard())
            .map_err(|_| ())?;
        let (second, delivered) = node.send_sync_batch(second).map_err(|_| ())?;
        second.into_inner().shutdown().map_err(|_| ())?;

        let third = connect(peer).map_err(|_| ())?;
        let third = node
            .begin_session(third, SessionLimits::standard())
            .map_err(|_| ())?;
        let (third, duplicate) = node.send_sync_batch(third).map_err(|_| ())?;
        third.into_inner().shutdown().map_err(|_| ())?;
        let copies = node
            .queue()
            .get(identifier)
            .map(|entry| entry.route().copies_left())
            .ok_or(())?;
        Ok::<_, ()>((delivered, duplicate, copies))
    });

    let first_connection = listener
        .accept()
        .unwrap_or_else(|_| panic!("receiver should accept the interrupted connection"));
    let mut first_session = BoundedSession::new(first_connection, SessionLimits::standard());
    let mut buffer = [0_u8; MAX_FRAME_BYTES];
    let offer = first_session
        .receive_frame(&mut buffer)
        .unwrap_or_else(|_| panic!("receiver should read the first Offer"))
        .unwrap_or_else(|| panic!("sender should not close before the first Offer"));
    let offer =
        decode_sync_frame(offer).unwrap_or_else(|_| panic!("first reconnect Offer should decode"));
    let identifiers = offer
        .identifiers()
        .unwrap_or_else(|| panic!("first reconnect frame should be Offer"));
    let request = SyncFrame::request(identifiers.to_vec())
        .unwrap_or_else(|_| panic!("first reconnect Request should be valid"));
    let request = encode_sync_frame(&request)
        .unwrap_or_else(|_| panic!("first reconnect Request should encode"));
    first_session
        .send_frame(&request)
        .unwrap_or_else(|_| panic!("receiver should send the first Request"));
    first_session
        .into_inner()
        .shutdown()
        .unwrap_or_else(|_| panic!("receiver should close the interrupted connection"));

    let second_connection = listener
        .accept()
        .unwrap_or_else(|_| panic!("receiver should accept the reconnect"));
    let second_session = receiver
        .begin_session(second_connection, SessionLimits::standard())
        .unwrap_or_else(|_| panic!("receiver should create the reconnect session"));
    let (second_session, delivered) = receiver
        .receive_sync_batch(second_session)
        .unwrap_or_else(|_| panic!("receiver should finish after reconnect"));
    second_session
        .into_inner()
        .shutdown()
        .unwrap_or_else(|_| panic!("receiver should close the completed reconnect"));

    let third_connection = listener
        .accept()
        .unwrap_or_else(|_| panic!("receiver should accept the duplicate reconnect"));
    let third_session = receiver
        .begin_session(third_connection, SessionLimits::standard())
        .unwrap_or_else(|_| panic!("receiver should create the duplicate session"));
    let (third_session, duplicate) = receiver
        .receive_sync_batch(third_session)
        .unwrap_or_else(|_| panic!("receiver should reject the duplicate by ID"));
    third_session
        .into_inner()
        .shutdown()
        .unwrap_or_else(|_| panic!("receiver should close the duplicate reconnect"));
    let (sender_delivered, sender_duplicate, sender_copies) = match sender.join() {
        Ok(Ok(result)) => result,
        Ok(Err(())) => panic!("sender did not finish the reconnect sequence"),
        Err(_) => panic!("sender reconnect thread should not panic"),
    };

    assert_eq!(delivered.transferred(), 1);
    assert_eq!(sender_delivered.transferred(), 1);
    assert_eq!(duplicate.transferred(), 0);
    assert_eq!(sender_duplicate.transferred(), 0);
    assert_eq!(receiver.queue().len(), 1);
    assert!(receiver.queue().get(identifier).is_some());
    assert!(sender_copies <= 16);
}
