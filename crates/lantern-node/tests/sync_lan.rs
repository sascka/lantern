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
use lantern_node::NodeRuntime;
use lantern_sync::{RouteGrant, TransferredEnvelope, send_batch};
use lantern_transport::{BoundedSession, SessionLimits};

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
