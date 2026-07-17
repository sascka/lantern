// SPDX-License-Identifier: MPL-2.0

use core::str::FromStr;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use lantern_core::{Envelope, MESSAGE_ID_LENGTH, NORMAL_PRIORITY, PROTOCOL_VERSION, QueueLimits};
use lantern_diagnostics::JournalLimits;
use lantern_lan::{BindAddress, LanListener, PeerAddress, connect};
use lantern_node::{EncounterRole, EncounterSummary, NodeRuntime};
use lantern_transport::SessionLimits;

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new(name: &str) -> Self {
        let number = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "lantern-three-node-{name}-{}-{number}.sqlite3",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
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

fn listener_and_peer() -> (LanListener, PeerAddress) {
    let bind = BindAddress::from_str("127.0.0.1:0")
        .unwrap_or_else(|_| panic!("three-node loopback bind should be valid"));
    let listener =
        LanListener::bind(bind).unwrap_or_else(|_| panic!("three-node listener should bind"));
    let local = listener
        .local_address()
        .unwrap_or_else(|_| panic!("three-node listener should report its port"));
    let peer = PeerAddress::from_str(&format!("127.0.0.1:{}", local.port()))
        .unwrap_or_else(|_| panic!("three-node peer address should be valid"));
    (listener, peer)
}

fn synthetic_envelope(max_hops: u8) -> Envelope {
    Envelope::try_from_fields(
        PROTOCOL_VERSION,
        [0xc1; MESSAGE_ID_LENGTH],
        [0xc2; 16],
        300,
        u64::from(max_hops),
        NORMAL_PRIORITY,
        b"SYNTHETIC THREE NODE CIPHERTEXT".to_vec(),
    )
    .unwrap_or_else(|_| panic!("three-node Envelope fixture should be valid"))
}

fn start_node(path: &Path) -> NodeRuntime {
    NodeRuntime::start(path, QueueLimits::default(), JournalLimits::default())
        .unwrap_or_else(|_| panic!("three-node runtime should start"))
}

fn accept_encounter(node: &mut NodeRuntime, listener: &LanListener) -> EncounterSummary {
    let connection = listener
        .accept()
        .unwrap_or_else(|_| panic!("three-node connection should be accepted"));
    let session = node
        .begin_session(connection, SessionLimits::standard())
        .unwrap_or_else(|_| panic!("three-node responder session should start"));
    let (session, summary) = node
        .run_encounter(session, EncounterRole::Responder)
        .unwrap_or_else(|_| panic!("three-node responder encounter should complete"));
    session
        .into_inner()
        .shutdown()
        .unwrap_or_else(|_| panic!("three-node responder connection should close"));
    summary
}

fn connect_encounter(node: &mut NodeRuntime, peer: PeerAddress) -> EncounterSummary {
    let connection =
        connect(peer).unwrap_or_else(|_| panic!("three-node outgoing connection should complete"));
    let session = node
        .begin_session(connection, SessionLimits::standard())
        .unwrap_or_else(|_| panic!("three-node initiator session should start"));
    let (session, summary) = node
        .run_encounter(session, EncounterRole::Initiator)
        .unwrap_or_else(|_| panic!("three-node initiator encounter should complete"));
    session
        .into_inner()
        .shutdown()
        .unwrap_or_else(|_| panic!("three-node initiator connection should close"));
    summary
}

#[test]
fn envelope_crosses_restarted_relay_without_alice_bob_connection() {
    let alice_database = TestDatabase::new("alice");
    let relay_database = TestDatabase::new("relay");
    let bob_database = TestDatabase::new("bob");
    let envelope = synthetic_envelope(2);
    let identifier = envelope.message_id();

    let (relay_listener, relay_peer) = listener_and_peer();
    let alice_path = alice_database.path().to_path_buf();
    let alice_envelope = envelope.clone();
    let alice = thread::spawn(move || {
        let mut alice = start_node(&alice_path);
        alice
            .enqueue_origin(alice_envelope)
            .unwrap_or_else(|_| panic!("Alice should store her origin Envelope"));
        let summary = connect_encounter(&mut alice, relay_peer);
        let copies = alice
            .queue()
            .get(identifier)
            .map(|entry| entry.route().copies_left())
            .unwrap_or_else(|| panic!("Alice should retain her local copy"));
        (summary, copies)
    });

    let mut relay = start_node(relay_database.path());
    let relay_received = accept_encounter(&mut relay, &relay_listener);
    let (alice_summary, alice_copies) = alice
        .join()
        .unwrap_or_else(|_| panic!("Alice thread should not panic"));

    assert_eq!(alice_summary.sent().transferred(), 1);
    assert_eq!(relay_received.received().transferred(), 1);
    assert_eq!(alice_copies, 16);
    assert_eq!(
        relay
            .queue()
            .get(identifier)
            .map(|entry| (entry.route().hops_taken(), entry.route().copies_left())),
        Some((1, 16))
    );
    drop(relay);

    let (bob_listener, bob_peer) = listener_and_peer();
    let relay_path = relay_database.path().to_path_buf();
    let forwarding_relay = thread::spawn(move || {
        let mut relay = start_node(&relay_path);
        let first = connect_encounter(&mut relay, bob_peer);
        let second = connect_encounter(&mut relay, bob_peer);
        let route = relay
            .queue()
            .get(identifier)
            .map(|entry| (entry.route().hops_taken(), entry.route().copies_left()))
            .unwrap_or_else(|| panic!("restarted Relay should retain the Envelope"));
        (first, second, route)
    });

    let mut bob = start_node(bob_database.path());
    let bob_first = accept_encounter(&mut bob, &bob_listener);
    let bob_second = accept_encounter(&mut bob, &bob_listener);
    let (relay_first, relay_second, relay_route) = forwarding_relay
        .join()
        .unwrap_or_else(|_| panic!("Relay thread should not panic"));

    assert_eq!(relay_first.sent().transferred(), 1);
    assert_eq!(bob_first.received().transferred(), 1);
    assert_eq!(relay_second.sent().transferred(), 0);
    assert_eq!(bob_second.received().transferred(), 0);
    assert_eq!(relay_route, (1, 8));
    let bob_entry = bob
        .queue()
        .get(identifier)
        .unwrap_or_else(|| panic!("Bob should receive the relayed Envelope"));
    assert_eq!(bob_entry.envelope(), &envelope);
    assert_eq!(bob_entry.route().hops_taken(), 2);
    assert_eq!(bob_entry.route().copies_left(), 8);
    drop(bob);

    let alice = start_node(alice_database.path());
    let relay = start_node(relay_database.path());
    let bob = start_node(bob_database.path());
    let alice_copies = alice
        .queue()
        .get(identifier)
        .map(|entry| entry.route().copies_left())
        .unwrap_or_else(|| panic!("Alice copy should survive restart"));
    let relay_copies = relay
        .queue()
        .get(identifier)
        .map(|entry| entry.route().copies_left())
        .unwrap_or_else(|| panic!("Relay copy should survive restart"));
    let bob_copies = bob
        .queue()
        .get(identifier)
        .map(|entry| entry.route().copies_left())
        .unwrap_or_else(|| panic!("Bob copy should survive restart"));
    assert_eq!(alice_copies + relay_copies + bob_copies, 32);
}

#[test]
fn relay_cannot_forward_after_the_only_hop_is_spent() {
    let alice_database = TestDatabase::new("hop-alice");
    let relay_database = TestDatabase::new("hop-relay");
    let bob_database = TestDatabase::new("hop-bob");
    let envelope = synthetic_envelope(1);
    let identifier = envelope.message_id();

    let (relay_listener, relay_peer) = listener_and_peer();
    let alice_path = alice_database.path().to_path_buf();
    let alice = thread::spawn(move || {
        let mut alice = start_node(&alice_path);
        alice
            .enqueue_origin(envelope)
            .unwrap_or_else(|_| panic!("Alice should store the hop-limit fixture"));
        connect_encounter(&mut alice, relay_peer)
    });
    let mut relay = start_node(relay_database.path());
    let received = accept_encounter(&mut relay, &relay_listener);
    let sent = alice
        .join()
        .unwrap_or_else(|_| panic!("hop-limit Alice thread should not panic"));
    assert_eq!(sent.sent().transferred(), 1);
    assert_eq!(received.received().transferred(), 1);
    assert_eq!(
        relay
            .queue()
            .get(identifier)
            .map(|entry| entry.route().hops_taken()),
        Some(1)
    );

    let (bob_listener, bob_peer) = listener_and_peer();
    let relay_path = relay_database.path().to_path_buf();
    drop(relay);
    let forwarding_relay = thread::spawn(move || {
        let mut relay = start_node(&relay_path);
        connect_encounter(&mut relay, bob_peer)
    });
    let mut bob = start_node(bob_database.path());
    let bob_summary = accept_encounter(&mut bob, &bob_listener);
    let relay_summary = forwarding_relay
        .join()
        .unwrap_or_else(|_| panic!("hop-limit Relay thread should not panic"));

    assert_eq!(relay_summary.sent().offered(), 0);
    assert_eq!(relay_summary.sent().transferred(), 0);
    assert_eq!(bob_summary.received().transferred(), 0);
    assert!(bob.queue().get(identifier).is_none());
}
