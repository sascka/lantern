// SPDX-License-Identifier: MPL-2.0

use core::str::FromStr;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use lantern_bridge::{IncomingChatResult, export_pending_outbox, process_incoming_chat};
use lantern_core::{EnqueueOutcome, QueueLimits};
use lantern_crypto::encrypt_chat;
use lantern_diagnostics::JournalLimits;
use lantern_lan::{BindAddress, LanListener, PeerAddress, connect};
use lantern_node::{EncounterRole, EncounterSummary, NodeRuntime};
use lantern_secret_storage::{ContactId, NewContact, Passphrase, SecretProfile};
use lantern_transport::SessionLimits;
use vodozemac::olm::{OlmMessage, SessionConfig};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

struct TestPath(PathBuf);

impl TestPath {
    fn new(label: &str) -> Self {
        let number = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "lantern-encrypted-three-node-{label}-{}-{number}",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestPath {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let _ = fs::remove_file(&self.0);
        for suffix in ["-journal", "-wal", "-shm", ".lock"] {
            let _ = fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

fn passphrase(value: &str) -> Passphrase {
    Passphrase::new(value.to_owned())
        .unwrap_or_else(|_| panic!("encrypted route test passphrase should be accepted"))
}

fn start_node(path: &Path) -> NodeRuntime {
    NodeRuntime::start(path, QueueLimits::default(), JournalLimits::default())
        .unwrap_or_else(|_| panic!("encrypted route test node should start"))
}

fn listener_and_peer() -> (LanListener, PeerAddress) {
    let bind = BindAddress::from_str("127.0.0.1:0")
        .unwrap_or_else(|_| panic!("encrypted route loopback bind should be valid"));
    let listener =
        LanListener::bind(bind).unwrap_or_else(|_| panic!("encrypted route listener should bind"));
    let local = listener
        .local_address()
        .unwrap_or_else(|_| panic!("encrypted route listener should report its port"));
    let peer = PeerAddress::from_str(&format!("127.0.0.1:{}", local.port()))
        .unwrap_or_else(|_| panic!("encrypted route peer address should be valid"));
    (listener, peer)
}

fn accept_encounter(node: &mut NodeRuntime, listener: &LanListener) -> EncounterSummary {
    let connection = listener
        .accept()
        .unwrap_or_else(|_| panic!("encrypted route connection should be accepted"));
    let session = node
        .begin_session(connection, SessionLimits::standard())
        .unwrap_or_else(|_| panic!("encrypted route responder session should start"));
    let (session, summary) = node
        .run_encounter(session, EncounterRole::Responder)
        .unwrap_or_else(|_| panic!("encrypted route responder encounter should complete"));
    session
        .into_inner()
        .shutdown()
        .unwrap_or_else(|_| panic!("encrypted route responder connection should close"));
    summary
}

fn connect_encounter(node: &mut NodeRuntime, peer: PeerAddress) -> EncounterSummary {
    let connection =
        connect(peer).unwrap_or_else(|_| panic!("encrypted route connection should complete"));
    let session = node
        .begin_session(connection, SessionLimits::standard())
        .unwrap_or_else(|_| panic!("encrypted route initiator session should start"));
    let (session, summary) = node
        .run_encounter(session, EncounterRole::Initiator)
        .unwrap_or_else(|_| panic!("encrypted route initiator encounter should complete"));
    session
        .into_inner()
        .shutdown()
        .unwrap_or_else(|_| panic!("encrypted route initiator connection should close"));
    summary
}

fn seed_test_contacts(
    alice: &mut SecretProfile,
    bob: &mut SecretProfile,
) -> (ContactId, ContactId) {
    let alice_account = alice
        .load_account()
        .unwrap_or_else(|_| panic!("Alice test account should load"));
    let mut bob_account = bob
        .load_account()
        .unwrap_or_else(|_| panic!("Bob test account should load"));
    bob_account.generate_one_time_keys(1);
    let one_time_key = bob_account
        .one_time_keys()
        .values()
        .next()
        .copied()
        .unwrap_or_else(|| panic!("Bob test one-time key should exist"));
    let mut alice_session = alice_account
        .create_outbound_session(
            SessionConfig::version_1(),
            bob_account.curve25519_key(),
            one_time_key,
        )
        .unwrap_or_else(|_| panic!("Alice test session should be created"));
    let first = alice_session
        .encrypt(b"contact fixture handshake")
        .unwrap_or_else(|_| panic!("contact fixture handshake should be encrypted"));
    let OlmMessage::PreKey(first) = first else {
        panic!("contact fixture first message should be pre-key");
    };
    let inbound = bob_account
        .create_inbound_session(
            SessionConfig::version_1(),
            alice_account.curve25519_key(),
            &first,
        )
        .unwrap_or_else(|_| panic!("Bob test session should be created"));
    let mut bob_session = inbound.session;
    let reply = bob_session
        .encrypt(b"contact fixture reply")
        .unwrap_or_else(|_| panic!("contact fixture reply should be encrypted"));
    assert!(
        alice_session
            .decrypt(&reply)
            .is_ok_and(|plaintext| plaintext == b"contact fixture reply")
    );

    let alice_contact = ContactId::from_bytes([0xa1; 16]);
    let bob_contact = ContactId::from_bytes([0xb2; 16]);
    let alice_hint = [0x31; 16];
    let bob_hint = [0x42; 16];
    alice
        .secret_store_mut()
        .add_active_contact(
            NewContact {
                contact_id: alice_contact,
                display_name: "Bob".to_owned(),
                signing_identity_key: *bob_account.ed25519_key().as_bytes(),
                curve_identity_key: bob_account.curve25519_key().to_bytes(),
                inbound_recipient_hint: alice_hint,
                outbound_recipient_hint: bob_hint,
            },
            &alice_session,
        )
        .unwrap_or_else(|_| panic!("Bob test contact should be stored for Alice"));
    bob.secret_store_mut()
        .add_active_contact_with_account(
            NewContact {
                contact_id: bob_contact,
                display_name: "Alice".to_owned(),
                signing_identity_key: *alice_account.ed25519_key().as_bytes(),
                curve_identity_key: alice_account.curve25519_key().to_bytes(),
                inbound_recipient_hint: bob_hint,
                outbound_recipient_hint: alice_hint,
            },
            &bob_session,
            &bob_account,
        )
        .unwrap_or_else(|_| panic!("Alice test contact should be stored for Bob"));
    (alice_contact, bob_contact)
}

fn assert_file_omits(path: &Path, marker: &[u8]) {
    let bytes = fs::read(path).unwrap_or_else(|_| panic!("test database should be readable"));
    assert!(!bytes.windows(marker.len()).any(|window| window == marker));
}

#[test]
fn encrypted_chat_crosses_relay_and_opens_only_in_bobs_persistent_profile() {
    let alice_profile_path = TestPath::new("alice-profile");
    let bob_profile_path = TestPath::new("bob-profile");
    let alice_queue_path = TestPath::new("alice-queue.sqlite3");
    let relay_queue_path = TestPath::new("relay-queue.sqlite3");
    let bob_queue_path = TestPath::new("bob-queue.sqlite3");
    let alice_passphrase = passphrase("Alice encrypted route passphrase 2026");
    let bob_passphrase = passphrase("Bob encrypted route passphrase 2026");
    let mut alice = SecretProfile::create(alice_profile_path.path(), &alice_passphrase)
        .unwrap_or_else(|_| panic!("Alice encrypted route profile should be created"));
    let mut bob = SecretProfile::create(bob_profile_path.path(), &bob_passphrase)
        .unwrap_or_else(|_| panic!("Bob encrypted route profile should be created"));
    let (alice_contact, _) = seed_test_contacts(&mut alice, &mut bob);

    let message_text = "private three node integration message";
    let envelope = encrypt_chat(
        alice.secret_store_mut(),
        alice_contact,
        message_text.to_owned(),
        3600,
        2,
    )
    .unwrap_or_else(|_| panic!("Alice chat should be encrypted"));
    let message_id = envelope.message_id();
    let mut alice_node = start_node(alice_queue_path.path());
    let exported = export_pending_outbox(alice.secret_store_mut(), &mut alice_node)
        .unwrap_or_else(|_| panic!("Alice outbox should reach the open queue"));
    assert_eq!(exported.inserted(), 1);
    assert_eq!(exported.acknowledged(), 1);
    assert!(
        alice
            .secret_store()
            .pending_outbox()
            .is_ok_and(|items| items.is_empty())
    );
    drop(alice_node);

    let (relay_listener, relay_peer) = listener_and_peer();
    let alice_queue = alice_queue_path.path().to_path_buf();
    let alice_sender = thread::spawn(move || {
        let mut alice_node = start_node(&alice_queue);
        connect_encounter(&mut alice_node, relay_peer)
    });
    let mut relay_node = start_node(relay_queue_path.path());
    let relay_received = accept_encounter(&mut relay_node, &relay_listener);
    let alice_sent = alice_sender
        .join()
        .unwrap_or_else(|_| panic!("Alice encrypted route thread should not panic"));
    assert_eq!(alice_sent.sent().transferred(), 1);
    assert_eq!(relay_received.received().transferred(), 1);
    assert_eq!(
        relay_node
            .queue()
            .get(message_id)
            .map(|entry| entry.envelope()),
        Some(&envelope)
    );
    assert_file_omits(relay_queue_path.path(), message_text.as_bytes());

    let (bob_listener, bob_peer) = listener_and_peer();
    let bob_queue = bob_queue_path.path().to_path_buf();
    let bob_receiver = thread::spawn(move || {
        let mut bob_node = start_node(&bob_queue);
        accept_encounter(&mut bob_node, &bob_listener)
    });
    let relay_sent = connect_encounter(&mut relay_node, bob_peer);
    let bob_received = bob_receiver
        .join()
        .unwrap_or_else(|_| panic!("Bob encrypted route thread should not panic"));
    assert_eq!(relay_sent.sent().transferred(), 1);
    assert_eq!(bob_received.received().transferred(), 1);
    assert_file_omits(bob_queue_path.path(), message_text.as_bytes());

    let mut bob_node = start_node(bob_queue_path.path());
    let alice_node = start_node(alice_queue_path.path());
    assert_eq!(
        bob_node
            .queue()
            .get(message_id)
            .map(|entry| entry.envelope()),
        Some(&envelope)
    );
    let alice_route = alice_node
        .queue()
        .get(message_id)
        .map(|entry| (entry.route().hops_taken(), entry.route().copies_left()))
        .unwrap_or_else(|| panic!("Alice should retain her encrypted Envelope"));
    let relay_route = relay_node
        .queue()
        .get(message_id)
        .map(|entry| (entry.route().hops_taken(), entry.route().copies_left()))
        .unwrap_or_else(|| panic!("Relay should retain its encrypted Envelope"));
    let bob_route = bob_node
        .queue()
        .get(message_id)
        .map(|entry| (entry.route().hops_taken(), entry.route().copies_left()))
        .unwrap_or_else(|| panic!("Bob should retain the received encrypted Envelope"));
    assert_eq!(alice_route, (0, 16));
    assert_eq!(relay_route, (1, 8));
    assert_eq!(bob_route, (2, 8));
    assert_eq!(alice_route.1 + relay_route.1 + bob_route.1, 32);
    drop(alice_node);
    let opened = process_incoming_chat(bob.secret_store_mut(), &mut bob_node, message_id)
        .unwrap_or_else(|_| panic!("Bob should process the encrypted chat"));
    assert!(!format!("{opened:?}").contains(message_text));
    let IncomingChatResult::Opened(chat) = opened else {
        panic!("only Bob should receive the chat text");
    };
    assert_eq!(chat.text(), message_text);
    assert!(bob_node.queue().get(message_id).is_none());
    assert!(
        bob.secret_store()
            .has_received_chat(*message_id.as_bytes())
            .is_ok_and(|received| received)
    );
    assert_eq!(
        bob_node
            .enqueue_origin(envelope.clone())
            .unwrap_or_else(|_| panic!("Bob replay should be handled"))
            .outcome(),
        EnqueueOutcome::DuplicateTombstone
    );

    drop(alice);
    drop(bob);
    drop(bob_node);
    drop(relay_node);
    let alice = SecretProfile::open(alice_profile_path.path(), &alice_passphrase)
        .unwrap_or_else(|_| panic!("Alice profile should reopen after sending"));
    let bob = SecretProfile::open(bob_profile_path.path(), &bob_passphrase)
        .unwrap_or_else(|_| panic!("Bob profile should reopen after receiving"));
    assert!(
        alice
            .secret_store()
            .pending_outbox()
            .is_ok_and(|items| items.is_empty())
    );
    assert!(
        bob.secret_store()
            .has_received_chat(*message_id.as_bytes())
            .is_ok_and(|received| received)
    );
    assert_file_omits(
        &alice_profile_path.path().join("secrets.sqlite3"),
        message_text.as_bytes(),
    );
    assert_file_omits(
        &bob_profile_path.path().join("secrets.sqlite3"),
        message_text.as_bytes(),
    );
    assert_file_omits(alice_queue_path.path(), message_text.as_bytes());
    assert_file_omits(relay_queue_path.path(), message_text.as_bytes());
    assert_file_omits(bob_queue_path.path(), message_text.as_bytes());
}
