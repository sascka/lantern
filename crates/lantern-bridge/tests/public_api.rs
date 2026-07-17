// SPDX-License-Identifier: MPL-2.0

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use lantern_bridge::{
    BridgeError, IncomingChatResult, export_pending_outbox, process_incoming_chat,
};
use lantern_core::{EnqueueOutcome, Envelope, QueueLimits};
use lantern_crypto::{CryptoError, decrypt_chat, encrypt_chat};
use lantern_diagnostics::JournalLimits;
use lantern_node::{NodeError, NodeRuntime};
use lantern_secret_storage::{ContactId, KdfHeader, NewContact, Passphrase, SecretStore};
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

struct TestPath(PathBuf);

impl TestPath {
    fn new(label: &str) -> Self {
        let number = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "lantern-bridge-{label}-{}-{number}.sqlite3",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        for suffix in ["-journal", "-wal", "-shm", ".lock"] {
            let _ = fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

struct ContactStores {
    alice: SecretStore,
    bob: SecretStore,
    alice_contact: ContactId,
    bob_contact: ContactId,
}

fn contact_stores(alice_path: &Path, bob_path: &Path) -> ContactStores {
    let header = KdfHeader::generate()
        .unwrap_or_else(|_| panic!("bridge test KDF header should be generated"));
    let passphrase = Passphrase::new("bridge integration passphrase".to_owned())
        .unwrap_or_else(|_| panic!("bridge test passphrase should be accepted"));
    let key = header
        .derive_database_key(&passphrase)
        .unwrap_or_else(|_| panic!("bridge test database key should be derived"));
    let mut alice = SecretStore::create(alice_path, &key)
        .unwrap_or_else(|_| panic!("Alice test secret store should be created"));
    let mut bob = SecretStore::create(bob_path, &key)
        .unwrap_or_else(|_| panic!("Bob test secret store should be created"));

    let (alice_account, bob_account, alice_session, bob_session) = established_sessions();
    let alice_contact = ContactId::from_bytes([0xa1; 16]);
    let bob_contact = ContactId::from_bytes([0xb2; 16]);
    let alice_hint = [0x31; 16];
    let bob_hint = [0x42; 16];
    alice
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
    bob.add_active_contact(
        NewContact {
            contact_id: bob_contact,
            display_name: "Alice".to_owned(),
            signing_identity_key: *alice_account.ed25519_key().as_bytes(),
            curve_identity_key: alice_account.curve25519_key().to_bytes(),
            inbound_recipient_hint: bob_hint,
            outbound_recipient_hint: alice_hint,
        },
        &bob_session,
    )
    .unwrap_or_else(|_| panic!("Alice test contact should be stored for Bob"));

    ContactStores {
        alice,
        bob,
        alice_contact,
        bob_contact,
    }
}

fn established_sessions() -> (Account, Account, Session, Session) {
    let alice = Account::new();
    let mut bob = Account::new();
    bob.generate_one_time_keys(1);
    let one_time_key = bob
        .one_time_keys()
        .values()
        .next()
        .copied()
        .unwrap_or_else(|| panic!("bridge test one-time key should exist"));
    let mut alice_session = alice
        .create_outbound_session(
            SessionConfig::version_1(),
            bob.curve25519_key(),
            one_time_key,
        )
        .unwrap_or_else(|_| panic!("bridge test outbound session should be created"));
    let first = alice_session
        .encrypt(b"initial handshake")
        .unwrap_or_else(|_| panic!("bridge test pre-key message should be encrypted"));
    let OlmMessage::PreKey(first) = first else {
        panic!("bridge test first Olm message should be pre-key");
    };
    let inbound = bob
        .create_inbound_session(SessionConfig::version_1(), alice.curve25519_key(), &first)
        .unwrap_or_else(|_| panic!("bridge test inbound session should be created"));
    let mut bob_session = inbound.session;
    let reply = bob_session
        .encrypt(b"handshake reply")
        .unwrap_or_else(|_| panic!("bridge test reply should be encrypted"));
    let decrypted = alice_session
        .decrypt(&reply)
        .unwrap_or_else(|_| panic!("bridge test reply should be decrypted"));
    assert_eq!(decrypted, b"handshake reply");
    (alice, bob, alice_session, bob_session)
}

fn start_node(path: &Path) -> NodeRuntime {
    NodeRuntime::start(path, QueueLimits::default(), JournalLimits::default())
        .unwrap_or_else(|_| panic!("bridge test node should start"))
}

#[test]
fn outbox_export_recovers_after_queue_persistence_and_rejects_identifier_conflicts() {
    let alice_path = TestPath::new("outbox-alice");
    let bob_path = TestPath::new("outbox-bob");
    let node_path = TestPath::new("outbox-node");
    let mut contacts = contact_stores(alice_path.path(), bob_path.path());

    let envelope = encrypt_chat(
        &mut contacts.alice,
        contacts.alice_contact,
        "first bridge message".to_owned(),
        3600,
        4,
    )
    .unwrap_or_else(|_| panic!("first bridge message should be encrypted"));
    let identifier = envelope.message_id();
    let mut node = start_node(node_path.path());
    assert_eq!(
        node.enqueue_origin(envelope.clone())
            .unwrap_or_else(|_| panic!("crash fixture should reach the node queue"))
            .outcome(),
        EnqueueOutcome::Stored
    );
    drop(node);

    let mut node = start_node(node_path.path());
    let recovered = export_pending_outbox(&mut contacts.alice, &mut node)
        .unwrap_or_else(|_| panic!("persisted outbox handoff should recover"));
    assert_eq!(recovered.examined(), 1);
    assert_eq!(recovered.inserted(), 0);
    assert_eq!(recovered.acknowledged(), 1);
    assert!(!recovered.deferred());
    assert!(
        contacts
            .alice
            .pending_outbox()
            .is_ok_and(|items| items.is_empty())
    );
    assert_eq!(
        node.queue().get(identifier).map(|entry| entry.envelope()),
        Some(&envelope)
    );

    let pending = encrypt_chat(
        &mut contacts.alice,
        contacts.alice_contact,
        "conflicting bridge message".to_owned(),
        3600,
        4,
    )
    .unwrap_or_else(|_| panic!("conflict fixture should be encrypted"));
    let conflict = Envelope::try_from_fields(
        pending.protocol_version(),
        *pending.message_id().as_bytes(),
        [0x77; 16],
        u64::from(pending.ttl_seconds().get()),
        u64::from(pending.max_hops().get()),
        pending.priority().as_raw(),
        pending.protected_payload().as_bytes().to_vec(),
    )
    .unwrap_or_else(|_| panic!("conflicting Envelope fixture should be valid"));
    assert_eq!(
        node.enqueue_origin(conflict)
            .unwrap_or_else(|_| panic!("conflicting Envelope should enter the test queue"))
            .outcome(),
        EnqueueOutcome::Stored
    );
    assert_eq!(
        export_pending_outbox(&mut contacts.alice, &mut node),
        Err(BridgeError::QueueConflict)
    );
    assert!(
        contacts
            .alice
            .pending_outbox()
            .is_ok_and(|items| items.len() == 1)
    );
    node.stop()
        .unwrap_or_else(|_| panic!("conflict test node should stop cleanly"));
    assert_eq!(
        export_pending_outbox(&mut contacts.alice, &mut node),
        Err(BridgeError::Node(NodeError::NotRunning))
    );
    assert!(
        contacts
            .alice
            .pending_outbox()
            .is_ok_and(|items| items.len() == 1)
    );
}

#[test]
fn incoming_chat_is_opened_once_and_crash_recovery_does_not_return_text_twice() {
    let alice_path = TestPath::new("incoming-alice");
    let bob_path = TestPath::new("incoming-bob");
    let node_path = TestPath::new("incoming-node");
    let mut contacts = contact_stores(alice_path.path(), bob_path.path());
    let mut node = start_node(node_path.path());

    let first = encrypt_chat(
        &mut contacts.alice,
        contacts.alice_contact,
        "opened exactly once".to_owned(),
        3600,
        4,
    )
    .unwrap_or_else(|_| panic!("first incoming chat should be encrypted"));
    let first_id = first.message_id();
    node.enqueue_origin(first.clone())
        .unwrap_or_else(|_| panic!("first incoming chat should enter Bob's queue"));
    let result = process_incoming_chat(&mut contacts.bob, &mut node, first_id)
        .unwrap_or_else(|_| panic!("first incoming chat should be processed"));
    assert!(!format!("{result:?}").contains("opened exactly once"));
    let IncomingChatResult::Opened(chat) = result else {
        panic!("first incoming chat should return its text");
    };
    assert_eq!(chat.text(), "opened exactly once");
    assert!(node.queue().get(first_id).is_none());
    drop(node);
    let mut node = start_node(node_path.path());
    assert_eq!(
        node.enqueue_origin(first)
            .unwrap_or_else(|_| panic!("replayed chat should be handled"))
            .outcome(),
        EnqueueOutcome::DuplicateTombstone
    );

    let second = encrypt_chat(
        &mut contacts.alice,
        contacts.alice_contact,
        "stored before queue cleanup".to_owned(),
        3600,
        4,
    )
    .unwrap_or_else(|_| panic!("second incoming chat should be encrypted"));
    let second_id = second.message_id();
    node.enqueue_origin(second.clone())
        .unwrap_or_else(|_| panic!("second incoming chat should enter Bob's queue"));
    let received = decrypt_chat(&mut contacts.bob, contacts.bob_contact, &second)
        .unwrap_or_else(|_| panic!("crash fixture should commit the received chat"));
    assert_eq!(received.text(), "stored before queue cleanup");
    drop(received);
    drop(node);
    let mut node = start_node(node_path.path());

    assert!(matches!(
        process_incoming_chat(&mut contacts.bob, &mut node, second_id),
        Ok(IncomingChatResult::Recovered)
    ));
    assert!(node.queue().get(second_id).is_none());
    assert!(matches!(
        process_incoming_chat(&mut contacts.bob, &mut node, second_id),
        Ok(IncomingChatResult::Missing)
    ));
}

#[test]
fn unknown_recipient_hint_is_left_for_forwarding_without_crypto_attempt() {
    let alice_path = TestPath::new("unknown-alice");
    let bob_path = TestPath::new("unknown-bob");
    let node_path = TestPath::new("unknown-node");
    let mut contacts = contact_stores(alice_path.path(), bob_path.path());
    let mut node = start_node(node_path.path());
    let envelope = Envelope::try_from_fields(
        1,
        [0x51; 16],
        [0x99; 16],
        3600,
        4,
        0,
        b"untrusted opaque payload".to_vec(),
    )
    .unwrap_or_else(|_| panic!("unknown-recipient fixture should be a valid Envelope"));
    let identifier = envelope.message_id();
    node.enqueue_origin(envelope)
        .unwrap_or_else(|_| panic!("unknown-recipient fixture should enter the queue"));

    assert!(matches!(
        process_incoming_chat(&mut contacts.bob, &mut node, identifier),
        Ok(IncomingChatResult::NotForThisProfile)
    ));
    assert!(matches!(
        process_incoming_chat(&mut contacts.bob, &mut node, identifier),
        Ok(IncomingChatResult::NotForThisProfile)
    ));
    assert!(node.queue().get(identifier).is_some());
    assert_eq!(contacts.bob.has_received_chat([0x51; 16]), Ok(false));
}

#[test]
fn protected_changes_are_rejected_without_committing_the_candidate_ratchet() {
    let alice_path = TestPath::new("tamper-alice");
    let bob_path = TestPath::new("tamper-bob");
    let node_path = TestPath::new("tamper-node");
    let mut contacts = contact_stores(alice_path.path(), bob_path.path());
    let mut node = start_node(node_path.path());

    let mut originals = Vec::new();
    for text in [
        "outer identifier fixture",
        "ttl fixture",
        "hop limit fixture",
        "ciphertext fixture",
        "later valid message",
    ] {
        originals.push(
            encrypt_chat(
                &mut contacts.alice,
                contacts.alice_contact,
                text.to_owned(),
                3600,
                4,
            )
            .unwrap_or_else(|_| panic!("tamper fixture should be encrypted")),
        );
    }

    let first = &originals[0];
    let changed_identifier = Envelope::try_from_fields(
        first.protocol_version(),
        [0xd1; 16],
        *first.recipient_hint().as_bytes(),
        u64::from(first.ttl_seconds().get()),
        u64::from(first.max_hops().get()),
        first.priority().as_raw(),
        first.protected_payload().as_bytes().to_vec(),
    )
    .unwrap_or_else(|_| panic!("changed identifier fixture should be valid"));

    let second = &originals[1];
    let changed_ttl = Envelope::try_from_fields(
        second.protocol_version(),
        *second.message_id().as_bytes(),
        *second.recipient_hint().as_bytes(),
        u64::from(second.ttl_seconds().get()) + 1,
        u64::from(second.max_hops().get()),
        second.priority().as_raw(),
        second.protected_payload().as_bytes().to_vec(),
    )
    .unwrap_or_else(|_| panic!("changed TTL fixture should be valid"));

    let third = &originals[2];
    let changed_hop_limit = Envelope::try_from_fields(
        third.protocol_version(),
        *third.message_id().as_bytes(),
        *third.recipient_hint().as_bytes(),
        u64::from(third.ttl_seconds().get()),
        u64::from(third.max_hops().get()) - 1,
        third.priority().as_raw(),
        third.protected_payload().as_bytes().to_vec(),
    )
    .unwrap_or_else(|_| panic!("changed hop limit fixture should be valid"));

    let fourth = &originals[3];
    let mut damaged_payload = fourth.protected_payload().as_bytes().to_vec();
    let last = damaged_payload
        .last_mut()
        .unwrap_or_else(|| panic!("protected payload should not be empty"));
    *last ^= 1;
    let changed_payload = Envelope::try_from_fields(
        fourth.protocol_version(),
        *fourth.message_id().as_bytes(),
        *fourth.recipient_hint().as_bytes(),
        u64::from(fourth.ttl_seconds().get()),
        u64::from(fourth.max_hops().get()),
        fourth.priority().as_raw(),
        damaged_payload,
    )
    .unwrap_or_else(|_| panic!("changed payload fixture should be valid"));

    for (envelope, expected_error) in [
        (changed_identifier, CryptoError::EnvelopeMismatch),
        (changed_ttl, CryptoError::EnvelopeMismatch),
        (changed_hop_limit, CryptoError::EnvelopeMismatch),
        (changed_payload, CryptoError::OlmRejected),
    ] {
        let identifier = envelope.message_id();
        assert_eq!(
            node.enqueue_origin(envelope)
                .unwrap_or_else(|_| panic!("tampered Envelope should enter the test queue"))
                .outcome(),
            EnqueueOutcome::Stored
        );
        let result = process_incoming_chat(&mut contacts.bob, &mut node, identifier);
        assert!(matches!(
            result,
            Err(BridgeError::Crypto(error)) if error == expected_error
        ));
        assert!(node.queue().get(identifier).is_some());
        assert_eq!(
            contacts.bob.has_received_chat(*identifier.as_bytes()),
            Ok(false)
        );
    }

    let valid = originals
        .pop()
        .unwrap_or_else(|| panic!("later valid fixture should exist"));
    let valid_identifier = valid.message_id();
    node.enqueue_origin(valid.clone())
        .unwrap_or_else(|_| panic!("later valid message should enter Bob's queue"));
    let opened = process_incoming_chat(&mut contacts.bob, &mut node, valid_identifier)
        .unwrap_or_else(|_| panic!("later valid message should still open"));
    let IncomingChatResult::Opened(chat) = opened else {
        panic!("later valid message should return its text");
    };
    assert_eq!(chat.text(), "later valid message");
    drop(chat);

    assert_eq!(
        node.enqueue_origin(valid)
            .unwrap_or_else(|_| panic!("replay should be checked against the tombstone"))
            .outcome(),
        EnqueueOutcome::DuplicateTombstone
    );
    assert!(matches!(
        process_incoming_chat(&mut contacts.bob, &mut node, valid_identifier),
        Ok(IncomingChatResult::Missing)
    ));
}
