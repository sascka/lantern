// SPDX-License-Identifier: MPL-2.0

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use lantern_core::QueueLimits;
use lantern_crypto::{
    ContactBundle, ContactResponse, Invitation, accept_initiator_confirmation,
    accept_receiver_confirmation, build_initiator_confirmation, decode_contact_qr,
    encode_invitation_qr, encode_response_qr,
};
use lantern_diagnostics::JournalLimits;
use lantern_node::NodeRuntime;
use lantern_secret_storage::{ContactId, NewContact, Passphrase, SecretProfile};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let number = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "lantern-persistent-contact-{label}-{}-{number}",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let _ = fs::remove_file(&self.0);
    }
}

fn passphrase(value: &str) -> Passphrase {
    Passphrase::new(value.to_owned())
        .unwrap_or_else(|_| panic!("persistent contact test passphrase should be accepted"))
}

#[test]
fn verified_contacts_survive_reopen_while_relay_has_only_an_open_queue() {
    let alice_directory = TestDirectory::new("alice");
    let bob_directory = TestDirectory::new("bob");
    let relay_directory = TestDirectory::new("relay");
    let alice_passphrase = passphrase("Alice local profile passphrase 2026");
    let bob_passphrase = passphrase("Bob local profile passphrase 2026");
    let mut alice = SecretProfile::create(alice_directory.path(), &alice_passphrase)
        .unwrap_or_else(|_| panic!("Alice secret profile should be created"));
    let mut bob = SecretProfile::create(bob_directory.path(), &bob_passphrase)
        .unwrap_or_else(|_| panic!("Bob secret profile should be created"));
    let alice_profile_id = alice.profile_id();
    let bob_profile_id = bob.profile_id();

    let mut alice_account = alice
        .load_account()
        .unwrap_or_else(|_| panic!("Alice account should be loaded"));
    let bob_account = bob
        .load_account()
        .unwrap_or_else(|_| panic!("Bob account should be loaded"));
    let alice_identity = alice_account.identity_keys();
    let bob_identity = bob_account.identity_keys();

    let (invitation, alice_sas) = Invitation::create(&mut alice_account)
        .unwrap_or_else(|_| panic!("Alice invitation should be created"));
    let invitation_qr = encode_invitation_qr(&invitation)
        .unwrap_or_else(|_| panic!("Alice invitation should be encoded"));
    let invitation = match decode_contact_qr(&invitation_qr) {
        Ok(ContactBundle::Invitation(invitation)) => invitation,
        _ => panic!("Bob should decode one signed invitation"),
    };

    let (response, bob_sas) = ContactResponse::create(&bob_account, &invitation)
        .unwrap_or_else(|_| panic!("Bob response should be created"));
    let response_qr =
        encode_response_qr(&response).unwrap_or_else(|_| panic!("Bob response should be encoded"));
    let response = match decode_contact_qr(&response_qr) {
        Ok(ContactBundle::Response(response)) => response,
        _ => panic!("Alice should decode one signed response"),
    };

    let alice_sas = alice_sas
        .finish(&invitation, &response)
        .unwrap_or_else(|_| panic!("Alice SAS should be derived"));
    let bob_sas = bob_sas
        .finish(&invitation, &response)
        .unwrap_or_else(|_| panic!("Bob SAS should be derived"));
    assert_eq!(alice_sas, bob_sas);

    let initiator = build_initiator_confirmation(&bob_account, &invitation, &response)
        .unwrap_or_else(|_| panic!("Bob confirmation should be created"));
    let (bob_candidate, initiator_envelope) = initiator.into_parts();
    let accepted =
        accept_initiator_confirmation(alice_account, &invitation, &response, &initiator_envelope)
            .unwrap_or_else(|_| panic!("Alice should accept Bob's confirmation"));
    let (alice_account, alice_session, receiver_envelope) = accepted.into_parts();
    let bob_session =
        accept_receiver_confirmation(bob_candidate, &invitation, &response, &receiver_envelope)
            .unwrap_or_else(|_| panic!("Bob should accept Alice's confirmation"));
    assert_eq!(alice_session.session_id(), bob_session.session_id());

    let alice_contact_id =
        ContactId::generate().unwrap_or_else(|_| panic!("Alice contact ID should be generated"));
    let bob_contact_id =
        ContactId::generate().unwrap_or_else(|_| panic!("Bob contact ID should be generated"));
    alice
        .secret_store_mut()
        .add_active_contact_with_account(
            NewContact {
                contact_id: alice_contact_id,
                display_name: "Bob".to_owned(),
                signing_identity_key: *response.signing_identity_key(),
                curve_identity_key: *response.curve_identity_key(),
                inbound_recipient_hint: *invitation.inbound_recipient_hint(),
                outbound_recipient_hint: *response.inbound_recipient_hint(),
            },
            &alice_session,
            &alice_account,
        )
        .unwrap_or_else(|_| panic!("Alice verified contact should be committed"));
    bob.secret_store_mut()
        .add_active_contact(
            NewContact {
                contact_id: bob_contact_id,
                display_name: "Alice".to_owned(),
                signing_identity_key: *invitation.signing_identity_key(),
                curve_identity_key: *invitation.curve_identity_key(),
                inbound_recipient_hint: *response.inbound_recipient_hint(),
                outbound_recipient_hint: *invitation.inbound_recipient_hint(),
            },
            &bob_session,
        )
        .unwrap_or_else(|_| panic!("Bob verified contact should be committed"));
    drop(alice);
    drop(bob);

    let alice = SecretProfile::open(alice_directory.path(), &alice_passphrase)
        .unwrap_or_else(|_| panic!("Alice secret profile should reopen"));
    let bob = SecretProfile::open(bob_directory.path(), &bob_passphrase)
        .unwrap_or_else(|_| panic!("Bob secret profile should reopen"));
    assert_eq!(alice.profile_id(), alice_profile_id);
    assert_eq!(bob.profile_id(), bob_profile_id);
    assert_eq!(
        alice.load_account().map(|account| account.identity_keys()),
        Ok(alice_identity)
    );
    assert_eq!(
        bob.load_account().map(|account| account.identity_keys()),
        Ok(bob_identity)
    );

    let alice_contact = alice
        .secret_store()
        .active_contact(alice_contact_id)
        .unwrap_or_else(|_| panic!("Alice contact lookup should succeed"))
        .unwrap_or_else(|| panic!("Alice should retain Bob as an active contact"));
    let bob_contact = bob
        .secret_store()
        .active_contact(bob_contact_id)
        .unwrap_or_else(|_| panic!("Bob contact lookup should succeed"))
        .unwrap_or_else(|| panic!("Bob should retain Alice as an active contact"));
    assert_eq!(alice_contact.display_name(), "Bob");
    assert_eq!(bob_contact.display_name(), "Alice");
    assert_eq!(
        alice_contact.signing_identity_key(),
        response.signing_identity_key()
    );
    assert_eq!(
        bob_contact.signing_identity_key(),
        invitation.signing_identity_key()
    );
    assert_eq!(
        alice_contact.outbound_recipient_hint(),
        bob_contact.inbound_recipient_hint()
    );
    assert_eq!(
        bob_contact.outbound_recipient_hint(),
        alice_contact.inbound_recipient_hint()
    );
    let alice_session = alice
        .secret_store()
        .load_session(alice_contact_id)
        .unwrap_or_else(|_| panic!("Alice session should reopen"));
    let bob_session = bob
        .secret_store()
        .load_session(bob_contact_id)
        .unwrap_or_else(|_| panic!("Bob session should reopen"));
    assert_eq!(alice_session.session_id(), bob_session.session_id());

    fs::create_dir(relay_directory.path())
        .unwrap_or_else(|_| panic!("Relay directory should be created"));
    let relay_database = relay_directory.path().join("queue.sqlite3");
    let relay = NodeRuntime::start(
        &relay_database,
        QueueLimits::default(),
        JournalLimits::default(),
    )
    .unwrap_or_else(|_| panic!("Relay node should start without a secret profile"));
    assert!(relay.queue().is_empty());
    assert!(!relay.persistent_diagnostics_enabled());
    drop(relay);

    let relay_entries = fs::read_dir(relay_directory.path())
        .unwrap_or_else(|_| panic!("Relay directory should be readable"))
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect::<Vec<_>>();
    assert!(
        relay_entries
            .iter()
            .all(|name| !name.to_string_lossy().starts_with("secrets"))
    );
    let relay_bytes = fs::read(&relay_database)
        .unwrap_or_else(|_| panic!("Relay queue database should be readable"));
    for marker in [
        alice_identity.ed25519.as_bytes().as_slice(),
        bob_identity.ed25519.as_bytes().as_slice(),
        invitation.invitation_secret().as_slice(),
        response.response_secret().as_slice(),
        invitation.inbound_recipient_hint().as_slice(),
        response.inbound_recipient_hint().as_slice(),
    ] {
        assert!(
            !relay_bytes
                .windows(marker.len())
                .any(|window| window == marker)
        );
    }
}
