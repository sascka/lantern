// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use lantern_core::{Envelope, PROTOCOL_VERSION, encode_envelope};
use lantern_secret_storage::{ContactId, SecretStorageError, SecretStore};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    CommonFields, Content, CryptoError, InnerMessage, OlmMessageType, ProtectedOlmMessage,
    decode_inner_message, decode_protected_payload, encode_inner_message, encode_protected_payload,
};

pub struct ReceivedChat {
    text: Zeroizing<String>,
}

impl ReceivedChat {
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for ReceivedChat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceivedChat")
            .field("text_length", &self.text.len())
            .finish()
    }
}

pub fn encrypt_chat(
    store: &mut SecretStore,
    contact_id: ContactId,
    text: String,
    ttl_seconds: u64,
    max_hops: u64,
) -> Result<Envelope, CryptoError> {
    let content = Content::chat(text)?;
    let message_id = random_array()?;
    let recipient_hint = store
        .outbound_recipient_hint(contact_id)
        .map_err(map_storage_error)?;
    let common = CommonFields::try_new(message_id, recipient_hint, ttl_seconds, max_hops)?;
    let inner = InnerMessage::try_new(common, content)?;
    inner.validate_olm_type(OlmMessageType::Normal)?;
    let mut plaintext = Zeroizing::new(encode_inner_message(&inner)?);

    let mut candidate = store.load_session(contact_id).map_err(map_storage_error)?;
    let olm = candidate
        .encrypt(plaintext.as_slice())
        .map_err(|_| CryptoError::OlmRejected)?;
    plaintext.as_mut_slice().zeroize();
    let protected = ProtectedOlmMessage::from_olm(&olm)?;
    if protected.message_type() != OlmMessageType::Normal {
        return Err(CryptoError::StateRejected);
    }
    let protected_payload = encode_protected_payload(&protected)?;
    let envelope = Envelope::try_from_fields(
        PROTOCOL_VERSION,
        message_id,
        recipient_hint,
        ttl_seconds,
        max_hops,
        0,
        protected_payload,
    )
    .map_err(|_| CryptoError::InvalidValue)?;
    if !inner.matches_envelope(&envelope) {
        return Err(CryptoError::EnvelopeMismatch);
    }
    let envelope_cbor = encode_envelope(&envelope).map_err(|_| CryptoError::InvalidValue)?;
    store
        .commit_outgoing(contact_id, &candidate, message_id, &envelope_cbor)
        .map_err(map_storage_error)?;
    Ok(envelope)
}

pub fn decrypt_chat(
    store: &mut SecretStore,
    contact_id: ContactId,
    envelope: &Envelope,
) -> Result<ReceivedChat, CryptoError> {
    let protected = decode_protected_payload(envelope.protected_payload().as_bytes())?;
    if protected.message_type() != OlmMessageType::Normal {
        return Err(CryptoError::UnsupportedType);
    }
    let olm = protected.to_olm()?;
    let message_id = *envelope.message_id().as_bytes();
    store
        .reserve_contact_attempt(message_id, contact_id)
        .map_err(map_storage_error)?;

    let mut candidate = store.load_session(contact_id).map_err(map_storage_error)?;
    let plaintext = candidate
        .decrypt(&olm)
        .map_err(|_| CryptoError::OlmRejected)?;
    if plaintext.is_empty() || plaintext.len() > crate::INNER_MESSAGE_MAX_BYTES {
        return Err(CryptoError::InvalidValue);
    }
    let plaintext = Zeroizing::new(plaintext);
    let inner = decode_inner_message(&plaintext)?;
    inner.validate_olm_type(protected.message_type())?;
    if !inner.matches_envelope(envelope) {
        return Err(CryptoError::EnvelopeMismatch);
    }
    let Content::ChatMessage(text) = inner.content() else {
        return Err(CryptoError::StateRejected);
    };
    store
        .commit_received_chat(message_id, contact_id, &candidate, text)
        .map_err(map_storage_error)?;
    Ok(ReceivedChat {
        text: Zeroizing::new(text.to_string()),
    })
}

fn random_array<const LENGTH: usize>() -> Result<[u8; LENGTH], CryptoError> {
    let mut bytes = [0; LENGTH];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::Entropy)?;
    Ok(bytes)
}

fn map_storage_error(error: SecretStorageError) -> CryptoError {
    match error {
        SecretStorageError::UnknownContact => CryptoError::StateRejected,
        SecretStorageError::RateLimited => CryptoError::RateLimited,
        SecretStorageError::AttemptAlreadyProcessed => CryptoError::StateRejected,
        _ => CryptoError::StorageFailed,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use lantern_core::{Envelope, encode_envelope};
    use lantern_secret_storage::{ContactId, KdfHeader, NewContact, Passphrase, SecretStore};
    use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};

    use super::{decrypt_chat, encrypt_chat};
    use crate::CryptoError;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TemporaryPath(PathBuf);

    impl TemporaryPath {
        fn new(label: &str) -> Self {
            let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "lantern-crypto-engine-{}-{sequence}-{label}.sqlite3",
                std::process::id()
            )))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TemporaryPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let mut journal = self.0.as_os_str().to_os_string();
            journal.push("-journal");
            let _ = fs::remove_file(PathBuf::from(journal));
        }
    }

    fn established_sessions() -> (Account, Account, Session, Session) {
        let alice = Account::new();
        let mut bob = Account::new();
        bob.generate_one_time_keys(1);
        let one_time_key = bob.one_time_keys().values().next().copied();
        let Some(one_time_key) = one_time_key else {
            panic!("test one-time key was not generated");
        };
        let session = alice.create_outbound_session(
            SessionConfig::version_1(),
            bob.curve25519_key(),
            one_time_key,
        );
        let Ok(mut alice_session) = session else {
            panic!("test outbound session could not be created");
        };
        let first = alice_session.encrypt(b"initial handshake");
        let Ok(OlmMessage::PreKey(first)) = first else {
            panic!("test first message was not pre-key");
        };
        let inbound =
            bob.create_inbound_session(SessionConfig::version_1(), alice.curve25519_key(), &first);
        let Ok(inbound) = inbound else {
            panic!("test inbound session could not be created");
        };
        let mut bob_session = inbound.session;
        let reply = bob_session.encrypt(b"handshake reply");
        let Ok(reply) = reply else {
            panic!("test handshake reply could not be encrypted");
        };
        let decrypted = alice_session.decrypt(&reply);
        assert!(decrypted.is_ok_and(|value| value == b"handshake reply"));
        (alice, bob, alice_session, bob_session)
    }

    #[test]
    fn encrypted_chat_survives_outbox_recovery_and_rolls_back_rejected_candidate() {
        let alice_path = TemporaryPath::new("alice");
        let bob_path = TemporaryPath::new("bob");
        let header = KdfHeader::generate();
        let Ok(header) = header else {
            panic!("test KDF header could not be generated");
        };
        let passphrase = Passphrase::new("engine integration passphrase".to_owned());
        let Ok(passphrase) = passphrase else {
            panic!("test passphrase was rejected");
        };
        let key = header.derive_database_key(&passphrase);
        let Ok(key) = key else {
            panic!("test database key could not be derived");
        };
        let alice_store = SecretStore::create(alice_path.path(), &key);
        let bob_store = SecretStore::create(bob_path.path(), &key);
        let (Ok(mut alice_store), Ok(mut bob_store)) = (alice_store, bob_store) else {
            panic!("test secret stores could not be created");
        };

        let (alice_account, bob_account, alice_session, bob_session) = established_sessions();
        let alice_contact = ContactId::from_bytes([0xa1; 16]);
        let bob_contact = ContactId::from_bytes([0xb2; 16]);
        let alice_hint = [0x31; 16];
        let bob_hint = [0x42; 16];
        assert!(
            alice_store
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
                .is_ok()
        );
        assert!(
            bob_store
                .add_active_contact(
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
                .is_ok()
        );

        let envelope = encrypt_chat(
            &mut alice_store,
            alice_contact,
            "private integration message".to_owned(),
            3600,
            4,
        );
        let Ok(envelope) = envelope else {
            panic!("test chat could not be encrypted: {envelope:?}");
        };
        let pending = alice_store.pending_outbox();
        let Ok(pending) = pending else {
            panic!("test outbox could not be read");
        };
        assert_eq!(pending.len(), 1);
        let encoded_envelope = encode_envelope(&envelope);
        let Ok(encoded_envelope) = encoded_envelope else {
            panic!("test envelope could not be encoded");
        };
        assert_eq!(pending[0].envelope_cbor(), encoded_envelope);

        let changed = Envelope::try_from_fields(
            envelope.protocol_version(),
            [0xee; 16],
            *envelope.recipient_hint().as_bytes(),
            u64::from(envelope.ttl_seconds().get()),
            u64::from(envelope.max_hops().get()),
            envelope.priority().as_raw(),
            envelope.protected_payload().as_bytes().to_vec(),
        );
        let Ok(changed) = changed else {
            panic!("changed test envelope was rejected by core");
        };
        assert!(matches!(
            decrypt_chat(&mut bob_store, bob_contact, &changed),
            Err(CryptoError::EnvelopeMismatch)
        ));

        let received = decrypt_chat(&mut bob_store, bob_contact, &envelope);
        let Ok(received) = received else {
            panic!("valid chat was not decrypted after candidate rollback");
        };
        assert_eq!(received.text(), "private integration message");
        assert!(!format!("{received:?}").contains("private integration message"));
        assert!(matches!(
            decrypt_chat(&mut bob_store, bob_contact, &envelope),
            Err(CryptoError::StateRejected)
        ));
    }
}
