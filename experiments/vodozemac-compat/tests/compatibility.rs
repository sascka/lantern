// SPDX-License-Identifier: MPL-2.0

use std::{error::Error, io};

use vodozemac::olm::{
    Account, AccountPickle, DecryptionError, InboundCreationResult, OlmMessage, Session,
    SessionConfig, SessionPickle,
};

const PICKLE_KEY: [u8; 32] = [0x51; 32];
const WRONG_PICKLE_KEY: [u8; 32] = [0xA7; 32];
const INITIAL_MESSAGE: &[u8] = b"lantern compatibility handshake";

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct EstablishedPair {
    alice_account: Account,
    bob_account: Account,
    alice_session: Session,
    bob_session: Session,
}

fn test_error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn create_inbound_result(
    plaintext: &[u8],
) -> TestResult<(Account, Account, Session, InboundCreationResult)> {
    let alice = Account::new();
    let mut bob = Account::new();

    bob.generate_one_time_keys(1);
    let one_time_key = bob
        .one_time_keys()
        .values()
        .next()
        .copied()
        .ok_or_else(|| test_error("Bob did not generate a one-time key"))?;
    bob.mark_keys_as_published();

    let mut alice_session = alice.create_outbound_session(
        SessionConfig::version_1(),
        bob.curve25519_key(),
        one_time_key,
    )?;
    let first_message = alice_session.encrypt(plaintext)?;
    let pre_key_message = match first_message {
        OlmMessage::PreKey(message) => message,
        OlmMessage::Normal(_) => {
            return Err(test_error("the first outbound message was not a pre-key message").into());
        }
    };

    let inbound = bob.create_inbound_session(
        SessionConfig::version_1(),
        alice.curve25519_key(),
        &pre_key_message,
    )?;

    Ok((alice, bob, alice_session, inbound))
}

fn established_pair() -> TestResult<EstablishedPair> {
    let (alice_account, bob_account, mut alice_session, inbound) =
        create_inbound_result(INITIAL_MESSAGE)?;
    assert_eq!(inbound.plaintext, INITIAL_MESSAGE);

    let mut bob_session = inbound.session;
    let reply = bob_session.encrypt(b"handshake reply")?;
    assert_eq!(alice_session.decrypt(&reply)?, b"handshake reply");

    Ok(EstablishedPair {
        alice_account,
        bob_account,
        alice_session,
        bob_session,
    })
}

fn restore_session(encrypted: &str) -> TestResult<Session> {
    let pickle = SessionPickle::from_encrypted(encrypted, &PICKLE_KEY)?;
    Ok(Session::from_pickle(pickle))
}

#[test]
fn establishes_an_asynchronous_session_and_replies() -> TestResult {
    let pair = established_pair()?;

    assert_eq!(
        pair.alice_session.session_id(),
        pair.bob_session.session_id()
    );
    assert_eq!(
        pair.alice_session.session_config(),
        SessionConfig::version_1()
    );
    assert_eq!(
        pair.bob_session.session_config(),
        SessionConfig::version_1()
    );

    Ok(())
}

#[test]
fn rejects_each_single_byte_mutation_without_consuming_the_valid_message() -> TestResult {
    let mut pair = established_pair()?;
    let plaintext = b"mutation sentinel: 91b0f19d";
    let valid_message = pair.alice_session.encrypt(plaintext)?;
    let (message_type, encoded) = valid_message.to_parts();
    let receiver_state = pair.bob_session.pickle().encrypt(&PICKLE_KEY);

    assert_eq!(
        message_type, 1,
        "established sessions must use normal messages"
    );

    for byte_index in 0..encoded.len() {
        let mut mutated = encoded.clone();
        mutated[byte_index] ^= 1;
        let Ok(mutated_message) = OlmMessage::from_parts(message_type, &mutated) else {
            continue;
        };

        let mut receiver = restore_session(&receiver_state)?;
        assert!(
            receiver.decrypt(&mutated_message).is_err(),
            "mutation at encoded byte {byte_index} was accepted"
        );
        assert_eq!(
            receiver.decrypt(&valid_message)?,
            plaintext,
            "mutation at encoded byte {byte_index} changed receiver state"
        );
    }

    Ok(())
}

#[test]
fn rejects_a_replay_and_continues_with_the_next_message() -> TestResult {
    let mut pair = established_pair()?;
    let first = pair.alice_session.encrypt(b"first normal message")?;

    assert_eq!(pair.bob_session.decrypt(&first)?, b"first normal message");
    assert!(matches!(
        pair.bob_session.decrypt(&first),
        Err(DecryptionError::MissingMessageKey(_))
    ));

    let second = pair.alice_session.encrypt(b"message after replay")?;
    assert_eq!(pair.bob_session.decrypt(&second)?, b"message after replay");

    Ok(())
}

#[test]
fn decrypts_32_messages_in_reverse_order() -> TestResult {
    let mut pair = established_pair()?;
    let mut messages = Vec::with_capacity(32);

    for index in 0..32 {
        let plaintext = format!("reverse-order-{index}");
        messages.push((plaintext.clone(), pair.alice_session.encrypt(plaintext)?));
    }

    for (plaintext, message) in messages.iter().rev() {
        assert_eq!(pair.bob_session.decrypt(message)?, plaintext.as_bytes());
    }

    Ok(())
}

#[test]
fn confirms_the_40_skipped_key_limit() -> TestResult {
    let mut pair = established_pair()?;
    let mut messages = Vec::with_capacity(42);

    for index in 0..42 {
        let plaintext = format!("skipped-key-{index}");
        messages.push((plaintext.clone(), pair.alice_session.encrypt(plaintext)?));
    }

    assert_eq!(
        pair.bob_session.decrypt(&messages[41].1)?,
        messages[41].0.as_bytes()
    );
    assert!(matches!(
        pair.bob_session.decrypt(&messages[0].1),
        Err(DecryptionError::MissingMessageKey(_))
    ));

    for (plaintext, message) in messages.iter().skip(1).take(40) {
        assert_eq!(pair.bob_session.decrypt(message)?, plaintext.as_bytes());
    }

    Ok(())
}

#[test]
fn encrypted_pickles_restore_accounts_and_live_sessions() -> TestResult {
    let pair = established_pair()?;
    let alice_account_pickle = pair.alice_account.pickle().encrypt(&PICKLE_KEY);
    let bob_account_pickle = pair.bob_account.pickle().encrypt(&PICKLE_KEY);
    let alice_pickle = pair.alice_session.pickle().encrypt(&PICKLE_KEY);
    let bob_pickle = pair.bob_session.pickle().encrypt(&PICKLE_KEY);

    let restored_alice_account = Account::from_pickle(AccountPickle::from_encrypted(
        &alice_account_pickle,
        &PICKLE_KEY,
    )?);
    let restored_bob_account = Account::from_pickle(AccountPickle::from_encrypted(
        &bob_account_pickle,
        &PICKLE_KEY,
    )?);
    let mut restored_alice = restore_session(&alice_pickle)?;
    let mut restored_bob = restore_session(&bob_pickle)?;

    assert_eq!(
        pair.bob_account.identity_keys(),
        restored_bob_account.identity_keys()
    );
    assert_eq!(
        pair.alice_account.identity_keys(),
        restored_alice_account.identity_keys()
    );

    let message = restored_alice.encrypt(b"message after restore")?;
    assert_eq!(restored_bob.decrypt(&message)?, b"message after restore");
    let reply = restored_bob.encrypt(b"reply after restore")?;
    assert_eq!(restored_alice.decrypt(&reply)?, b"reply after restore");

    Ok(())
}

#[test]
fn rejects_encrypted_pickles_with_the_wrong_key() -> TestResult {
    let pair = established_pair()?;
    let account_pickle = pair.bob_account.pickle().encrypt(&PICKLE_KEY);
    let session_pickle = pair.bob_session.pickle().encrypt(&PICKLE_KEY);

    assert!(AccountPickle::from_encrypted(&account_pickle, &WRONG_PICKLE_KEY).is_err());
    assert!(SessionPickle::from_encrypted(&session_pickle, &WRONG_PICKLE_KEY).is_err());

    Ok(())
}

#[test]
fn debug_probe_records_the_plaintext_exposure_boundary() -> TestResult {
    let plaintext = b"debug plaintext sentinel";
    let (_, _, _, inbound) = create_inbound_result(plaintext)?;
    let plaintext_debug = format!("{:?}", plaintext.as_slice());
    let inbound_debug = format!("{inbound:?}");
    let session_debug = format!("{:?}", inbound.session);

    assert!(
        inbound_debug.contains(&plaintext_debug),
        "InboundCreationResult no longer exposes plaintext through Debug; review this finding"
    );
    assert!(!session_debug.contains(&plaintext_debug));

    let mut pair = established_pair()?;
    let message = pair.alice_session.encrypt(plaintext)?;
    let (message_type, mut encoded) = message.to_parts();
    let last_byte = encoded
        .last_mut()
        .ok_or_else(|| test_error("encrypted message was empty"))?;
    *last_byte ^= 1;
    let mutated = OlmMessage::from_parts(message_type, &encoded)?;
    let decryption_error = match pair.bob_session.decrypt(&mutated) {
        Ok(_) => return Err(test_error("modified message was accepted").into()),
        Err(error) => error,
    };
    let ciphertext_debug = format!("{encoded:?}");
    let error_text = format!("{decryption_error:?} {decryption_error}");
    let receiver_debug = format!("{:?}", pair.bob_session);
    let plaintext_text = String::from_utf8_lossy(plaintext);

    assert!(!error_text.contains(plaintext_text.as_ref()));
    assert!(!error_text.contains(&plaintext_debug));
    assert!(!error_text.contains(&ciphertext_debug));
    assert!(!receiver_debug.contains(&plaintext_debug));

    Ok(())
}
