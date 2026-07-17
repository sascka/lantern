// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use lantern_core::{Envelope, PROTOCOL_VERSION};
use vodozemac::{
    Curve25519PublicKey,
    olm::{Account, OlmMessage, Session, SessionConfig},
};
use zeroize::Zeroizing;

use crate::{
    CommonFields, ConfirmFields, ContactResponse, Content, CryptoError, InnerMessage, Invitation,
    OlmMessageType, ProtectedOlmMessage, decode_inner_message, decode_protected_payload,
    encode_inner_message, encode_protected_payload,
};

const CONFIRM_TTL_SECONDS: u64 = 604_800;
const CONFIRM_MAX_HOPS: u64 = 2;

pub struct InitiatorConfirmation {
    session: Session,
    envelope: Envelope,
}

impl InitiatorConfirmation {
    pub const fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    pub fn into_parts(self) -> (Session, Envelope) {
        (self.session, self.envelope)
    }
}

pub struct AcceptedInitiator {
    account: Account,
    session: Session,
    receiver_confirmation: Envelope,
}

impl AcceptedInitiator {
    pub const fn receiver_confirmation(&self) -> &Envelope {
        &self.receiver_confirmation
    }

    pub fn into_parts(self) -> (Account, Session, Envelope) {
        (self.account, self.session, self.receiver_confirmation)
    }
}

impl fmt::Debug for InitiatorConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitiatorConfirmation")
            .field("session", &"redacted")
            .field("envelope", &self.envelope)
            .finish()
    }
}

impl fmt::Debug for AcceptedInitiator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedInitiator")
            .field("account", &"redacted")
            .field("session", &"redacted")
            .field("receiver_confirmation", &self.receiver_confirmation)
            .finish()
    }
}

pub fn build_initiator_confirmation(
    bob_account: &Account,
    invitation: &Invitation,
    response: &ContactResponse,
) -> Result<InitiatorConfirmation, CryptoError> {
    validate_bundle_pair(invitation, response)?;
    if bob_account.ed25519_key().as_bytes() != response.signing_identity_key()
        || bob_account.curve25519_key().as_bytes() != response.curve_identity_key()
    {
        return Err(CryptoError::StateRejected);
    }
    let alice_identity = Curve25519PublicKey::from_slice(invitation.curve_identity_key())
        .map_err(|_| CryptoError::InvalidValue)?;
    let one_time_key = Curve25519PublicKey::from_slice(invitation.one_time_key())
        .map_err(|_| CryptoError::InvalidValue)?;
    let mut session = bob_account
        .create_outbound_session(SessionConfig::version_1(), alice_identity, one_time_key)
        .map_err(|_| CryptoError::OlmRejected)?;
    let common = CommonFields::try_new(
        random_array()?,
        *invitation.inbound_recipient_hint(),
        CONFIRM_TTL_SECONDS,
        CONFIRM_MAX_HOPS,
    )?;
    let inner = InnerMessage::try_new(
        common,
        Content::ContactInitiatorConfirm(confirm_fields(invitation, response)),
    )?;
    let envelope = encrypt_confirmation(&mut session, &inner, OlmMessageType::PreKey)?;
    Ok(InitiatorConfirmation { session, envelope })
}

pub fn accept_initiator_confirmation(
    mut alice_account: Account,
    invitation: &Invitation,
    response: &ContactResponse,
    envelope: &Envelope,
) -> Result<AcceptedInitiator, CryptoError> {
    validate_bundle_pair(invitation, response)?;
    if alice_account.ed25519_key().as_bytes() != invitation.signing_identity_key()
        || alice_account.curve25519_key().as_bytes() != invitation.curve_identity_key()
        || envelope.recipient_hint().as_bytes() != invitation.inbound_recipient_hint()
        || envelope.ttl_seconds().get() != 604_800
        || envelope.max_hops().get() != 2
    {
        return Err(CryptoError::EnvelopeMismatch);
    }
    let protected = decode_protected_payload(envelope.protected_payload().as_bytes())?;
    if protected.message_type() != OlmMessageType::PreKey {
        return Err(CryptoError::UnsupportedType);
    }
    let olm = protected.to_olm()?;
    let OlmMessage::PreKey(pre_key) = olm else {
        return Err(CryptoError::UnsupportedType);
    };
    let bob_identity = Curve25519PublicKey::from_slice(response.curve_identity_key())
        .map_err(|_| CryptoError::InvalidValue)?;
    let inbound = alice_account
        .create_inbound_session(SessionConfig::version_1(), bob_identity, &pre_key)
        .map_err(|_| CryptoError::OlmRejected)?;
    let plaintext = Zeroizing::new(inbound.plaintext);
    let inner = decode_inner_message(&plaintext)?;
    validate_confirmation(
        &inner,
        envelope,
        protected.message_type(),
        true,
        invitation,
        response,
    )?;

    let mut session = inbound.session;
    let common = CommonFields::try_new(
        random_array()?,
        *response.inbound_recipient_hint(),
        CONFIRM_TTL_SECONDS,
        CONFIRM_MAX_HOPS,
    )?;
    let reply = InnerMessage::try_new(
        common,
        Content::ContactReceiverConfirm(confirm_fields(invitation, response)),
    )?;
    let receiver_confirmation = encrypt_confirmation(&mut session, &reply, OlmMessageType::Normal)?;
    Ok(AcceptedInitiator {
        account: alice_account,
        session,
        receiver_confirmation,
    })
}

pub fn accept_receiver_confirmation(
    mut bob_candidate: Session,
    invitation: &Invitation,
    response: &ContactResponse,
    envelope: &Envelope,
) -> Result<Session, CryptoError> {
    validate_bundle_pair(invitation, response)?;
    if envelope.recipient_hint().as_bytes() != response.inbound_recipient_hint()
        || envelope.ttl_seconds().get() != 604_800
        || envelope.max_hops().get() != 2
    {
        return Err(CryptoError::EnvelopeMismatch);
    }
    let protected = decode_protected_payload(envelope.protected_payload().as_bytes())?;
    if protected.message_type() != OlmMessageType::Normal {
        return Err(CryptoError::UnsupportedType);
    }
    let olm = protected.to_olm()?;
    let plaintext = bob_candidate
        .decrypt(&olm)
        .map_err(|_| CryptoError::OlmRejected)?;
    let plaintext = Zeroizing::new(plaintext);
    let inner = decode_inner_message(&plaintext)?;
    validate_confirmation(
        &inner,
        envelope,
        protected.message_type(),
        false,
        invitation,
        response,
    )?;
    Ok(bob_candidate)
}

fn encrypt_confirmation(
    session: &mut Session,
    inner: &InnerMessage,
    expected_type: OlmMessageType,
) -> Result<Envelope, CryptoError> {
    inner.validate_olm_type(expected_type)?;
    let plaintext = Zeroizing::new(encode_inner_message(inner)?);
    let olm = session
        .encrypt(plaintext.as_slice())
        .map_err(|_| CryptoError::OlmRejected)?;
    let protected = ProtectedOlmMessage::from_olm(&olm)?;
    if protected.message_type() != expected_type {
        return Err(CryptoError::StateRejected);
    }
    let envelope = Envelope::try_from_fields(
        PROTOCOL_VERSION,
        *inner.common().message_id(),
        *inner.common().recipient_hint(),
        u64::from(inner.common().ttl_seconds()),
        u64::from(inner.common().max_hops()),
        0,
        encode_protected_payload(&protected)?,
    )
    .map_err(|_| CryptoError::InvalidValue)?;
    if !inner.matches_envelope(&envelope) {
        return Err(CryptoError::EnvelopeMismatch);
    }
    Ok(envelope)
}

fn validate_confirmation(
    inner: &InnerMessage,
    envelope: &Envelope,
    message_type: OlmMessageType,
    initiator: bool,
    invitation: &Invitation,
    response: &ContactResponse,
) -> Result<(), CryptoError> {
    inner.validate_olm_type(message_type)?;
    if !inner.matches_envelope(envelope) {
        return Err(CryptoError::EnvelopeMismatch);
    }
    let expected = confirm_fields(invitation, response);
    match (initiator, inner.content()) {
        (true, Content::ContactInitiatorConfirm(fields)) if fields == &expected => Ok(()),
        (false, Content::ContactReceiverConfirm(fields)) if fields == &expected => Ok(()),
        _ => Err(CryptoError::StateRejected),
    }
}

fn validate_bundle_pair(
    invitation: &Invitation,
    response: &ContactResponse,
) -> Result<(), CryptoError> {
    if invitation.invitation_id() != response.invitation_id() {
        return Err(CryptoError::StateRejected);
    }
    Ok(())
}

fn confirm_fields(invitation: &Invitation, response: &ContactResponse) -> ConfirmFields {
    ConfirmFields::new(
        *invitation.invitation_id(),
        *response.response_id(),
        *invitation.invitation_secret(),
        *response.response_secret(),
    )
}

fn random_array<const LENGTH: usize>() -> Result<[u8; LENGTH], CryptoError> {
    let mut bytes = [0; LENGTH];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::Entropy)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use lantern_core::Envelope;
    use vodozemac::olm::{Account, AccountPickle};

    use super::{
        accept_initiator_confirmation, accept_receiver_confirmation, build_initiator_confirmation,
    };
    use crate::{ContactResponse, Invitation};

    const PICKLE_KEY: [u8; 32] = [0x91; 32];

    #[test]
    fn two_qr_sas_and_both_encrypted_confirmations_establish_one_session() {
        let mut alice_account = Account::new();
        let bob_account = Account::new();
        let invitation = Invitation::create(&mut alice_account);
        let Ok((invitation, alice_sas)) = invitation else {
            panic!("test invitation could not be created");
        };
        let response = ContactResponse::create(&bob_account, &invitation);
        let Ok((response, bob_sas)) = response else {
            panic!("test response could not be created");
        };
        let alice_display = alice_sas.finish(&invitation, &response);
        let bob_display = bob_sas.finish(&invitation, &response);
        assert!(matches!((alice_display, bob_display), (Ok(left), Ok(right)) if left == right));

        let initiator = build_initiator_confirmation(&bob_account, &invitation, &response);
        let Ok(initiator) = initiator else {
            panic!("test initiator confirmation could not be created");
        };
        assert_eq!(initiator.envelope().ttl_seconds().get(), 604_800);
        assert_eq!(initiator.envelope().max_hops().get(), 2);
        assert_eq!(
            initiator.envelope().recipient_hint().as_bytes(),
            invitation.inbound_recipient_hint()
        );
        let (bob_session, initiator_envelope) = initiator.into_parts();

        let account_pickle = alice_account.pickle().encrypt(&PICKLE_KEY);
        let changed = Envelope::try_from_fields(
            initiator_envelope.protocol_version(),
            [0xfe; 16],
            *initiator_envelope.recipient_hint().as_bytes(),
            u64::from(initiator_envelope.ttl_seconds().get()),
            u64::from(initiator_envelope.max_hops().get()),
            initiator_envelope.priority().as_raw(),
            initiator_envelope.protected_payload().as_bytes().to_vec(),
        );
        let Ok(changed) = changed else {
            panic!("changed confirmation was rejected by core");
        };
        let candidate =
            AccountPickle::from_encrypted(&account_pickle, &PICKLE_KEY).map(Account::from_pickle);
        let Ok(candidate) = candidate else {
            panic!("test account candidate could not be restored");
        };
        assert!(
            accept_initiator_confirmation(candidate, &invitation, &response, &changed).is_err()
        );

        let candidate =
            AccountPickle::from_encrypted(&account_pickle, &PICKLE_KEY).map(Account::from_pickle);
        let Ok(candidate) = candidate else {
            panic!("test account candidate could not be restored after rejection");
        };
        let accepted =
            accept_initiator_confirmation(candidate, &invitation, &response, &initiator_envelope);
        let Ok(accepted) = accepted else {
            panic!("valid initiator confirmation was rejected");
        };
        assert_eq!(
            accepted.receiver_confirmation().recipient_hint().as_bytes(),
            response.inbound_recipient_hint()
        );
        let (_, mut alice_session, receiver_envelope) = accepted.into_parts();
        let bob_session =
            accept_receiver_confirmation(bob_session, &invitation, &response, &receiver_envelope);
        let Ok(mut bob_session) = bob_session else {
            panic!("valid receiver confirmation was rejected");
        };
        assert_eq!(alice_session.session_id(), bob_session.session_id());

        let mut messages = Vec::new();
        for index in 0..32 {
            let text = format!("post-confirmation-{index}");
            let encrypted = alice_session.encrypt(text.as_bytes());
            let Ok(encrypted) = encrypted else {
                panic!("post-confirmation message could not be encrypted");
            };
            messages.push((text, encrypted));
        }
        for (text, encrypted) in messages.iter().rev() {
            let decrypted = bob_session.decrypt(encrypted);
            assert!(decrypted.is_ok_and(|value| value == text.as_bytes()));
        }
    }
}
