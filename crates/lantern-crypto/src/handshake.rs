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

