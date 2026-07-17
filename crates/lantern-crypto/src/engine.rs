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

