// SPDX-License-Identifier: MPL-2.0

//! Transport-independent E2EE formats used by Lantern v0.1.

mod contact;
mod engine;
mod error;
mod handshake;
mod inner;
mod wrapper;

pub use contact::{
    CONTACT_CBOR_MAX_BYTES, CONTACT_QR_MAX_BYTES, ContactBundle, ContactResponse, Invitation,
    SasDisplay, SasHandle, decode_contact_qr, encode_invitation_qr, encode_response_qr,
    identity_fingerprint,
};
pub use engine::{ReceivedChat, decrypt_chat, encrypt_chat};
pub use error::CryptoError;
pub use handshake::{
    AcceptedInitiator, InitiatorConfirmation, accept_initiator_confirmation,
    accept_receiver_confirmation, build_initiator_confirmation,
};
pub use inner::{
    CONTACT_CONFIRM_MAX_BYTES, CommonFields, ConfirmFields, Content, HINT_MESSAGE_MAX_BYTES,
    HintFields, INNER_MESSAGE_MAX_BYTES, InnerMessage, USER_TEXT_MAX_BYTES, decode_inner_message,
    encode_inner_message,
};
pub use wrapper::{
    OLM_MESSAGE_MAX_BYTES, OlmMessageType, PROTECTED_PAYLOAD_MAX_BYTES, ProtectedOlmMessage,
    decode_protected_payload, encode_protected_payload,
};
