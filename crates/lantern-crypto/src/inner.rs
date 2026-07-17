// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use lantern_core::{Envelope, MESSAGE_ID_LENGTH, PROTOCOL_VERSION, RECIPIENT_HINT_LENGTH};
use minicbor::{Decoder, Encoder, data::Type};

use crate::{CryptoError, OlmMessageType};

const INNER_VERSION: u8 = 1;
const PROTECTED_PAYLOAD_VERSION: u8 = 1;
const CHAT_FIELDS: u64 = 10;
const CONFIRM_FIELDS: u64 = 13;
const HINT_FIELDS: u64 = 11;
const SECRET_LENGTH: usize = 32;

pub const USER_TEXT_MAX_BYTES: usize = 4096;
pub const INNER_MESSAGE_MAX_BYTES: usize = 4155;
pub const CONTACT_CONFIRM_MAX_BYTES: usize = 161;
pub const HINT_MESSAGE_MAX_BYTES: usize = 79;

#[derive(Clone, Eq, PartialEq)]
pub struct CommonFields {
    message_id: [u8; MESSAGE_ID_LENGTH],
    recipient_hint: [u8; RECIPIENT_HINT_LENGTH],
    ttl_seconds: u32,
    max_hops: u8,
}

impl CommonFields {
    pub fn try_new(
        message_id: [u8; MESSAGE_ID_LENGTH],
        recipient_hint: [u8; RECIPIENT_HINT_LENGTH],
        ttl_seconds: u64,
        max_hops: u64,
    ) -> Result<Self, CryptoError> {
        let probe = Envelope::try_from_fields(
            PROTOCOL_VERSION,
            message_id,
            recipient_hint,
            ttl_seconds,
            max_hops,
            0,
            vec![0],
        )
        .map_err(|_| CryptoError::InvalidValue)?;
        Ok(Self {
            message_id,
            recipient_hint,
            ttl_seconds: probe.ttl_seconds().get(),
            max_hops: probe.max_hops().get(),
        })
    }

    pub fn from_envelope(envelope: &Envelope) -> Self {
        Self {
            message_id: *envelope.message_id().as_bytes(),
            recipient_hint: *envelope.recipient_hint().as_bytes(),
            ttl_seconds: envelope.ttl_seconds().get(),
            max_hops: envelope.max_hops().get(),
        }
    }

    pub const fn message_id(&self) -> &[u8; MESSAGE_ID_LENGTH] {
        &self.message_id
    }

    pub const fn recipient_hint(&self) -> &[u8; RECIPIENT_HINT_LENGTH] {
        &self.recipient_hint
    }

    pub const fn ttl_seconds(&self) -> u32 {
        self.ttl_seconds
    }

    pub const fn max_hops(&self) -> u8 {
        self.max_hops
    }
}

impl fmt::Debug for CommonFields {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommonFields")
            .field("message_id", &"redacted")
            .field("recipient_hint", &"redacted")
            .field("ttl_seconds", &self.ttl_seconds)
            .field("max_hops", &self.max_hops)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConfirmFields {
    invitation_id: [u8; 16],
    response_id: [u8; 16],
    invitation_secret: [u8; SECRET_LENGTH],
    response_secret: [u8; SECRET_LENGTH],
}

impl ConfirmFields {
    pub const fn new(
        invitation_id: [u8; 16],
        response_id: [u8; 16],
        invitation_secret: [u8; SECRET_LENGTH],
        response_secret: [u8; SECRET_LENGTH],
    ) -> Self {
        Self {
            invitation_id,
            response_id,
            invitation_secret,
            response_secret,
        }
    }

    pub const fn invitation_id(&self) -> &[u8; 16] {
        &self.invitation_id
    }

    pub const fn response_id(&self) -> &[u8; 16] {
        &self.response_id
    }

    pub const fn invitation_secret(&self) -> &[u8; SECRET_LENGTH] {
        &self.invitation_secret
    }

    pub const fn response_secret(&self) -> &[u8; SECRET_LENGTH] {
        &self.response_secret
    }
}

impl fmt::Debug for ConfirmFields {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfirmFields([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HintFields {
    generation: u32,
    new_recipient_hint: [u8; RECIPIENT_HINT_LENGTH],
}

impl HintFields {
    pub fn try_new(
        generation: u64,
        new_recipient_hint: [u8; RECIPIENT_HINT_LENGTH],
    ) -> Result<Self, CryptoError> {
        let generation = u32::try_from(generation).map_err(|_| CryptoError::InvalidValue)?;
        if generation == 0 {
            return Err(CryptoError::InvalidValue);
        }
        Ok(Self {
            generation,
            new_recipient_hint,
        })
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn new_recipient_hint(&self) -> &[u8; RECIPIENT_HINT_LENGTH] {
        &self.new_recipient_hint
    }
}

impl fmt::Debug for HintFields {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HintFields")
            .field("generation", &self.generation)
            .field("new_recipient_hint", &"redacted")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum Content {
    ChatMessage(Box<str>),
    ContactInitiatorConfirm(ConfirmFields),
    ContactReceiverConfirm(ConfirmFields),
    HintProposal(HintFields),
    HintAccepted(HintFields),
    HintCommitted(HintFields),
    HintFinal(HintFields),
}

impl Content {
    pub fn chat(text: String) -> Result<Self, CryptoError> {
        if text.is_empty() || text.len() > USER_TEXT_MAX_BYTES || text.chars().any(char::is_control)
        {
            return Err(CryptoError::InvalidValue);
        }
        Ok(Self::ChatMessage(text.into_boxed_str()))
    }

    pub const fn content_type(&self) -> u8 {
        match self {
            Self::ChatMessage(_) => 0,
            Self::ContactInitiatorConfirm(_) => 1,
            Self::ContactReceiverConfirm(_) => 2,
            Self::HintProposal(_) => 3,
            Self::HintAccepted(_) => 4,
            Self::HintCommitted(_) => 5,
            Self::HintFinal(_) => 6,
        }
    }

    pub fn text(&self) -> Option<&str> {
        match self {
            Self::ChatMessage(text) => Some(text),
            _ => None,
        }
    }
}

impl fmt::Debug for Content {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChatMessage(text) => formatter
                .debug_struct("ChatMessage")
                .field("text_length", &text.len())
                .finish(),
            Self::ContactInitiatorConfirm(_) => {
                formatter.write_str("ContactInitiatorConfirm([REDACTED])")
            }
            Self::ContactReceiverConfirm(_) => {
                formatter.write_str("ContactReceiverConfirm([REDACTED])")
            }
            Self::HintProposal(fields) => {
                formatter.debug_tuple("HintProposal").field(fields).finish()
            }
            Self::HintAccepted(fields) => {
                formatter.debug_tuple("HintAccepted").field(fields).finish()
            }
            Self::HintCommitted(fields) => formatter
                .debug_tuple("HintCommitted")
                .field(fields)
                .finish(),
            Self::HintFinal(fields) => formatter.debug_tuple("HintFinal").field(fields).finish(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerMessage {
    common: CommonFields,
    content: Content,
}

impl InnerMessage {
    pub fn try_new(common: CommonFields, content: Content) -> Result<Self, CryptoError> {
        let service = !matches!(content, Content::ChatMessage(_));
        if service && (common.ttl_seconds != 604_800 || common.max_hops != 2) {
            return Err(CryptoError::InvalidValue);
        }
        if matches!(content, Content::HintFinal(ref fields) if fields.new_recipient_hint != common.recipient_hint)
        {
            return Err(CryptoError::InvalidValue);
        }
        Ok(Self { common, content })
    }

    pub const fn common(&self) -> &CommonFields {
        &self.common
    }

    pub const fn content(&self) -> &Content {
        &self.content
    }

    pub fn validate_olm_type(&self, message_type: OlmMessageType) -> Result<(), CryptoError> {
        match (&self.content, message_type) {
            (Content::ContactInitiatorConfirm(_), OlmMessageType::PreKey) => Ok(()),
            (Content::ContactInitiatorConfirm(_), OlmMessageType::Normal)
            | (_, OlmMessageType::PreKey) => Err(CryptoError::UnsupportedType),
            (_, OlmMessageType::Normal) => Ok(()),
        }
    }

    pub fn matches_envelope(&self, envelope: &Envelope) -> bool {
        self.common.message_id == *envelope.message_id().as_bytes()
            && self.common.recipient_hint == *envelope.recipient_hint().as_bytes()
            && self.common.ttl_seconds == envelope.ttl_seconds().get()
            && self.common.max_hops == envelope.max_hops().get()
            && envelope.protocol_version() == PROTOCOL_VERSION
            && envelope.priority().as_raw() == 0
    }
}

pub fn encode_inner_message(message: &InnerMessage) -> Result<Vec<u8>, CryptoError> {
    let fields = match message.content {
        Content::ChatMessage(_) => CHAT_FIELDS,
        Content::ContactInitiatorConfirm(_) | Content::ContactReceiverConfirm(_) => CONFIRM_FIELDS,
        Content::HintProposal(_)
        | Content::HintAccepted(_)
        | Content::HintCommitted(_)
        | Content::HintFinal(_) => HINT_FIELDS,
    };
    let mut encoder = Encoder::new(Vec::with_capacity(192));
    encoder.map(fields).map_err(|_| CryptoError::Malformed)?;
    encode_common(&mut encoder, message)?;
    match &message.content {
        Content::ChatMessage(text) => {
            encoder
                .u8(9)
                .and_then(|value| value.str(text))
                .map_err(|_| CryptoError::Malformed)?;
        }
        Content::ContactInitiatorConfirm(confirm) | Content::ContactReceiverConfirm(confirm) => {
            encoder
                .u8(9)
                .and_then(|value| value.bytes(&confirm.invitation_id))
                .and_then(|value| value.u8(10))
                .and_then(|value| value.bytes(&confirm.response_id))
                .and_then(|value| value.u8(11))
                .and_then(|value| value.bytes(&confirm.invitation_secret))
                .and_then(|value| value.u8(12))
                .and_then(|value| value.bytes(&confirm.response_secret))
                .map_err(|_| CryptoError::Malformed)?;
        }
        Content::HintProposal(hint)
        | Content::HintAccepted(hint)
        | Content::HintCommitted(hint)
        | Content::HintFinal(hint) => {
            encoder
                .u8(9)
                .and_then(|value| value.u32(hint.generation))
                .and_then(|value| value.u8(10))
                .and_then(|value| value.bytes(&hint.new_recipient_hint))
                .map_err(|_| CryptoError::Malformed)?;
        }
    }
    let encoded = encoder.into_writer();
    if encoded.len() > INNER_MESSAGE_MAX_BYTES {
        return Err(CryptoError::InputTooLarge);
    }
    Ok(encoded)
}

fn encode_common(
    encoder: &mut Encoder<Vec<u8>>,
    message: &InnerMessage,
) -> Result<(), CryptoError> {
    encoder
        .u8(0)
        .and_then(|value| value.u8(INNER_VERSION))
        .and_then(|value| value.u8(1))
        .and_then(|value| value.u8(message.content.content_type()))
        .and_then(|value| value.u8(2))
        .and_then(|value| value.u8(PROTECTED_PAYLOAD_VERSION))
        .and_then(|value| value.u8(3))
        .and_then(|value| value.u8(1))
        .and_then(|value| value.u8(4))
        .and_then(|value| value.bytes(&message.common.message_id))
        .and_then(|value| value.u8(5))
        .and_then(|value| value.bytes(&message.common.recipient_hint))
        .and_then(|value| value.u8(6))
        .and_then(|value| value.u32(message.common.ttl_seconds))
        .and_then(|value| value.u8(7))
        .and_then(|value| value.u8(message.common.max_hops))
        .and_then(|value| value.u8(8))
        .and_then(|value| value.u8(0))
        .map_err(|_| CryptoError::Malformed)?;
    Ok(())
}

pub fn decode_inner_message(input: &[u8]) -> Result<InnerMessage, CryptoError> {
    if input.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    if input.len() > INNER_MESSAGE_MAX_BYTES {
        return Err(CryptoError::InputTooLarge);
    }
    let mut decoder = Decoder::new(input);
    if decoder.datatype().map_err(|_| CryptoError::Malformed)? != Type::Map {
        return Err(CryptoError::Malformed);
    }
    let fields = decoder
        .map()
        .map_err(|_| CryptoError::Malformed)?
        .ok_or(CryptoError::Malformed)?;

    expect_key(&mut decoder, 0)?;
    if decode_unsigned(&mut decoder)? != u64::from(INNER_VERSION) {
        return Err(CryptoError::UnsupportedVersion);
    }
    expect_key(&mut decoder, 1)?;
    let content_type = decode_unsigned(&mut decoder)?;
    let expected_fields = match content_type {
        0 => CHAT_FIELDS,
        1 | 2 => CONFIRM_FIELDS,
        3..=6 => HINT_FIELDS,
        _ => return Err(CryptoError::UnsupportedType),
    };
    if fields != expected_fields {
        return Err(CryptoError::Malformed);
    }
    expect_key(&mut decoder, 2)?;
    if decode_unsigned(&mut decoder)? != u64::from(PROTECTED_PAYLOAD_VERSION) {
        return Err(CryptoError::UnsupportedVersion);
    }
    expect_key(&mut decoder, 3)?;
    if decode_unsigned(&mut decoder)? != PROTOCOL_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    expect_key(&mut decoder, 4)?;
    let message_id = decode_fixed::<MESSAGE_ID_LENGTH>(&mut decoder)?;
    expect_key(&mut decoder, 5)?;
    let recipient_hint = decode_fixed::<RECIPIENT_HINT_LENGTH>(&mut decoder)?;
    expect_key(&mut decoder, 6)?;
    let ttl_seconds = decode_unsigned(&mut decoder)?;
    expect_key(&mut decoder, 7)?;
    let max_hops = decode_unsigned(&mut decoder)?;
    expect_key(&mut decoder, 8)?;
    if decode_unsigned(&mut decoder)? != 0 {
        return Err(CryptoError::InvalidValue);
    }
    let common = CommonFields::try_new(message_id, recipient_hint, ttl_seconds, max_hops)?;

    let content = match content_type {
        0 => {
            expect_key(&mut decoder, 9)?;
            if decoder.datatype().map_err(|_| CryptoError::Malformed)? != Type::String {
                return Err(CryptoError::Malformed);
            }
            let text = decoder.str().map_err(|_| CryptoError::Malformed)?;
            Content::chat(text.to_owned())?
        }
        1 | 2 => {
            expect_key(&mut decoder, 9)?;
            let invitation_id = decode_fixed::<16>(&mut decoder)?;
            expect_key(&mut decoder, 10)?;
            let response_id = decode_fixed::<16>(&mut decoder)?;
            expect_key(&mut decoder, 11)?;
            let invitation_secret = decode_fixed::<SECRET_LENGTH>(&mut decoder)?;
            expect_key(&mut decoder, 12)?;
            let response_secret = decode_fixed::<SECRET_LENGTH>(&mut decoder)?;
            let fields = ConfirmFields::new(
                invitation_id,
                response_id,
                invitation_secret,
                response_secret,
            );
            if content_type == 1 {
                Content::ContactInitiatorConfirm(fields)
            } else {
                Content::ContactReceiverConfirm(fields)
            }
        }
        3..=6 => {
            expect_key(&mut decoder, 9)?;
            let generation = decode_unsigned(&mut decoder)?;
            expect_key(&mut decoder, 10)?;
            let new_hint = decode_fixed::<RECIPIENT_HINT_LENGTH>(&mut decoder)?;
            let fields = HintFields::try_new(generation, new_hint)?;
            match content_type {
                3 => Content::HintProposal(fields),
                4 => Content::HintAccepted(fields),
                5 => Content::HintCommitted(fields),
                6 => Content::HintFinal(fields),
                _ => return Err(CryptoError::UnsupportedType),
            }
        }
        _ => return Err(CryptoError::UnsupportedType),
    };
    if decoder.position() != input.len() {
        return Err(CryptoError::Malformed);
    }
    let decoded = InnerMessage::try_new(common, content)?;
    if encode_inner_message(&decoded)?.as_slice() != input {
        return Err(CryptoError::NonCanonical);
    }
    Ok(decoded)
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), CryptoError> {
    if decode_unsigned(decoder)? != u64::from(expected) {
        return Err(CryptoError::Malformed);
    }
    Ok(())
}

fn decode_unsigned(decoder: &mut Decoder<'_>) -> Result<u64, CryptoError> {
    match decoder.datatype().map_err(|_| CryptoError::Malformed)? {
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
            decoder.u64().map_err(|_| CryptoError::Malformed)
        }
        _ => Err(CryptoError::Malformed),
    }
}

fn decode_fixed<const LENGTH: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<[u8; LENGTH], CryptoError> {
    if decoder.datatype().map_err(|_| CryptoError::Malformed)? != Type::Bytes {
        return Err(CryptoError::Malformed);
    }
    let bytes = decoder.bytes().map_err(|_| CryptoError::Malformed)?;
    <[u8; LENGTH]>::try_from(bytes).map_err(|_| CryptoError::WrongLength)
}

#[cfg(test)]
mod tests {
    use lantern_core::Envelope;

    use super::{
        CommonFields, ConfirmFields, Content, HintFields, InnerMessage, decode_inner_message,
        encode_inner_message,
    };
    use crate::{CryptoError, OlmMessageType};

    fn common(hint: [u8; 16], service: bool) -> CommonFields {
        let result = CommonFields::try_new(
            [0x11; 16],
            hint,
            if service { 604_800 } else { 60 },
            if service { 2 } else { 1 },
        );
        let Ok(result) = result else {
            panic!("test common fields were rejected");
        };
        result
    }

    fn confirm() -> ConfirmFields {
        ConfirmFields::new([0x33; 16], [0x44; 16], [0x55; 32], [0x66; 32])
    }

    fn hint() -> HintFields {
        let result = HintFields::try_new(1, [0x77; 16]);
        let Ok(result) = result else {
            panic!("test hint fields were rejected");
        };
        result
    }

    fn message(content: Content) -> InnerMessage {
        let is_chat = matches!(content, Content::ChatMessage(_));
        let recipient_hint = if matches!(content, Content::HintFinal(_)) {
            [0x77; 16]
        } else {
            [0x22; 16]
        };
        let result = InnerMessage::try_new(common(recipient_hint, !is_chat), content);
        let Ok(result) = result else {
            panic!("test inner message was rejected");
        };
        result
    }

    fn to_hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;

        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            assert!(write!(output, "{byte:02x}").is_ok());
        }
        output
    }

    #[test]
    fn all_seven_types_have_fixed_canonical_vectors() {
        let chat = Content::chat("hello".to_owned());
        let Ok(chat) = chat else {
            panic!("test chat was rejected");
        };
        let messages = [
            message(chat),
            message(Content::ContactInitiatorConfirm(confirm())),
            message(Content::ContactReceiverConfirm(confirm())),
            message(Content::HintProposal(hint())),
            message(Content::HintAccepted(hint())),
            message(Content::HintCommitted(hint())),
            message(Content::HintFinal(hint())),
        ];
        let encoded = messages
            .iter()
            .map(|value| encode_inner_message(value).map(|bytes| to_hex(&bytes)))
            .collect::<Result<Vec<_>, _>>();
        let Ok(encoded) = encoded else {
            panic!("test vectors could not be encoded");
        };
        assert_eq!(
            encoded,
            [
                "aa000101000201030104501111111111111111111111111111111105502222222222222222222222222222222206183c07010800096568656c6c6f",
                "ad0001010102010301045011111111111111111111111111111111055022222222222222222222222222222222061a00093a80070208000950333333333333333333333333333333330a50444444444444444444444444444444440b582055555555555555555555555555555555555555555555555555555555555555550c58206666666666666666666666666666666666666666666666666666666666666666",
                "ad0001010202010301045011111111111111111111111111111111055022222222222222222222222222222222061a00093a80070208000950333333333333333333333333333333330a50444444444444444444444444444444440b582055555555555555555555555555555555555555555555555555555555555555550c58206666666666666666666666666666666666666666666666666666666666666666",
                "ab0001010302010301045011111111111111111111111111111111055022222222222222222222222222222222061a00093a800702080009010a5077777777777777777777777777777777",
                "ab0001010402010301045011111111111111111111111111111111055022222222222222222222222222222222061a00093a800702080009010a5077777777777777777777777777777777",
                "ab0001010502010301045011111111111111111111111111111111055022222222222222222222222222222222061a00093a800702080009010a5077777777777777777777777777777777",
                "ab0001010602010301045011111111111111111111111111111111055077777777777777777777777777777777061a00093a800702080009010a5077777777777777777777777777777777",
            ]
        );

        for value in messages {
            let bytes = encode_inner_message(&value);
            let Ok(bytes) = bytes else {
                panic!("test vector could not be encoded");
            };
            assert_eq!(decode_inner_message(&bytes), Ok(value));
        }
    }

    #[test]
    fn text_limits_controls_and_service_parameters_are_enforced() {
        assert!(Content::chat("a".repeat(4096)).is_ok());
        assert_eq!(
            Content::chat("a".repeat(4097)),
            Err(CryptoError::InvalidValue)
        );
        for text in ["", "line\nfeed", "tab\there", "nul\0here", "escape\u{1b}"] {
            assert_eq!(
                Content::chat(text.to_owned()),
                Err(CryptoError::InvalidValue)
            );
        }

        let invalid =
            InnerMessage::try_new(common([0x22; 16], false), Content::HintProposal(hint()));
        assert_eq!(invalid, Err(CryptoError::InvalidValue));
        let wrong_final =
            InnerMessage::try_new(common([0x22; 16], true), Content::HintFinal(hint()));
        assert_eq!(wrong_final, Err(CryptoError::InvalidValue));
    }

    #[test]
    fn olm_type_and_envelope_copies_are_checked() {
        let initiator = message(Content::ContactInitiatorConfirm(confirm()));
        assert!(initiator.validate_olm_type(OlmMessageType::PreKey).is_ok());
        assert_eq!(
            initiator.validate_olm_type(OlmMessageType::Normal),
            Err(CryptoError::UnsupportedType)
        );
        let chat = Content::chat("hello".to_owned());
        let Ok(chat) = chat else {
            panic!("test chat was rejected");
        };
        let chat = message(chat);
        assert_eq!(
            chat.validate_olm_type(OlmMessageType::PreKey),
            Err(CryptoError::UnsupportedType)
        );

        let envelope = Envelope::try_from_fields(1, [0x11; 16], [0x22; 16], 60, 1, 0, vec![1]);
        let Ok(envelope) = envelope else {
            panic!("test envelope was rejected");
        };
        assert!(chat.matches_envelope(&envelope));
        let changed = Envelope::try_from_fields(1, [0x12; 16], [0x22; 16], 60, 1, 0, vec![1]);
        let Ok(changed) = changed else {
            panic!("changed test envelope was rejected");
        };
        assert!(!chat.matches_envelope(&changed));
    }

    #[test]
    fn every_truncated_prefix_and_noncanonical_integer_is_rejected() {
        let chat = Content::chat("hello".to_owned());
        let Ok(chat) = chat else {
            panic!("test chat was rejected");
        };
        let encoded = encode_inner_message(&message(chat));
        let Ok(encoded) = encoded else {
            panic!("test message could not be encoded");
        };
        for length in 0..encoded.len() {
            assert!(decode_inner_message(&encoded[..length]).is_err());
        }

        let mut noncanonical = encoded;
        noncanonical.splice(1..2, [0x18, 0x00]);
        assert_eq!(
            decode_inner_message(&noncanonical),
            Err(CryptoError::NonCanonical)
        );
    }
}
