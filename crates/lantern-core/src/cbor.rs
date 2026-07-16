// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use minicbor::{Decoder, Encoder, data::Type};

use crate::{
    CoreError, Envelope, Field, MAX_ENVELOPE_SIZE, MAX_PROTECTED_PAYLOAD_SIZE, MESSAGE_ID_LENGTH,
    MaxHops, PROTOCOL_VERSION, Priority, RECIPIENT_HINT_LENGTH, TtlSeconds,
};

const ENVELOPE_FIELD_COUNT: u64 = 7;
const ENCODED_FIXED_CAPACITY: usize = 64;

/// Location of a strict CBOR validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CborField {
    Envelope,
    MapKey,
    ProtocolVersion,
    MessageId,
    RecipientHint,
    TtlSeconds,
    MaxHops,
    Priority,
    ProtectedPayload,
}

/// Safe CBOR error category that does not contain input bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CborError {
    EmptyInput,
    InputTooLarge,
    Malformed,
    ExpectedMap,
    IndefiniteLength { field: CborField },
    WrongMapLength,
    UnexpectedMapKey { expected: u8 },
    WrongType { field: CborField },
    WrongLength { field: CborField },
    NonCanonical { field: CborField },
    TrailingData,
    EnvelopeValidation(CoreError),
    EncodingFailed,
    OutputTooLarge,
}

impl fmt::Display for CborError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => formatter.write_str("empty CBOR input"),
            Self::InputTooLarge => formatter.write_str("CBOR input exceeds the size limit"),
            Self::Malformed => formatter.write_str("malformed CBOR input"),
            Self::ExpectedMap => formatter.write_str("top-level CBOR value must be a map"),
            Self::IndefiniteLength { field } => {
                write!(formatter, "indefinite CBOR length for {field:?}")
            }
            Self::WrongMapLength => formatter.write_str("wrong Envelope map length"),
            Self::UnexpectedMapKey { expected } => {
                write!(
                    formatter,
                    "unexpected Envelope map key; expected {expected}"
                )
            }
            Self::WrongType { field } => write!(formatter, "wrong CBOR type for {field:?}"),
            Self::WrongLength { field } => write!(formatter, "wrong CBOR length for {field:?}"),
            Self::NonCanonical { field } => {
                write!(formatter, "non-canonical CBOR representation for {field:?}")
            }
            Self::TrailingData => formatter.write_str("trailing data after Envelope"),
            Self::EnvelopeValidation(error) => write!(formatter, "invalid Envelope: {error}"),
            Self::EncodingFailed => formatter.write_str("CBOR encoding failed"),
            Self::OutputTooLarge => formatter.write_str("encoded Envelope exceeds the size limit"),
        }
    }
}

impl std::error::Error for CborError {}

impl From<CoreError> for CborError {
    fn from(error: CoreError) -> Self {
        Self::EnvelopeValidation(error)
    }
}

/// Encode an Envelope using the deterministic v0.1 CBOR representation.
pub fn encode_envelope(envelope: &Envelope) -> Result<Vec<u8>, CborError> {
    let initial_capacity = envelope
        .protected_payload()
        .len()
        .checked_add(ENCODED_FIXED_CAPACITY)
        .ok_or(CborError::OutputTooLarge)?
        .min(MAX_ENVELOPE_SIZE);
    let mut encoder = Encoder::new(Vec::with_capacity(initial_capacity));

    encoder
        .map(ENVELOPE_FIELD_COUNT)
        .map_err(|_| CborError::EncodingFailed)?;
    encode_key(&mut encoder, 0)?;
    encoder
        .u64(envelope.protocol_version())
        .map_err(|_| CborError::EncodingFailed)?;
    encode_key(&mut encoder, 1)?;
    encoder
        .bytes(envelope.message_id().as_bytes())
        .map_err(|_| CborError::EncodingFailed)?;
    encode_key(&mut encoder, 2)?;
    encoder
        .bytes(envelope.recipient_hint().as_bytes())
        .map_err(|_| CborError::EncodingFailed)?;
    encode_key(&mut encoder, 3)?;
    encoder
        .u64(u64::from(envelope.ttl_seconds().get()))
        .map_err(|_| CborError::EncodingFailed)?;
    encode_key(&mut encoder, 4)?;
    encoder
        .u64(u64::from(envelope.max_hops().get()))
        .map_err(|_| CborError::EncodingFailed)?;
    encode_key(&mut encoder, 5)?;
    encoder
        .u64(envelope.priority().as_raw())
        .map_err(|_| CborError::EncodingFailed)?;
    encode_key(&mut encoder, 6)?;
    encoder
        .bytes(envelope.protected_payload().as_bytes())
        .map_err(|_| CborError::EncodingFailed)?;

    let encoded = encoder.into_writer();
    if encoded.len() > MAX_ENVELOPE_SIZE {
        return Err(CborError::OutputTooLarge);
    }
    Ok(encoded)
}

/// Decode one strict deterministic Envelope from a bounded byte slice.
pub fn decode_envelope(input: &[u8]) -> Result<Envelope, CborError> {
    if input.is_empty() {
        return Err(CborError::EmptyInput);
    }
    if input.len() > MAX_ENVELOPE_SIZE {
        return Err(CborError::InputTooLarge);
    }

    let mut decoder = Decoder::new(input);
    decode_map_header(&mut decoder)?;

    expect_key(&mut decoder, 0)?;
    let protocol_version = decode_unsigned(&mut decoder, CborField::ProtocolVersion)?;
    if protocol_version != PROTOCOL_VERSION {
        return Err(CoreError::UnsupportedValue {
            field: Field::ProtocolVersion,
        }
        .into());
    }

    expect_key(&mut decoder, 1)?;
    let message_id_bytes = decode_bytes(&mut decoder, CborField::MessageId)?;
    let message_id = <[u8; MESSAGE_ID_LENGTH]>::try_from(message_id_bytes).map_err(|_| {
        CborError::WrongLength {
            field: CborField::MessageId,
        }
    })?;

    expect_key(&mut decoder, 2)?;
    let recipient_hint_bytes = decode_bytes(&mut decoder, CborField::RecipientHint)?;
    let recipient_hint =
        <[u8; RECIPIENT_HINT_LENGTH]>::try_from(recipient_hint_bytes).map_err(|_| {
            CborError::WrongLength {
                field: CborField::RecipientHint,
            }
        })?;

    expect_key(&mut decoder, 3)?;
    let ttl_seconds = decode_unsigned(&mut decoder, CborField::TtlSeconds)?;
    TtlSeconds::try_from_raw(ttl_seconds)?;

    expect_key(&mut decoder, 4)?;
    let max_hops = decode_unsigned(&mut decoder, CborField::MaxHops)?;
    MaxHops::try_from_raw(max_hops)?;

    expect_key(&mut decoder, 5)?;
    let priority = decode_unsigned(&mut decoder, CborField::Priority)?;
    Priority::try_from_raw(priority)?;

    expect_key(&mut decoder, 6)?;
    let protected_payload = decode_bytes(&mut decoder, CborField::ProtectedPayload)?;
    if protected_payload.is_empty() || protected_payload.len() > MAX_PROTECTED_PAYLOAD_SIZE {
        return Err(CborError::WrongLength {
            field: CborField::ProtectedPayload,
        });
    }

    if decoder.position() != input.len() {
        return Err(CborError::TrailingData);
    }

    Envelope::try_from_fields(
        protocol_version,
        message_id,
        recipient_hint,
        ttl_seconds,
        max_hops,
        priority,
        protected_payload.to_vec(),
    )
    .map_err(Into::into)
}

fn encode_key(encoder: &mut Encoder<Vec<u8>>, key: u8) -> Result<(), CborError> {
    encoder.u8(key).map_err(|_| CborError::EncodingFailed)?;
    Ok(())
}

fn decode_map_header(decoder: &mut Decoder<'_>) -> Result<(), CborError> {
    match decoder.datatype().map_err(|_| CborError::Malformed)? {
        Type::MapIndef => {
            return Err(CborError::IndefiniteLength {
                field: CborField::Envelope,
            });
        }
        Type::Map => {}
        _ => return Err(CborError::ExpectedMap),
    }

    let start = decoder.position();
    let length =
        decoder
            .map()
            .map_err(|_| CborError::Malformed)?
            .ok_or(CborError::IndefiniteLength {
                field: CborField::Envelope,
            })?;
    if length != ENVELOPE_FIELD_COUNT {
        return Err(CborError::WrongMapLength);
    }
    ensure_canonical_map_header(decoder, start, length)
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), CborError> {
    let key = decode_unsigned(decoder, CborField::MapKey)?;
    if key != u64::from(expected) {
        return Err(CborError::UnexpectedMapKey { expected });
    }
    Ok(())
}

fn decode_unsigned(decoder: &mut Decoder<'_>, field: CborField) -> Result<u64, CborError> {
    match decoder.datatype().map_err(|_| CborError::Malformed)? {
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => {}
        _ => return Err(CborError::WrongType { field }),
    }

    let start = decoder.position();
    let value = decoder.u64().map_err(|_| CborError::Malformed)?;
    ensure_canonical_unsigned(decoder, start, value, field)?;
    Ok(value)
}

fn decode_bytes<'input>(
    decoder: &mut Decoder<'input>,
    field: CborField,
) -> Result<&'input [u8], CborError> {
    match decoder.datatype().map_err(|_| CborError::Malformed)? {
        Type::BytesIndef => return Err(CborError::IndefiniteLength { field }),
        Type::Bytes => {}
        _ => return Err(CborError::WrongType { field }),
    }

    let start = decoder.position();
    let bytes = decoder.bytes().map_err(|_| CborError::Malformed)?;
    ensure_canonical_bytes_header(decoder, start, bytes.len(), field)?;
    Ok(bytes)
}

fn ensure_canonical_map_header(
    decoder: &Decoder<'_>,
    start: usize,
    length: u64,
) -> Result<(), CborError> {
    let mut encoder = Encoder::new(Vec::with_capacity(9));
    encoder.map(length).map_err(|_| CborError::EncodingFailed)?;
    let expected = encoder.into_writer();
    compare_consumed(decoder, start, &expected, CborField::Envelope)
}

fn ensure_canonical_unsigned(
    decoder: &Decoder<'_>,
    start: usize,
    value: u64,
    field: CborField,
) -> Result<(), CborError> {
    let mut encoder = Encoder::new(Vec::with_capacity(9));
    encoder.u64(value).map_err(|_| CborError::EncodingFailed)?;
    let expected = encoder.into_writer();
    compare_consumed(decoder, start, &expected, field)
}

fn ensure_canonical_bytes_header(
    decoder: &Decoder<'_>,
    start: usize,
    byte_length: usize,
    field: CborField,
) -> Result<(), CborError> {
    let header_end = decoder
        .position()
        .checked_sub(byte_length)
        .ok_or(CborError::Malformed)?;
    let length = u64::try_from(byte_length).map_err(|_| CborError::InputTooLarge)?;
    let mut encoder = Encoder::new(Vec::with_capacity(9));
    encoder
        .bytes_len(length)
        .map_err(|_| CborError::EncodingFailed)?;
    let expected = encoder.into_writer();
    let actual = decoder
        .input()
        .get(start..header_end)
        .ok_or(CborError::Malformed)?;
    if actual != expected {
        return Err(CborError::NonCanonical { field });
    }
    Ok(())
}

fn compare_consumed(
    decoder: &Decoder<'_>,
    start: usize,
    expected: &[u8],
    field: CborField,
) -> Result<(), CborError> {
    let actual = decoder
        .input()
        .get(start..decoder.position())
        .ok_or(CborError::Malformed)?;
    if actual != expected {
        return Err(CborError::NonCanonical { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MAX_MAX_HOPS, MAX_TTL_SECONDS, MIN_MAX_HOPS, MIN_TTL_SECONDS};

    const MINIMAL_ENVELOPE_CBOR: [u8; 49] = [
        0xa7, 0x00, 0x01, 0x01, 0x50, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x50, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x03, 0x18, 0x3c, 0x04, 0x01, 0x05,
        0x00, 0x06, 0x41, 0x54,
    ];

    fn minimal_envelope() -> Envelope {
        let result = Envelope::try_from_fields(
            PROTOCOL_VERSION,
            [0x11; MESSAGE_ID_LENGTH],
            [0x22; RECIPIENT_HINT_LENGTH],
            MIN_TTL_SECONDS,
            MIN_MAX_HOPS,
            0,
            vec![0x54],
        );
        let Ok(envelope) = result else {
            panic!("valid minimal Envelope was rejected");
        };
        envelope
    }

    fn replace_range(input: &[u8], range: core::ops::Range<usize>, replacement: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(input.len() - range.len() + replacement.len());
        output.extend_from_slice(&input[..range.start]);
        output.extend_from_slice(replacement);
        output.extend_from_slice(&input[range.end..]);
        output
    }

    fn encode_unsigned_for_test(value: u64) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        let result = encoder.u64(value);
        assert!(result.is_ok());
        encoder.into_writer()
    }

    fn encode_unchecked_payload(payload_size: usize) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        let operations = (|| {
            encoder.map(ENVELOPE_FIELD_COUNT)?;
            encoder.u8(0)?.u8(1)?;
            encoder.u8(1)?.bytes(&[0x11; MESSAGE_ID_LENGTH])?;
            encoder.u8(2)?.bytes(&[0x22; RECIPIENT_HINT_LENGTH])?;
            encoder.u8(3)?.u64(MIN_TTL_SECONDS)?;
            encoder.u8(4)?.u64(MIN_MAX_HOPS)?;
            encoder.u8(5)?.u8(0)?;
            encoder.u8(6)?.bytes(&vec![0x54; payload_size])?;
            Ok::<(), minicbor::encode::Error<core::convert::Infallible>>(())
        })();
        assert!(operations.is_ok());
        encoder.into_writer()
    }

    #[test]
    fn exact_minimal_vector_decodes_and_reencodes_identically() {
        let result = decode_envelope(&MINIMAL_ENVELOPE_CBOR);
        let Ok(envelope) = result else {
            panic!("minimal CBOR vector was rejected");
        };

        assert_eq!(envelope.protocol_version(), PROTOCOL_VERSION);
        assert_eq!(u64::from(envelope.ttl_seconds().get()), MIN_TTL_SECONDS);
        assert_eq!(u64::from(envelope.max_hops().get()), MIN_MAX_HOPS);
        assert_eq!(
            encode_envelope(&envelope),
            Ok(MINIMAL_ENVELOPE_CBOR.to_vec())
        );
    }

    #[test]
    fn maximum_logical_envelope_stays_below_serialized_limit() {
        let result = Envelope::try_from_fields(
            PROTOCOL_VERSION,
            [0x11; MESSAGE_ID_LENGTH],
            [0x22; RECIPIENT_HINT_LENGTH],
            MAX_TTL_SECONDS,
            MAX_MAX_HOPS,
            0,
            vec![0x54; MAX_PROTECTED_PAYLOAD_SIZE],
        );
        let Ok(envelope) = result else {
            panic!("valid maximum Envelope was rejected");
        };
        let encoded = encode_envelope(&envelope);
        let Ok(bytes) = encoded else {
            panic!("maximum Envelope could not be encoded");
        };

        assert_eq!(bytes.len(), 64_565);
        assert!(bytes.len() <= MAX_ENVELOPE_SIZE);
        assert_eq!(decode_envelope(&bytes), Ok(envelope));
    }

    #[test]
    fn rejects_empty_and_oversized_total_input_before_decoding() {
        assert_eq!(decode_envelope(&[]), Err(CborError::EmptyInput));
        assert_eq!(
            decode_envelope(&vec![0; MAX_ENVELOPE_SIZE + 1]),
            Err(CborError::InputTooLarge)
        );
    }

    #[test]
    fn rejects_wrong_indefinite_and_noncanonical_top_level_maps() {
        assert_eq!(decode_envelope(&[0x80]), Err(CborError::ExpectedMap));
        assert_eq!(
            decode_envelope(&[0xbf, 0xff]),
            Err(CborError::IndefiniteLength {
                field: CborField::Envelope,
            })
        );
        assert_eq!(decode_envelope(&[0xa6]), Err(CborError::WrongMapLength));

        let noncanonical = replace_range(&MINIMAL_ENVELOPE_CBOR, 0..1, &[0xb8, 0x07]);
        assert_eq!(
            decode_envelope(&noncanonical),
            Err(CborError::NonCanonical {
                field: CborField::Envelope,
            })
        );
    }

    #[test]
    fn rejects_duplicate_unknown_reordered_and_noncanonical_keys() {
        let mut duplicate = MINIMAL_ENVELOPE_CBOR;
        duplicate[3] = 0;
        assert_eq!(
            decode_envelope(&duplicate),
            Err(CborError::UnexpectedMapKey { expected: 1 })
        );

        let mut unknown = MINIMAL_ENVELOPE_CBOR;
        unknown[46] = 7;
        assert_eq!(
            decode_envelope(&unknown),
            Err(CborError::UnexpectedMapKey { expected: 6 })
        );

        let mut reordered = MINIMAL_ENVELOPE_CBOR;
        reordered[3] = 2;
        assert_eq!(
            decode_envelope(&reordered),
            Err(CborError::UnexpectedMapKey { expected: 1 })
        );

        let noncanonical = replace_range(&MINIMAL_ENVELOPE_CBOR, 3..4, &[0x18, 0x01]);
        assert_eq!(
            decode_envelope(&noncanonical),
            Err(CborError::NonCanonical {
                field: CborField::MapKey,
            })
        );
    }

    #[test]
    fn rejects_unknown_version_before_other_fields() {
        let mut input = MINIMAL_ENVELOPE_CBOR;
        input[2] = 2;
        assert_eq!(
            decode_envelope(&input),
            Err(CborError::EnvelopeValidation(CoreError::UnsupportedValue {
                field: Field::ProtocolVersion,
            }))
        );
    }

    #[test]
    fn rejects_wrong_scalar_type_and_noncanonical_integer() {
        let mut wrong_type = MINIMAL_ENVELOPE_CBOR;
        wrong_type[2] = 0xf4;
        assert_eq!(
            decode_envelope(&wrong_type),
            Err(CborError::WrongType {
                field: CborField::ProtocolVersion,
            })
        );

        let noncanonical = replace_range(&MINIMAL_ENVELOPE_CBOR, 2..3, &[0x18, 0x01]);
        assert_eq!(
            decode_envelope(&noncanonical),
            Err(CborError::NonCanonical {
                field: CborField::ProtocolVersion,
            })
        );
    }

    #[test]
    fn rejects_wrong_and_indefinite_identifier_lengths() {
        let mut short = MINIMAL_ENVELOPE_CBOR;
        short[4] = 0x4f;
        assert_eq!(
            decode_envelope(&short),
            Err(CborError::WrongLength {
                field: CborField::MessageId,
            })
        );

        let long = replace_range(
            &MINIMAL_ENVELOPE_CBOR,
            4..21,
            &[
                0x51, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11,
            ],
        );
        assert_eq!(
            decode_envelope(&long),
            Err(CborError::WrongLength {
                field: CborField::MessageId,
            })
        );

        let mut indefinite = MINIMAL_ENVELOPE_CBOR;
        indefinite[4] = 0x5f;
        assert_eq!(
            decode_envelope(&indefinite),
            Err(CborError::IndefiniteLength {
                field: CborField::MessageId,
            })
        );

        let mut short_hint = MINIMAL_ENVELOPE_CBOR;
        short_hint[22] = 0x4f;
        assert_eq!(
            decode_envelope(&short_hint),
            Err(CborError::WrongLength {
                field: CborField::RecipientHint,
            })
        );

        let long_hint = replace_range(
            &MINIMAL_ENVELOPE_CBOR,
            22..39,
            &[
                0x51, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22,
            ],
        );
        assert_eq!(
            decode_envelope(&long_hint),
            Err(CborError::WrongLength {
                field: CborField::RecipientHint,
            })
        );
    }

    #[test]
    fn rejects_noncanonical_byte_string_length() {
        let noncanonical = replace_range(&MINIMAL_ENVELOPE_CBOR, 4..5, &[0x58, 0x10]);
        assert_eq!(
            decode_envelope(&noncanonical),
            Err(CborError::NonCanonical {
                field: CborField::MessageId,
            })
        );
    }

    #[test]
    fn rejects_empty_and_oversized_protected_payload() {
        let empty = replace_range(&MINIMAL_ENVELOPE_CBOR, 47..49, &[0x40]);
        assert_eq!(
            decode_envelope(&empty),
            Err(CborError::WrongLength {
                field: CborField::ProtectedPayload,
            })
        );

        let oversized = encode_unchecked_payload(MAX_PROTECTED_PAYLOAD_SIZE + 1);
        assert!(oversized.len() <= MAX_ENVELOPE_SIZE);
        assert_eq!(
            decode_envelope(&oversized),
            Err(CborError::WrongLength {
                field: CborField::ProtectedPayload,
            })
        );

        let mut indefinite = MINIMAL_ENVELOPE_CBOR;
        indefinite[47] = 0x5f;
        assert_eq!(
            decode_envelope(&indefinite),
            Err(CborError::IndefiniteLength {
                field: CborField::ProtectedPayload,
            })
        );
    }

    #[test]
    fn rejects_protocol_values_outside_allowed_ranges() {
        let ttl_below = replace_range(
            &MINIMAL_ENVELOPE_CBOR,
            40..42,
            &encode_unsigned_for_test(MIN_TTL_SECONDS - 1),
        );
        assert_eq!(
            decode_envelope(&ttl_below),
            Err(CborError::EnvelopeValidation(
                CoreError::ValueBelowMinimum {
                    field: Field::TtlSeconds,
                }
            ))
        );

        let ttl_above = replace_range(
            &MINIMAL_ENVELOPE_CBOR,
            40..42,
            &encode_unsigned_for_test(MAX_TTL_SECONDS + 1),
        );
        assert_eq!(
            decode_envelope(&ttl_above),
            Err(CborError::EnvelopeValidation(
                CoreError::ValueAboveMaximum {
                    field: Field::TtlSeconds,
                }
            ))
        );

        let hops_below = replace_range(
            &MINIMAL_ENVELOPE_CBOR,
            43..44,
            &encode_unsigned_for_test(MIN_MAX_HOPS - 1),
        );
        assert_eq!(
            decode_envelope(&hops_below),
            Err(CborError::EnvelopeValidation(
                CoreError::ValueBelowMinimum {
                    field: Field::MaxHops,
                }
            ))
        );

        let hops_above = replace_range(
            &MINIMAL_ENVELOPE_CBOR,
            43..44,
            &encode_unsigned_for_test(MAX_MAX_HOPS + 1),
        );
        assert_eq!(
            decode_envelope(&hops_above),
            Err(CborError::EnvelopeValidation(
                CoreError::ValueAboveMaximum {
                    field: Field::MaxHops,
                }
            ))
        );

        let priority = replace_range(&MINIMAL_ENVELOPE_CBOR, 45..46, &[0x01]);
        assert_eq!(
            decode_envelope(&priority),
            Err(CborError::EnvelopeValidation(CoreError::UnsupportedValue {
                field: Field::Priority,
            }))
        );
    }

    #[test]
    fn rejects_noncanonical_ttl_encoding() {
        let noncanonical = replace_range(&MINIMAL_ENVELOPE_CBOR, 40..42, &[0x19, 0x00, 0x3c]);
        assert_eq!(
            decode_envelope(&noncanonical),
            Err(CborError::NonCanonical {
                field: CborField::TtlSeconds,
            })
        );
    }

    #[test]
    fn rejects_text_keys_tags_floats_and_nested_values() {
        let text_key = replace_range(&MINIMAL_ENVELOPE_CBOR, 1..2, &[0x61, b'0']);
        assert_eq!(
            decode_envelope(&text_key),
            Err(CborError::WrongType {
                field: CborField::MapKey,
            })
        );

        let tagged_version = replace_range(&MINIMAL_ENVELOPE_CBOR, 2..3, &[0xc0, 0x01]);
        assert_eq!(
            decode_envelope(&tagged_version),
            Err(CborError::WrongType {
                field: CborField::ProtocolVersion,
            })
        );

        let float_version = replace_range(&MINIMAL_ENVELOPE_CBOR, 2..3, &[0xf9, 0x3c, 0x00]);
        assert_eq!(
            decode_envelope(&float_version),
            Err(CborError::WrongType {
                field: CborField::ProtocolVersion,
            })
        );

        let nested_version = replace_range(&MINIMAL_ENVELOPE_CBOR, 2..3, &[0x81, 0x01]);
        assert_eq!(
            decode_envelope(&nested_version),
            Err(CborError::WrongType {
                field: CborField::ProtocolVersion,
            })
        );
    }

    #[test]
    fn rejects_trailing_and_truncated_data() {
        let mut trailing = MINIMAL_ENVELOPE_CBOR.to_vec();
        trailing.push(0);
        assert_eq!(decode_envelope(&trailing), Err(CborError::TrailingData));

        for end in 1..MINIMAL_ENVELOPE_CBOR.len() {
            assert!(decode_envelope(&MINIMAL_ENVELOPE_CBOR[..end]).is_err());
        }
    }

    #[test]
    fn arbitrary_short_inputs_return_errors_without_panicking() {
        for first in u8::MIN..=u8::MAX {
            let input = [first];
            assert!(decode_envelope(&input).is_err());
        }
    }

    #[test]
    fn deterministic_malformed_corpus_never_panics() {
        let mut state = 0x4c41_4e54_4552_4e01_u64;
        for length in 0..=512 {
            let mut input = Vec::with_capacity(length);
            for _ in 0..length {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                input.push(state.to_le_bytes()[0]);
            }
            let _result = decode_envelope(&input);
        }
    }

    #[test]
    fn errors_do_not_include_input_bytes() {
        let secret_marker = b"OBVIOUS-SECRET-TEST-MARKER";
        let mut input = vec![0x81];
        input.extend_from_slice(secret_marker);
        let error = decode_envelope(&input);
        let Err(error) = error else {
            panic!("invalid input was accepted");
        };
        let output = format!("{error:?} {error}");
        assert!(!output.contains("OBVIOUS-SECRET-TEST-MARKER"));
    }

    #[test]
    fn encoder_is_deterministic() {
        let envelope = minimal_envelope();
        assert_eq!(encode_envelope(&envelope), encode_envelope(&envelope));
    }
}
