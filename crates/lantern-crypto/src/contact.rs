// SPDX-License-Identifier: MPL-2.0

use core::fmt::{self, Write as _};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use minicbor::{Decoder, Encoder, data::Type};
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature, olm::Account, sas::Sas};
use zeroize::Zeroizing;

use crate::CryptoError;

const QR_PREFIX: &str = "lantern-contact-v1:";
const BUNDLE_VERSION: u8 = 1;
const INVITE_KIND: u8 = 0;
const RESPONSE_KIND: u8 = 1;
const SIGNED_FIELDS: u64 = 13;
const UNSIGNED_FIELDS: u64 = 12;
const INVITE_DOMAIN: &[u8] = b"Lantern contact invite signature v1\0";
const RESPONSE_DOMAIN: &[u8] = b"Lantern contact response signature v1\0";
const SAS_DOMAIN: &str = "Lantern contact SAS v1\0";

pub const CONTACT_QR_MAX_BYTES: usize = 704;
pub const CONTACT_CBOR_MAX_BYTES: usize = 512;

#[derive(Clone, Eq, PartialEq)]
pub struct Invitation {
    invitation_id: [u8; 16],
    signing_identity_key: [u8; 32],
    curve_identity_key: [u8; 32],
    one_time_key: [u8; 32],
    sas_key: [u8; 32],
    invitation_secret: [u8; 32],
    inbound_recipient_hint: [u8; 16],
    signature: [u8; 64],
}

#[derive(Clone, Eq, PartialEq)]
pub struct ContactResponse {
    response_id: [u8; 16],
    invitation_id: [u8; 16],
    signing_identity_key: [u8; 32],
    curve_identity_key: [u8; 32],
    sas_key: [u8; 32],
    response_secret: [u8; 32],
    inbound_recipient_hint: [u8; 16],
    signature: [u8; 64],
}

pub enum ContactBundle {
    Invitation(Invitation),
    Response(ContactResponse),
}

pub struct SasHandle(Sas);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SasDisplay {
    emoji_indices: [u8; 7],
    decimals: (u16, u16, u16),
}

impl SasDisplay {
    pub const fn emoji_indices(&self) -> &[u8; 7] {
        &self.emoji_indices
    }

    pub const fn decimals(&self) -> (u16, u16, u16) {
        self.decimals
    }
}

impl Invitation {
    pub fn create(account: &mut Account) -> Result<(Self, SasHandle), CryptoError> {
        let previous_keys = account.one_time_keys();
        account.generate_one_time_keys(1);
        let generated = account
            .one_time_keys()
            .into_iter()
            .find(|(id, _)| !previous_keys.contains_key(id))
            .map(|(_, key)| key)
            .ok_or(CryptoError::StateRejected)?;
        account.mark_keys_as_published();
        let sas = Sas::new();
        let mut invitation = Self {
            invitation_id: random_array()?,
            signing_identity_key: *account.ed25519_key().as_bytes(),
            curve_identity_key: account.curve25519_key().to_bytes(),
            one_time_key: generated.to_bytes(),
            sas_key: sas.public_key().to_bytes(),
            invitation_secret: random_array()?,
            inbound_recipient_hint: random_array()?,
            signature: [0; 64],
        };
        let unsigned = invitation.encode_unsigned()?;
        invitation.signature = account
            .sign(signing_input(INVITE_DOMAIN, &unsigned))
            .to_bytes();
        Ok((invitation, SasHandle(sas)))
    }

    pub const fn invitation_id(&self) -> &[u8; 16] {
        &self.invitation_id
    }

    pub const fn signing_identity_key(&self) -> &[u8; 32] {
        &self.signing_identity_key
    }

    pub const fn curve_identity_key(&self) -> &[u8; 32] {
        &self.curve_identity_key
    }

    pub const fn one_time_key(&self) -> &[u8; 32] {
        &self.one_time_key
    }

    pub const fn invitation_secret(&self) -> &[u8; 32] {
        &self.invitation_secret
    }

    pub const fn inbound_recipient_hint(&self) -> &[u8; 16] {
        &self.inbound_recipient_hint
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, CryptoError> {
        let mut encoder = Encoder::new(Vec::with_capacity(228));
        encoder.map(UNSIGNED_FIELDS).map_err(encoding_error)?;
        encode_versions(&mut encoder, INVITE_KIND, true)?;
        encoder
            .u8(5)
            .and_then(|value| value.bytes(&self.invitation_id))
            .and_then(|value| value.u8(6))
            .and_then(|value| value.bytes(&self.signing_identity_key))
            .and_then(|value| value.u8(7))
            .and_then(|value| value.bytes(&self.curve_identity_key))
            .and_then(|value| value.u8(8))
            .and_then(|value| value.bytes(&self.one_time_key))
            .and_then(|value| value.u8(9))
            .and_then(|value| value.bytes(&self.sas_key))
            .and_then(|value| value.u8(10))
            .and_then(|value| value.bytes(&self.invitation_secret))
            .and_then(|value| value.u8(11))
            .and_then(|value| value.bytes(&self.inbound_recipient_hint))
            .map_err(encoding_error)?;
        Ok(encoder.into_writer())
    }

    fn encode_signed(&self) -> Result<Vec<u8>, CryptoError> {
        let mut encoded = self.encode_unsigned()?;
        encoded[0] = 0xad;
        let mut encoder = Encoder::new(encoded);
        encoder.writer_mut().extend_from_slice(&[0x0c, 0x58, 0x40]);
        encoder.writer_mut().extend_from_slice(&self.signature);
        Ok(encoder.into_writer())
    }

    fn verify(&self) -> Result<(), CryptoError> {
        validate_curve_keys(&[&self.curve_identity_key, &self.one_time_key, &self.sas_key])?;
        verify_signature(
            &self.signing_identity_key,
            &self.signature,
            INVITE_DOMAIN,
            &self.encode_unsigned()?,
        )
    }
}

impl ContactResponse {
    pub fn create(
        account: &Account,
        invitation: &Invitation,
    ) -> Result<(Self, SasHandle), CryptoError> {
        invitation.verify()?;
        let sas = Sas::new();
        let mut response = Self {
            response_id: random_array()?,
            invitation_id: invitation.invitation_id,
            signing_identity_key: *account.ed25519_key().as_bytes(),
            curve_identity_key: account.curve25519_key().to_bytes(),
            sas_key: sas.public_key().to_bytes(),
            response_secret: random_array()?,
            inbound_recipient_hint: random_array()?,
            signature: [0; 64],
        };
        let unsigned = response.encode_unsigned()?;
        response.signature = account
            .sign(signing_input(RESPONSE_DOMAIN, &unsigned))
            .to_bytes();
        Ok((response, SasHandle(sas)))
    }

    pub const fn response_id(&self) -> &[u8; 16] {
        &self.response_id
    }

    pub const fn invitation_id(&self) -> &[u8; 16] {
        &self.invitation_id
    }

    pub const fn signing_identity_key(&self) -> &[u8; 32] {
        &self.signing_identity_key
    }

    pub const fn curve_identity_key(&self) -> &[u8; 32] {
        &self.curve_identity_key
    }

    pub const fn response_secret(&self) -> &[u8; 32] {
        &self.response_secret
    }

    pub const fn inbound_recipient_hint(&self) -> &[u8; 16] {
        &self.inbound_recipient_hint
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, CryptoError> {
        let mut encoder = Encoder::new(Vec::with_capacity(208));
        encoder.map(UNSIGNED_FIELDS).map_err(encoding_error)?;
        encode_versions(&mut encoder, RESPONSE_KIND, false)?;
        encoder
            .u8(5)
            .and_then(|value| value.bytes(&self.response_id))
            .and_then(|value| value.u8(6))
            .and_then(|value| value.bytes(&self.invitation_id))
            .and_then(|value| value.u8(7))
            .and_then(|value| value.bytes(&self.signing_identity_key))
            .and_then(|value| value.u8(8))
            .and_then(|value| value.bytes(&self.curve_identity_key))
            .and_then(|value| value.u8(9))
            .and_then(|value| value.bytes(&self.sas_key))
            .and_then(|value| value.u8(10))
            .and_then(|value| value.bytes(&self.response_secret))
            .and_then(|value| value.u8(11))
            .and_then(|value| value.bytes(&self.inbound_recipient_hint))
            .map_err(encoding_error)?;
        Ok(encoder.into_writer())
    }

    fn encode_signed(&self) -> Result<Vec<u8>, CryptoError> {
        let mut encoded = self.encode_unsigned()?;
        encoded[0] = 0xad;
        encoded.extend_from_slice(&[0x0c, 0x58, 0x40]);
        encoded.extend_from_slice(&self.signature);
        Ok(encoded)
    }

    fn verify(&self) -> Result<(), CryptoError> {
        validate_curve_keys(&[&self.curve_identity_key, &self.sas_key])?;
        verify_signature(
            &self.signing_identity_key,
            &self.signature,
            RESPONSE_DOMAIN,
            &self.encode_unsigned()?,
        )
    }
}

impl SasHandle {
    pub fn finish(
        self,
        invitation: &Invitation,
        response: &ContactResponse,
    ) -> Result<SasDisplay, CryptoError> {
        invitation.verify()?;
        response.verify()?;
        if response.invitation_id != invitation.invitation_id {
            return Err(CryptoError::StateRejected);
        }
        let own_key = self.0.public_key().to_bytes();
        let their_key = if own_key == invitation.sas_key {
            response.sas_key
        } else if own_key == response.sas_key {
            invitation.sas_key
        } else {
            return Err(CryptoError::StateRejected);
        };
        let their_key =
            Curve25519PublicKey::from_slice(&their_key).map_err(|_| CryptoError::InvalidValue)?;
        let established = self
            .0
            .diffie_hellman(their_key)
            .map_err(|_| CryptoError::InvalidValue)?;
        let info = sas_info(invitation, response)?;
        let bytes = established.bytes(&info);
        Ok(SasDisplay {
            emoji_indices: bytes.emoji_indices(),
            decimals: bytes.decimals(),
        })
    }
}

impl fmt::Debug for Invitation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Invitation([REDACTED])")
    }
}

impl fmt::Debug for ContactResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContactResponse([REDACTED])")
    }
}

impl fmt::Debug for ContactBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invitation(_) => formatter.write_str("ContactBundle::Invitation([REDACTED])"),
            Self::Response(_) => formatter.write_str("ContactBundle::Response([REDACTED])"),
        }
    }
}

impl fmt::Debug for SasHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SasHandle([REDACTED])")
    }
}

pub fn encode_invitation_qr(invitation: &Invitation) -> Result<String, CryptoError> {
    encode_qr(&invitation.encode_signed()?)
}

pub fn encode_response_qr(response: &ContactResponse) -> Result<String, CryptoError> {
    encode_qr(&response.encode_signed()?)
}

fn encode_qr(cbor: &[u8]) -> Result<String, CryptoError> {
    if cbor.len() > CONTACT_CBOR_MAX_BYTES {
        return Err(CryptoError::InputTooLarge);
    }
    let mut output = String::with_capacity(QR_PREFIX.len() + 684);
    output.push_str(QR_PREFIX);
    URL_SAFE_NO_PAD.encode_string(cbor, &mut output);
    if output.len() > CONTACT_QR_MAX_BYTES {
        return Err(CryptoError::InputTooLarge);
    }
    Ok(output)
}

pub fn decode_contact_qr(input: &str) -> Result<ContactBundle, CryptoError> {
    if input.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    if input.len() > CONTACT_QR_MAX_BYTES || !input.is_ascii() {
        return Err(CryptoError::InputTooLarge);
    }
    let encoded = input
        .strip_prefix(QR_PREFIX)
        .ok_or(CryptoError::Malformed)?;
    if encoded.is_empty() || encoded.contains('=') {
        return Err(CryptoError::Malformed);
    }
    let mut cbor = vec![0; encoded.len().saturating_mul(3).div_ceil(4)];
    let length = URL_SAFE_NO_PAD
        .decode_slice(encoded, &mut cbor)
        .map_err(|_| CryptoError::Malformed)?;
    cbor.truncate(length);
    if cbor.is_empty() || cbor.len() > CONTACT_CBOR_MAX_BYTES {
        return Err(CryptoError::WrongLength);
    }
    if encode_qr(&cbor)? != input {
        return Err(CryptoError::NonCanonical);
    }
    decode_contact_cbor(&cbor)
}

pub fn identity_fingerprint(signing_identity_key: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut encoded = String::with_capacity(52);
    let mut buffer = 0_u32;
    let mut buffered_bits = 0_u8;
    for byte in signing_identity_key {
        buffer = (buffer << 8) | u32::from(*byte);
        buffered_bits += 8;
        while buffered_bits >= 5 {
            buffered_bits -= 5;
            let index = ((buffer >> buffered_bits) & 0x1f) as usize;
            encoded.push(char::from(ALPHABET[index]));
        }
    }
    if buffered_bits > 0 {
        let index = ((buffer << (5 - buffered_bits)) & 0x1f) as usize;
        encoded.push(char::from(ALPHABET[index]));
    }

    let mut grouped = String::with_capacity(67);
    grouped.push_str("L1-");
    for (index, character) in encoded.chars().enumerate() {
        if index > 0 && index % 4 == 0 {
            grouped.push('-');
        }
        grouped.push(character);
    }
    grouped
}

fn decode_contact_cbor(input: &[u8]) -> Result<ContactBundle, CryptoError> {
    let mut decoder = Decoder::new(input);
    expect_map(&mut decoder, SIGNED_FIELDS)?;
    expect_key(&mut decoder, 0)?;
    if decode_unsigned(&mut decoder)? != u64::from(BUNDLE_VERSION) {
        return Err(CryptoError::UnsupportedVersion);
    }
    expect_key(&mut decoder, 1)?;
    let kind = decode_unsigned(&mut decoder)?;
    let bundle = match kind {
        0 => ContactBundle::Invitation(decode_invitation(&mut decoder)?),
        1 => ContactBundle::Response(decode_response(&mut decoder)?),
        _ => return Err(CryptoError::UnsupportedType),
    };
    if decoder.position() != input.len() {
        return Err(CryptoError::Malformed);
    }
    let canonical = match &bundle {
        ContactBundle::Invitation(value) => {
            value.verify()?;
            value.encode_signed()?
        }
        ContactBundle::Response(value) => {
            value.verify()?;
            value.encode_signed()?
        }
    };
    if canonical.as_slice() != input {
        return Err(CryptoError::NonCanonical);
    }
    Ok(bundle)
}

fn decode_invitation(decoder: &mut Decoder<'_>) -> Result<Invitation, CryptoError> {
    decode_version_arrays(decoder)?;
    expect_key(decoder, 5)?;
    let invitation_id = decode_fixed(decoder)?;
    expect_key(decoder, 6)?;
    let signing_identity_key = decode_fixed(decoder)?;
    expect_key(decoder, 7)?;
    let curve_identity_key = decode_fixed(decoder)?;
    expect_key(decoder, 8)?;
    let one_time_key = decode_fixed(decoder)?;
    expect_key(decoder, 9)?;
    let sas_key = decode_fixed(decoder)?;
    expect_key(decoder, 10)?;
    let invitation_secret = decode_fixed(decoder)?;
    expect_key(decoder, 11)?;
    let inbound_recipient_hint = decode_fixed(decoder)?;
    expect_key(decoder, 12)?;
    let signature = decode_fixed(decoder)?;
    Ok(Invitation {
        invitation_id,
        signing_identity_key,
        curve_identity_key,
        one_time_key,
        sas_key,
        invitation_secret,
        inbound_recipient_hint,
        signature,
    })
}

fn decode_response(decoder: &mut Decoder<'_>) -> Result<ContactResponse, CryptoError> {
    decode_selected_versions(decoder)?;
    expect_key(decoder, 5)?;
    let response_id = decode_fixed(decoder)?;
    expect_key(decoder, 6)?;
    let invitation_id = decode_fixed(decoder)?;
    expect_key(decoder, 7)?;
    let signing_identity_key = decode_fixed(decoder)?;
    expect_key(decoder, 8)?;
    let curve_identity_key = decode_fixed(decoder)?;
    expect_key(decoder, 9)?;
    let sas_key = decode_fixed(decoder)?;
    expect_key(decoder, 10)?;
    let response_secret = decode_fixed(decoder)?;
    expect_key(decoder, 11)?;
    let inbound_recipient_hint = decode_fixed(decoder)?;
    expect_key(decoder, 12)?;
    let signature = decode_fixed(decoder)?;
    Ok(ContactResponse {
        response_id,
        invitation_id,
        signing_identity_key,
        curve_identity_key,
        sas_key,
        response_secret,
        inbound_recipient_hint,
        signature,
    })
}

fn encode_versions(
    encoder: &mut Encoder<Vec<u8>>,
    kind: u8,
    arrays: bool,
) -> Result<(), CryptoError> {
    encoder
        .u8(0)
        .and_then(|value| value.u8(BUNDLE_VERSION))
        .and_then(|value| value.u8(1))
        .and_then(|value| value.u8(kind))
        .map_err(encoding_error)?;
    for key in 2..=4 {
        encoder.u8(key).map_err(encoding_error)?;
        if arrays {
            encoder
                .array(1)
                .and_then(|value| value.u8(1))
                .map_err(encoding_error)?;
        } else {
            encoder.u8(1).map_err(encoding_error)?;
        }
    }
    Ok(())
}

fn decode_version_arrays(decoder: &mut Decoder<'_>) -> Result<(), CryptoError> {
    for key in 2..=4 {
        expect_key(decoder, key)?;
        if decoder.datatype().map_err(|_| CryptoError::Malformed)? != Type::Array
            || decoder.array().map_err(|_| CryptoError::Malformed)? != Some(1)
            || decode_unsigned(decoder)? != 1
        {
            return Err(CryptoError::UnsupportedVersion);
        }
    }
    Ok(())
}

fn decode_selected_versions(decoder: &mut Decoder<'_>) -> Result<(), CryptoError> {
    for key in 2..=4 {
        expect_key(decoder, key)?;
        if decode_unsigned(decoder)? != 1 {
            return Err(CryptoError::UnsupportedVersion);
        }
    }
    Ok(())
}

fn signing_input(domain: &[u8], unsigned: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + unsigned.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(unsigned);
    input
}

fn verify_signature(
    key: &[u8; 32],
    signature: &[u8; 64],
    domain: &[u8],
    unsigned: &[u8],
) -> Result<(), CryptoError> {
    let key = Ed25519PublicKey::from_slice(key).map_err(|_| CryptoError::SignatureRejected)?;
    let signature =
        Ed25519Signature::from_slice(signature).map_err(|_| CryptoError::SignatureRejected)?;
    key.verify(&signing_input(domain, unsigned), &signature)
        .map_err(|_| CryptoError::SignatureRejected)
}

fn validate_curve_keys(keys: &[&[u8; 32]]) -> Result<(), CryptoError> {
    for key in keys {
        Curve25519PublicKey::from_slice(*key).map_err(|_| CryptoError::InvalidValue)?;
    }
    Ok(())
}

fn sas_info(
    invitation: &Invitation,
    response: &ContactResponse,
) -> Result<Zeroizing<String>, CryptoError> {
    let invitation = invitation.encode_signed()?;
    let response = response.encode_signed()?;
    let invitation_length =
        u16::try_from(invitation.len()).map_err(|_| CryptoError::WrongLength)?;
    let response_length = u16::try_from(response.len()).map_err(|_| CryptoError::WrongLength)?;
    let mut info = Zeroizing::new(String::with_capacity(800));
    info.push_str(SAS_DOMAIN);
    write!(info, "{invitation_length:04x}:").map_err(|_| CryptoError::Malformed)?;
    URL_SAFE_NO_PAD.encode_string(&invitation, &mut info);
    write!(info, ":{response_length:04x}:").map_err(|_| CryptoError::Malformed)?;
    URL_SAFE_NO_PAD.encode_string(&response, &mut info);
    Ok(info)
}

fn random_array<const LENGTH: usize>() -> Result<[u8; LENGTH], CryptoError> {
    let mut bytes = [0; LENGTH];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::Entropy)?;
    Ok(bytes)
}

fn expect_map(decoder: &mut Decoder<'_>, fields: u64) -> Result<(), CryptoError> {
    if decoder.datatype().map_err(|_| CryptoError::Malformed)? != Type::Map
        || decoder.map().map_err(|_| CryptoError::Malformed)? != Some(fields)
    {
        return Err(CryptoError::Malformed);
    }
    Ok(())
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

fn encoding_error<T>(_error: T) -> CryptoError {
    CryptoError::Malformed
}

