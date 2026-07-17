// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    io::{BufRead, Write},
    path::Path,
};

use lantern_core::{MAX_ENVELOPE_SIZE, decode_envelope, encode_envelope};
use lantern_crypto::{
    CONTACT_QR_MAX_BYTES, ContactBundle, ContactResponse, Invitation, SasDisplay,
    accept_initiator_confirmation, accept_receiver_confirmation, build_initiator_confirmation,
    decode_contact_qr, encode_invitation_qr, encode_response_qr, identity_fingerprint,
};
use lantern_secret_storage::{ContactId, NewContact, SecretProfile};

use crate::{
    error::CliError,
    files::{read_passphrase, wait_and_read, write_private},
};

pub struct InvitePaths<'a> {
    pub invitation_out: &'a Path,
    pub response_in: &'a Path,
    pub initiator_confirmation_in: &'a Path,
    pub receiver_confirmation_out: &'a Path,
}

pub struct RespondPaths<'a> {
    pub invitation_in: &'a Path,
    pub response_out: &'a Path,
    pub initiator_confirmation_out: &'a Path,
    pub receiver_confirmation_in: &'a Path,
}

pub fn invite(
    profile_path: &Path,
    passphrase_path: &Path,
    display_name: String,
    paths: InvitePaths<'_>,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    validate_display_name(&display_name)?;
    let passphrase = read_passphrase(passphrase_path)?;
    let mut profile =
        SecretProfile::open(profile_path, &passphrase).map_err(|_| CliError::Profile)?;
    let mut account = profile.load_account().map_err(|_| CliError::Profile)?;
    let (invitation, sas) = Invitation::create(&mut account).map_err(|_| CliError::Crypto)?;
    let encoded = encode_invitation_qr(&invitation).map_err(|_| CliError::Crypto)?;
    write_private(paths.invitation_out, encoded.as_bytes())?;
    writeln!(output, "Invitation file ready. Waiting for the response.")
        .map_err(|_| CliError::Io)?;
    output.flush().map_err(|_| CliError::Io)?;

    let response_bytes = wait_and_read(paths.response_in, CONTACT_QR_MAX_BYTES)?;
    let response_text = std::str::from_utf8(&response_bytes).map_err(|_| CliError::Contact)?;
    let ContactBundle::Response(response) =
        decode_contact_qr(response_text).map_err(|_| CliError::Contact)?
    else {
        return Err(CliError::Contact);
    };
    let display = sas
        .finish(&invitation, &response)
        .map_err(|_| CliError::Crypto)?;
    confirm_sas(display, input, output)?;

    let initiator_bytes = wait_and_read(paths.initiator_confirmation_in, MAX_ENVELOPE_SIZE)?;
    let initiator_envelope = decode_envelope(&initiator_bytes).map_err(|_| CliError::Contact)?;
    let accepted =
        accept_initiator_confirmation(account, &invitation, &response, &initiator_envelope)
            .map_err(|_| CliError::Crypto)?;
    let (account, session, receiver_confirmation) = accepted.into_parts();
    let contact = NewContact {
        contact_id: ContactId::generate().map_err(|_| CliError::Profile)?,
        display_name,
        signing_identity_key: *response.signing_identity_key(),
        curve_identity_key: *response.curve_identity_key(),
        inbound_recipient_hint: *invitation.inbound_recipient_hint(),
        outbound_recipient_hint: *response.inbound_recipient_hint(),
    };
    profile
        .secret_store_mut()
        .add_active_contact_with_account(contact, &session, &account)
        .map_err(|_| CliError::Profile)?;
    let encoded = encode_envelope(&receiver_confirmation).map_err(|_| CliError::Contact)?;
    write_private(paths.receiver_confirmation_out, &encoded)?;
    writeln!(output, "Contact is active.").map_err(|_| CliError::Io)
}

pub fn respond(
    profile_path: &Path,
    passphrase_path: &Path,
    display_name: String,
    paths: RespondPaths<'_>,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    validate_display_name(&display_name)?;
    let passphrase = read_passphrase(passphrase_path)?;
    let mut profile =
        SecretProfile::open(profile_path, &passphrase).map_err(|_| CliError::Profile)?;
    let account = profile.load_account().map_err(|_| CliError::Profile)?;
    let invitation_bytes = wait_and_read(paths.invitation_in, CONTACT_QR_MAX_BYTES)?;
    let invitation_text = std::str::from_utf8(&invitation_bytes).map_err(|_| CliError::Contact)?;
    let ContactBundle::Invitation(invitation) =
        decode_contact_qr(invitation_text).map_err(|_| CliError::Contact)?
    else {
        return Err(CliError::Contact);
    };
    let (response, sas) =
        ContactResponse::create(&account, &invitation).map_err(|_| CliError::Crypto)?;
    let encoded = encode_response_qr(&response).map_err(|_| CliError::Crypto)?;
    write_private(paths.response_out, encoded.as_bytes())?;
    let display = sas
        .finish(&invitation, &response)
        .map_err(|_| CliError::Crypto)?;
    confirm_sas(display, input, output)?;

    let confirmation = build_initiator_confirmation(&account, &invitation, &response)
        .map_err(|_| CliError::Crypto)?;
    let (candidate, initiator_envelope) = confirmation.into_parts();
    let encoded = encode_envelope(&initiator_envelope).map_err(|_| CliError::Contact)?;
    write_private(paths.initiator_confirmation_out, &encoded)?;
    let receiver_bytes = wait_and_read(paths.receiver_confirmation_in, MAX_ENVELOPE_SIZE)?;
    let receiver_envelope = decode_envelope(&receiver_bytes).map_err(|_| CliError::Contact)?;
    let session =
        accept_receiver_confirmation(candidate, &invitation, &response, &receiver_envelope)
            .map_err(|_| CliError::Crypto)?;
    let contact = NewContact {
        contact_id: ContactId::generate().map_err(|_| CliError::Profile)?,
        display_name,
        signing_identity_key: *invitation.signing_identity_key(),
        curve_identity_key: *invitation.curve_identity_key(),
        inbound_recipient_hint: *response.inbound_recipient_hint(),
        outbound_recipient_hint: *invitation.inbound_recipient_hint(),
    };
    profile
        .secret_store_mut()
        .add_active_contact(contact, &session)
        .map_err(|_| CliError::Profile)?;
    writeln!(output, "Contact is active.").map_err(|_| CliError::Io)
}

pub fn list(
    profile_path: &Path,
    passphrase_path: &Path,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let passphrase = read_passphrase(passphrase_path)?;
    let profile = SecretProfile::open(profile_path, &passphrase).map_err(|_| CliError::Profile)?;
    let contacts = profile
        .secret_store()
        .active_contacts()
        .map_err(|_| CliError::Profile)?;
    if contacts.is_empty() {
        writeln!(output, "No active contacts.").map_err(|_| CliError::Io)?;
        return Ok(());
    }
    for contact in contacts {
        writeln!(
            output,
            "{} {}",
            contact.display_name(),
            identity_fingerprint(contact.signing_identity_key())
        )
        .map_err(|_| CliError::Io)?;
    }
    Ok(())
}

fn validate_display_name(value: &str) -> Result<(), CliError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        Err(CliError::InvalidText)
    } else {
        Ok(())
    }
}

fn confirm_sas(
    display: SasDisplay,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let (first, second, third) = display.decimals();
    writeln!(output, "SAS: {first:04} {second:04} {third:04}").map_err(|_| CliError::Io)?;
    writeln!(
        output,
        "Compare all three numbers on both devices, then type MATCH."
    )
    .map_err(|_| CliError::Io)?;
    output.flush().map_err(|_| CliError::Io)?;

    let mut answer = [0_u8; 8];
    let mut length = 0;
    loop {
        if length == answer.len() {
            return Err(CliError::SasRejected);
        }
        let read = input
            .read(&mut answer[length..length + 1])
            .map_err(|_| CliError::Io)?;
        if read == 0 || answer[length] == b'\n' {
            break;
        }
        length += 1;
    }
    if answer[..length].ends_with(b"\r") {
        length = length.saturating_sub(1);
    }
    if &answer[..length] != b"MATCH" {
        return Err(CliError::SasRejected);
    }
    Ok(())
}
