// SPDX-License-Identifier: AGPL-3.0-or-later

use core::str::FromStr;
use std::{io::Write, path::Path};

use lantern_bridge::{
    BridgeError, IncomingChatResult, export_pending_outbox, process_incoming_chat,
};
use lantern_core::QueueLimits;
use lantern_crypto::{USER_TEXT_MAX_BYTES, encrypt_chat};
use lantern_diagnostics::JournalLimits;
use lantern_lan::{BindAddress, LanListener, PeerAddress, connect};
use lantern_node::{EncounterRole, NodeRuntime};
use lantern_secret_storage::{ContactId, SecretProfile};
use lantern_transport::SessionLimits;

use crate::{
    error::CliError,
    files::{create_private_directory, read_message, read_passphrase, validate_private_directory},
};

const QUEUE_FILENAME: &str = "queue.sqlite3";
const DIAGNOSTIC_FILENAME: &str = "diagnostics.sqlite3";

pub struct SendRequest<'a> {
    pub profile_path: &'a Path,
    pub passphrase_path: &'a Path,
    pub node_path: &'a Path,
    pub contact_name: &'a str,
    pub message_path: &'a Path,
    pub ttl_seconds: u64,
    pub max_hops: u64,
}

pub fn create_node(directory: &Path, output: &mut dyn Write) -> Result<(), CliError> {
    create_private_directory(directory)?;
    let mut node = open_node(directory)?;
    node.stop().map_err(|_| CliError::Node)?;
    writeln!(output, "Node directory created.").map_err(|_| CliError::Io)
}

pub fn send(request: SendRequest<'_>, output: &mut dyn Write) -> Result<(), CliError> {
    let passphrase = read_passphrase(request.passphrase_path)?;
    let mut profile =
        SecretProfile::open(request.profile_path, &passphrase).map_err(|_| CliError::Profile)?;
    let contact_id = find_contact(profile.secret_store(), request.contact_name)?;
    let message = read_message(request.message_path, USER_TEXT_MAX_BYTES)?;
    encrypt_chat(
        profile.secret_store_mut(),
        contact_id,
        message,
        request.ttl_seconds,
        request.max_hops,
    )
    .map_err(|_| CliError::Crypto)?;
    let mut node = open_node(request.node_path)?;
    let report = export_pending_outbox(profile.secret_store_mut(), &mut node)
        .map_err(|_| CliError::Bridge)?;
    if report.deferred() {
        return Err(CliError::QueueDeferred);
    }
    node.stop().map_err(|_| CliError::Node)?;
    writeln!(output, "Message stored in the local queue.").map_err(|_| CliError::Io)
}

pub fn listen_once(
    node_path: &Path,
    address: &str,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let bind = BindAddress::from_str(address).map_err(|_| CliError::Lan)?;
    let listener = LanListener::bind(bind).map_err(|_| CliError::Lan)?;
    let local = listener.local_address().map_err(|_| CliError::Lan)?;
    writeln!(output, "Listening on port {}.", local.port()).map_err(|_| CliError::Io)?;
    output.flush().map_err(|_| CliError::Io)?;
    let mut node = open_node(node_path)?;
    let connection = listener.accept().map_err(|_| CliError::Lan)?;
    let session = node
        .begin_session(connection, SessionLimits::standard())
        .map_err(|_| CliError::Node)?;
    let (session, summary) = node
        .run_encounter(session, EncounterRole::Responder)
        .map_err(|_| CliError::Node)?;
    session.into_inner().shutdown().map_err(|_| CliError::Lan)?;
    node.stop().map_err(|_| CliError::Node)?;
    write_summary(summary, output)
}

pub fn connect_once(
    node_path: &Path,
    address: &str,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let peer = PeerAddress::from_str(address).map_err(|_| CliError::Lan)?;
    let connection = connect(peer).map_err(|_| CliError::Lan)?;
    let mut node = open_node(node_path)?;
    let session = node
        .begin_session(connection, SessionLimits::standard())
        .map_err(|_| CliError::Node)?;
    let (session, summary) = node
        .run_encounter(session, EncounterRole::Initiator)
        .map_err(|_| CliError::Node)?;
    session.into_inner().shutdown().map_err(|_| CliError::Lan)?;
    node.stop().map_err(|_| CliError::Node)?;
    write_summary(summary, output)
}

pub fn receive(
    profile_path: &Path,
    passphrase_path: &Path,
    node_path: &Path,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let passphrase = read_passphrase(passphrase_path)?;
    let mut profile =
        SecretProfile::open(profile_path, &passphrase).map_err(|_| CliError::Profile)?;
    let mut node = open_node(node_path)?;
    let identifiers = node
        .queue()
        .entries()
        .map(|entry| entry.envelope().message_id())
        .collect::<Vec<_>>();
    let mut opened = 0_usize;
    let mut recovered = 0_usize;
    let mut rejected = 0_usize;
    for identifier in identifiers {
        match process_incoming_chat(profile.secret_store_mut(), &mut node, identifier) {
            Ok(IncomingChatResult::Opened(message)) => {
                writeln!(output, "MESSAGE: {}", message.text()).map_err(|_| CliError::Io)?;
                opened += 1;
            }
            Ok(IncomingChatResult::Recovered) => recovered += 1,
            Ok(IncomingChatResult::NotForThisProfile | IncomingChatResult::Missing) => {}
            Err(BridgeError::Crypto(_)) => rejected += 1,
            Err(_) => return Err(CliError::Bridge),
        }
    }
    node.stop().map_err(|_| CliError::Node)?;
    writeln!(
        output,
        "Receive complete: opened {opened}, recovered {recovered}, rejected {rejected}."
    )
    .map_err(|_| CliError::Io)
}

pub fn inbox(
    profile_path: &Path,
    passphrase_path: &Path,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let passphrase = read_passphrase(passphrase_path)?;
    let profile = SecretProfile::open(profile_path, &passphrase).map_err(|_| CliError::Profile)?;
    let messages = profile
        .secret_store()
        .received_messages()
        .map_err(|_| CliError::Profile)?;
    if messages.is_empty() {
        writeln!(output, "Inbox is empty.").map_err(|_| CliError::Io)?;
        return Ok(());
    }
    for message in messages {
        let contact = profile
            .secret_store()
            .active_contact(message.contact_id())
            .map_err(|_| CliError::Profile)?
            .ok_or(CliError::Profile)?;
        writeln!(output, "{}: {}", contact.display_name(), message.text())
            .map_err(|_| CliError::Io)?;
    }
    Ok(())
}

pub fn diagnostics(node_path: &Path, output: &mut dyn Write) -> Result<(), CliError> {
    let mut node = open_node(node_path)?;
    let view = node.diagnostics().map_err(|_| CliError::Node)?;
    for record in view.records() {
        writeln!(
            output,
            "{:?} {:?} {} {:?} {:?}",
            record.code(),
            record.outcome(),
            record.object_count(),
            record.size_bucket(),
            record.duration_bucket()
        )
        .map_err(|_| CliError::Io)?;
    }
    Ok(())
}

fn open_node(directory: &Path) -> Result<NodeRuntime, CliError> {
    validate_private_directory(directory)?;
    NodeRuntime::start_with_persistent_diagnostics(
        &directory.join(QUEUE_FILENAME),
        &directory.join(DIAGNOSTIC_FILENAME),
        QueueLimits::default(),
        JournalLimits::default(),
    )
    .map_err(|_| CliError::Node)
}

fn find_contact(
    store: &lantern_secret_storage::SecretStore,
    name: &str,
) -> Result<ContactId, CliError> {
    let matches = store
        .active_contacts()
        .map_err(|_| CliError::Profile)?
        .into_iter()
        .filter(|contact| contact.display_name() == name)
        .map(|contact| contact.contact_id())
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Err(CliError::UnknownContact),
        [contact_id] => Ok(*contact_id),
        _ => Err(CliError::AmbiguousContact),
    }
}

fn write_summary(
    summary: lantern_node::EncounterSummary,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    writeln!(
        output,
        "Encounter complete: sent {}, received {}.",
        summary.sent().transferred(),
        summary.received().transferred()
    )
    .map_err(|_| CliError::Io)
}
