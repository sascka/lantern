// SPDX-License-Identifier: MPL-2.0

//! Transactional handoff between Lantern cryptography and the open node queue.

#![forbid(unsafe_code)]

mod error;

use core::fmt;

use lantern_core::{EnqueueOutcome, MessageId, decode_envelope};
use lantern_crypto::{ReceivedChat, decrypt_chat};
use lantern_node::{NodeClock, NodeRuntime};
use lantern_secret_storage::SecretStore;

pub use error::BridgeError;

pub const OUTBOX_EXPORT_BATCH: usize = 32;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OutboxExportReport {
    examined: usize,
    inserted: usize,
    acknowledged: usize,
    deferred: bool,
}

impl OutboxExportReport {
    pub const fn examined(self) -> usize {
        self.examined
    }

    pub const fn inserted(self) -> usize {
        self.inserted
    }

    pub const fn acknowledged(self) -> usize {
        self.acknowledged
    }

    pub const fn deferred(self) -> bool {
        self.deferred
    }
}

pub enum IncomingChatResult {
    Opened(ReceivedChat),
    Recovered,
    NotForThisProfile,
    Missing,
}

impl fmt::Debug for IncomingChatResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Opened(chat) => formatter.debug_tuple("Opened").field(chat).finish(),
            Self::Recovered => formatter.write_str("Recovered"),
            Self::NotForThisProfile => formatter.write_str("NotForThisProfile"),
            Self::Missing => formatter.write_str("Missing"),
        }
    }
}

pub fn export_pending_outbox<C: NodeClock>(
    store: &mut SecretStore,
    node: &mut NodeRuntime<C>,
) -> Result<OutboxExportReport, BridgeError> {
    node.maintain()?;
    let mut report = OutboxExportReport::default();
    while report.examined < OUTBOX_EXPORT_BATCH {
        let Some(pending) = store.next_pending_outbox()? else {
            break;
        };
        report.examined += 1;
        let envelope = decode_envelope(pending.envelope_cbor())?;
        if envelope.message_id().as_bytes() != pending.message_id() {
            return Err(BridgeError::OutboxIdentifierMismatch);
        }

        let message_id = envelope.message_id();
        if let Some(entry) = node.queue().get(message_id) {
            if entry.envelope() != &envelope {
                return Err(BridgeError::QueueConflict);
            }
            acknowledge(store, message_id)?;
            report.acknowledged += 1;
            continue;
        }

        match node.enqueue_origin(envelope.clone())?.outcome() {
            EnqueueOutcome::Stored => {
                report.inserted += 1;
                acknowledge(store, message_id)?;
                report.acknowledged += 1;
            }
            EnqueueOutcome::DuplicateActive => {
                let exact_match = node
                    .queue()
                    .get(message_id)
                    .is_some_and(|entry| entry.envelope() == &envelope);
                if !exact_match {
                    return Err(BridgeError::QueueConflict);
                }
                acknowledge(store, message_id)?;
                report.acknowledged += 1;
            }
            EnqueueOutcome::DuplicateTombstone
            | EnqueueOutcome::Expired
            | EnqueueOutcome::ItemExceedsByteQuota => {
                report.deferred = true;
                break;
            }
        }
    }
    Ok(report)
}

pub fn process_incoming_chat<C: NodeClock>(
    store: &mut SecretStore,
    node: &mut NodeRuntime<C>,
    message_id: MessageId,
) -> Result<IncomingChatResult, BridgeError> {
    node.maintain()?;
    let Some(envelope) = node
        .queue()
        .get(message_id)
        .map(|entry| entry.envelope().clone())
    else {
        return Ok(IncomingChatResult::Missing);
    };
    let raw_message_id = *message_id.as_bytes();

    if store.has_received_chat(raw_message_id)? {
        node.complete_opened(message_id)?;
        return Ok(IncomingChatResult::Recovered);
    }

    let Some(contact_id) = store.contact_for_inbound_hint(*envelope.recipient_hint().as_bytes())?
    else {
        return Ok(IncomingChatResult::NotForThisProfile);
    };

    let chat = decrypt_chat(store, contact_id, &envelope)?;
    node.complete_opened(message_id)?;
    Ok(IncomingChatResult::Opened(chat))
}

fn acknowledge(store: &mut SecretStore, message_id: MessageId) -> Result<(), BridgeError> {
    if store.remove_pending_outbox(*message_id.as_bytes())? {
        Ok(())
    } else {
        Err(BridgeError::OutboxAcknowledgementLost)
    }
}
