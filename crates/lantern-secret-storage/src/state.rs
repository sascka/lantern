// SPDX-License-Identifier: MPL-2.0

use core::fmt;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use vodozemac::olm::{Session, SessionPickle};
use zeroize::Zeroizing;

use crate::{SecretStorageError, SecretStore, database::database_error};

const CONTACT_ID_LENGTH: usize = 16;
const MESSAGE_ID_LENGTH: usize = 16;
const MAX_CONTACTS: i64 = 128;
const MAX_ATTEMPTS: i64 = 2000;
const MAX_OUTBOX: i64 = 1000;
const MAX_OUTBOX_ENTRIES: usize = 1000;
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_HISTORY: i64 = 8192;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_PICKLE_BYTES: usize = 64 * 1024;
const PROFILE_CAPACITY: i64 = 32;
const CONTACT_CAPACITY: i64 = 8;
const PENDING_CAPACITY: i64 = 4;
const PROFILE_PERIOD: Duration = Duration::from_secs(10);
const CONTACT_PERIOD: Duration = Duration::from_secs(60);
const PENDING_PERIOD: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ContactId([u8; CONTACT_ID_LENGTH]);

impl ContactId {
    pub fn generate() -> Result<Self, SecretStorageError> {
        let mut bytes = [0; CONTACT_ID_LENGTH];
        getrandom::fill(&mut bytes).map_err(|_| SecretStorageError::Entropy)?;
        Ok(Self(bytes))
    }

    pub const fn from_bytes(bytes: [u8; CONTACT_ID_LENGTH]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; CONTACT_ID_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for ContactId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContactId([REDACTED])")
    }
}

pub struct NewContact {
    pub contact_id: ContactId,
    pub display_name: String,
    pub signing_identity_key: [u8; 32],
    pub curve_identity_key: [u8; 32],
    pub inbound_recipient_hint: [u8; 16],
    pub outbound_recipient_hint: [u8; 16],
}

impl fmt::Debug for NewContact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewContact")
            .field("contact_id", &"redacted")
            .field("display_name_length", &self.display_name.len())
            .field("keys", &"redacted")
            .field("hints", &"redacted")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PendingEnvelope {
    message_id: [u8; MESSAGE_ID_LENGTH],
    envelope_cbor: Box<[u8]>,
}

impl PendingEnvelope {
    pub const fn message_id(&self) -> &[u8; MESSAGE_ID_LENGTH] {
        &self.message_id
    }

    pub fn envelope_cbor(&self) -> &[u8] {
        &self.envelope_cbor
    }
}

impl fmt::Debug for PendingEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingEnvelope")
            .field("message_id", &"redacted")
            .field("envelope_length", &self.envelope_cbor.len())
            .finish()
    }
}

pub(crate) struct LimiterRuntime {
    profile_anchor: Instant,
    pending_anchor: Instant,
    contact_anchors: HashMap<ContactId, Instant>,
}

impl LimiterRuntime {
    pub(crate) fn new() -> Self {
        let now = Instant::now();
        Self {
            profile_anchor: now,
            pending_anchor: now,
            contact_anchors: HashMap::new(),
        }
    }
}

impl SecretStore {
    pub fn contact_for_inbound_hint(
        &self,
        recipient_hint: [u8; 16],
    ) -> Result<Option<ContactId>, SecretStorageError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT contact_id FROM contacts
                 WHERE state = 3 AND (
                    inbound_current_hint = ?1
                    OR inbound_proposed_hint = ?1
                    OR inbound_retiring_hint = ?1
                 )
                 ORDER BY contact_id LIMIT 2",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map(params![recipient_hint.as_slice()], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(database_error)?;
        let mut matches = Vec::with_capacity(2);
        for row in rows {
            let bytes = row.map_err(database_error)?;
            let bytes = <[u8; CONTACT_ID_LENGTH]>::try_from(bytes)
                .map_err(|_| SecretStorageError::CorruptStorage)?;
            matches.push(ContactId::from_bytes(bytes));
        }
        match matches.as_slice() {
            [] => Ok(None),
            [contact_id] => Ok(Some(*contact_id)),
            _ => Err(SecretStorageError::CorruptStorage),
        }
    }

    pub fn outbound_recipient_hint(
        &self,
        contact_id: ContactId,
    ) -> Result<[u8; 16], SecretStorageError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT outbound_current_hint FROM contacts
                 WHERE contact_id = ?1 AND state = 3",
                params![contact_id.0.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        let bytes = bytes.ok_or(SecretStorageError::UnknownContact)?;
        <[u8; 16]>::try_from(bytes).map_err(|_| SecretStorageError::CorruptStorage)
    }

    pub fn add_active_contact(
        &mut self,
        contact: NewContact,
        session: &Session,
    ) -> Result<(), SecretStorageError> {
        validate_contact(&contact)?;
        let encrypted = Zeroizing::new(session.pickle().encrypt(&self.pickle_key.0));
        if encrypted.is_empty() || encrypted.len() > MAX_PICKLE_BYTES {
            return Err(SecretStorageError::QuotaExceeded);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if count(&transaction, "contacts")? >= MAX_CONTACTS {
            return Err(SecretStorageError::QuotaExceeded);
        }
        transaction
            .execute(
                "INSERT INTO contacts (
                    contact_id, display_name, signing_identity_key, curve_identity_key,
                    inbound_current_hint, outbound_current_hint, inbound_generation,
                    outbound_generation, inbound_message_count, state, contact_tokens
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, 0, 3, 8)",
                params![
                    contact.contact_id.0.as_slice(),
                    contact.display_name,
                    contact.signing_identity_key.as_slice(),
                    contact.curve_identity_key.as_slice(),
                    contact.inbound_recipient_hint.as_slice(),
                    contact.outbound_recipient_hint.as_slice(),
                ],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO session_state(contact_id, encrypted_pickle) VALUES (?1, ?2)",
                params![contact.contact_id.0.as_slice(), encrypted.as_str()],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        self.limiter
            .contact_anchors
            .insert(contact.contact_id, Instant::now());
        Ok(())
    }

    pub fn load_session(&self, contact_id: ContactId) -> Result<Session, SecretStorageError> {
        let encrypted: Option<String> = self
            .connection
            .query_row(
                "SELECT encrypted_pickle FROM session_state WHERE contact_id = ?1",
                params![contact_id.0.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        let encrypted = encrypted.ok_or(SecretStorageError::UnknownContact)?;
        if encrypted.is_empty() || encrypted.len() > MAX_PICKLE_BYTES {
            return Err(SecretStorageError::CorruptStorage);
        }
        let encrypted = Zeroizing::new(encrypted);
        let pickle = SessionPickle::from_encrypted(&encrypted, &self.pickle_key.0)
            .map_err(|_| SecretStorageError::CorruptStorage)?;
        Ok(Session::from_pickle(pickle))
    }

    pub fn reserve_contact_attempt(
        &mut self,
        message_id: [u8; MESSAGE_ID_LENGTH],
        contact_id: ContactId,
    ) -> Result<(), SecretStorageError> {
        let now = Instant::now();
        let contact_anchor = *self
            .limiter
            .contact_anchors
            .entry(contact_id)
            .or_insert(now);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        ensure_new_attempt(&transaction, &message_id)?;
        if count(&transaction, "crypto_attempts")? >= MAX_ATTEMPTS {
            return Err(SecretStorageError::QuotaExceeded);
        }
        let profile_tokens = read_single_token(&transaction, "profile_tokens")?;
        let contact_tokens: Option<i64> = transaction
            .query_row(
                "SELECT contact_tokens FROM contacts WHERE contact_id = ?1 AND state = 3",
                params![contact_id.0.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        let contact_tokens = contact_tokens.ok_or(SecretStorageError::UnknownContact)?;
        let (profile_tokens, profile_anchor) = refill(
            profile_tokens,
            PROFILE_CAPACITY,
            PROFILE_PERIOD,
            self.limiter.profile_anchor,
            now,
        );
        let (contact_tokens, contact_anchor) = refill(
            contact_tokens,
            CONTACT_CAPACITY,
            CONTACT_PERIOD,
            contact_anchor,
            now,
        );
        if profile_tokens == 0 || contact_tokens == 0 {
            update_profile_tokens(&transaction, profile_tokens)?;
            update_contact_tokens(&transaction, contact_id, contact_tokens)?;
            transaction.commit().map_err(database_error)?;
            self.limiter.profile_anchor = profile_anchor;
            self.limiter
                .contact_anchors
                .insert(contact_id, contact_anchor);
            return Err(SecretStorageError::RateLimited);
        }
        update_profile_tokens(&transaction, profile_tokens - 1)?;
        update_contact_tokens(&transaction, contact_id, contact_tokens - 1)?;
        insert_attempt(&transaction, &message_id, Some(contact_id), 0)?;
        transaction.commit().map_err(database_error)?;
        self.limiter.profile_anchor = profile_anchor;
        self.limiter
            .contact_anchors
            .insert(contact_id, contact_anchor);
        Ok(())
    }

    pub fn reserve_pending_contact_attempt(
        &mut self,
        message_id: [u8; MESSAGE_ID_LENGTH],
    ) -> Result<(), SecretStorageError> {
        let now = Instant::now();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        ensure_new_attempt(&transaction, &message_id)?;
        if count(&transaction, "crypto_attempts")? >= MAX_ATTEMPTS {
            return Err(SecretStorageError::QuotaExceeded);
        }
        let profile_tokens = read_single_token(&transaction, "profile_tokens")?;
        let pending_tokens = read_single_token(&transaction, "pending_contact_tokens")?;
        let (profile_tokens, profile_anchor) = refill(
            profile_tokens,
            PROFILE_CAPACITY,
            PROFILE_PERIOD,
            self.limiter.profile_anchor,
            now,
        );
        let (pending_tokens, pending_anchor) = refill(
            pending_tokens,
            PENDING_CAPACITY,
            PENDING_PERIOD,
            self.limiter.pending_anchor,
            now,
        );
        if profile_tokens == 0 || pending_tokens == 0 {
            update_profile_tokens(&transaction, profile_tokens)?;
            update_pending_tokens(&transaction, pending_tokens)?;
            transaction.commit().map_err(database_error)?;
            self.limiter.profile_anchor = profile_anchor;
            self.limiter.pending_anchor = pending_anchor;
            return Err(SecretStorageError::RateLimited);
        }
        update_profile_tokens(&transaction, profile_tokens - 1)?;
        update_pending_tokens(&transaction, pending_tokens - 1)?;
        insert_attempt(&transaction, &message_id, None, 1)?;
        transaction.commit().map_err(database_error)?;
        self.limiter.profile_anchor = profile_anchor;
        self.limiter.pending_anchor = pending_anchor;
        Ok(())
    }

    pub fn commit_contact_attempt(
        &mut self,
        message_id: [u8; MESSAGE_ID_LENGTH],
        contact_id: ContactId,
        candidate: &Session,
    ) -> Result<(), SecretStorageError> {
        let encrypted = Zeroizing::new(candidate.pickle().encrypt(&self.pickle_key.0));
        if encrypted.is_empty() || encrypted.len() > MAX_PICKLE_BYTES {
            return Err(SecretStorageError::QuotaExceeded);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        ensure_reserved_attempt(&transaction, &message_id, Some(contact_id), 0)?;
        update_session(&transaction, contact_id, &encrypted)?;
        refund_contact_tokens(&transaction, contact_id)?;
        mark_attempt_success(&transaction, &message_id)?;
        transaction.commit().map_err(database_error)
    }

    pub fn commit_received_chat(
        &mut self,
        message_id: [u8; MESSAGE_ID_LENGTH],
        contact_id: ContactId,
        candidate: &Session,
        text: &str,
    ) -> Result<(), SecretStorageError> {
        if text.is_empty() || text.len() > MAX_TEXT_BYTES || text.chars().any(char::is_control) {
            return Err(SecretStorageError::CorruptStorage);
        }
        let encrypted = Zeroizing::new(candidate.pickle().encrypt(&self.pickle_key.0));
        if encrypted.is_empty() || encrypted.len() > MAX_PICKLE_BYTES {
            return Err(SecretStorageError::QuotaExceeded);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        ensure_reserved_attempt(&transaction, &message_id, Some(contact_id), 0)?;
        if count(&transaction, "messages")? >= MAX_HISTORY {
            return Err(SecretStorageError::QuotaExceeded);
        }
        update_session(&transaction, contact_id, &encrypted)?;
        let sequence = next_sequence(&transaction, "messages")?;
        transaction
            .execute(
                "INSERT INTO messages(message_id, contact_id, direction, text, sequence)
                 VALUES (?1, ?2, 0, ?3, ?4)",
                params![
                    message_id.as_slice(),
                    contact_id.0.as_slice(),
                    text,
                    sequence
                ],
            )
            .map_err(database_error)?;
        refund_contact_tokens(&transaction, contact_id)?;
        mark_attempt_success(&transaction, &message_id)?;
        transaction.commit().map_err(database_error)
    }

    pub fn defer_contact_attempt(
        &mut self,
        message_id: [u8; MESSAGE_ID_LENGTH],
        contact_id: ContactId,
    ) -> Result<(), SecretStorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        ensure_reserved_attempt(&transaction, &message_id, Some(contact_id), 0)?;
        refund_contact_tokens(&transaction, contact_id)?;
        transaction
            .execute(
                "DELETE FROM crypto_attempts WHERE message_id = ?1",
                params![message_id.as_slice()],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)
    }

    pub fn commit_outgoing(
        &mut self,
        contact_id: ContactId,
        candidate: &Session,
        message_id: [u8; MESSAGE_ID_LENGTH],
        envelope_cbor: &[u8],
    ) -> Result<(), SecretStorageError> {
        if envelope_cbor.is_empty() || envelope_cbor.len() > MAX_ENVELOPE_BYTES {
            return Err(SecretStorageError::QuotaExceeded);
        }
        let encrypted = Zeroizing::new(candidate.pickle().encrypt(&self.pickle_key.0));
        if encrypted.is_empty() || encrypted.len() > MAX_PICKLE_BYTES {
            return Err(SecretStorageError::QuotaExceeded);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if count(&transaction, "pending_outbox")? >= MAX_OUTBOX {
            return Err(SecretStorageError::QuotaExceeded);
        }
        update_session(&transaction, contact_id, &encrypted)?;
        let sequence = next_sequence(&transaction, "pending_outbox")?;
        transaction
            .execute(
                "INSERT INTO pending_outbox(message_id, envelope_cbor, sequence)
                 VALUES (?1, ?2, ?3)",
                params![message_id.as_slice(), envelope_cbor, sequence],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)
    }

    pub fn pending_outbox(&self) -> Result<Vec<PendingEnvelope>, SecretStorageError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT message_id, envelope_cbor FROM pending_outbox
                 ORDER BY sequence LIMIT 1001",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(database_error)?;
        let mut output = Vec::new();
        for row in rows {
            let (message_id, envelope) = row.map_err(database_error)?;
            if output.len() >= MAX_OUTBOX_ENTRIES
                || envelope.is_empty()
                || envelope.len() > MAX_ENVELOPE_BYTES
            {
                return Err(SecretStorageError::CorruptStorage);
            }
            let message_id = <[u8; MESSAGE_ID_LENGTH]>::try_from(message_id)
                .map_err(|_| SecretStorageError::CorruptStorage)?;
            output.push(PendingEnvelope {
                message_id,
                envelope_cbor: envelope.into_boxed_slice(),
            });
        }
        Ok(output)
    }

    pub fn next_pending_outbox(&self) -> Result<Option<PendingEnvelope>, SecretStorageError> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT message_id, envelope_cbor FROM pending_outbox
                 ORDER BY sequence LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(database_error)?;
        let Some((message_id, envelope_cbor)) = row else {
            return Ok(None);
        };
        if envelope_cbor.is_empty() || envelope_cbor.len() > MAX_ENVELOPE_BYTES {
            return Err(SecretStorageError::CorruptStorage);
        }
        let message_id = <[u8; MESSAGE_ID_LENGTH]>::try_from(message_id)
            .map_err(|_| SecretStorageError::CorruptStorage)?;
        Ok(Some(PendingEnvelope {
            message_id,
            envelope_cbor: envelope_cbor.into_boxed_slice(),
        }))
    }

    pub fn has_received_chat(
        &self,
        message_id: [u8; MESSAGE_ID_LENGTH],
    ) -> Result<bool, SecretStorageError> {
        self.connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM messages
                    WHERE message_id = ?1 AND direction = 0
                 )",
                params![message_id.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .map(|exists| exists == 1)
            .map_err(database_error)
    }

    pub fn remove_pending_outbox(
        &mut self,
        message_id: [u8; MESSAGE_ID_LENGTH],
    ) -> Result<bool, SecretStorageError> {
        let changed = self
            .connection
            .execute(
                "DELETE FROM pending_outbox WHERE message_id = ?1",
                params![message_id.as_slice()],
            )
            .map_err(database_error)?;
        Ok(changed == 1)
    }
}

fn validate_contact(contact: &NewContact) -> Result<(), SecretStorageError> {
    if contact.display_name.is_empty()
        || contact.display_name.len() > 128
        || contact.display_name.chars().any(char::is_control)
        || contact.inbound_recipient_hint == contact.outbound_recipient_hint
    {
        return Err(SecretStorageError::CorruptStorage);
    }
    Ok(())
}

fn refill(
    tokens: i64,
    capacity: i64,
    period: Duration,
    anchor: Instant,
    now: Instant,
) -> (i64, Instant) {
    let elapsed = now.saturating_duration_since(anchor);
    let periods = elapsed.as_secs() / period.as_secs();
    let added = i64::try_from(periods).unwrap_or(i64::MAX);
    let tokens = tokens.saturating_add(added).min(capacity);
    let advance = period.saturating_mul(u32::try_from(periods).unwrap_or(u32::MAX));
    let anchor = anchor.checked_add(advance).unwrap_or(now).min(now);
    (tokens, anchor)
}

fn ensure_new_attempt(
    transaction: &Transaction<'_>,
    message_id: &[u8; MESSAGE_ID_LENGTH],
) -> Result<(), SecretStorageError> {
    let exists: i64 = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM crypto_attempts WHERE message_id = ?1)",
            params![message_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if exists == 0 {
        Ok(())
    } else {
        Err(SecretStorageError::AttemptAlreadyProcessed)
    }
}

fn insert_attempt(
    transaction: &Transaction<'_>,
    message_id: &[u8; MESSAGE_ID_LENGTH],
    contact_id: Option<ContactId>,
    kind: i64,
) -> Result<(), SecretStorageError> {
    let sequence = next_sequence(transaction, "crypto_attempts")?;
    transaction
        .execute(
            "INSERT INTO crypto_attempts(
                message_id, contact_id, attempt_kind, attempt_state, sequence
             ) VALUES (?1, ?2, ?3, 0, ?4)",
            params![
                message_id.as_slice(),
                contact_id.map(|value| value.0.to_vec()),
                kind,
                sequence
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

fn ensure_reserved_attempt(
    transaction: &Transaction<'_>,
    message_id: &[u8; MESSAGE_ID_LENGTH],
    contact_id: Option<ContactId>,
    kind: i64,
) -> Result<(), SecretStorageError> {
    let row: Option<(Option<Vec<u8>>, i64, i64)> = transaction
        .query_row(
            "SELECT contact_id, attempt_kind, attempt_state
             FROM crypto_attempts WHERE message_id = ?1",
            params![message_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(database_error)?;
    let expected = contact_id.map(|value| value.0.to_vec());
    match row {
        Some((stored_contact, stored_kind, 0))
            if stored_contact == expected && stored_kind == kind =>
        {
            Ok(())
        }
        _ => Err(SecretStorageError::AttemptAlreadyProcessed),
    }
}

fn update_session(
    transaction: &Transaction<'_>,
    contact_id: ContactId,
    encrypted: &str,
) -> Result<(), SecretStorageError> {
    let changed = transaction
        .execute(
            "UPDATE session_state SET encrypted_pickle = ?1 WHERE contact_id = ?2",
            params![encrypted, contact_id.0.as_slice()],
        )
        .map_err(database_error)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(SecretStorageError::UnknownContact)
    }
}

fn refund_contact_tokens(
    transaction: &Transaction<'_>,
    contact_id: ContactId,
) -> Result<(), SecretStorageError> {
    transaction
        .execute(
            "UPDATE metadata SET profile_tokens = min(profile_tokens + 1, 32)
             WHERE singleton = 1",
            [],
        )
        .map_err(database_error)?;
    let changed = transaction
        .execute(
            "UPDATE contacts SET contact_tokens = min(contact_tokens + 1, 8)
             WHERE contact_id = ?1",
            params![contact_id.0.as_slice()],
        )
        .map_err(database_error)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(SecretStorageError::UnknownContact)
    }
}

fn mark_attempt_success(
    transaction: &Transaction<'_>,
    message_id: &[u8; MESSAGE_ID_LENGTH],
) -> Result<(), SecretStorageError> {
    let changed = transaction
        .execute(
            "UPDATE crypto_attempts SET attempt_state = 1 WHERE message_id = ?1",
            params![message_id.as_slice()],
        )
        .map_err(database_error)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(SecretStorageError::AttemptAlreadyProcessed)
    }
}

fn read_single_token(
    transaction: &Transaction<'_>,
    column: &str,
) -> Result<i64, SecretStorageError> {
    transaction
        .query_row(
            &format!("SELECT {column} FROM metadata WHERE singleton = 1"),
            [],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn update_profile_tokens(
    transaction: &Transaction<'_>,
    value: i64,
) -> Result<(), SecretStorageError> {
    transaction
        .execute(
            "UPDATE metadata SET profile_tokens = ?1 WHERE singleton = 1",
            params![value],
        )
        .map_err(database_error)?;
    Ok(())
}

fn update_pending_tokens(
    transaction: &Transaction<'_>,
    value: i64,
) -> Result<(), SecretStorageError> {
    transaction
        .execute(
            "UPDATE metadata SET pending_contact_tokens = ?1 WHERE singleton = 1",
            params![value],
        )
        .map_err(database_error)?;
    Ok(())
}

fn update_contact_tokens(
    transaction: &Transaction<'_>,
    contact_id: ContactId,
    value: i64,
) -> Result<(), SecretStorageError> {
    transaction
        .execute(
            "UPDATE contacts SET contact_tokens = ?1 WHERE contact_id = ?2",
            params![value, contact_id.0.as_slice()],
        )
        .map_err(database_error)?;
    Ok(())
}

fn count(transaction: &Transaction<'_>, table: &str) -> Result<i64, SecretStorageError> {
    transaction
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .map_err(database_error)
}

fn next_sequence(transaction: &Transaction<'_>, table: &str) -> Result<i64, SecretStorageError> {
    let current: i64 = transaction
        .query_row(
            &format!("SELECT coalesce(max(sequence), 0) FROM {table}"),
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    current
        .checked_add(1)
        .ok_or(SecretStorageError::QuotaExceeded)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant},
    };

    use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};

    use super::{ContactId, NewContact, refill};
    use crate::{DatabaseKey, SecretStorageError, SecretStore};

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TemporaryPath(PathBuf);

    impl TemporaryPath {
        fn new(label: &str) -> Self {
            let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "lantern-secret-state-{}-{sequence}-{label}.sqlite3",
                std::process::id()
            )))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TemporaryPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let mut journal = self.0.as_os_str().to_os_string();
            journal.push("-journal");
            let _ = fs::remove_file(PathBuf::from(journal));
        }
    }

    fn key() -> DatabaseKey {
        DatabaseKey::from_bytes([0x39; 32])
    }

    fn established_sessions() -> (Session, Session) {
        let alice = Account::new();
        let mut bob = Account::new();
        bob.generate_one_time_keys(1);
        let one_time_key = bob.one_time_keys().values().next().copied();
        let Some(one_time_key) = one_time_key else {
            panic!("test one-time key was not generated");
        };
        let session = alice.create_outbound_session(
            SessionConfig::version_1(),
            bob.curve25519_key(),
            one_time_key,
        );
        let Ok(mut alice_session) = session else {
            panic!("test outbound session could not be created");
        };
        let first = alice_session.encrypt(b"first");
        let Ok(OlmMessage::PreKey(first)) = first else {
            panic!("test first message was not pre-key");
        };
        let inbound =
            bob.create_inbound_session(SessionConfig::version_1(), alice.curve25519_key(), &first);
        let Ok(inbound) = inbound else {
            panic!("test inbound session could not be created");
        };
        (alice_session, inbound.session)
    }

    fn contact(id: ContactId) -> NewContact {
        NewContact {
            contact_id: id,
            display_name: "Alice".to_owned(),
            signing_identity_key: [0x11; 32],
            curve_identity_key: [0x22; 32],
            inbound_recipient_hint: [0x33; 16],
            outbound_recipient_hint: [0x44; 16],
        }
    }

    fn store_with_contact(path: &Path) -> (SecretStore, ContactId, Session) {
        let store = SecretStore::create(path, &key());
        let Ok(mut store) = store else {
            panic!("test secret store could not be created");
        };
        let id = ContactId::from_bytes([0x51; 16]);
        let (alice, bob) = established_sessions();
        assert!(store.add_active_contact(contact(id), &alice).is_ok());
        (store, id, bob)
    }

    #[test]
    fn contact_and_pending_bursts_stop_before_extra_decrypt() {
        let temporary = TemporaryPath::new("bursts");
        let (mut store, contact_id, _) = store_with_contact(temporary.path());
        for value in 0..8_u8 {
            assert!(
                store
                    .reserve_contact_attempt([value; 16], contact_id)
                    .is_ok()
            );
        }
        assert_eq!(
            store.reserve_contact_attempt([0x80; 16], contact_id),
            Err(SecretStorageError::RateLimited)
        );
        drop(store);

        let reopened = SecretStore::open(temporary.path(), &key());
        let Ok(mut reopened) = reopened else {
            panic!("test secret store could not be reopened");
        };
        assert_eq!(
            reopened.reserve_contact_attempt([0x81; 16], contact_id),
            Err(SecretStorageError::RateLimited)
        );

        for value in 0..4_u8 {
            assert!(
                reopened
                    .reserve_pending_contact_attempt([0xa0 + value; 16])
                    .is_ok()
            );
        }
        assert_eq!(
            reopened.reserve_pending_contact_attempt([0xaf; 16]),
            Err(SecretStorageError::RateLimited)
        );
    }

    #[test]
    fn successful_commit_refunds_one_attempt_and_persists_candidate_ratchet() {
        let temporary = TemporaryPath::new("commit");
        let (mut store, contact_id, mut receiver) = store_with_contact(temporary.path());
        let message_id = [0x61; 16];
        assert!(
            store
                .reserve_contact_attempt(message_id, contact_id)
                .is_ok()
        );
        let mut candidate = store.load_session(contact_id);
        let Ok(ref mut candidate) = candidate else {
            panic!("test session could not be loaded");
        };
        let encrypted = candidate.encrypt(b"committed ratchet");
        let Ok(encrypted) = encrypted else {
            panic!("test message could not be encrypted");
        };
        assert!(
            store
                .commit_contact_attempt(message_id, contact_id, candidate)
                .is_ok()
        );
        assert_eq!(
            store.reserve_contact_attempt(message_id, contact_id),
            Err(SecretStorageError::AttemptAlreadyProcessed)
        );
        let decrypted = receiver.decrypt(&encrypted);
        assert!(decrypted.is_ok_and(|value| value == b"committed ratchet"));
        assert!(
            store
                .reserve_contact_attempt([0x62; 16], contact_id)
                .is_ok()
        );
    }

    #[test]
    fn outgoing_ratchet_and_pending_envelope_commit_together() {
        let temporary = TemporaryPath::new("outbox");
        let (mut store, contact_id, mut receiver) = store_with_contact(temporary.path());
        let mut candidate = store.load_session(contact_id);
        let Ok(ref mut candidate) = candidate else {
            panic!("test session could not be loaded");
        };
        let encrypted = candidate.encrypt(b"outbox message");
        let Ok(encrypted) = encrypted else {
            panic!("test outbox message could not be encrypted");
        };
        let message_id = [0x71; 16];
        let envelope = b"immutable envelope bytes";
        assert!(
            store
                .commit_outgoing(contact_id, candidate, message_id, envelope)
                .is_ok()
        );
        drop(store);

        let reopened = SecretStore::open(temporary.path(), &key());
        let Ok(mut reopened) = reopened else {
            panic!("test secret store could not be reopened");
        };
        let pending = reopened.pending_outbox();
        let Ok(pending) = pending else {
            panic!("test pending outbox could not be loaded");
        };
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].message_id(), &message_id);
        assert_eq!(pending[0].envelope_cbor(), envelope);
        let decrypted = receiver.decrypt(&encrypted);
        assert!(decrypted.is_ok_and(|value| value == b"outbox message"));
        assert!(
            reopened
                .remove_pending_outbox(message_id)
                .is_ok_and(|value| value)
        );
        assert!(
            reopened
                .pending_outbox()
                .is_ok_and(|value| value.is_empty())
        );
    }

    #[test]
    fn discrete_refill_preserves_remainder_and_never_exceeds_capacity() {
        let anchor = Instant::now();
        let now = anchor + Duration::from_secs(125);
        let (tokens, moved) = refill(2, 8, Duration::from_secs(60), anchor, now);
        assert_eq!(tokens, 4);
        assert_eq!(now.duration_since(moved), Duration::from_secs(5));

        let later = now + Duration::from_secs(10_000);
        let (tokens, moved) = refill(tokens, 8, Duration::from_secs(60), moved, later);
        assert_eq!(tokens, 8);
        assert!(moved <= later);
        assert!(later.duration_since(moved) < Duration::from_secs(60));
    }

    #[test]
    fn encrypted_file_does_not_contain_contact_or_outbox_markers() {
        let temporary = TemporaryPath::new("plaintext-search");
        let store = SecretStore::create(temporary.path(), &key());
        let Ok(mut store) = store else {
            panic!("test secret store could not be created");
        };
        let id = ContactId::from_bytes([0x81; 16]);
        let (session, _) = established_sessions();
        let mut new_contact = contact(id);
        new_contact.display_name = "contact-plaintext-marker-4f83".to_owned();
        assert!(store.add_active_contact(new_contact, &session).is_ok());
        let mut candidate = store.load_session(id);
        let Ok(ref mut candidate) = candidate else {
            panic!("test session could not be restored");
        };
        assert!(candidate.encrypt(b"ratchet advance").is_ok());
        let envelope = b"outbox-plaintext-marker-819d";
        assert!(
            store
                .commit_outgoing(id, candidate, [0x82; 16], envelope)
                .is_ok()
        );
        drop(store);

        let bytes = fs::read(temporary.path());
        let Ok(bytes) = bytes else {
            panic!("encrypted database file could not be read");
        };
        for marker in [
            b"contact-plaintext-marker-4f83".as_slice(),
            b"outbox-plaintext-marker-819d".as_slice(),
        ] {
            assert!(!bytes.windows(marker.len()).any(|window| window == marker));
        }
    }
}
