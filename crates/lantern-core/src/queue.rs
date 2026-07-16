// SPDX-License-Identifier: MPL-2.0

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CborError, ContainerState, Envelope, LocalRouteRecord, MAX_QUEUE_BYTES, MAX_QUEUE_ENTRIES,
    MAX_TOMBSTONE_RETENTION_SECONDS, MAX_TOMBSTONES, MIN_TTL_SECONDS, MessageId,
    encoded_envelope_size,
};

/// Queue setting associated with a configuration or arithmetic failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueField {
    MaxEntries,
    MaxBytes,
    MaxTombstones,
    TombstoneRetention,
    TombstoneDeadline,
    StoredBytes,
}

/// Safe queue error category that never contains an identifier or payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    InvalidLimit { field: QueueField },
    RouteMessageIdMismatch,
    RouteNotStored,
    ArithmeticOverflow { field: QueueField },
    EnvelopeEncoding(CborError),
    InvariantViolation,
}

impl fmt::Display for QueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "invalid queue limit for {field:?}"),
            Self::RouteMessageIdMismatch => {
                formatter.write_str("route record does not match Envelope")
            }
            Self::RouteNotStored => formatter.write_str("route record is not in stored state"),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "queue arithmetic overflow for {field:?}")
            }
            Self::EnvelopeEncoding(error) => {
                write!(formatter, "could not measure encoded Envelope: {error}")
            }
            Self::InvariantViolation => formatter.write_str("queue invariant violation"),
        }
    }
}

impl std::error::Error for QueueError {}

impl From<CborError> for QueueError {
    fn from(error: CborError) -> Self {
        Self::EnvelopeEncoding(error)
    }
}

/// Hard upper limits for one in-memory Envelope queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueLimits {
    max_entries: usize,
    max_bytes: usize,
    max_tombstones: usize,
    tombstone_retention_seconds: u64,
}

impl QueueLimits {
    pub fn try_new(
        max_entries: usize,
        max_bytes: usize,
        max_tombstones: usize,
        tombstone_retention_seconds: u64,
    ) -> Result<Self, QueueError> {
        validate_limit(max_entries, MAX_QUEUE_ENTRIES, QueueField::MaxEntries)?;
        validate_limit(max_bytes, MAX_QUEUE_BYTES, QueueField::MaxBytes)?;
        validate_limit(max_tombstones, MAX_TOMBSTONES, QueueField::MaxTombstones)?;
        if !(MIN_TTL_SECONDS..=MAX_TOMBSTONE_RETENTION_SECONDS)
            .contains(&tombstone_retention_seconds)
        {
            return Err(QueueError::InvalidLimit {
                field: QueueField::TombstoneRetention,
            });
        }

        Ok(Self {
            max_entries,
            max_bytes,
            max_tombstones,
            tombstone_retention_seconds,
        })
    }

    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    pub const fn max_tombstones(self) -> usize {
        self.max_tombstones
    }

    pub const fn tombstone_retention_seconds(self) -> u64 {
        self.tombstone_retention_seconds
    }
}

impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            max_entries: MAX_QUEUE_ENTRIES,
            max_bytes: MAX_QUEUE_BYTES,
            max_tombstones: MAX_TOMBSTONES,
            tombstone_retention_seconds: MAX_TOMBSTONE_RETENTION_SECONDS,
        }
    }
}

fn validate_limit(value: usize, maximum: usize, field: QueueField) -> Result<(), QueueError> {
    if value == 0 || value > maximum {
        return Err(QueueError::InvalidLimit { field });
    }
    Ok(())
}

/// One immutable Envelope and its mutable local route metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct QueueEntry {
    envelope: Envelope,
    route: LocalRouteRecord,
    encoded_size: usize,
}

impl QueueEntry {
    fn try_new(envelope: Envelope, route: LocalRouteRecord) -> Result<Self, QueueError> {
        if envelope.message_id() != route.message_id() {
            return Err(QueueError::RouteMessageIdMismatch);
        }
        if route.state() != ContainerState::Stored {
            return Err(QueueError::RouteNotStored);
        }
        let encoded_size = encoded_envelope_size(&envelope)?;
        Ok(Self {
            envelope,
            route,
            encoded_size,
        })
    }

    fn transition_to(&mut self, state: ContainerState) -> Result<(), QueueError> {
        self.route
            .transition_to(state)
            .map_err(|_| QueueError::InvariantViolation)
    }

    pub const fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    pub const fn route(&self) -> &LocalRouteRecord {
        &self.route
    }

    pub const fn encoded_size(&self) -> usize {
        self.encoded_size
    }
}

impl fmt::Debug for QueueEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueueEntry")
            .field("envelope", &self.envelope)
            .field("route", &self.route)
            .field("encoded_size", &self.encoded_size)
            .finish()
    }
}

/// Bounded record that prevents a recently removed identifier from returning.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TombstoneEntry {
    message_id: MessageId,
    recorded_at: u64,
    expires_at: u64,
}

impl TombstoneEntry {
    pub const fn message_id(self) -> MessageId {
        self.message_id
    }

    pub const fn recorded_at(self) -> u64 {
        self.recorded_at
    }

    pub const fn expires_at(self) -> u64 {
        self.expires_at
    }

    pub const fn is_active_at(self, at: u64) -> bool {
        at < self.expires_at
    }
}

impl fmt::Debug for TombstoneEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TombstoneEntry")
            .field("message_id", &self.message_id)
            .field("timing", &"redacted")
            .finish()
    }
}

/// Result of checking one identifier against active and removed entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeduplicationStatus {
    Unknown,
    Active,
    Tombstone,
}

/// Result of attempting to add one Envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnqueueOutcome {
    Stored,
    DuplicateActive,
    DuplicateTombstone,
    Expired,
    ItemExceedsByteQuota,
}

/// Bounded side effects produced by one queue operation.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct QueueEffects {
    removed_entries: Vec<QueueEntry>,
    expired_tombstones: Vec<TombstoneEntry>,
    evicted_tombstones: Vec<TombstoneEntry>,
}

impl QueueEffects {
    pub fn removed_entries(&self) -> &[QueueEntry] {
        &self.removed_entries
    }

    pub fn expired_tombstones(&self) -> &[TombstoneEntry] {
        &self.expired_tombstones
    }

    pub fn evicted_tombstones(&self) -> &[TombstoneEntry] {
        &self.evicted_tombstones
    }

    pub const fn is_empty(&self) -> bool {
        self.removed_entries.is_empty()
            && self.expired_tombstones.is_empty()
            && self.evicted_tombstones.is_empty()
    }
}

/// Full result of an enqueue operation, including maintenance effects.
#[derive(Debug, Eq, PartialEq)]
pub struct EnqueueResult {
    outcome: EnqueueOutcome,
    effects: QueueEffects,
}

impl EnqueueResult {
    pub const fn outcome(&self) -> EnqueueOutcome {
        self.outcome
    }

    pub const fn effects(&self) -> &QueueEffects {
        &self.effects
    }
}

/// Bounded in-memory queue with active and tombstone deduplication.
pub struct EnvelopeQueue {
    limits: QueueLimits,
    entries: BTreeMap<MessageId, QueueEntry>,
    fifo_order: BTreeSet<(u64, MessageId)>,
    stored_bytes: usize,
    tombstones: BTreeMap<MessageId, TombstoneEntry>,
}

impl EnvelopeQueue {
    pub fn new(limits: QueueLimits) -> Self {
        Self {
            limits,
            entries: BTreeMap::new(),
            fifo_order: BTreeSet::new(),
            stored_bytes: 0,
            tombstones: BTreeMap::new(),
        }
    }

    pub const fn limits(&self) -> QueueLimits {
        self.limits
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub const fn stored_bytes(&self) -> usize {
        self.stored_bytes
    }

    pub fn tombstone_count(&self) -> usize {
        self.tombstones.len()
    }

    pub fn get(&self, message_id: MessageId) -> Option<&QueueEntry> {
        self.entries.get(&message_id)
    }

    pub fn entries(&self) -> impl Iterator<Item = &QueueEntry> {
        self.entries.values()
    }

    pub fn tombstones(&self) -> impl Iterator<Item = &TombstoneEntry> {
        self.tombstones.values()
    }

    pub fn deduplication_status(&self, message_id: MessageId, at: u64) -> DeduplicationStatus {
        if self.entries.contains_key(&message_id) {
            return DeduplicationStatus::Active;
        }
        match self.tombstones.get(&message_id) {
            Some(tombstone) if tombstone.is_active_at(at) => DeduplicationStatus::Tombstone,
            _ => DeduplicationStatus::Unknown,
        }
    }

    pub fn enqueue(
        &mut self,
        envelope: Envelope,
        route: LocalRouteRecord,
        at: u64,
    ) -> Result<EnqueueResult, QueueError> {
        let incoming = QueueEntry::try_new(envelope, route)?;
        let incoming_id = incoming.envelope().message_id();
        let incoming_expired = incoming.route().local_deadline() <= at;

        if incoming_expired {
            self.tombstone_deadline(at)?;
        }

        let mut effects = self.expire_due(at)?;

        match self.deduplication_status(incoming_id, at) {
            DeduplicationStatus::Active => {
                return Ok(EnqueueResult {
                    outcome: EnqueueOutcome::DuplicateActive,
                    effects,
                });
            }
            DeduplicationStatus::Tombstone => {
                return Ok(EnqueueResult {
                    outcome: EnqueueOutcome::DuplicateTombstone,
                    effects,
                });
            }
            DeduplicationStatus::Unknown => {}
        }

        if incoming_expired {
            let deadline = self.tombstone_deadline(at)?;
            let evicted = self.record_tombstone(incoming_id, at, deadline);
            if let Some(tombstone) = evicted {
                effects.evicted_tombstones.push(tombstone);
            }
            return Ok(EnqueueResult {
                outcome: EnqueueOutcome::Expired,
                effects,
            });
        }

        if incoming.encoded_size() > self.limits.max_bytes {
            return Ok(EnqueueResult {
                outcome: EnqueueOutcome::ItemExceedsByteQuota,
                effects,
            });
        }

        let eviction_ids = self.eviction_candidates(incoming.encoded_size())?;
        let tombstone_deadline = if eviction_ids.is_empty() {
            None
        } else {
            Some(self.tombstone_deadline(at)?)
        };

        for message_id in eviction_ids {
            let mut removed = self.remove_active(message_id)?;
            removed.transition_to(ContainerState::Evicted)?;
            let evicted_tombstone = self.record_tombstone(
                message_id,
                at,
                tombstone_deadline.ok_or(QueueError::InvariantViolation)?,
            );
            effects.removed_entries.push(removed);
            if let Some(tombstone) = evicted_tombstone {
                effects.evicted_tombstones.push(tombstone);
            }
        }

        let next_stored_bytes = self
            .stored_bytes
            .checked_add(incoming.encoded_size())
            .ok_or(QueueError::ArithmeticOverflow {
                field: QueueField::StoredBytes,
            })?;
        if next_stored_bytes > self.limits.max_bytes
            || self.entries.len() >= self.limits.max_entries
        {
            return Err(QueueError::InvariantViolation);
        }

        let fifo_key = (incoming.route().first_seen_at(), incoming_id);
        if self.entries.contains_key(&incoming_id) || self.fifo_order.contains(&fifo_key) {
            return Err(QueueError::InvariantViolation);
        }
        self.fifo_order.insert(fifo_key);
        self.entries.insert(incoming_id, incoming);
        self.stored_bytes = next_stored_bytes;

        Ok(EnqueueResult {
            outcome: EnqueueOutcome::Stored,
            effects,
        })
    }

    /// Remove an entry after a separate cryptographic component opened it.
    ///
    /// This queue does not authenticate payloads. The caller must only invoke
    /// this method after successful sender and integrity verification.
    pub fn remove_opened(
        &mut self,
        message_id: MessageId,
        at: u64,
    ) -> Result<QueueEffects, QueueError> {
        let deadline = if self.entries.contains_key(&message_id) {
            Some(self.tombstone_deadline(at)?)
        } else {
            None
        };
        let mut effects = QueueEffects {
            expired_tombstones: self.purge_expired_tombstones(at),
            ..QueueEffects::default()
        };
        if !self.entries.contains_key(&message_id) {
            return Ok(effects);
        }

        let mut removed = self.remove_active(message_id)?;
        removed.transition_to(ContainerState::Opened)?;
        if let Some(tombstone) = self.record_tombstone(
            message_id,
            at,
            deadline.ok_or(QueueError::InvariantViolation)?,
        ) {
            effects.evicted_tombstones.push(tombstone);
        }
        effects.removed_entries.push(removed);
        Ok(effects)
    }

    pub fn expire_due(&mut self, at: u64) -> Result<QueueEffects, QueueError> {
        let due_ids: Vec<MessageId> = self
            .fifo_order
            .iter()
            .filter_map(|(_, message_id)| {
                self.entries
                    .get(message_id)
                    .filter(|entry| entry.route().local_deadline() <= at)
                    .map(|_| *message_id)
            })
            .collect();

        let tombstone_deadline = if due_ids.is_empty() {
            None
        } else {
            Some(self.tombstone_deadline(at)?)
        };
        let mut effects = QueueEffects {
            expired_tombstones: self.purge_expired_tombstones(at),
            ..QueueEffects::default()
        };

        for message_id in due_ids {
            let mut removed = self.remove_active(message_id)?;
            removed.transition_to(ContainerState::Expired)?;
            let evicted_tombstone = self.record_tombstone(
                message_id,
                at,
                tombstone_deadline.ok_or(QueueError::InvariantViolation)?,
            );
            effects.removed_entries.push(removed);
            if let Some(tombstone) = evicted_tombstone {
                effects.evicted_tombstones.push(tombstone);
            }
        }
        Ok(effects)
    }

    pub fn purge_expired_tombstones(&mut self, at: u64) -> Vec<TombstoneEntry> {
        let mut expired: Vec<TombstoneEntry> = self
            .tombstones
            .values()
            .filter(|entry| !entry.is_active_at(at))
            .copied()
            .collect();
        expired.sort_by_key(|entry| (entry.expires_at, entry.message_id));
        for entry in &expired {
            self.tombstones.remove(&entry.message_id);
        }
        expired
    }

    fn eviction_candidates(&self, incoming_size: usize) -> Result<Vec<MessageId>, QueueError> {
        let mut remaining_count = self.entries.len();
        let mut remaining_bytes = self.stored_bytes;
        let mut candidates = Vec::new();

        for (_, message_id) in &self.fifo_order {
            let count_fits = remaining_count < self.limits.max_entries;
            let bytes_fit = remaining_bytes
                .checked_add(incoming_size)
                .is_some_and(|total| total <= self.limits.max_bytes);
            if count_fits && bytes_fit {
                break;
            }

            let entry = self
                .entries
                .get(message_id)
                .ok_or(QueueError::InvariantViolation)?;
            if entry.route().state() != ContainerState::Stored {
                return Err(QueueError::InvariantViolation);
            }
            remaining_count = remaining_count
                .checked_sub(1)
                .ok_or(QueueError::InvariantViolation)?;
            remaining_bytes = remaining_bytes
                .checked_sub(entry.encoded_size())
                .ok_or(QueueError::InvariantViolation)?;
            candidates.push(*message_id);
        }

        let count_fits = remaining_count < self.limits.max_entries;
        let bytes_fit = remaining_bytes
            .checked_add(incoming_size)
            .is_some_and(|total| total <= self.limits.max_bytes);
        if !count_fits || !bytes_fit {
            return Err(QueueError::InvariantViolation);
        }
        Ok(candidates)
    }

    fn remove_active(&mut self, message_id: MessageId) -> Result<QueueEntry, QueueError> {
        let entry = self
            .entries
            .get(&message_id)
            .ok_or(QueueError::InvariantViolation)?;
        if entry.route().state() != ContainerState::Stored {
            return Err(QueueError::InvariantViolation);
        }
        let fifo_key = (entry.route().first_seen_at(), message_id);
        if !self.fifo_order.contains(&fifo_key) {
            return Err(QueueError::InvariantViolation);
        }
        let next_stored_bytes = self
            .stored_bytes
            .checked_sub(entry.encoded_size())
            .ok_or(QueueError::InvariantViolation)?;

        let removed = self
            .entries
            .remove(&message_id)
            .ok_or(QueueError::InvariantViolation)?;
        if !self.fifo_order.remove(&fifo_key) {
            return Err(QueueError::InvariantViolation);
        }
        self.stored_bytes = next_stored_bytes;
        Ok(removed)
    }

    fn tombstone_deadline(&self, at: u64) -> Result<u64, QueueError> {
        at.checked_add(self.limits.tombstone_retention_seconds)
            .ok_or(QueueError::ArithmeticOverflow {
                field: QueueField::TombstoneDeadline,
            })
    }

    fn record_tombstone(
        &mut self,
        message_id: MessageId,
        recorded_at: u64,
        expires_at: u64,
    ) -> Option<TombstoneEntry> {
        let evicted = if self.tombstones.len() >= self.limits.max_tombstones
            && !self.tombstones.contains_key(&message_id)
        {
            let oldest_id = self
                .tombstones
                .values()
                .min_by_key(|entry| (entry.recorded_at, entry.message_id))
                .map(|entry| entry.message_id);
            oldest_id.and_then(|oldest| self.tombstones.remove(&oldest))
        } else {
            None
        };

        self.tombstones.insert(
            message_id,
            TombstoneEntry {
                message_id,
                recorded_at,
                expires_at,
            },
        );
        evicted
    }
}

impl Default for EnvelopeQueue {
    fn default() -> Self {
        Self::new(QueueLimits::default())
    }
}

impl fmt::Debug for EnvelopeQueue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeQueue")
            .field("limits", &self.limits)
            .field("entry_count", &self.entries.len())
            .field("stored_bytes", &self.stored_bytes)
            .field("tombstone_count", &self.tombstones.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MAX_TTL_SECONDS, NORMAL_PRIORITY, PROTOCOL_VERSION, encode_envelope};

    fn message_id(number: u64) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[8..].copy_from_slice(&number.to_be_bytes());
        bytes
    }

    fn test_envelope(number: u64, payload_size: usize, ttl_seconds: u64) -> Envelope {
        let result = Envelope::try_from_fields(
            PROTOCOL_VERSION,
            message_id(number),
            [0x22; 16],
            ttl_seconds,
            16,
            NORMAL_PRIORITY,
            vec![0x54; payload_size],
        );
        let Ok(envelope) = result else {
            panic!("valid queue fixture was rejected");
        };
        envelope
    }

    fn origin_pair(
        number: u64,
        first_seen_at: u64,
        payload_size: usize,
        ttl_seconds: u64,
    ) -> (Envelope, LocalRouteRecord) {
        let envelope = test_envelope(number, payload_size, ttl_seconds);
        let route = LocalRouteRecord::for_origin(&envelope, first_seen_at);
        let Ok(route) = route else {
            panic!("valid origin route was rejected");
        };
        (envelope, route)
    }

    fn small_limits(max_entries: usize, max_bytes: usize, max_tombstones: usize) -> QueueLimits {
        let result = QueueLimits::try_new(max_entries, max_bytes, max_tombstones, 60);
        let Ok(limits) = result else {
            panic!("valid queue limits were rejected");
        };
        limits
    }

    fn enqueue_fixture(
        queue: &mut EnvelopeQueue,
        number: u64,
        first_seen_at: u64,
        payload_size: usize,
    ) -> EnqueueResult {
        let (envelope, route) = origin_pair(number, first_seen_at, payload_size, 300);
        let result = queue.enqueue(envelope, route, first_seen_at);
        let Ok(result) = result else {
            panic!("valid queue fixture was rejected");
        };
        result
    }

    #[test]
    fn default_and_custom_limits_are_bounded() {
        let defaults = QueueLimits::default();
        assert_eq!(defaults.max_entries(), MAX_QUEUE_ENTRIES);
        assert_eq!(defaults.max_bytes(), MAX_QUEUE_BYTES);
        assert_eq!(defaults.max_tombstones(), MAX_TOMBSTONES);
        assert_eq!(
            defaults.tombstone_retention_seconds(),
            MAX_TOMBSTONE_RETENTION_SECONDS
        );

        assert_eq!(
            QueueLimits::try_new(0, 1, 1, 60),
            Err(QueueError::InvalidLimit {
                field: QueueField::MaxEntries,
            })
        );
        assert_eq!(
            QueueLimits::try_new(MAX_QUEUE_ENTRIES + 1, 1, 1, 60),
            Err(QueueError::InvalidLimit {
                field: QueueField::MaxEntries,
            })
        );
        assert_eq!(
            QueueLimits::try_new(1, 0, 1, 60),
            Err(QueueError::InvalidLimit {
                field: QueueField::MaxBytes,
            })
        );
        assert_eq!(
            QueueLimits::try_new(1, MAX_QUEUE_BYTES + 1, 1, 60),
            Err(QueueError::InvalidLimit {
                field: QueueField::MaxBytes,
            })
        );
        assert_eq!(
            QueueLimits::try_new(1, 1, 0, 60),
            Err(QueueError::InvalidLimit {
                field: QueueField::MaxTombstones,
            })
        );
        assert_eq!(
            QueueLimits::try_new(1, 1, MAX_TOMBSTONES + 1, 60),
            Err(QueueError::InvalidLimit {
                field: QueueField::MaxTombstones,
            })
        );
        assert_eq!(
            QueueLimits::try_new(1, 1, 1, MIN_TTL_SECONDS - 1),
            Err(QueueError::InvalidLimit {
                field: QueueField::TombstoneRetention,
            })
        );
        assert_eq!(
            QueueLimits::try_new(1, 1, 1, MAX_TOMBSTONE_RETENTION_SECONDS + 1),
            Err(QueueError::InvalidLimit {
                field: QueueField::TombstoneRetention,
            })
        );
    }

    #[test]
    fn default_entry_limit_holds_at_exact_protocol_boundary() {
        let mut queue = EnvelopeQueue::default();
        for number in 0..MAX_QUEUE_ENTRIES as u64 {
            let (envelope, route) = origin_pair(number, 0, 1, MAX_TTL_SECONDS);
            let result = queue.enqueue(envelope, route, 0);
            let Ok(result) = result else {
                panic!("valid default-boundary Envelope was rejected");
            };
            assert_eq!(result.outcome(), EnqueueOutcome::Stored);
        }
        assert_eq!(queue.len(), MAX_QUEUE_ENTRIES);

        let (incoming, incoming_route) =
            origin_pair(MAX_QUEUE_ENTRIES as u64, 1, 1, MAX_TTL_SECONDS);
        let result = queue.enqueue(incoming, incoming_route, 1);
        let Ok(result) = result else {
            panic!("default queue could not apply FIFO at its boundary");
        };

        assert_eq!(result.outcome(), EnqueueOutcome::Stored);
        assert_eq!(result.effects().removed_entries().len(), 1);
        assert_eq!(queue.len(), MAX_QUEUE_ENTRIES);
        assert_eq!(
            result.effects().removed_entries()[0]
                .envelope()
                .message_id(),
            MessageId::from_bytes(message_id(0))
        );
    }

    #[test]
    fn default_tombstone_limit_holds_at_exact_protocol_boundary() {
        let mut queue = EnvelopeQueue::default();

        for number in 0..=MAX_TOMBSTONES as u64 {
            let (envelope, route) = origin_pair(number, 0, 1, MAX_TTL_SECONDS);
            let inserted = queue.enqueue(envelope, route, 0);
            let Ok(inserted) = inserted else {
                panic!("valid tombstone-boundary Envelope was rejected");
            };
            assert_eq!(inserted.outcome(), EnqueueOutcome::Stored);
            let removed = queue.remove_opened(MessageId::from_bytes(message_id(number)), 0);
            let Ok(removed) = removed else {
                panic!("valid tombstone-boundary removal failed");
            };
            if number == MAX_TOMBSTONES as u64 {
                assert_eq!(removed.evicted_tombstones().len(), 1);
                assert_eq!(
                    removed.evicted_tombstones()[0].message_id(),
                    MessageId::from_bytes(message_id(0))
                );
            }
        }

        assert_eq!(queue.tombstone_count(), MAX_TOMBSTONES);
        assert_eq!(
            queue.deduplication_status(MessageId::from_bytes(message_id(0)), 0),
            DeduplicationStatus::Unknown
        );
    }

    #[test]
    fn stores_full_cbor_size_and_returns_entry_by_identifier() {
        let mut queue = EnvelopeQueue::default();
        let (envelope, route) = origin_pair(1, 100, 12, 300);
        let expected_bytes = encode_envelope(&envelope);
        let Ok(expected_bytes) = expected_bytes else {
            panic!("valid Envelope could not be encoded");
        };
        let identifier = envelope.message_id();

        let result = queue.enqueue(envelope, route, 100);
        let Ok(result) = result else {
            panic!("valid Envelope was not stored");
        };

        assert_eq!(result.outcome(), EnqueueOutcome::Stored);
        assert!(result.effects().is_empty());
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.stored_bytes(), expected_bytes.len());
        assert_eq!(
            queue.get(identifier).map(QueueEntry::encoded_size),
            Some(expected_bytes.len())
        );
        assert_eq!(
            queue.deduplication_status(identifier, 100),
            DeduplicationStatus::Active
        );
    }

    #[test]
    fn active_duplicate_never_replaces_or_evicts_existing_entry() {
        let mut queue = EnvelopeQueue::new(small_limits(1, 1_000, 2));
        let first = enqueue_fixture(&mut queue, 1, 10, 1);
        assert_eq!(first.outcome(), EnqueueOutcome::Stored);
        let original_bytes = queue.stored_bytes();

        let (conflicting, route) = origin_pair(1, 20, 20, 300);
        let result = queue.enqueue(conflicting, route, 20);
        let Ok(result) = result else {
            panic!("duplicate check failed");
        };

        assert_eq!(result.outcome(), EnqueueOutcome::DuplicateActive);
        assert!(result.effects().removed_entries().is_empty());
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.stored_bytes(), original_bytes);
        assert_eq!(
            queue
                .get(MessageId::from_bytes(message_id(1)))
                .map(|entry| entry.envelope().protected_payload().len()),
            Some(1)
        );
    }

    #[test]
    fn opened_entry_becomes_tombstone_until_expiration_boundary() {
        let mut queue = EnvelopeQueue::new(small_limits(2, 1_000, 2));
        enqueue_fixture(&mut queue, 1, 10, 1);
        let identifier = MessageId::from_bytes(message_id(1));

        let removed = queue.remove_opened(identifier, 20);
        let Ok(removed) = removed else {
            panic!("stored entry could not be opened");
        };
        assert_eq!(removed.removed_entries().len(), 1);
        assert_eq!(
            removed.removed_entries()[0].route().state(),
            ContainerState::Opened
        );
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.tombstone_count(), 1);
        assert_eq!(
            queue.deduplication_status(identifier, 79),
            DeduplicationStatus::Tombstone
        );

        let (duplicate, duplicate_route) = origin_pair(1, 79, 1, 300);
        let duplicate_result = queue.enqueue(duplicate, duplicate_route, 79);
        let Ok(duplicate_result) = duplicate_result else {
            panic!("tombstone lookup failed");
        };
        assert_eq!(
            duplicate_result.outcome(),
            EnqueueOutcome::DuplicateTombstone
        );

        let (after_expiry, after_expiry_route) = origin_pair(1, 80, 1, 300);
        let after_expiry_result = queue.enqueue(after_expiry, after_expiry_route, 80);
        let Ok(after_expiry_result) = after_expiry_result else {
            panic!("expired tombstone blocked a valid entry");
        };
        assert_eq!(after_expiry_result.outcome(), EnqueueOutcome::Stored);
        assert_eq!(after_expiry_result.effects().expired_tombstones().len(), 1);
        assert_eq!(queue.tombstone_count(), 0);
    }

    #[test]
    fn count_quota_evicts_oldest_entry_with_stable_tiebreaker() {
        let mut queue = EnvelopeQueue::new(small_limits(2, 2_000, 4));
        enqueue_fixture(&mut queue, 2, 10, 1);
        enqueue_fixture(&mut queue, 1, 10, 1);

        let result = enqueue_fixture(&mut queue, 3, 20, 1);

        assert_eq!(result.outcome(), EnqueueOutcome::Stored);
        assert_eq!(result.effects().removed_entries().len(), 1);
        let evicted = &result.effects().removed_entries()[0];
        assert_eq!(
            evicted.envelope().message_id(),
            MessageId::from_bytes(message_id(1))
        );
        assert_eq!(evicted.route().state(), ContainerState::Evicted);
        assert_eq!(queue.len(), 2);
        assert!(queue.get(MessageId::from_bytes(message_id(2))).is_some());
        assert!(queue.get(MessageId::from_bytes(message_id(3))).is_some());
        assert_eq!(
            queue.deduplication_status(MessageId::from_bytes(message_id(1)), 20),
            DeduplicationStatus::Tombstone
        );
    }

    #[test]
    fn byte_quota_can_evict_multiple_entries_before_one_insert() {
        let small_size = encoded_envelope_size(&test_envelope(1, 10, 300));
        let incoming_size = encoded_envelope_size(&test_envelope(3, 50, 300));
        let (Ok(small_size), Ok(incoming_size)) = (small_size, incoming_size) else {
            panic!("valid Envelope size could not be measured");
        };
        let limits = small_limits(10, incoming_size + small_size - 1, 10);
        let mut queue = EnvelopeQueue::new(limits);
        enqueue_fixture(&mut queue, 1, 10, 10);
        enqueue_fixture(&mut queue, 2, 20, 10);

        let result = enqueue_fixture(&mut queue, 3, 30, 50);

        assert_eq!(result.outcome(), EnqueueOutcome::Stored);
        assert_eq!(result.effects().removed_entries().len(), 2);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.stored_bytes(), incoming_size);
        assert!(queue.stored_bytes() <= limits.max_bytes());
    }

    #[test]
    fn item_larger_than_byte_quota_is_rejected_without_queue_eviction() {
        let existing_size = encoded_envelope_size(&test_envelope(1, 1, 300));
        let incoming_size = encoded_envelope_size(&test_envelope(2, 20, 300));
        let (Ok(existing_size), Ok(incoming_size)) = (existing_size, incoming_size) else {
            panic!("valid Envelope size could not be measured");
        };
        assert!(incoming_size > existing_size);
        let mut queue = EnvelopeQueue::new(small_limits(2, existing_size, 2));
        enqueue_fixture(&mut queue, 1, 10, 1);

        let result = enqueue_fixture(&mut queue, 2, 20, 20);

        assert_eq!(result.outcome(), EnqueueOutcome::ItemExceedsByteQuota);
        assert!(result.effects().removed_entries().is_empty());
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.stored_bytes(), existing_size);
        assert!(queue.get(MessageId::from_bytes(message_id(1))).is_some());
    }

    #[test]
    fn tombstone_capacity_evicts_oldest_with_stable_tiebreaker() {
        let mut queue = EnvelopeQueue::new(small_limits(3, 3_000, 2));
        enqueue_fixture(&mut queue, 2, 1, 1);
        enqueue_fixture(&mut queue, 1, 1, 1);
        enqueue_fixture(&mut queue, 3, 1, 1);

        let second = queue.remove_opened(MessageId::from_bytes(message_id(2)), 10);
        let first = queue.remove_opened(MessageId::from_bytes(message_id(1)), 10);
        let third = queue.remove_opened(MessageId::from_bytes(message_id(3)), 20);
        let (Ok(second), Ok(first), Ok(third)) = (second, first, third) else {
            panic!("stored entries could not be removed");
        };

        assert!(second.evicted_tombstones().is_empty());
        assert!(first.evicted_tombstones().is_empty());
        assert_eq!(third.evicted_tombstones().len(), 1);
        assert_eq!(
            third.evicted_tombstones()[0].message_id(),
            MessageId::from_bytes(message_id(1))
        );
        assert_eq!(queue.tombstone_count(), 2);
        assert_eq!(
            queue.deduplication_status(MessageId::from_bytes(message_id(1)), 20),
            DeduplicationStatus::Unknown
        );
    }

    #[test]
    fn due_entries_expire_and_incoming_expired_entry_is_not_stored() {
        let mut queue = EnvelopeQueue::new(small_limits(3, 3_000, 3));
        let (envelope, route) = origin_pair(1, 10, 1, 60);
        let stored = queue.enqueue(envelope, route, 10);
        assert!(stored.is_ok());

        let before = queue.expire_due(69);
        let Ok(before) = before else {
            panic!("pre-deadline maintenance failed");
        };
        assert!(before.removed_entries().is_empty());

        let at_boundary = queue.expire_due(70);
        let Ok(at_boundary) = at_boundary else {
            panic!("deadline maintenance failed");
        };
        assert_eq!(at_boundary.removed_entries().len(), 1);
        assert_eq!(
            at_boundary.removed_entries()[0].route().state(),
            ContainerState::Expired
        );
        assert_eq!(queue.len(), 0);

        let (expired, expired_route) = origin_pair(2, 10, 1, 60);
        let result = queue.enqueue(expired, expired_route, 70);
        let Ok(result) = result else {
            panic!("expired incoming entry caused an error");
        };
        assert_eq!(result.outcome(), EnqueueOutcome::Expired);
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.tombstone_count(), 2);
    }

    #[test]
    fn enqueue_runs_expiration_before_applying_quota() {
        let mut queue = EnvelopeQueue::new(small_limits(1, 1_000, 3));
        let (old, old_route) = origin_pair(1, 0, 1, 60);
        let old_result = queue.enqueue(old, old_route, 0);
        assert!(old_result.is_ok());
        let (new, new_route) = origin_pair(2, 60, 1, 60);

        let result = queue.enqueue(new, new_route, 60);
        let Ok(result) = result else {
            panic!("valid replacement after expiration was rejected");
        };

        assert_eq!(result.outcome(), EnqueueOutcome::Stored);
        assert_eq!(result.effects().removed_entries().len(), 1);
        assert_eq!(
            result.effects().removed_entries()[0].route().state(),
            ContainerState::Expired
        );
        assert!(queue.get(MessageId::from_bytes(message_id(2))).is_some());
    }

    #[test]
    fn mismatched_and_terminal_routes_are_rejected_without_mutation() {
        let mut queue = EnvelopeQueue::default();
        let envelope = test_envelope(1, 1, 300);
        let other = test_envelope(2, 1, 300);
        let other_route = LocalRouteRecord::for_origin(&other, 10);
        let Ok(other_route) = other_route else {
            panic!("valid route fixture was rejected");
        };
        assert_eq!(
            queue.enqueue(envelope, other_route, 10),
            Err(QueueError::RouteMessageIdMismatch)
        );

        let (envelope, mut route) = origin_pair(1, 10, 1, 300);
        assert_eq!(route.transition_to(ContainerState::Expired), Ok(()));
        assert_eq!(
            queue.enqueue(envelope, route, 10),
            Err(QueueError::RouteNotStored)
        );
        assert!(queue.is_empty());
        assert_eq!(queue.tombstone_count(), 0);
    }

    #[test]
    fn tombstone_deadline_overflow_leaves_active_queue_unchanged() {
        let mut queue = EnvelopeQueue::new(small_limits(2, 1_000, 2));
        enqueue_fixture(&mut queue, 1, 0, 1);
        let stored_bytes = queue.stored_bytes();

        assert_eq!(
            queue.remove_opened(MessageId::from_bytes(message_id(1)), u64::MAX),
            Err(QueueError::ArithmeticOverflow {
                field: QueueField::TombstoneDeadline,
            })
        );
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.stored_bytes(), stored_bytes);
        assert_eq!(queue.tombstone_count(), 0);
    }

    #[test]
    fn deterministic_varied_sequence_preserves_all_hard_limits() {
        let limits = small_limits(7, 700, 13);
        let mut queue = EnvelopeQueue::new(limits);
        let mut state = 0x4c41_4e54_4552_4e03_u64;

        for step in 0..500_u64 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let payload_size = usize::from(state.to_le_bytes()[0] % 70) + 1;
            let (envelope, route) = origin_pair(step + 1, step, payload_size, 300);
            let result = queue.enqueue(envelope, route, step);
            assert!(result.is_ok());

            if step % 11 == 0 {
                let first_id = queue
                    .entries()
                    .next()
                    .map(|entry| entry.envelope().message_id());
                if let Some(identifier) = first_id {
                    let removed = queue.remove_opened(identifier, step);
                    assert!(removed.is_ok());
                }
            }

            let measured_bytes: usize = queue.entries().map(QueueEntry::encoded_size).sum();
            assert!(queue.len() <= limits.max_entries());
            assert!(queue.stored_bytes() <= limits.max_bytes());
            assert!(queue.tombstone_count() <= limits.max_tombstones());
            assert_eq!(queue.stored_bytes(), measured_bytes);
            assert!(
                queue
                    .entries()
                    .all(|entry| entry.route().state() == ContainerState::Stored)
            );
        }
    }

    #[test]
    fn debug_and_errors_do_not_disclose_payload_identifiers_or_exact_times() {
        let secret = b"OBVIOUS-QUEUE-SECRET-MARKER";
        let envelope = Envelope::try_from_fields(
            PROTOCOL_VERSION,
            [0x7a; 16],
            [0x6b; 16],
            MAX_TTL_SECONDS,
            16,
            NORMAL_PRIORITY,
            secret.to_vec(),
        );
        let Ok(envelope) = envelope else {
            panic!("valid debug fixture was rejected");
        };
        let route = LocalRouteRecord::for_origin(&envelope, 123_456_789);
        let Ok(route) = route else {
            panic!("valid route fixture was rejected");
        };
        let mut queue = EnvelopeQueue::default();
        let result = queue.enqueue(envelope, route, 123_456_789);
        assert!(result.is_ok());
        let entry = queue.entries().next();
        let Some(entry) = entry else {
            panic!("stored debug fixture disappeared");
        };

        let output = format!("{queue:?} {entry:?}");
        assert!(!output.contains("OBVIOUS-QUEUE-SECRET-MARKER"));
        assert!(!output.contains("122, 122"));
        assert!(!output.contains("107, 107"));
        assert!(!output.contains("123456789"));

        let removed = queue.remove_opened(entry.envelope().message_id(), 123_456_790);
        let Ok(removed) = removed else {
            panic!("debug fixture could not be removed");
        };
        let tombstone = queue.tombstones().next();
        let Some(tombstone) = tombstone else {
            panic!("expected tombstone was not recorded");
        };
        let output = format!("{removed:?} {tombstone:?}");
        assert!(!output.contains("123456790"));
        assert!(!output.contains("122, 122"));
    }
}
