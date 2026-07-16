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

