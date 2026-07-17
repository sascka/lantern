// SPDX-License-Identifier: MPL-2.0

use core::fmt;
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use lantern_core::{
    ContainerState, DeduplicationStatus, EnqueueOutcome, Envelope, EnvelopeQueue, LocalRouteRecord,
    MessageId, QueueEffects, QueueLimits,
};
use lantern_diagnostics::{
    DiagnosticEvent, EventCode, EventOutcome, JournalLimits, JournalMaintenance, JournalView,
    PersistentDiagnosticRecovery, SizeBucket,
};
use lantern_storage::{ClockRecovery, RecoveryReport, SqliteQueueStore};
use lantern_sync::{EnvelopeSink, SyncSinkError, SyncSummary, TransferredEnvelope, receive_batch};
use lantern_time::{ClockStatus, SystemRuntimeClock};
use lantern_transport::{BoundedSession, FrameTransport, SessionLimits};

use crate::{NodeClock, NodeError, diagnostics::NodeDiagnostics, profile_lock::ProfileLock};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeState {
    Running,
    Failed,
    Stopped,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NodeMaintenance {
    clock_rollback_detected: bool,
    expired_entries: usize,
    evicted_entries: usize,
    expired_tombstones: usize,
    evicted_tombstones: usize,
    expired_diagnostics: usize,
    evicted_diagnostics: usize,
    cleared_diagnostics: usize,
}

impl NodeMaintenance {
    pub const fn clock_rollback_detected(self) -> bool {
        self.clock_rollback_detected
    }

    pub const fn expired_entries(self) -> usize {
        self.expired_entries
    }

    pub const fn evicted_entries(self) -> usize {
        self.evicted_entries
    }

    pub const fn expired_tombstones(self) -> usize {
        self.expired_tombstones
    }

    pub const fn evicted_tombstones(self) -> usize {
        self.evicted_tombstones
    }

    pub const fn expired_diagnostics(self) -> usize {
        self.expired_diagnostics
    }

    pub const fn evicted_diagnostics(self) -> usize {
        self.evicted_diagnostics
    }

    pub const fn cleared_diagnostics(self) -> usize {
        self.cleared_diagnostics
    }

    fn include_queue_effects(&mut self, effects: &QueueEffects) {
        for entry in effects.removed_entries() {
            match entry.route().state() {
                ContainerState::Expired => self.expired_entries += 1,
                ContainerState::Evicted => self.evicted_entries += 1,
                _ => {}
            }
        }
        self.expired_tombstones += effects.expired_tombstones().len();
        self.evicted_tombstones += effects.evicted_tombstones().len();
    }

    fn include_journal_maintenance(&mut self, maintenance: JournalMaintenance) {
        self.expired_diagnostics += maintenance.expired_records();
        self.evicted_diagnostics += maintenance.evicted_records();
        self.cleared_diagnostics += maintenance.rollback_cleared_records();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeEnqueueReport {
    outcome: EnqueueOutcome,
    maintenance: NodeMaintenance,
}

impl NodeEnqueueReport {
    pub const fn outcome(self) -> EnqueueOutcome {
        self.outcome
    }

    pub const fn maintenance(self) -> NodeMaintenance {
        self.maintenance
    }
}

pub struct NodeRuntime<C = SystemRuntimeClock> {
    state: NodeState,
    clock: C,
    profile_lock: Option<ProfileLock>,
    diagnostic_lock: Option<ProfileLock>,
    store: SqliteQueueStore,
    queue: EnvelopeQueue,
    diagnostics: NodeDiagnostics,
    startup_recovery: RecoveryReport,
    startup_diagnostic_recovery: PersistentDiagnosticRecovery,
    last_wall_seconds: u64,
}

impl NodeRuntime<SystemRuntimeClock> {
    pub fn start(
        database_path: &Path,
        queue_limits: QueueLimits,
        journal_limits: JournalLimits,
    ) -> Result<Self, NodeError> {
        let clock = SystemRuntimeClock::start()?;
        Self::start_with_clock(database_path, queue_limits, journal_limits, clock)
    }

    pub fn start_with_persistent_diagnostics(
        database_path: &Path,
        diagnostic_path: &Path,
        queue_limits: QueueLimits,
        journal_limits: JournalLimits,
    ) -> Result<Self, NodeError> {
        let clock = SystemRuntimeClock::start()?;
        Self::start_with_clock_and_persistent_diagnostics(
            database_path,
            diagnostic_path,
            queue_limits,
            journal_limits,
            clock,
        )
    }
}

impl<C: NodeClock> NodeRuntime<C> {
    pub fn start_with_clock(
        database_path: &Path,
        queue_limits: QueueLimits,
        journal_limits: JournalLimits,
        clock: C,
    ) -> Result<Self, NodeError> {
        Self::start_configured(database_path, None, queue_limits, journal_limits, clock)
    }

    pub fn start_with_clock_and_persistent_diagnostics(
        database_path: &Path,
        diagnostic_path: &Path,
        queue_limits: QueueLimits,
        journal_limits: JournalLimits,
        clock: C,
    ) -> Result<Self, NodeError> {
        Self::start_configured(
            database_path,
            Some(diagnostic_path),
            queue_limits,
            journal_limits,
            clock,
        )
    }

    fn start_configured(
        database_path: &Path,
        diagnostic_path: Option<&Path>,
        queue_limits: QueueLimits,
        journal_limits: JournalLimits,
        mut clock: C,
    ) -> Result<Self, NodeError> {
        if let Some(path) = diagnostic_path {
            validate_profile_paths(database_path, path)?;
        }
        let profile_lock = ProfileLock::acquire(database_path)?;
        let diagnostic_lock = diagnostic_path.map(ProfileLock::acquire).transpose()?;
        let reading = clock.read()?;
        let mut store = SqliteQueueStore::open(database_path, queue_limits)?;
        let recovered = store.load(reading.wall_seconds())?;
        let startup_recovery = recovered.report();
        let (mut diagnostics, startup_diagnostic_recovery) = match diagnostic_path {
            Some(path) => {
                NodeDiagnostics::persistent(path, journal_limits, reading.wall_seconds())?
            }
            None => (
                NodeDiagnostics::memory(journal_limits),
                PersistentDiagnosticRecovery::default(),
            ),
        };
        if startup_recovery.clock_recovery() == ClockRecovery::RollbackDetected {
            diagnostics.clear(reading.wall_seconds())?;
        }
        let mut runtime = Self {
            state: NodeState::Running,
            clock,
            profile_lock: Some(profile_lock),
            diagnostic_lock,
            store,
            queue: recovered.into_queue(),
            diagnostics,
            startup_recovery,
            startup_diagnostic_recovery,
            last_wall_seconds: reading.wall_seconds(),
        };

        runtime.record_event(EventCode::NodeStarted, EventOutcome::Success, 1)?;
        runtime.record_event(EventCode::StorageOpened, EventOutcome::Success, 1)?;
        runtime.record_event(
            EventCode::QueueRecovered,
            EventOutcome::Success,
            runtime.queue.len(),
        )?;
        if startup_recovery.clock_recovery() == ClockRecovery::RollbackDetected {
            runtime.record_event(
                EventCode::ClockRollbackDetected,
                EventOutcome::ClockRollback,
                startup_recovery.expired_entries(),
            )?;
        }
        Ok(runtime)
    }

    pub const fn state(&self) -> NodeState {
        self.state
    }

    pub const fn queue(&self) -> &EnvelopeQueue {
        &self.queue
    }

    pub const fn startup_recovery(&self) -> RecoveryReport {
        self.startup_recovery
    }

    pub const fn startup_diagnostic_recovery(&self) -> PersistentDiagnosticRecovery {
        self.startup_diagnostic_recovery
    }

    pub const fn persistent_diagnostics_enabled(&self) -> bool {
        self.diagnostics.is_persistent()
    }

    pub fn maintain(&mut self) -> Result<NodeMaintenance, NodeError> {
        self.observe_and_persist()
    }

    pub fn enqueue_origin(&mut self, envelope: Envelope) -> Result<NodeEnqueueReport, NodeError> {
        let (now, mut maintenance) = self.observe_time()?;
        let route = match LocalRouteRecord::for_origin(&envelope, now) {
            Ok(route) => route,
            Err(error) => return self.fail(error.into()),
        };
        let result = match self.queue.enqueue(envelope, route, now) {
            Ok(result) => result,
            Err(error) => return self.fail(error.into()),
        };
        let outcome = result.outcome();
        maintenance.include_queue_effects(result.effects());
        if let Err(error) = self.store.save(&self.queue, now) {
            return self.fail(error.into());
        }

        let (code, event_outcome) = match outcome {
            EnqueueOutcome::Stored => (EventCode::EnvelopeAccepted, EventOutcome::Success),
            EnqueueOutcome::DuplicateActive | EnqueueOutcome::DuplicateTombstone => {
                (EventCode::DuplicateIgnored, EventOutcome::Duplicate)
            }
            EnqueueOutcome::Expired => (EventCode::EnvelopeRejected, EventOutcome::Expired),
            EnqueueOutcome::ItemExceedsByteQuota => {
                (EventCode::EnvelopeRejected, EventOutcome::QuotaReached)
            }
        };
        if let Err(error) = self.record_event_with_report(code, event_outcome, 1, &mut maintenance)
        {
            return self.fail(error);
        }
        Ok(NodeEnqueueReport {
            outcome,
            maintenance,
        })
    }

    pub fn diagnostics(&mut self) -> Result<JournalView<'_>, NodeError> {
        self.observe_and_persist()?;
        self.diagnostics.view(self.last_wall_seconds)
    }

    pub fn begin_session<T: FrameTransport>(
        &self,
        transport: T,
        limits: SessionLimits,
    ) -> Result<BoundedSession<T>, NodeError> {
        self.ensure_running()?;
        Ok(BoundedSession::new(transport, limits))
    }

    pub fn receive_sync_batch<T: FrameTransport>(
        &mut self,
        session: BoundedSession<T>,
    ) -> Result<(BoundedSession<T>, SyncSummary), NodeError> {
        self.observe_and_persist()?;
        let mut sink = NodeSyncSink {
            runtime: self,
            internal_error: None,
        };
        let result = receive_batch(session, &mut sink);
        if let Some(error) = sink.internal_error {
            return Err(error);
        }
        result.map_err(NodeError::from)
    }

    pub fn stop(&mut self) -> Result<NodeMaintenance, NodeError> {
        let mut maintenance = self.observe_and_persist()?;
        if let Err(error) = self.record_event_with_report(
            EventCode::NodeStopped,
            EventOutcome::Success,
            1,
            &mut maintenance,
        ) {
            return self.fail(error);
        }
        self.state = NodeState::Stopped;
        self.profile_lock = None;
        self.diagnostic_lock = None;
        Ok(maintenance)
    }

    fn observe_and_persist(&mut self) -> Result<NodeMaintenance, NodeError> {
        let (now, mut maintenance) = self.observe_time()?;
        if let Err(error) = self.store.save(&self.queue, now) {
            return self.fail(error.into());
        }
        if maintenance.clock_rollback_detected {
            let count = maintenance.expired_entries;
            if let Err(error) = self.record_event_with_report(
                EventCode::ClockRollbackDetected,
                EventOutcome::ClockRollback,
                count,
                &mut maintenance,
            ) {
                return self.fail(error);
            }
        }
        if maintenance.expired_entries > 0 {
            let count = maintenance.expired_entries;
            if let Err(error) = self.record_event_with_report(
                EventCode::EnvelopeExpired,
                EventOutcome::Expired,
                count,
                &mut maintenance,
            ) {
                return self.fail(error);
            }
        }
        Ok(maintenance)
    }

    fn accept_transferred(
        &mut self,
        item: TransferredEnvelope,
    ) -> Result<EnqueueOutcome, NodeError> {
        let (now, mut maintenance) = self.observe_time()?;
        let (envelope, grant) = item.into_parts();
        let route = match LocalRouteRecord::from_received(
            &envelope,
            now,
            u64::from(grant.remaining_ttl_seconds()),
            u64::from(grant.hops_taken()),
            u64::from(grant.copies_left()),
        ) {
            Ok(route) => route,
            Err(error) => return self.fail(error.into()),
        };
        let result = match self.queue.enqueue(envelope, route, now) {
            Ok(result) => result,
            Err(error) => return self.fail(error.into()),
        };
        let outcome = result.outcome();
        maintenance.include_queue_effects(result.effects());
        if let Err(error) = self.store.save(&self.queue, now) {
            return self.fail(error.into());
        }

        let (code, event_outcome) = match outcome {
            EnqueueOutcome::Stored => (EventCode::EnvelopeAccepted, EventOutcome::Success),
            EnqueueOutcome::DuplicateActive | EnqueueOutcome::DuplicateTombstone => {
                (EventCode::DuplicateIgnored, EventOutcome::Duplicate)
            }
            EnqueueOutcome::Expired => (EventCode::EnvelopeRejected, EventOutcome::Expired),
            EnqueueOutcome::ItemExceedsByteQuota => {
                (EventCode::EnvelopeRejected, EventOutcome::QuotaReached)
            }
        };
        if let Err(error) = self.record_event_with_report(code, event_outcome, 1, &mut maintenance)
        {
            return self.fail(error);
        }
        Ok(outcome)
    }

    fn observe_time(&mut self) -> Result<(u64, NodeMaintenance), NodeError> {
        self.ensure_running()?;
        let reading = match self.clock.read() {
            Ok(reading) => reading,
            Err(error) => return self.fail(error.into()),
        };
        let now = reading.wall_seconds();
        let effects = if reading.status() == ClockStatus::WallClockRollbackDetected {
            self.queue.expire_all(now)
        } else {
            self.queue.expire_due(now)
        };
        let effects = match effects {
            Ok(effects) => effects,
            Err(error) => return self.fail(error.into()),
        };

        let mut maintenance = NodeMaintenance {
            clock_rollback_detected: reading.status().requires_conservative_cleanup(),
            ..NodeMaintenance::default()
        };
        maintenance.include_queue_effects(&effects);
        if maintenance.clock_rollback_detected {
            let cleared = match self.diagnostics.clear(now) {
                Ok(cleared) => cleared,
                Err(error) => return self.fail(error),
            };
            maintenance.cleared_diagnostics = cleared;
        } else {
            let journal_maintenance = match self.diagnostics.maintain(now) {
                Ok(maintenance) => maintenance,
                Err(error) => return self.fail(error),
            };
            maintenance.include_journal_maintenance(journal_maintenance);
        }
        self.last_wall_seconds = now;
        Ok((now, maintenance))
    }

    fn record_event(
        &mut self,
        code: EventCode,
        outcome: EventOutcome,
        object_count: usize,
    ) -> Result<(), NodeError> {
        let mut maintenance = NodeMaintenance::default();
        self.record_event_with_report(code, outcome, object_count, &mut maintenance)
    }

    fn record_event_with_report(
        &mut self,
        code: EventCode,
        outcome: EventOutcome,
        object_count: usize,
        maintenance: &mut NodeMaintenance,
    ) -> Result<(), NodeError> {
        let object_count = u16::try_from(object_count)
            .map_err(|_| lantern_diagnostics::DiagnosticError::ObjectCountTooLarge)?;
        let event = DiagnosticEvent::try_new(code, outcome, object_count, None, None)?;
        let result = self.diagnostics.record(event, self.last_wall_seconds)?;
        maintenance.include_journal_maintenance(result.maintenance());
        Ok(())
    }

    fn ensure_running(&self) -> Result<(), NodeError> {
        if self.state == NodeState::Running {
            Ok(())
        } else {
            Err(NodeError::NotRunning)
        }
    }

    fn fail<T>(&mut self, error: NodeError) -> Result<T, NodeError> {
        self.state = NodeState::Failed;
        self.profile_lock = None;
        self.diagnostic_lock = None;
        Err(error)
    }
}

struct NodeSyncSink<'runtime, C> {
    runtime: &'runtime mut NodeRuntime<C>,
    internal_error: Option<NodeError>,
}

impl<C: NodeClock> EnvelopeSink for NodeSyncSink<'_, C> {
    fn wants(&mut self, message_id: MessageId) -> Result<bool, SyncSinkError> {
        self.runtime
            .ensure_running()
            .map_err(|_| SyncSinkError::Unavailable)?;
        Ok(matches!(
            self.runtime
                .queue
                .deduplication_status(message_id, self.runtime.last_wall_seconds),
            DeduplicationStatus::Unknown
        ))
    }

    fn accept(&mut self, item: TransferredEnvelope) -> Result<(), SyncSinkError> {
        match self.runtime.accept_transferred(item) {
            Ok(EnqueueOutcome::Stored)
            | Ok(EnqueueOutcome::DuplicateActive | EnqueueOutcome::DuplicateTombstone) => Ok(()),
            Ok(EnqueueOutcome::ItemExceedsByteQuota) => Err(SyncSinkError::ResourceExhausted),
            Ok(EnqueueOutcome::Expired) => Err(SyncSinkError::Rejected),
            Err(error) => {
                self.internal_error = Some(error);
                Err(SyncSinkError::Unavailable)
            }
        }
    }
}

fn validate_profile_paths(database_path: &Path, diagnostic_path: &Path) -> Result<(), NodeError> {
    let database_path = normalize_storage_path(database_path)?;
    let diagnostic_path = normalize_storage_path(diagnostic_path)?;
    let queue_files = [
        database_path.clone(),
        path_with_suffix(&database_path, "-journal"),
        path_with_suffix(&database_path, "-wal"),
        path_with_suffix(&database_path, "-shm"),
        path_with_suffix(&database_path, ".lock"),
    ];
    let diagnostic_files = [
        diagnostic_path.clone(),
        path_with_suffix(&diagnostic_path, "-journal"),
        path_with_suffix(&diagnostic_path, "-wal"),
        path_with_suffix(&diagnostic_path, "-shm"),
        path_with_suffix(&diagnostic_path, ".lock"),
    ];
    if queue_files.iter().any(|queue| {
        diagnostic_files
            .iter()
            .any(|diagnostic| queue == diagnostic)
    }) {
        return Err(NodeError::InvalidProfilePaths);
    }
    Ok(())
}

fn normalize_storage_path(path: &Path) -> Result<PathBuf, NodeError> {
    let filename = path.file_name().ok_or(NodeError::InvalidProfilePaths)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = match parent {
        Some(parent) => parent,
        None => Path::new("."),
    };
    let parent = fs::canonicalize(parent).map_err(|_| NodeError::InvalidProfilePaths)?;
    Ok(parent.join(filename))
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

impl<C> fmt::Debug for NodeRuntime<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let queue_size = SizeBucket::from_bytes(Some(self.queue.stored_bytes()));
        formatter
            .debug_struct("NodeRuntime")
            .field("state", &self.state)
            .field("queue_entries", &self.queue.len())
            .field("queue_size", &queue_size)
            .field("diagnostic_records", &self.diagnostics.len())
            .field("persistent_diagnostics", &self.diagnostics.is_persistent())
            .field("startup_recovery", &self.startup_recovery)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_core::{NORMAL_PRIORITY, PROTOCOL_VERSION};
    use lantern_diagnostics::{
        DIAGNOSTIC_RECORD_LOGICAL_BYTES, DiagnosticEvent, DiagnosticJournal,
    };

    fn envelope(number: u8) -> Envelope {
        let result = Envelope::try_from_fields(
            PROTOCOL_VERSION,
            [number; 16],
            [0x22; 16],
            60,
            4,
            NORMAL_PRIORITY,
            vec![0x33; 32],
        );
        let Ok(envelope) = result else {
            panic!("valid maintenance test Envelope was rejected");
        };
        envelope
    }

    fn route(envelope: &Envelope, now: u64) -> LocalRouteRecord {
        let result = LocalRouteRecord::for_origin(envelope, now);
        let Ok(route) = result else {
            panic!("valid maintenance test route was rejected");
        };
        route
    }

    #[test]
    fn maintenance_classifies_evicted_and_expired_entries() {
        let limits = QueueLimits::try_new(1, 64 * 1024, 4, 60);
        let Ok(limits) = limits else {
            panic!("valid maintenance queue limits were rejected");
        };
        let mut queue = EnvelopeQueue::new(limits);
        let first = envelope(0x11);
        assert!(
            queue
                .enqueue(first.clone(), route(&first, 100), 100)
                .is_ok()
        );
        let second = envelope(0x22);
        let result = queue.enqueue(second.clone(), route(&second, 101), 101);
        let Ok(result) = result else {
            panic!("valid maintenance test enqueue failed");
        };
        let mut maintenance = NodeMaintenance::default();
        maintenance.include_queue_effects(result.effects());
        assert_eq!(maintenance.evicted_entries(), 1);
        assert_eq!(maintenance.expired_entries(), 0);

        let effects = queue.expire_due(161);
        let Ok(effects) = effects else {
            panic!("maintenance test expiration failed");
        };
        maintenance.include_queue_effects(&effects);
        assert_eq!(maintenance.evicted_entries(), 1);
        assert_eq!(maintenance.expired_entries(), 1);
    }

    #[test]
    fn maintenance_accumulates_journal_expiration_and_eviction() {
        let limits = JournalLimits::try_new(1, DIAGNOSTIC_RECORD_LOGICAL_BYTES, 60);
        let Ok(limits) = limits else {
            panic!("valid maintenance journal limits were rejected");
        };
        let event =
            DiagnosticEvent::try_new(EventCode::NodeStarted, EventOutcome::Success, 1, None, None);
        let Ok(event) = event else {
            panic!("valid maintenance diagnostic event was rejected");
        };
        let mut journal = DiagnosticJournal::new(limits);
        assert!(journal.record(event, 100).is_ok());
        let second = journal.record(event, 101);
        let Ok(second) = second else {
            panic!("second maintenance diagnostic event was rejected");
        };
        let mut maintenance = NodeMaintenance::default();
        maintenance.include_journal_maintenance(second.maintenance());
        assert_eq!(maintenance.evicted_diagnostics(), 1);

        maintenance.include_journal_maintenance(journal.maintain(161));
        assert_eq!(maintenance.expired_diagnostics(), 1);
    }
}
