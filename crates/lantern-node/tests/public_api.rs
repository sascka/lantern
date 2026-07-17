// SPDX-License-Identifier: MPL-2.0

use std::{
    cell::Cell,
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use lantern_core::{
    EnqueueOutcome, Envelope, MessageId, NORMAL_PRIORITY, PROTOCOL_VERSION, QueueLimits,
};
use lantern_diagnostics::{EventCode, JournalLimits};
use lantern_node::{NodeClock, NodeError, NodeRuntime, NodeState, ProfileLockError};
use lantern_storage::ClockRecovery;
use lantern_sync::{
    RouteGrant, SyncError, SyncFrame, SyncSinkError, TransferredEnvelope, decode_sync_frame,
    encode_sync_frame,
};
use lantern_time::{ClockError, ClockReading, ClockTracker};
use lantern_transport::{FrameReceive, FrameTransport, SessionLimits, TransportFailureKind};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new(name: &str) -> Self {
        let number = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "lantern-node-{name}-{}-{number}.sqlite3",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        for suffix in ["-journal", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
        let _ = fs::remove_file(format!("{}.lock", self.0.display()));
    }
}

struct ScriptedClock {
    tracker: ClockTracker,
    observations: VecDeque<(Duration, u64)>,
    reads: Rc<Cell<usize>>,
}

impl ScriptedClock {
    fn new(anchor: u64, observations: &[(u64, u64)]) -> (Self, Rc<Cell<usize>>) {
        let tracker = ClockTracker::try_new(anchor);
        let Ok(tracker) = tracker else {
            panic!("valid test clock anchor was rejected");
        };
        let reads = Rc::new(Cell::new(0));
        (
            Self {
                tracker,
                observations: observations
                    .iter()
                    .map(|(elapsed, wall)| (Duration::from_secs(*elapsed), *wall))
                    .collect(),
                reads: Rc::clone(&reads),
            },
            reads,
        )
    }
}

impl NodeClock for ScriptedClock {
    fn read(&mut self) -> Result<ClockReading, ClockError> {
        self.reads.set(self.reads.get() + 1);
        let Some((elapsed, wall)) = self.observations.pop_front() else {
            return Err(ClockError::ArithmeticOverflow);
        };
        self.tracker.observe(elapsed, wall)
    }
}

struct ClosedTransport;

impl FrameTransport for ClosedTransport {
    fn receive_frame(
        &mut self,
        _destination: &mut [u8],
    ) -> Result<FrameReceive, TransportFailureKind> {
        Ok(FrameReceive::ConnectionClosed)
    }

    fn send_frame(&mut self, _frame: &[u8]) -> Result<(), TransportFailureKind> {
        Ok(())
    }
}

#[derive(Default)]
struct ScriptedTransport {
    incoming: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

impl FrameTransport for ScriptedTransport {
    fn receive_frame(
        &mut self,
        destination: &mut [u8],
    ) -> Result<FrameReceive, TransportFailureKind> {
        let Some(frame) = self.incoming.pop_front() else {
            return Ok(FrameReceive::ConnectionClosed);
        };
        if frame.len() > destination.len() {
            return Err(TransportFailureKind::ResourceExhausted);
        }
        destination[..frame.len()].copy_from_slice(&frame);
        Ok(FrameReceive::Complete(frame.len()))
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportFailureKind> {
        self.sent.push(frame.to_vec());
        Ok(())
    }
}

fn queue_limits() -> QueueLimits {
    let result = QueueLimits::try_new(8, 256 * 1024, 16, 600);
    let Ok(limits) = result else {
        panic!("valid node queue limits were rejected");
    };
    limits
}

fn envelope(number: u8, ttl_seconds: u64) -> Envelope {
    let result = Envelope::try_from_fields(
        PROTOCOL_VERSION,
        [number; 16],
        [0x22; 16],
        ttl_seconds,
        4,
        NORMAL_PRIORITY,
        vec![0x33; 32],
    );
    let Ok(envelope) = result else {
        panic!("valid node test Envelope was rejected");
    };
    envelope
}

fn transferred(number: u8, remaining_ttl: u32) -> TransferredEnvelope {
    let envelope = envelope(number, 300);
    let route = RouteGrant::try_new(remaining_ttl, 1, 16)
        .unwrap_or_else(|_| panic!("valid node route grant was rejected"));
    TransferredEnvelope::try_new(envelope, route)
        .unwrap_or_else(|_| panic!("valid transferred Envelope was rejected"))
}

fn sync_frame(frame: &SyncFrame) -> Vec<u8> {
    encode_sync_frame(frame).unwrap_or_else(|_| panic!("valid sync fixture could not be encoded"))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn node_persists_an_origin_envelope_across_restart() {
    let database = TestDatabase::new("restart");
    let (clock, _) = ScriptedClock::new(100, &[(0, 100), (1, 101), (2, 102)]);
    let runtime = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut runtime) = runtime else {
        panic!("node could not start");
    };
    let report = runtime.enqueue_origin(envelope(0x11, 300));
    let Ok(report) = report else {
        panic!("origin Envelope could not be stored");
    };
    assert_eq!(report.outcome(), EnqueueOutcome::Stored);
    assert_eq!(runtime.queue().len(), 1);
    assert!(runtime.stop().is_ok());
    assert_eq!(runtime.state(), NodeState::Stopped);
    drop(runtime);

    let (clock, _) = ScriptedClock::new(110, &[(0, 110)]);
    let recovered = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(recovered) = recovered else {
        panic!("node could not recover its queue");
    };
    assert_eq!(recovered.queue().len(), 1);
    assert_eq!(
        recovered.startup_recovery().clock_recovery(),
        ClockRecovery::Normal
    );
}

#[test]
fn restart_clock_rollback_expires_persisted_entries() {
    let database = TestDatabase::new("restart-rollback");
    let (clock, _) = ScriptedClock::new(1_000, &[(0, 1_000), (1, 1_001), (2, 1_002)]);
    let runtime = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut runtime) = runtime else {
        panic!("node could not start before rollback test");
    };
    assert!(runtime.enqueue_origin(envelope(0x22, 300)).is_ok());
    assert!(runtime.stop().is_ok());
    drop(runtime);

    let (clock, _) = ScriptedClock::new(900, &[(0, 900)]);
    let recovered = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(recovered) = recovered else {
        panic!("node did not handle restart clock rollback");
    };
    assert_eq!(
        recovered.startup_recovery().clock_recovery(),
        ClockRecovery::RollbackDetected
    );
    assert_eq!(recovered.startup_recovery().expired_entries(), 1);
    assert!(recovered.queue().is_empty());
    assert_eq!(recovered.queue().tombstone_count(), 1);
}

#[test]
fn runtime_clock_rollback_clears_diagnostics_and_expires_queue() {
    let database = TestDatabase::new("runtime-rollback");
    let (clock, _) = ScriptedClock::new(100, &[(0, 100), (10, 110), (20, 90), (21, 91)]);
    let runtime = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut runtime) = runtime else {
        panic!("node could not start for runtime rollback test");
    };
    assert!(runtime.enqueue_origin(envelope(0x33, 300)).is_ok());

    let maintenance = runtime.maintain();
    let Ok(maintenance) = maintenance else {
        panic!("node did not handle runtime clock rollback");
    };
    assert!(maintenance.clock_rollback_detected());
    assert_eq!(maintenance.expired_entries(), 1);
    assert!(maintenance.cleared_diagnostics() >= 4);
    assert!(runtime.queue().is_empty());

    let diagnostics = runtime.diagnostics();
    let Ok(diagnostics) = diagnostics else {
        panic!("node diagnostics could not be read after rollback");
    };
    let codes: Vec<EventCode> = diagnostics.records().map(|record| record.code()).collect();
    assert_eq!(
        codes,
        [EventCode::ClockRollbackDetected, EventCode::EnvelopeExpired]
    );
}

#[test]
fn duplicate_is_ignored_and_remains_persisted_once() {
    let database = TestDatabase::new("duplicate");
    let (clock, _) = ScriptedClock::new(100, &[(0, 100), (1, 101), (2, 102)]);
    let runtime = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut runtime) = runtime else {
        panic!("node could not start for duplicate test");
    };
    assert_eq!(
        runtime
            .enqueue_origin(envelope(0x44, 300))
            .map(|r| r.outcome()),
        Ok(EnqueueOutcome::Stored)
    );
    assert_eq!(
        runtime
            .enqueue_origin(envelope(0x44, 300))
            .map(|r| r.outcome()),
        Ok(EnqueueOutcome::DuplicateActive)
    );
    assert_eq!(runtime.queue().len(), 1);
}

#[test]
fn one_clock_read_drives_each_public_lifecycle_operation() {
    let database = TestDatabase::new("single-read");
    let (clock, reads) =
        ScriptedClock::new(100, &[(0, 100), (1, 101), (2, 102), (3, 103), (4, 104)]);
    let runtime = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut runtime) = runtime else {
        panic!("node could not start for clock read test");
    };
    assert_eq!(reads.get(), 1);
    assert!(runtime.enqueue_origin(envelope(0x55, 300)).is_ok());
    assert_eq!(reads.get(), 2);
    assert!(runtime.maintain().is_ok());
    assert_eq!(reads.get(), 3);
    assert!(runtime.diagnostics().is_ok());
    assert_eq!(reads.get(), 4);
    assert!(runtime.stop().is_ok());
    assert_eq!(reads.get(), 5);
}

#[test]
fn clock_failure_stops_further_node_operations() {
    let database = TestDatabase::new("clock-failure");
    let (clock, _) = ScriptedClock::new(100, &[(10, 110), (5, 115)]);
    let runtime = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut runtime) = runtime else {
        panic!("node could not start before clock failure");
    };
    assert_eq!(
        runtime.maintain(),
        Err(NodeError::Clock(ClockError::MonotonicRegression))
    );
    assert_eq!(runtime.state(), NodeState::Failed);
    assert!(matches!(
        runtime.begin_session(ClosedTransport, SessionLimits::standard()),
        Err(NodeError::NotRunning)
    ));
    assert_eq!(
        runtime.enqueue_origin(envelope(0x66, 300)),
        Err(NodeError::NotRunning)
    );
    let (replacement_clock, _) = ScriptedClock::new(120, &[(0, 120)]);
    assert!(
        NodeRuntime::start_with_clock(
            database.path(),
            queue_limits(),
            JournalLimits::default(),
            replacement_clock,
        )
        .is_ok()
    );
}

#[test]
fn running_node_creates_only_a_bounded_transport_session() {
    let database = TestDatabase::new("transport-session");
    let (clock, _) = ScriptedClock::new(100, &[(0, 100), (1, 101)]);
    let runtime = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut runtime) = runtime else {
        panic!("node could not start for transport test");
    };
    let limits = SessionLimits::try_new(4, 4 * 1024);
    let Ok(limits) = limits else {
        panic!("valid transport limits were rejected");
    };
    let session = runtime.begin_session(ClosedTransport, limits);
    let Ok(session) = session else {
        panic!("running node did not create a bounded session");
    };
    assert_eq!(session.limits(), limits);
    assert!(runtime.stop().is_ok());
    assert!(matches!(
        runtime.begin_session(ClosedTransport, limits),
        Err(NodeError::NotRunning)
    ));
}

#[test]
fn received_sync_envelope_is_persisted_with_its_bounded_route() {
    let database = TestDatabase::new("received-sync-restart");
    let (clock, _) = ScriptedClock::new(100, &[(0, 100), (1, 101), (2, 102)]);
    let runtime = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut runtime) = runtime else {
        panic!("node could not start for sync persistence test");
    };
    let item = transferred(0x91, 250);
    let offer = SyncFrame::offer(vec![item.message_id()])
        .unwrap_or_else(|_| panic!("sync offer fixture should be valid"));
    let transport = ScriptedTransport {
        incoming: VecDeque::from([
            sync_frame(&offer),
            sync_frame(&SyncFrame::transfer(item.clone())),
            sync_frame(&SyncFrame::done()),
        ]),
        sent: Vec::new(),
    };
    let session = runtime
        .begin_session(transport, SessionLimits::standard())
        .unwrap_or_else(|_| panic!("node did not create a sync session"));

    let (session, summary) = runtime
        .receive_sync_batch(session)
        .unwrap_or_else(|_| panic!("node did not receive a valid sync batch"));

    assert_eq!(summary.offered(), 1);
    assert_eq!(summary.requested(), 1);
    assert_eq!(summary.transferred(), 1);
    let entry = runtime
        .queue()
        .get(item.message_id())
        .unwrap_or_else(|| panic!("received Envelope is missing from memory"));
    assert_eq!(entry.route().first_seen_at(), 102);
    assert_eq!(entry.route().remaining_ttl(), 250);
    assert_eq!(entry.route().hops_taken(), 1);
    assert_eq!(entry.route().copies_left(), 16);
    let sent = session.into_inner().sent;
    assert_eq!(sent.len(), 1);
    assert_eq!(
        decode_sync_frame(&sent[0]),
        Ok(SyncFrame::request(vec![item.message_id()])
            .unwrap_or_else(|_| panic!("request fixture should be valid")))
    );

    drop(runtime);
    let (clock, _) = ScriptedClock::new(110, &[(0, 110)]);
    let recovered = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    )
    .unwrap_or_else(|_| panic!("node did not recover the received Envelope"));
    let recovered_entry = recovered
        .queue()
        .get(item.message_id())
        .unwrap_or_else(|| panic!("received Envelope was not persisted"));
    assert_eq!(recovered_entry.envelope(), item.envelope());
    assert_eq!(recovered_entry.route().first_seen_at(), 102);
    assert_eq!(recovered_entry.route().remaining_ttl(), 250);
}

#[test]
fn active_sync_duplicate_is_not_requested_again() {
    let database = TestDatabase::new("active-sync-duplicate");
    let (clock, _) = ScriptedClock::new(100, &[(0, 100), (1, 101), (2, 102)]);
    let runtime = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut runtime) = runtime else {
        panic!("node could not start for sync duplicate test");
    };
    assert!(runtime.enqueue_origin(envelope(0x92, 300)).is_ok());
    let identifier = MessageId::from_bytes([0x92; 16]);
    let offer = SyncFrame::offer(vec![identifier])
        .unwrap_or_else(|_| panic!("sync offer fixture should be valid"));
    let transport = ScriptedTransport {
        incoming: VecDeque::from([sync_frame(&offer), sync_frame(&SyncFrame::done())]),
        sent: Vec::new(),
    };
    let session = runtime
        .begin_session(transport, SessionLimits::standard())
        .unwrap_or_else(|_| panic!("node did not create a duplicate sync session"));

    let (session, summary) = runtime
        .receive_sync_batch(session)
        .unwrap_or_else(|_| panic!("duplicate sync batch should complete"));

    assert_eq!(summary.requested(), 0);
    assert_eq!(runtime.queue().len(), 1);
    assert_eq!(
        session.into_inner().sent,
        [sync_frame(&SyncFrame::request(Vec::new()).unwrap_or_else(
            |_| panic!("empty request should be valid")
        ))]
    );
}

#[test]
fn interrupted_sync_transfer_never_reaches_memory_or_sqlite() {
    let database = TestDatabase::new("interrupted-sync-transfer");
    let (clock, _) = ScriptedClock::new(100, &[(0, 100), (1, 101)]);
    let runtime = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut runtime) = runtime else {
        panic!("node could not start for interrupted sync test");
    };
    let identifier = MessageId::from_bytes([0x93; 16]);
    let offer = SyncFrame::offer(vec![identifier])
        .unwrap_or_else(|_| panic!("sync offer fixture should be valid"));
    let transport = ScriptedTransport {
        incoming: VecDeque::from([sync_frame(&offer), vec![1, 3, 0, 0]]),
        sent: Vec::new(),
    };
    let session = runtime
        .begin_session(transport, SessionLimits::standard())
        .unwrap_or_else(|_| panic!("node did not create an interrupted sync session"));

    assert!(matches!(
        runtime.receive_sync_batch(session),
        Err(NodeError::Sync(SyncError::InvalidFrameLength))
    ));
    assert_eq!(runtime.state(), NodeState::Running);
    assert!(runtime.queue().is_empty());

    drop(runtime);
    let (clock, _) = ScriptedClock::new(110, &[(0, 110)]);
    let recovered = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    )
    .unwrap_or_else(|_| panic!("node could not reopen after interrupted sync"));
    assert!(recovered.queue().is_empty());
}

#[test]
fn sync_item_above_local_queue_quota_is_not_persisted() {
    let database = TestDatabase::new("sync-queue-quota");
    let limits = QueueLimits::try_new(8, 1, 16, 600)
        .unwrap_or_else(|_| panic!("small queue limits should be valid"));
    let (clock, _) = ScriptedClock::new(100, &[(0, 100), (1, 101), (2, 102)]);
    let runtime =
        NodeRuntime::start_with_clock(database.path(), limits, JournalLimits::default(), clock);
    let Ok(mut runtime) = runtime else {
        panic!("node could not start for sync quota test");
    };
    let item = transferred(0x94, 250);
    let offer = SyncFrame::offer(vec![item.message_id()])
        .unwrap_or_else(|_| panic!("sync offer fixture should be valid"));
    let transport = ScriptedTransport {
        incoming: VecDeque::from([sync_frame(&offer), sync_frame(&SyncFrame::transfer(item))]),
        sent: Vec::new(),
    };
    let session = runtime
        .begin_session(transport, SessionLimits::standard())
        .unwrap_or_else(|_| panic!("node did not create a quota sync session"));

    assert!(matches!(
        runtime.receive_sync_batch(session),
        Err(NodeError::Sync(SyncError::Sink(
            SyncSinkError::ResourceExhausted
        )))
    ));
    assert_eq!(runtime.state(), NodeState::Running);
    assert!(runtime.queue().is_empty());
}

#[test]
fn debug_and_errors_do_not_reveal_path_identifier_or_exact_time() {
    let database = TestDatabase::new("private-marker-987654321");
    let (clock, _) = ScriptedClock::new(987_654_321, &[(0, 987_654_321), (1, 987_654_322)]);
    let runtime = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut runtime) = runtime else {
        panic!("node could not start for redaction test");
    };
    assert!(runtime.enqueue_origin(envelope(0x11, 300)).is_ok());
    let output = format!("{runtime:?}");
    assert!(!output.contains("private-marker"));
    assert!(!output.contains("987654321"));
    assert!(!output.contains("1111111111111111"));
    assert!(!output.contains("3333333333333333"));
    assert!(output.contains("UpTo1KiB"));
    assert!(!format!("{:?}", NodeError::NotRunning).contains("private-marker"));
}

#[test]
fn profile_lock_rejects_a_second_node_and_stop_releases_it() {
    let database = TestDatabase::new("profile-lock");
    let (clock, _) = ScriptedClock::new(100, &[(0, 100), (1, 101)]);
    let first = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut first) = first else {
        panic!("first node could not acquire its profile");
    };

    let (clock, reads) = ScriptedClock::new(100, &[(0, 100)]);
    let second = NodeRuntime::start_with_clock(
        database.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    assert!(matches!(
        second,
        Err(NodeError::ProfileLock(ProfileLockError::AlreadyInUse))
    ));
    assert_eq!(reads.get(), 0);

    assert!(first.stop().is_ok());
    let (clock, _) = ScriptedClock::new(102, &[(0, 102)]);
    assert!(
        NodeRuntime::start_with_clock(
            database.path(),
            queue_limits(),
            JournalLimits::default(),
            clock,
        )
        .is_ok()
    );
}

#[test]
fn persistent_diagnostics_survive_node_restart_when_explicitly_enabled() {
    let database = TestDatabase::new("persistent-queue");
    let diagnostics = TestDatabase::new("persistent-diagnostics");
    let (clock, _) = ScriptedClock::new(100, &[(0, 100), (1, 101), (2, 102)]);
    let first = NodeRuntime::start_with_clock_and_persistent_diagnostics(
        database.path(),
        diagnostics.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut first) = first else {
        panic!("node could not start with persistent diagnostics");
    };
    assert!(first.persistent_diagnostics_enabled());
    assert!(first.enqueue_origin(envelope(0x77, 300)).is_ok());
    assert!(first.stop().is_ok());
    drop(first);

    let (clock, _) = ScriptedClock::new(110, &[(0, 110), (1, 111)]);
    let second = NodeRuntime::start_with_clock_and_persistent_diagnostics(
        database.path(),
        diagnostics.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut second) = second else {
        panic!("node could not recover persistent diagnostics");
    };
    let view = second.diagnostics();
    let Ok(view) = view else {
        panic!("recovered persistent diagnostics could not be viewed");
    };
    let codes = view
        .records()
        .map(|record| record.code())
        .collect::<Vec<_>>();
    assert!(codes.contains(&EventCode::EnvelopeAccepted));
    assert!(codes.contains(&EventCode::NodeStopped));
}

#[test]
fn persistent_diagnostics_do_not_store_envelope_secrets() {
    const PAYLOAD_MARKER: &[u8] = b"LANTERN-TEST-PRIVATE-PAYLOAD-7d2e9c4a";
    const MESSAGE_ID: [u8; 16] = [0xa7; 16];
    const RECIPIENT_HINT: [u8; 16] = [0xb8; 16];

    let database = TestDatabase::new("private-queue-marker");
    let diagnostics = TestDatabase::new("private-diagnostic-marker");
    let (clock, _) = ScriptedClock::new(100, &[(0, 100), (1, 101), (2, 102)]);
    let runtime = NodeRuntime::start_with_clock_and_persistent_diagnostics(
        database.path(),
        diagnostics.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut runtime) = runtime else {
        panic!("node could not start for persistent diagnostic privacy test");
    };
    let envelope = Envelope::try_from_fields(
        PROTOCOL_VERSION,
        MESSAGE_ID,
        RECIPIENT_HINT,
        300,
        4,
        NORMAL_PRIORITY,
        PAYLOAD_MARKER.to_vec(),
    );
    let Ok(envelope) = envelope else {
        panic!("valid privacy-test Envelope was rejected");
    };
    assert!(runtime.enqueue_origin(envelope).is_ok());
    assert!(runtime.stop().is_ok());
    drop(runtime);

    let stored = fs::read(diagnostics.path());
    let Ok(stored) = stored else {
        panic!("persistent diagnostic database could not be read");
    };
    assert!(!contains_bytes(&stored, PAYLOAD_MARKER));
    assert!(!contains_bytes(&stored, &MESSAGE_ID));
    assert!(!contains_bytes(&stored, &RECIPIENT_HINT));
    assert!(!contains_bytes(&stored, b"private-queue-marker"));
}

#[test]
fn persistent_diagnostics_are_cleared_after_restart_clock_rollback() {
    let database = TestDatabase::new("diagnostic-rollback-queue");
    let diagnostics = TestDatabase::new("diagnostic-rollback-log");
    let (clock, _) = ScriptedClock::new(1_000, &[(0, 1_000), (1, 1_001), (2, 1_002)]);
    let first = NodeRuntime::start_with_clock_and_persistent_diagnostics(
        database.path(),
        diagnostics.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut first) = first else {
        panic!("node could not start before diagnostic rollback");
    };
    assert!(first.enqueue_origin(envelope(0x88, 300)).is_ok());
    assert!(first.stop().is_ok());
    drop(first);

    let (clock, _) = ScriptedClock::new(900, &[(0, 900), (1, 901)]);
    let recovered = NodeRuntime::start_with_clock_and_persistent_diagnostics(
        database.path(),
        diagnostics.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut recovered) = recovered else {
        panic!("node did not recover after diagnostic clock rollback");
    };
    assert!(
        recovered
            .startup_diagnostic_recovery()
            .clock_rollback_detected()
    );
    assert!(recovered.startup_diagnostic_recovery().cleared_records() >= 5);
    let view = recovered.diagnostics();
    let Ok(view) = view else {
        panic!("diagnostics could not be viewed after restart rollback");
    };
    let codes = view
        .records()
        .map(|record| record.code())
        .collect::<Vec<_>>();
    assert!(!codes.contains(&EventCode::EnvelopeAccepted));
    assert!(!codes.contains(&EventCode::NodeStopped));
    assert!(codes.contains(&EventCode::ClockRollbackDetected));
}

#[test]
fn overlapping_queue_diagnostic_and_lock_paths_are_rejected() {
    let database = TestDatabase::new("path-overlap");
    let (clock, reads) = ScriptedClock::new(100, &[(0, 100)]);
    assert!(matches!(
        NodeRuntime::start_with_clock_and_persistent_diagnostics(
            database.path(),
            database.path(),
            queue_limits(),
            JournalLimits::default(),
            clock,
        ),
        Err(NodeError::InvalidProfilePaths)
    ));
    assert_eq!(reads.get(), 0);

    let lock_path = PathBuf::from(format!("{}.lock", database.path().display()));
    let (clock, reads) = ScriptedClock::new(100, &[(0, 100)]);
    assert!(matches!(
        NodeRuntime::start_with_clock_and_persistent_diagnostics(
            database.path(),
            &lock_path,
            queue_limits(),
            JournalLimits::default(),
            clock,
        ),
        Err(NodeError::InvalidProfilePaths)
    ));
    assert_eq!(reads.get(), 0);

    let queue_journal = PathBuf::from(format!("{}-journal", database.path().display()));
    let (clock, reads) = ScriptedClock::new(100, &[(0, 100)]);
    assert!(matches!(
        NodeRuntime::start_with_clock_and_persistent_diagnostics(
            database.path(),
            &queue_journal,
            queue_limits(),
            JournalLimits::default(),
            clock,
        ),
        Err(NodeError::InvalidProfilePaths)
    ));
    assert_eq!(reads.get(), 0);
}

#[test]
fn different_profiles_cannot_share_one_persistent_diagnostic_file() {
    let first_database = TestDatabase::new("shared-diagnostics-first");
    let second_database = TestDatabase::new("shared-diagnostics-second");
    let diagnostics = TestDatabase::new("shared-diagnostics-log");
    let (clock, _) = ScriptedClock::new(100, &[(0, 100), (1, 101)]);
    let first = NodeRuntime::start_with_clock_and_persistent_diagnostics(
        first_database.path(),
        diagnostics.path(),
        queue_limits(),
        JournalLimits::default(),
        clock,
    );
    let Ok(mut first) = first else {
        panic!("first profile could not open persistent diagnostics");
    };

    let (clock, reads) = ScriptedClock::new(100, &[(0, 100)]);
    assert!(matches!(
        NodeRuntime::start_with_clock_and_persistent_diagnostics(
            second_database.path(),
            diagnostics.path(),
            queue_limits(),
            JournalLimits::default(),
            clock,
        ),
        Err(NodeError::ProfileLock(ProfileLockError::AlreadyInUse))
    ));
    assert_eq!(reads.get(), 0);
    assert!(first.stop().is_ok());
}
