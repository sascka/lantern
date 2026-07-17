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

use lantern_core::{EnqueueOutcome, Envelope, NORMAL_PRIORITY, PROTOCOL_VERSION, QueueLimits};
use lantern_diagnostics::{EventCode, JournalLimits};
use lantern_node::{NodeClock, NodeError, NodeRuntime, NodeState};
use lantern_storage::ClockRecovery;
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
