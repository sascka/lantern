// SPDX-License-Identifier: MPL-2.0

use std::time::Duration;

use lantern_core::{
    ContainerState, Envelope, EnvelopeQueue, LocalRouteRecord, NORMAL_PRIORITY, PROTOCOL_VERSION,
    QueueLimits,
};
use lantern_diagnostics::{
    DIAGNOSTIC_RECORD_LOGICAL_BYTES, DiagnosticEvent, DiagnosticJournal, EventCode, EventOutcome,
    JournalLimits,
};
use lantern_time::{ClockStatus, ClockTracker};

fn queue_limits() -> QueueLimits {
    let result = QueueLimits::try_new(4, 64 * 1024, 8, 600);
    let Ok(limits) = result else {
        panic!("valid integration queue limits were rejected");
    };
    limits
}

fn journal_limits() -> JournalLimits {
    let result = JournalLimits::try_new(4, 4 * DIAGNOSTIC_RECORD_LOGICAL_BYTES, 60);
    let Ok(limits) = result else {
        panic!("valid integration journal limits were rejected");
    };
    limits
}

fn queue_with_one_entry(first_seen_at: u64) -> EnvelopeQueue {
    let envelope = Envelope::try_from_fields(
        PROTOCOL_VERSION,
        [0x11; 16],
        [0x22; 16],
        60,
        4,
        NORMAL_PRIORITY,
        vec![0x33; 16],
    );
    let Ok(envelope) = envelope else {
        panic!("valid integration Envelope was rejected");
    };
    let route = LocalRouteRecord::for_origin(&envelope, first_seen_at);
    let Ok(route) = route else {
        panic!("valid integration route was rejected");
    };
    let mut queue = EnvelopeQueue::new(queue_limits());
    assert!(queue.enqueue(envelope, route, first_seen_at).is_ok());
    queue
}

fn event(code: EventCode, outcome: EventOutcome) -> DiagnosticEvent {
    let result = DiagnosticEvent::try_new(code, outcome, 1, None, None);
    let Ok(event) = result else {
        panic!("valid integration diagnostic event was rejected");
    };
    event
}

#[test]
fn one_logical_reading_drives_queue_and_journal_expiration() {
    let tracker = ClockTracker::try_new(100);
    let Ok(mut tracker) = tracker else {
        panic!("valid integration clock anchor was rejected");
    };
    let mut queue = queue_with_one_entry(100);
    let mut journal = DiagnosticJournal::new(journal_limits());
    assert!(
        journal
            .record(event(EventCode::NodeStarted, EventOutcome::Success), 100)
            .is_ok()
    );

    let reading = tracker.observe(Duration::from_secs(60), 160);
    let Ok(reading) = reading else {
        panic!("valid integration clock observation was rejected");
    };
    let expired = queue.expire_due(reading.wall_seconds());
    let Ok(expired) = expired else {
        panic!("queue expiration failed");
    };
    assert_eq!(expired.removed_entries().len(), 1);
    assert_eq!(
        expired.removed_entries()[0].route().state(),
        ContainerState::Expired
    );
    assert!(journal.view(reading.wall_seconds()).is_empty());
}

#[test]
fn runtime_wall_rollback_requests_fail_closed_cleanup() {
    let tracker = ClockTracker::try_new(100);
    let Ok(mut tracker) = tracker else {
        panic!("valid integration clock anchor was rejected");
    };
    let mut queue = queue_with_one_entry(100);
    let mut journal = DiagnosticJournal::new(journal_limits());
    assert!(
        journal
            .record(event(EventCode::NodeStarted, EventOutcome::Success), 100)
            .is_ok()
    );
    assert!(tracker.observe(Duration::from_secs(10), 110).is_ok());

    let reading = tracker.observe(Duration::from_secs(20), 90);
    let Ok(reading) = reading else {
        panic!("runtime rollback observation was rejected");
    };
    assert_eq!(reading.status(), ClockStatus::WallClockRollbackDetected);
    assert!(reading.status().requires_conservative_cleanup());
    let expired = queue.expire_all(reading.wall_seconds());
    let Ok(expired) = expired else {
        panic!("fail-closed queue expiration failed");
    };
    assert_eq!(expired.removed_entries().len(), 1);
    assert!(queue.is_empty());
    assert_eq!(journal.clear(), 1);
    assert!(journal.is_empty());
}
