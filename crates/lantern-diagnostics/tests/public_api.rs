// SPDX-License-Identifier: MPL-2.0

use lantern_diagnostics::{
    DIAGNOSTIC_RECORD_LOGICAL_BYTES, DiagnosticEvent, DiagnosticJournal, EventCode, EventOutcome,
    JournalLimits, SizeBucket,
};

#[cfg(feature = "persistence")]
use lantern_diagnostics::PersistentDiagnosticJournal;

fn limits() -> JournalLimits {
    let result = JournalLimits::try_new(2, 2 * DIAGNOSTIC_RECORD_LOGICAL_BYTES, 60);
    let Ok(limits) = result else {
        panic!("valid public diagnostic limits were rejected");
    };
    limits
}

fn event(code: EventCode, size: Option<usize>) -> DiagnosticEvent {
    let result = DiagnosticEvent::try_new(code, EventOutcome::Success, 1, size, None);
    let Ok(event) = result else {
        panic!("valid public diagnostic event was rejected");
    };
    event
}

#[test]
fn public_api_keeps_categories_without_exact_size_or_time() {
    let mut journal = DiagnosticJournal::new(limits());
    let result = journal.record(event(EventCode::QueueSaved, Some(12_345)), 987_654_321);
    let Ok(result) = result else {
        panic!("public diagnostic event could not be recorded");
    };
    assert_eq!(result.record().size_bucket(), SizeBucket::UpTo16KiB);
    let view = journal.view(987_654_321);
    assert_eq!(view.len(), 1);
    assert_eq!(
        view.records().next().map(|record| record.code()),
        Some(EventCode::QueueSaved)
    );
    let output = format!("{result:?} {view:?}");
    assert!(!output.contains("12345"));
    assert!(!output.contains("987654321"));
}

#[test]
fn public_api_bounds_capacity_and_clears_on_clock_rollback() {
    let mut journal = DiagnosticJournal::new(limits());
    assert!(
        journal
            .record(event(EventCode::NodeStarted, None), 100)
            .is_ok()
    );
    assert!(
        journal
            .record(event(EventCode::StorageOpened, None), 101)
            .is_ok()
    );
    let eviction = journal.record(event(EventCode::QueueRecovered, None), 102);
    let Ok(eviction) = eviction else {
        panic!("public quota handling failed");
    };
    assert_eq!(eviction.maintenance().evicted_records(), 1);
    assert_eq!(journal.len(), 2);

    let rollback = journal.record(event(EventCode::ClockRollbackDetected, None), 90);
    let Ok(rollback) = rollback else {
        panic!("public clock rollback handling failed");
    };
    assert_eq!(rollback.maintenance().rollback_cleared_records(), 2);
    assert_eq!(journal.len(), 1);
}

#[cfg(feature = "persistence")]
#[test]
fn public_persistent_api_recovers_only_typed_records() {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "lantern-diagnostic-public-{}-{sequence}.sqlite3",
        std::process::id()
    ));
    let opened = PersistentDiagnosticJournal::open(&path, limits(), 100);
    let Ok((mut journal, _)) = opened else {
        panic!("public persistent diagnostics API could not open");
    };
    assert!(
        journal
            .record(event(EventCode::QueueSaved, Some(12_345)), 100)
            .is_ok()
    );
    drop(journal);

    let reopened = PersistentDiagnosticJournal::open(&path, limits(), 101);
    let Ok((mut reopened, _)) = reopened else {
        panic!("public persistent diagnostics API could not recover");
    };
    {
        let view = reopened.view(101);
        let Ok(view) = view else {
            panic!("public persistent diagnostics API could not produce a view");
        };
        let Some(record) = view.records().next() else {
            panic!("public persistent diagnostics API lost its record");
        };
        assert_eq!(record.code(), EventCode::QueueSaved);
        assert_eq!(record.size_bucket(), SizeBucket::UpTo16KiB);
    }
    drop(reopened);
    let _ = fs::remove_file(&path);
    for suffix in ["-journal", "-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
