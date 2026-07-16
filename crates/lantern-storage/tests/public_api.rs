// SPDX-License-Identifier: MPL-2.0

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use lantern_core::{
    EnqueueOutcome, Envelope, EnvelopeQueue, LocalRouteRecord, MessageId, NORMAL_PRIORITY,
    PROTOCOL_VERSION, QueueLimits,
};
use lantern_storage::{ClockRecovery, SqliteQueueStore};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new() -> Self {
        let number = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "lantern-storage-public-api-{}-{number}.sqlite3",
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

fn limits() -> QueueLimits {
    let result = QueueLimits::try_new(4, 64 * 1024, 8, 600);
    let Ok(limits) = result else {
        panic!("valid public test limits were rejected");
    };
    limits
}

fn queue_with_one_entry(limits: QueueLimits, first_seen_at: u64) -> EnvelopeQueue {
    let envelope = Envelope::try_from_fields(
        PROTOCOL_VERSION,
        [0x11; 16],
        [0x22; 16],
        300,
        4,
        NORMAL_PRIORITY,
        vec![0x33; 32],
    );
    let Ok(envelope) = envelope else {
        panic!("valid public test Envelope was rejected");
    };
    let route = LocalRouteRecord::for_origin(&envelope, first_seen_at);
    let Ok(route) = route else {
        panic!("valid public test route was rejected");
    };
    let mut queue = EnvelopeQueue::new(limits);
    let result = queue.enqueue(envelope, route, first_seen_at);
    let Ok(result) = result else {
        panic!("valid public test entry was rejected");
    };
    assert_eq!(result.outcome(), EnqueueOutcome::Stored);
    queue
}

#[test]
fn public_store_api_recovers_a_committed_queue() {
    let database = TestDatabase::new();
    let limits = limits();
    let queue = queue_with_one_entry(limits, 100);
    let store = SqliteQueueStore::open(database.path(), limits);
    let Ok(mut store) = store else {
        panic!("public storage API could not create a database");
    };
    assert_eq!(store.save(&queue, 100), Ok(()));
    drop(store);

    let store = SqliteQueueStore::open(database.path(), limits);
    let Ok(mut store) = store else {
        panic!("public storage API could not reopen a database");
    };
    let recovered = store.load(101);
    let Ok(recovered) = recovered else {
        panic!("public storage API could not recover a committed queue");
    };
    assert_eq!(recovered.queue().len(), 1);
    assert!(
        recovered
            .queue()
            .get(MessageId::from_bytes([0x11; 16]))
            .is_some()
    );
}

#[test]
fn public_store_api_reports_clock_rollback_and_fails_closed() {
    let database = TestDatabase::new();
    let limits = limits();
    let queue = queue_with_one_entry(limits, 900);
    let store = SqliteQueueStore::open(database.path(), limits);
    let Ok(mut store) = store else {
        panic!("public storage API could not create a database");
    };
    assert_eq!(store.save(&queue, 1_000), Ok(()));
    drop(store);

    let store = SqliteQueueStore::open(database.path(), limits);
    let Ok(mut store) = store else {
        panic!("public storage API could not reopen a database");
    };
    let recovered = store.load(900);
    let Ok(recovered) = recovered else {
        panic!("public storage API could not handle clock rollback");
    };
    assert_eq!(
        recovered.report().clock_recovery(),
        ClockRecovery::RollbackDetected
    );
    assert_eq!(recovered.report().expired_entries(), 1);
    assert!(recovered.queue().is_empty());
}
