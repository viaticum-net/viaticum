// Tests of the machine's block work lock (К-b3, spec v3.9a #4).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use viaticum_core::types::SourceBlockId;

use super::machine_lock::*;
use super::*;

fn block(byte: u8) -> SourceBlockId {
    SourceBlockId([byte; 32])
}

fn acquired(outcome: LockOutcome) -> MachineLock {
    match outcome {
        LockOutcome::Acquired(l) => l,
        other => panic!("expected the lock, got {other:?}"),
    }
}

/// M73: the path depends on the uid only — never on `TMPDIR`, `XDG_RUNTIME_DIR` or `HOME`, so that
/// a process with another environment meets the same file.
#[test]
fn machine_lock_path_depends_only_on_uid() {
    let bare = lock_dir_with(1000, &|_| None);
    let noisy = lock_dir_with(1000, &|k| match k {
        "TMPDIR" | "XDG_RUNTIME_DIR" | "HOME" => Some(format!("/somewhere/else/{k}")),
        _ => None,
    });
    assert_eq!(bare, noisy);
    #[cfg(unix)]
    assert_eq!(bare, Path::new("/tmp/viaticum-1000"));
    assert_ne!(bare, lock_dir_with(1001, &|_| None));
}

/// W5 (spec v3.9b): the directory of a test, set by `VIATICUM_TEST_MACHINE_LOCK_DIR`, with a WARN
/// `(test only)`; an empty value is no value.
#[cfg(feature = "e2e-tools")]
#[test]
fn test_lock_dir_overrides_with_a_warn() {
    #[derive(Clone, Default)]
    struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let dir = tracing::subscriber::with_default(subscriber, || {
        let set = lock_dir_with(1000, &|k| {
            (k == TEST_LOCK_DIR_ENV).then(|| "/run/scenario-7".to_string())
        });
        let empty = lock_dir_with(1000, &|k| (k == TEST_LOCK_DIR_ENV).then(String::new));
        assert_eq!(empty, lock_dir_with(1000, &|_| None), "empty: no value");
        set
    });
    assert_eq!(dir, Path::new("/run/scenario-7"));
    let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("WARN"), "{log}");
    assert!(log.contains("(test only)"), "{log}");
    assert!(log.contains(TEST_LOCK_DIR_ENV), "{log}");
}

/// Without the `e2e-tools` feature the variable is not read at all.
#[cfg(not(feature = "e2e-tools"))]
#[test]
fn test_lock_dir_is_ignored_without_the_test_feature() {
    let dir = lock_dir_with(1000, &|k| {
        (k == TEST_LOCK_DIR_ENV).then(|| "/run/scenario-7".to_string())
    });
    assert_eq!(dir, lock_dir_with(1000, &|_| None));
}

/// N3 (spec v3.9b): the record is written whole into a file of its own, never into the locked
/// file: that file stays empty, and no half-written record is there to read.
#[test]
fn machine_lock_record_is_written_whole_beside_the_locked_file() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("viaticum-test");
    let _node = acquired(try_lock(&dir, &LockRecord::daemon(Path::new("/data/node"))));
    assert_eq!(
        std::fs::metadata(dir.join(LOCK_FILE_NAME)).unwrap().len(),
        0,
        "the locked file carries nothing"
    );
    let text = std::fs::read_to_string(dir.join(RECORD_FILE_NAME)).unwrap();
    let record: LockRecord = serde_json::from_str(&text).unwrap();
    assert_eq!(record.kind, LockKind::Daemon);
    let temps: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(temps.is_empty(), "no temporary file is left: {temps:?}");
}

/// The holder writes its record; another try finds the lock held and reads who holds it.
#[test]
fn machine_lock_is_exclusive_and_says_who_holds_it() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path().join("viaticum-test");
    let node = acquired(try_lock(&dir, &LockRecord::daemon(Path::new("/data/node"))));
    match try_lock(&dir, &LockRecord::dr()) {
        LockOutcome::HeldElsewhere(Some(record)) => {
            assert_eq!(record.kind, LockKind::Daemon);
            assert_eq!(record.data_dir.as_deref(), Some("/data/node"));
            assert_eq!(record.pid, std::process::id());
        }
        other => panic!("expected the lock held by the node, got {other:?}"),
    }
    drop(node);
    let dr = acquired(try_lock(&dir, &LockRecord::dr()));
    match try_lock(&dir, &LockRecord::daemon(Path::new("/data/node"))) {
        LockOutcome::HeldElsewhere(Some(record)) => assert_eq!(record.kind, LockKind::Dr),
        other => panic!("expected the lock held by the DR, got {other:?}"),
    }
    drop(dr);
}

/// The directory is 0700; a directory open to others is not trusted.
#[cfg(unix)]
#[test]
fn machine_lock_directory_is_private_and_a_wide_one_is_not_trusted() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("viaticum-test");
    let lock = acquired(try_lock(&dir, &LockRecord::dr()));
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    drop(lock);

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    match try_lock(&dir, &LockRecord::dr()) {
        LockOutcome::Unavailable(why) => assert!(why.contains("open to other users"), "{why}"),
        other => panic!("a directory open to others must not be trusted, got {other:?}"),
    }
}

/// M71: a node that starts while a DR holds the lock brings its budget up CLOSED: block work
/// waits, in order, and starts when the DR is done (the keeper tries the lock again).
#[tokio::test]
async fn daemon_defers_block_work_while_dr_holds_the_machine_lock() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("viaticum-test");
    let dr = acquired(try_lock(&dir, &LockRecord::dr()));
    let record = LockRecord::daemon(Path::new("/data/node"));

    let (budget, startup) = start_daemon_budget(64 * MIB, &dir, &record);
    assert!(matches!(startup, Startup::DrHolds));
    assert!(budget.is_closed());
    assert!(
        budget
            .try_acquire(HolderKind::Worker, &block(1), MIB)
            .is_none(),
        "no block work while the DR holds the lock"
    );

    let cancel = CancellationToken::new();
    let keeper = spawn_keeper(
        startup,
        dir.clone(),
        record,
        Arc::clone(&budget),
        cancel.clone(),
        Duration::from_millis(20),
    );
    let waiting = Arc::clone(&budget);
    let waiter = tokio::spawn(async move {
        waiting
            .acquire_plain(HolderKind::Worker, &block(1), MIB)
            .await
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!waiter.is_finished(), "the worker waits for the DR");
    assert_eq!(budget.outstanding_bytes(), 0);

    drop(dr);
    let permit = tokio::time::timeout(Duration::from_secs(10), waiter)
        .await
        .expect("the budget opens when the DR is done")
        .unwrap();
    assert!(!budget.is_closed());
    assert_eq!(permit.bytes(), MIB);
    drop(permit);

    // The node holds the lock now: a DR that comes finds it.
    match try_lock(&dir, &LockRecord::dr()) {
        LockOutcome::HeldElsewhere(Some(r)) => assert_eq!(r.kind, LockKind::Daemon),
        other => panic!("the node must hold the lock, got {other:?}"),
    }
    cancel.cancel();
    keeper.await.unwrap();
    // The node ended: the lock is free.
    let _free = acquired(try_lock(&dir, &LockRecord::dr()));
}

/// A free lock: the node takes it at start with an open budget.
#[tokio::test]
async fn daemon_takes_a_free_machine_lock_and_starts_open() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("viaticum-test");
    let record = LockRecord::daemon(Path::new("/data/node"));
    let (budget, startup) = start_daemon_budget(64 * MIB, &dir, &record);
    assert!(matches!(startup, Startup::Owns(_)));
    assert!(!budget.is_closed());
    assert!(
        budget
            .try_acquire(HolderKind::Worker, &block(1), MIB)
            .is_some()
    );
}

/// Another node of this user holds the lock: this one works as before (WARN), open.
#[tokio::test]
async fn daemon_beside_another_node_starts_open() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("viaticum-test");
    let _first = acquired(try_lock(&dir, &LockRecord::daemon(Path::new("/data/a"))));
    let (budget, startup) =
        start_daemon_budget(64 * MIB, &dir, &LockRecord::daemon(Path::new("/data/b")));
    assert!(matches!(startup, Startup::OtherNode));
    assert!(!budget.is_closed());
}

#[test]
fn closed_budget_opens_once_and_queues_in_order() {
    let budget = MemBudget::new_closed(8 * MIB);
    assert!(budget.is_closed());
    assert!(
        budget
            .try_acquire(HolderKind::Pos, &block(1), MIB)
            .is_none()
    );
    budget.open();
    budget.open();
    assert!(!budget.is_closed());
    let a = budget
        .try_acquire(HolderKind::Pos, &block(1), 8 * MIB)
        .unwrap();
    assert_eq!(
        budget.semaphore_free_bytes(),
        0,
        "opened once: 8 MiB, not 16"
    );
    drop(a);
    assert_eq!(budget.semaphore_free_bytes(), 8 * MIB);
}
