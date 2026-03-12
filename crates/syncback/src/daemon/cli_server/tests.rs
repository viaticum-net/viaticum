use std::io::{BufRead, Write};

use tokio_util::sync::CancellationToken;

use crate::daemon::{CliCmd, ProcessorMsg, StatusReply};

use super::{CliRequest, CliResponse};

// ============================================================
// Test helpers
// ============================================================

/// Spawn a CLI server bound to a temp socket. Returns (task handle, cancel,
/// processor_rx, socket_path). The TempDir is kept alive by the returned
/// `_dir` so callers must hold it in scope.
async fn spawn_test_server() -> (
    tokio::task::JoinHandle<()>,
    CancellationToken,
    tokio::sync::mpsc::Receiver<ProcessorMsg>,
    std::path::PathBuf,
    tempfile::TempDir,
) {
    let dir = tempfile::TempDir::new().unwrap();
    let socket_path = dir.path().join("test.sock");
    let cancel = CancellationToken::new();
    let (processor_tx, processor_rx) = tokio::sync::mpsc::channel(16);
    let handle = tokio::spawn(super::run(
        cancel.clone(),
        processor_tx,
        socket_path.clone(),
    ));
    // Give the task time to bind.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (handle, cancel, processor_rx, socket_path, dir)
}

/// Send a `CliRequest` over the socket and return the `CliResponse`.
/// Uses synchronous std I/O — must be called from `spawn_blocking`.
fn send_cli_request(socket_path: &std::path::Path, req: &CliRequest) -> CliResponse {
    let stream = std::os::unix::net::UnixStream::connect(socket_path).unwrap();
    let mut writer = std::io::BufWriter::new(&stream);
    let mut reader = std::io::BufReader::new(&stream);
    writeln!(writer, "{}", serde_json::to_string(req).unwrap()).unwrap();
    writer.flush().unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(line.trim()).unwrap()
}

// ============================================================
// Tests
// ============================================================

#[tokio::test]
async fn status_returns_status_payload_when_processor_responds() {
    let (handle, cancel, mut rx, socket_path, _dir) = spawn_test_server().await;

    // Simulate processor responding to Status command.
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let ProcessorMsg::Cli(CliCmd::Status { reply }) = msg {
                let _ = reply.send(StatusReply {
                    uptime_secs: 42,
                    peer_count: 3,
                    shards_held: 100,
                    shards_placed: 500,
                    budget_gb: 12.5,
                    dirty_files: 2,
                });
            }
        }
    });

    let response = tokio::task::spawn_blocking({
        let p = socket_path.clone();
        move || send_cli_request(&p, &CliRequest::Status)
    })
    .await
    .unwrap();

    match response {
        CliResponse::StatusOk(s) => {
            assert_eq!(s.uptime_secs, 42);
            assert_eq!(s.peer_count, 3);
            assert_eq!(s.shards_held, 100);
            assert_eq!(s.shards_placed, 500);
            assert!((s.budget_gb - 12.5).abs() < f64::EPSILON);
            assert_eq!(s.dirty_files, 2);
        }
        other => panic!("unexpected response: {:?}", other),
    }

    cancel.cancel();
    let _ = handle.await;
}

#[tokio::test]
async fn bad_json_returns_error_response() {
    let (handle, cancel, _rx, socket_path, _dir) = spawn_test_server().await;

    let response = tokio::task::spawn_blocking({
        let p = socket_path.clone();
        move || {
            let stream = std::os::unix::net::UnixStream::connect(&p).unwrap();
            let mut writer = std::io::BufWriter::new(&stream);
            let mut reader = std::io::BufReader::new(&stream);
            writeln!(writer, "not valid json").unwrap();
            writer.flush().unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            serde_json::from_str::<CliResponse>(line.trim()).unwrap()
        }
    })
    .await
    .unwrap();

    match response {
        CliResponse::Error { message } => {
            assert!(message.contains("bad request"), "got: {message}");
        }
        other => panic!("unexpected response: {:?}", other),
    }

    cancel.cancel();
    let _ = handle.await;
}

#[tokio::test]
async fn shutdown_sends_cli_cmd_shutdown_to_processor() {
    let (handle, cancel, mut rx, socket_path, _dir) = spawn_test_server().await;

    let received_shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = received_shutdown.clone();

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let ProcessorMsg::Cli(CliCmd::Shutdown) = msg {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
    });

    let response = tokio::task::spawn_blocking({
        let p = socket_path.clone();
        move || send_cli_request(&p, &CliRequest::Shutdown)
    })
    .await
    .unwrap();

    match response {
        CliResponse::Ok { .. } => {}
        other => panic!("expected Ok, got: {:?}", other),
    }

    // Give the spawned task time to receive the message.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        received_shutdown.load(std::sync::atomic::Ordering::SeqCst),
        "processor should have received Shutdown"
    );

    cancel.cancel();
    let _ = handle.await;
}

#[tokio::test]
async fn backup_now_relays_backup_cmd_and_returns_ok() {
    let (handle, cancel, mut rx, socket_path, _dir) = spawn_test_server().await;

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let ProcessorMsg::Cli(CliCmd::BackupNow { reply }) = msg {
                let _ = reply.send(Ok(()));
            }
        }
    });

    let response = tokio::task::spawn_blocking({
        let p = socket_path.clone();
        move || send_cli_request(&p, &CliRequest::BackupNow)
    })
    .await
    .unwrap();

    match response {
        CliResponse::Ok { message } => {
            assert_eq!(message, "backup triggered");
        }
        other => panic!("unexpected response: {:?}", other),
    }

    cancel.cancel();
    let _ = handle.await;
}

#[tokio::test]
async fn multiple_concurrent_connections_handled_independently() {
    let (handle, cancel, mut rx, socket_path, _dir) = spawn_test_server().await;

    // Processor mock: answer all Status commands.
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let ProcessorMsg::Cli(CliCmd::Status { reply }) = msg {
                let _ = reply.send(StatusReply {
                    uptime_secs: 1,
                    peer_count: 0,
                    shards_held: 0,
                    shards_placed: 0,
                    budget_gb: 0.0,
                    dirty_files: 0,
                });
            }
        }
    });

    let mut tasks = Vec::new();
    for _ in 0..5 {
        let p = socket_path.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            send_cli_request(&p, &CliRequest::Status)
        }));
    }

    for task in tasks {
        let response = task.await.unwrap();
        // Each should be StatusOk or Error — no panic or deadlock.
        match response {
            CliResponse::StatusOk(_) | CliResponse::Error { .. } => {}
            other => panic!("unexpected response: {:?}", other),
        }
    }

    cancel.cancel();
    let _ = handle.await;
}

#[tokio::test]
async fn server_stops_when_cancelled() {
    let (handle, cancel, _rx, _socket_path, _dir) = spawn_test_server().await;
    cancel.cancel();
    tokio::time::timeout(std::time::Duration::from_millis(200), handle)
        .await
        .expect("server did not stop within timeout")
        .expect("server panicked");
}
