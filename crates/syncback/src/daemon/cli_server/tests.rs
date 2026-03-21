use std::io::{Read, Write};

use tokio_util::sync::CancellationToken;

use crate::cli::types::{CliRequest, CliResponse};

use super::dispatch;

// ============================================================
// Unit tests for dispatch
// ============================================================

#[tokio::test]
async fn dispatch_status_returns_status_response() {
    let response = dispatch(CliRequest::Status).await;
    assert!(matches!(response, CliResponse::Status(_)));
}

#[tokio::test]
async fn dispatch_files_returns_files_response() {
    let response = dispatch(CliRequest::Files { path_prefix: None }).await;
    assert!(matches!(response, CliResponse::Files(_)));
}

#[tokio::test]
async fn dispatch_restore_returns_restore_response() {
    let request = CliRequest::Restore {
        path: "f".into(),
        version: None,
        date: None,
        dest: None,
    };
    let response = dispatch(request).await;
    let CliResponse::Restore(data) = response else {
        panic!("expected Restore response, got something else");
    };
    assert_eq!(data.path, "f");
}

#[tokio::test]
async fn dispatch_device_revoke_echoes_id() {
    let id = "aa".repeat(16);
    let request = CliRequest::DeviceRevoke {
        device_id_hex: id.clone(),
    };
    let response = dispatch(request).await;
    let CliResponse::DeviceRevoked { device_id_hex } = response else {
        panic!("expected DeviceRevoked response");
    };
    assert_eq!(device_id_hex, id);
}

#[tokio::test]
async fn dispatch_versions_returns_versions_response() {
    let request = CliRequest::Versions {
        path: "photos/img.jpg".into(),
    };
    let response = dispatch(request).await;
    assert!(matches!(response, CliResponse::Versions(_)));
}

#[tokio::test]
async fn dispatch_device_list_returns_device_list_response() {
    let response = dispatch(CliRequest::DeviceList).await;
    assert!(matches!(response, CliResponse::DeviceList(_)));
}

#[tokio::test]
async fn dispatch_device_add_returns_device_added_with_label() {
    let response = dispatch(CliRequest::DeviceAdd {
        label: "my-laptop".into(),
    })
    .await;
    let CliResponse::DeviceAdded(entry) = response else {
        panic!("expected DeviceAdded");
    };
    assert_eq!(entry.label, "my-laptop");
}

// ============================================================
// Integration test: full round-trip over Unix socket
// ============================================================

#[tokio::test]
async fn cli_server_accepts_connection_and_responds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("test.sock");
    let socket_path_str = socket_path.to_str().expect("valid path").to_string();

    let cancel = CancellationToken::new();
    let config = super::CliServerConfig {
        socket_path: socket_path_str.clone(),
    };

    let _handle = super::start(config, cancel.clone())
        .await
        .expect("server start");

    // Give the server a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Connect via blocking UnixStream (CLI side).
    let socket_path_clone = socket_path_str.clone();
    let result = tokio::task::spawn_blocking(move || {
        use std::os::unix::net::UnixStream;

        let stream = UnixStream::connect(&socket_path_clone).expect("connect");

        // Encode CliRequest::Status.
        let request = CliRequest::Status;
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&request, &mut buf).expect("encode");
        let len = buf.len() as u32;

        let mut writer = &stream;
        writer.write_all(&len.to_be_bytes()).expect("write len");
        writer.write_all(&buf).expect("write payload");

        // Read response.
        let mut reader = &stream;
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).expect("read len");
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; resp_len];
        reader.read_exact(&mut payload).expect("read payload");

        let response: CliResponse =
            ciborium::de::from_reader(payload.as_slice()).expect("decode response");
        response
    })
    .await
    .expect("task");

    assert!(
        matches!(result, CliResponse::Status(_)),
        "expected Status response"
    );

    cancel.cancel();
}
