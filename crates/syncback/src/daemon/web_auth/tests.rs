use super::*;
use std::fs;

#[test]
fn load_or_create_token_creates_file_if_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let token = load_or_create_token(tmp.path()).unwrap();
    assert_eq!(token.len(), 43, "32 random bytes base64 (no padding) = 43 chars");
    let file_path = tmp.path().join("api-token");
    assert!(file_path.exists());
    let contents = fs::read_to_string(&file_path).unwrap();
    assert_eq!(contents.trim(), token);
}

#[test]
fn load_or_create_token_reuses_existing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let token1 = load_or_create_token(tmp.path()).unwrap();
    let token2 = load_or_create_token(tmp.path()).unwrap();
    assert_eq!(token1, token2);
}

#[cfg(unix)]
#[test]
fn load_or_create_token_sets_mode_0600_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    load_or_create_token(tmp.path()).unwrap();
    let meta = fs::metadata(tmp.path().join("api-token")).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn write_port_file_creates_file_with_port() {
    let tmp = tempfile::tempdir().unwrap();
    write_port_file(tmp.path(), 45678).unwrap();
    let contents = fs::read_to_string(tmp.path().join("api-port")).unwrap();
    assert_eq!(contents.trim(), "45678");
}

#[test]
fn read_port_and_token_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let written_token = load_or_create_token(tmp.path()).unwrap();
    write_port_file(tmp.path(), 12345).unwrap();
    let (port, token) = read_port_and_token(tmp.path()).unwrap();
    assert_eq!(port, 12345);
    assert_eq!(token, written_token);
}

#[test]
fn read_port_and_token_errors_when_files_missing() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(read_port_and_token(tmp.path()).is_err());
}

#[cfg(unix)]
#[test]
fn write_port_file_sets_mode_0600_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    write_port_file(tmp.path(), 8080).unwrap();
    let meta = fs::metadata(tmp.path().join("api-port")).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}
