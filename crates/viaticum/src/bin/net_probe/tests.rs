// Unit tests for net-probe's argument → request mapping.

use clap::Parser;

use super::{Args, Cmd, request_of};

#[test]
fn disconnect_and_reach_map_to_their_endpoints() {
    let args = Args::try_parse_from([
        "net-probe",
        "--data-dir",
        "/d",
        "disconnect",
        "0a0b0c0d0e0f1011",
    ])
    .expect("parse");
    assert_eq!(
        args.cmd,
        Cmd::Disconnect {
            device: "0a0b0c0d0e0f1011".into()
        }
    );
    let (path, body) = request_of(&args.cmd);
    assert_eq!(path, "/api/e2e/disconnect");
    assert_eq!(body, serde_json::json!({ "device": "0a0b0c0d0e0f1011" }));

    let args =
        Args::try_parse_from(["net-probe", "--data-dir", "/d", "reach", "ffff"]).expect("parse");
    let (path, body) = request_of(&args.cmd);
    assert_eq!(path, "/api/e2e/reach");
    assert_eq!(body, serde_json::json!({ "device": "ffff" }));
}

#[test]
fn data_dir_is_required() {
    assert!(Args::try_parse_from(["net-probe", "reach", "ffff"]).is_err());
}
