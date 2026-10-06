// net-probe — test instrument of the discovery scenario (C-DK Р-16,
// experiments/local_discovery_test.sh). NOT a user-facing CLI; built only with
// the `e2e-tools` feature.
//
//   net-probe --data-dir D disconnect [--hold-secs N] <DEVICE_HEX>
//       Close every connection of D's daemon to that peer (both sides then drop
//       it from `authenticated_devices`). --hold-secs N: for N seconds D's
//       daemon closes every new connection with the peer before the cert
//       exchange — Kademlia's dials, the redial pass, the peer's own inbound —
//       except D's on-demand dial (`send_to_device`), which still reaches it.
//   net-probe --data-dir D reach <DEVICE_HEX>
//       Send the peer a PeerAnnounce through `send_to_device`, the path every
//       production request takes; succeeds when the peer answered.
//
// DEVICE_HEX = at least 16 hex chars of the peer's DeviceId (the `known_devices`
// form). The daemon is reached like `viaticum status`: its web API port and
// token from the data dir. Exit 0 with `{"device","detail","elapsed_ms"}` on
// stdout; otherwise the reason on stderr and exit 1.

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(about = "Disconnect from / reach a known peer through a running daemon (E2E instrument)")]
struct Args {
    /// Data directory of the running daemon.
    #[arg(long)]
    data_dir: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug, PartialEq)]
enum Cmd {
    /// Close every connection to the peer.
    Disconnect {
        /// DeviceId prefix (at least 16 hex chars).
        device: String,
        /// Hold the peer this long: only the daemon's on-demand dial reconnects it.
        #[arg(long)]
        hold_secs: Option<u64>,
    },
    /// Send the peer a PeerAnnounce through send_to_device.
    Reach {
        /// DeviceId prefix (at least 16 hex chars).
        device: String,
    },
}

/// The web-API path and JSON body of `cmd`.
fn request_of(cmd: &Cmd) -> (&'static str, serde_json::Value) {
    match cmd {
        Cmd::Disconnect { device, hold_secs } => (
            "/api/e2e/disconnect",
            serde_json::json!({ "device": device, "hold_secs": hold_secs }),
        ),
        Cmd::Reach { device } => ("/api/e2e/reach", serde_json::json!({ "device": device })),
    }
}

fn run(args: &Args) -> Result<String, String> {
    let (port, token) =
        viaticum::daemon::web_auth::read_port_and_token(&args.data_dir).map_err(|e| {
            format!(
                "cannot read the daemon's api-port/api-token in {}: {e}",
                args.data_dir.display()
            )
        })?;
    let (path, body) = request_of(&args.cmd);
    // Longer than send_to_device's own 30 s deadline: the daemon answers first.
    let client = viaticum::http_client::blocking_builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let resp = client
        .post(format!("http://127.0.0.1:{port}{path}"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .map_err(|e| format!("daemon not reachable: {e}"))?;
    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    if status.is_success() {
        Ok(text)
    } else {
        Err(format!("HTTP {status}: {text}"))
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("net-probe: {e}");
            ExitCode::FAILURE
        }
    }
}
