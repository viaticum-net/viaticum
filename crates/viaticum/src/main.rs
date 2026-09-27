use std::process::ExitCode;

use clap::Parser;
use viaticum::cli::{Cli, Command};
use viaticum::daemon::handle::shutdown::{SHUTDOWN_DRAIN, ShutdownSignals};
use viaticum::daemon::handle::{DaemonConfig, DaemonHandle};
use viaticum_core::types::hex_encode;

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(not(target_os = "linux"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// The exit status is returned from `main`, never set with `std::process::exit`
// on the daemon's start/stop path: `#[tokio::main]` drops the runtime (and with
// it every task and the last `Db` clone, so redb closes cleanly) before `main`
// returns the code. Codes: 0 clean stop, 1 failed stop, 75/78 refused start
// (see `daemon::handle::startup`). The one exception is a second stop signal
// during the drain (R1-a: "exit immediately", repair on the next start is
// accepted) — waiting for the runtime there would defeat its purpose.
#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let global_dir = viaticum::cli::expand_data_dir(cli.data_dir.as_deref());

    match &cli.command {
        Command::Daemon {
            time_scale,
            watch_dir,
            log_format,
        } => {
            let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
            if log_format == "json" {
                tracing_subscriber::fmt()
                    .json()
                    .with_env_filter(env_filter)
                    .init();
            } else {
                tracing_subscriber::fmt().with_env_filter(env_filter).init();
            }

            let cfg = DaemonConfig {
                data_dir: global_dir.clone(),
                time_scale: *time_scale,
                watch_dirs: watch_dir.clone(),
            };
            return run_daemon(cfg).await;
        }
        Command::Init {
            mnemonic,
            new_device,
        } => {
            let dir = global_dir.clone();
            let result = match (mnemonic, new_device) {
                (Some(m), true) => viaticum::daemon::identity::init_identity_new_device(&dir, m),
                (Some(m), false) => {
                    viaticum::daemon::identity::init_identity_from_mnemonic(&dir, m)
                }
                (None, _) => viaticum::daemon::identity::init_identity(&dir),
            };
            match result {
                Ok(keyfile) => {
                    println!("Identity initialized.");
                    println!("Public key: {}", hex_encode(&keyfile.identity_pub));
                    println!("Device ID:  {}", hex_encode(&keyfile.device_id));
                    println!("\nMnemonic (SAVE THIS):\n  {}", keyfile.mnemonic);
                    if mnemonic.is_some() && !*new_device {
                        println!(
                            "\nIf you are recovering a lost machine, stop here and use \
                             'viaticum dr' instead: a node started from an empty catalog does \
                             not bring your files back."
                        );
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::Dr {
            mnemonic,
            peer,
            data_dir,
        } => {
            // Logs go to stderr (RUST_LOG, default errors only); stdout is DR's report.
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .init();
            let dr_dir = match data_dir {
                Some(d) => viaticum::cli::expand_data_dir(Some(d)),
                None => global_dir.clone(),
            };
            let opts = viaticum::daemon::dr::DrOptions {
                mnemonic: mnemonic.clone(),
                peers: peer.clone(),
                data_dir: dr_dir,
            };
            if let Err(e) = viaticum::daemon::dr::run_dr(opts).await {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        Command::Open => {
            let connection = resolve_or_exit(&cli, &global_dir);
            if let Err(e) = viaticum::cli::cmd_open(&connection) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        Command::Token { url } => {
            let connection = resolve_or_exit(&cli, &global_dir);
            viaticum::cli::cmd_token(&connection, *url);
        }
        other => {
            let connection = resolve_or_exit(&cli, &global_dir);
            match viaticum::cli::run_command(other, &connection) {
                Ok(0) => {}
                // restore: 2 = partially restored, 1 = nothing / refused / lost contact.
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
    ExitCode::SUCCESS
}

/// Run the daemon until a stop signal; returns the process exit status.
async fn run_daemon(cfg: DaemonConfig) -> ExitCode {
    // daemon-i1: a start failure or a crash ends the process; only a service
    // manager brings it back. Say so up front when there is none.
    if !viaticum::daemon::restart::under_service_manager() {
        tracing::warn!(
            "not running under a service manager (systemd unit with {}=1, or a \
             container restart policy): if this daemon stops or fails to start, \
             nothing will restart it",
            viaticum::daemon::restart::SUPERVISED_ENV
        );
    }

    // Stop signals are registered BEFORE start (network-i6): a SIGTERM
    // while the daemon is still starting (e.g. waiting for the DB lock)
    // aborts the start cleanly instead of killing the process.
    let mut signals = match ShutdownSignals::install() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot install stop-signal handlers: {e}");
            return ExitCode::FAILURE;
        }
    };
    let handle = tokio::select! {
        started = DaemonHandle::start(cfg) => match started {
            Ok(handle) => handle,
            Err(e) => {
                // One line with the reason, before the node ever appeared on
                // the network (daemon-i1). 78 = needs a person, 75 = retry.
                tracing::error!(
                    kind = ?e.kind,
                    exit_code = e.exit_code(),
                    "daemon failed to start: {e}"
                );
                eprintln!("error: daemon failed to start: {e}");
                return ExitCode::from(e.exit_code());
            }
        },
        sig = signals.recv() => {
            // Dropping the start future drops everything it opened; the
            // tasks it already spawned are cancelled with the runtime.
            tracing::info!("received {sig} during startup, aborting start");
            tracing::info!("shutdown complete");
            return ExitCode::SUCCESS;
        }
    };
    let cancel = handle.cancel_token();

    tokio::select! {
        sig = signals.recv() => {
            tracing::info!("received {sig}, shutting down...");
        }
        _ = cancel.cancelled() => {
            tracing::info!("internal restart triggered, shutting down...");
        }
    }
    handle.stop();
    let outcome = tokio::select! {
        outcome = handle.wait_with_deadline(SHUTDOWN_DRAIN) => outcome,
        sig = signals.recv() => {
            tracing::error!(signal = sig, "second signal, exiting immediately");
            std::process::exit(1);
        }
    };
    match outcome.report() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn resolve_or_exit(cli: &Cli, global_dir: &std::path::Path) -> viaticum::cli::Connection {
    match viaticum::cli::resolve_connection(cli.server.clone(), cli.token.clone(), global_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
