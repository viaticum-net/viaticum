use clap::Parser;
use viaticum::cli::{Cli, Command};
use viaticum::daemon::handle::{DaemonConfig, DaemonHandle};
use viaticum_core::types::hex_encode;

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(not(target_os = "linux"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

            let handle = DaemonHandle::start(cfg).await?;
            let cancel = handle.cancel_token();

            tokio::select! {
                r = tokio::signal::ctrl_c() => {
                    r?;
                    tracing::info!("received Ctrl-C, shutting down...");
                }
                _ = cancel.cancelled() => {
                    tracing::info!("internal restart triggered, shutting down...");
                }
            }
            handle.stop();
            handle.wait().await?;
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
            if let Err(e) = viaticum::cli::run_command(other, &connection) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
    Ok(())
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
