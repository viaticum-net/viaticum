use clap::Parser;
use syncback::cli::{Cli, Command};
use syncback::daemon::handle::{DaemonConfig, DaemonHandle};
use syncback_core::types::hex_encode;

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(not(target_os = "linux"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let global_dir = syncback::cli::expand_data_dir(cli.data_dir.as_deref());

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
                (Some(m), true) => syncback::daemon::identity::init_identity_new_device(&dir, m),
                (Some(m), false) => {
                    syncback::daemon::identity::init_identity_from_mnemonic(&dir, m)
                }
                (None, _) => syncback::daemon::identity::init_identity(&dir),
            };
            match result {
                Ok(keyfile) => {
                    println!("Identity initialized.");
                    println!("Public key: {}", hex_encode(&keyfile.identity_pub));
                    println!("Device ID:  {}", hex_encode(&keyfile.device_id));
                    println!("\nMnemonic (SAVE THIS):\n  {}", keyfile.mnemonic);
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
            tracing_subscriber::fmt::init();
            let dr_dir = match data_dir {
                Some(d) => syncback::cli::expand_data_dir(Some(d)),
                None => global_dir.clone(),
            };
            if let Err(e) =
                syncback::daemon::dr::run_dr(mnemonic.clone(), peer.clone(), dr_dir).await
            {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        Command::Open => {
            let connection = resolve_or_exit(&cli, &global_dir);
            if let Err(e) = syncback::cli::cmd_open(&connection) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        Command::Token { url } => {
            let connection = resolve_or_exit(&cli, &global_dir);
            syncback::cli::cmd_token(&connection, *url);
        }
        other => {
            let connection = resolve_or_exit(&cli, &global_dir);
            if let Err(e) = syncback::cli::run_command(other, &connection) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

fn resolve_or_exit(cli: &Cli, global_dir: &std::path::Path) -> syncback::cli::Connection {
    match syncback::cli::resolve_connection(cli.server.clone(), cli.token.clone(), global_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
