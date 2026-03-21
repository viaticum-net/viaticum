use clap::Parser;
use syncback::cli::{Cli, Command};
use syncback::daemon::handle::{DaemonConfig, DaemonHandle};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Command::Daemon {
            time_scale,
            data_dir,
            watch_dir,
        } => {
            tracing_subscriber::fmt::init();

            let dir = syncback::cli::expand_data_dir(data_dir);
            let cfg = DaemonConfig {
                data_dir: dir,
                socket_path: syncback::cli::expand_socket_path(
                    syncback::cli::DEFAULT_SOCKET_PATH,
                ),
                time_scale: *time_scale,
                watch_dirs: watch_dir.clone(),
            };

            let handle = DaemonHandle::start(cfg).await?;

            tokio::signal::ctrl_c().await?;
            tracing::info!("received Ctrl-C, shutting down...");
            handle.stop();
            handle.wait().await?;
        }
        Command::Init { mnemonic, data_dir } => {
            let dir = syncback::cli::expand_data_dir(data_dir);
            let result = match mnemonic {
                Some(m) => {
                    syncback::daemon::identity::init_identity_from_mnemonic(&dir, m)
                }
                None => syncback::daemon::identity::init_identity(&dir),
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
        other => {
            let socket_path =
                syncback::cli::expand_socket_path(syncback::cli::DEFAULT_SOCKET_PATH);
            if let Err(e) = syncback::cli::run_command(other, &socket_path) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
