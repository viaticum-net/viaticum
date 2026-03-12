use syncback::cli;
use syncback::daemon::{Config, DaemonHandle};

use clap::Parser;
use cli::{Cli, Commands};

fn main() -> anyhow::Result<()> {
    let cli_args = Cli::parse();
    init_tracing();

    match cli_args.command {
        Commands::Daemon => run_daemon(),
        Commands::Init => cli::init::run_init(),
        Commands::Status => cli::run_status(),
        Commands::Backup => cli::run_backup(),
        Commands::Restore { path, dest } => cli::run_restore(path, dest),
        Commands::Peers => cli::run_peers(),
        Commands::Stop => cli::run_stop(),
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("RUST_LOG")
                .unwrap_or_else(|_| EnvFilter::new("syncback=debug,iroh=info")),
        )
        .with_writer(std::io::stderr)
        .init();
}

fn default_syncback_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").expect("HOME env var not set");
    std::path::PathBuf::from(home).join(".syncback")
}

fn run_daemon() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("syncback-worker")
        .enable_all()
        .build()?;

    rt.block_on(async {
        let config = Config::load(default_syncback_dir())?;
        let handle = DaemonHandle::start(config).await?;
        handle.join().await?;
        Ok(())
    })
}
