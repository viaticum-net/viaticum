use syncback::cli;
use syncback::daemon::{Config, DaemonHandle, IncludeEntry};

use clap::Parser;
use cli::{Cli, Commands};

fn main() -> anyhow::Result<()> {
    let cli_args = Cli::parse();
    init_tracing();

    match cli_args.command {
        Commands::Daemon { time_scale, quota_gb, includes } => run_daemon(time_scale, quota_gb, includes),
        Commands::Init { mnemonic } => {
            if let Some(phrase) = mnemonic {
                cli::init::run_init_with_phrase(&phrase)
            } else {
                cli::init::run_init()
            }
        }
        Commands::Status => cli::run_status(),
        Commands::Backup => cli::run_backup(),
        Commands::Restore { path, dest } => cli::run_restore(path, dest),
        Commands::Peers => cli::run_peers(),
        Commands::Stop => cli::run_stop(),
        Commands::DrRestore { seed, peer } => cli::run_dr_restore(seed, peer),
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

fn run_daemon(
    time_scale: Option<u64>,
    quota_gb: Option<u64>,
    includes: Vec<String>,
) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("syncback-worker")
        .enable_all()
        .build()?;

    rt.block_on(async {
        let mut config = Config::load(default_syncback_dir())?;
        if let Some(ts) = time_scale {
            config.time_scale = ts;
        }
        if let Some(q) = quota_gb {
            config.storage.quota_gb = q;
        }
        for inc in includes {
            // Format: "path:importance" — rsplitn(2) gives [importance, path]
            let parts: Vec<&str> = inc.rsplitn(2, ':').collect();
            if parts.len() == 2 {
                let importance: f64 = parts[0].parse().unwrap_or(0.5);
                let path = std::path::PathBuf::from(parts[1]);
                config.backup.include.push(IncludeEntry { path, importance });
            } else {
                config.backup.include.push(IncludeEntry {
                    path: std::path::PathBuf::from(&inc),
                    importance: 0.5,
                });
            }
        }
        let handle = DaemonHandle::start(config).await?;
        handle.join().await?;
        Ok(())
    })
}
