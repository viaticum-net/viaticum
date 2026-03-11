mod daemon;

use daemon::{Config, DaemonHandle};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(String::as_str);

    init_tracing();

    match subcommand {
        Some("daemon") => run_daemon(&args[2..]),
        Some("init") => run_init(&args[2..]),
        Some("status") => run_cli_status(&args[2..]),
        Some("stop") => run_cli_stop(&args[2..]),
        _ => {
            eprintln!("Usage: syncback <daemon|init|status|stop>");
            eprintln!("  daemon  — start the daemon (foreground)");
            eprintln!("  init    — initialize ~/.syncback/");
            eprintln!("  status  — print daemon status");
            eprintln!("  stop    — gracefully stop the running daemon");
            std::process::exit(1);
        }
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

fn run_daemon(_args: &[String]) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("syncback-worker")
        .enable_all()
        .build()?;

    rt.block_on(async {
        let config = Config::load(default_syncback_dir())?;
        let handle = DaemonHandle::start(config).await?;

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl+C, shutting down");
                handle.shutdown().await?;
            }
            r = handle.join() => {
                r?;
            }
        }
        Ok(())
    })
}

fn run_init(_args: &[String]) -> anyhow::Result<()> {
    eprintln!("syncback init: not yet implemented");
    Ok(())
}

fn run_cli_status(_args: &[String]) -> anyhow::Result<()> {
    eprintln!("syncback status: not yet implemented");
    Ok(())
}

fn run_cli_stop(_args: &[String]) -> anyhow::Result<()> {
    eprintln!("syncback stop: not yet implemented");
    Ok(())
}
