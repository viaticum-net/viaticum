use clap::Parser;
use syncback::cli::{Cli, Command};

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Command::Daemon => {
            // Start daemon (stub — wired in Phase 5).
            println!("syncback \u{03b2} daemon \u{2014} not yet implemented");
        }
        other => {
            let socket_path = syncback::cli::expand_socket_path(syncback::cli::DEFAULT_SOCKET_PATH);
            if let Err(e) = syncback::cli::run_command(other, &socket_path) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
}
