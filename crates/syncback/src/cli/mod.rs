use std::io::{BufRead, Write};

use clap::{Parser, Subcommand};

use crate::daemon::cli_server::{CliRequest, CliResponse};

pub mod init;

// ============================================================
// CLI argument definition
// ============================================================

#[derive(Parser, Debug)]
#[command(name = "syncback", about = "Decentralized P2P cold backup")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize ~/.syncback/ (generate seed phrase, derive keys)
    Init,
    /// Start the daemon (runs in foreground; use systemd for background)
    Daemon,
    /// Show daemon status
    Status,
    /// Trigger an immediate backup
    Backup,
    /// Request restore of a file
    Restore {
        /// Path of the file to restore (as backed up)
        path: String,
        /// Destination path (default: original path)
        #[arg(short, long)]
        dest: Option<String>,
    },
    /// List known peers with trust scores
    Peers,
    /// Gracefully stop the running daemon
    Stop,
    /// Disaster recovery: restore DB from a peer using your seed phrase
    DrRestore {
        /// 24-word BIP39 seed phrase (space-separated, in quotes)
        #[arg(long, required = true)]
        seed: String,
        /// JSON-encoded iroh EndpointAddr of a peer that holds your system state
        #[arg(long, required = true)]
        peer: String,
    },
}

// ============================================================
// Socket client helper
// ============================================================

fn default_socket_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").expect("HOME env var not set");
    std::path::PathBuf::from(home)
        .join(".syncback")
        .join("syncback.sock")
}

/// Send a `CliRequest` to the daemon via Unix socket, return the `CliResponse`.
/// Prints an error and exits with code 1 if the daemon is not running.
pub fn send_request(request: &CliRequest) -> anyhow::Result<CliResponse> {
    let socket_path = default_socket_path();
    let stream = std::os::unix::net::UnixStream::connect(&socket_path).map_err(|e| {
        anyhow::anyhow!("cannot connect to daemon at {:?}: {}", socket_path, e)
    })?;

    let mut writer = std::io::BufWriter::new(&stream);
    let mut reader = std::io::BufReader::new(&stream);

    let json = serde_json::to_string(request)?;
    writeln!(writer, "{json}")?;
    writer.flush()?;

    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response: CliResponse = serde_json::from_str(line.trim())?;
    Ok(response)
}

// ============================================================
// Client subcommand implementations
// ============================================================

pub fn run_status() -> anyhow::Result<()> {
    let response = send_request(&CliRequest::Status)?;
    match response {
        CliResponse::StatusOk(s) => {
            println!("uptime:        {}s", s.uptime_secs);
            println!("peers:         {}", s.peer_count);
            println!("shards held:   {}", s.shards_held);
            println!("shards placed: {}", s.shards_placed);
            println!("budget:        {:.1} GB", s.budget_gb);
            println!("dirty files:   {}", s.dirty_files);
        }
        CliResponse::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => {
            eprintln!("unexpected response: {:?}", other);
            std::process::exit(1);
        }
    }
    Ok(())
}

pub fn run_backup() -> anyhow::Result<()> {
    let response = send_request(&CliRequest::BackupNow)?;
    match response {
        CliResponse::Ok { message } => println!("{message}"),
        CliResponse::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => eprintln!("unexpected response: {:?}", other),
    }
    Ok(())
}

pub fn run_restore(path: String, dest: Option<String>) -> anyhow::Result<()> {
    let dest = dest.unwrap_or_else(|| path.clone());
    let response = send_request(&CliRequest::RestoreFile {
        path: path.clone(),
        dest: dest.clone(),
    })?;
    match response {
        CliResponse::Ok { message } => println!("{message}"),
        CliResponse::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => eprintln!("unexpected response: {:?}", other),
    }
    Ok(())
}

pub fn run_peers() -> anyhow::Result<()> {
    let response = send_request(&CliRequest::Peers)?;
    match response {
        CliResponse::PeersOk(payload) => {
            if payload.peers.is_empty() {
                println!("no known peers");
            } else {
                println!(
                    "{:<18} {:>6} {:>6} {:>6} {:>7} {:>8} {:>12}",
                    "identity", "P", "I", "S", "trust", "weeks", "shards_held"
                );
                for p in &payload.peers {
                    println!(
                        "{:<18} {:>6.3} {:>6.3} {:>6.3} {:>7.3} {:>8} {:>12}",
                        p.identity,
                        p.trust_p,
                        p.trust_i,
                        p.trust_s,
                        p.trust_score,
                        p.weeks_in_network,
                        p.shards_held_for_us
                    );
                }
            }
        }
        CliResponse::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => eprintln!("unexpected response: {:?}", other),
    }
    Ok(())
}

pub fn run_stop() -> anyhow::Result<()> {
    let response = send_request(&CliRequest::Shutdown)?;
    match response {
        CliResponse::Ok { message } => println!("{message}"),
        CliResponse::Error { message } => eprintln!("error: {message}"),
        other => eprintln!("unexpected response: {:?}", other),
    }
    Ok(())
}

pub fn run_dr_restore(seed: String, peer: String) -> anyhow::Result<()> {
    let response = send_request(&CliRequest::DrRestore {
        seed_phrase: seed,
        peer_addr: peer,
    })?;
    match response {
        CliResponse::Ok { message } => println!("{message}"),
        CliResponse::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => eprintln!("unexpected response: {:?}", other),
    }
    Ok(())
}
