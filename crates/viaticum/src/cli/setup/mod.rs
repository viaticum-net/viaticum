// `viaticum setup` (R3b b3): one command, two questions, 24 words on paper.
//
// The first question is the mode, BEFORE any identity is created: "restore"
// runs `dr` in the data directory first (F18, M16). A new installation creates
// the identity, asks for folders and disk space, shows the phrase in a grid
// (tty only) and checks three words. Interrupting at the check leaves
// `identity.key` and no `phrase-confirmed`: a re-run shows the same phrase.
//
// `setup` does not start a daemon and does not install a service (R3c does
// that). Its last line says what to do next; `--json` carries the result for
// the future installer.

#[cfg(test)]
mod tests;

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use viaticum_core::config::{AppConfig, expand_watch_path};

use crate::daemon::handle::{disk_available_bytes, disk_size_bytes};
use crate::daemon::identity::{
    CONFIG_FILE_NAME, IdentityError, KEYFILE_NAME, default_config_toml, init_identity,
    load_identity, parse_mnemonic, write_default_config_if_absent,
};

/// First question of `setup` (install-i13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SetupMode {
    New,
    Restore,
}

impl SetupMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SetupMode::New => "new",
            SetupMode::Restore => "restore",
        }
    }
}

/// Answers that end up in `config.toml` (spec §2.2).
#[derive(Debug, Clone, PartialEq)]
pub struct SetupAnswers {
    pub watch: Vec<PathBuf>,
    pub quota_gb: f64,
    pub reserve_gb: f64,
    pub seeds: Option<Vec<String>>,
    pub web_port: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error(
        "setup does not run as root: it would leave root-owned files in the friend's \
         home. Run it as the user who will own the node, or pass --allow-root if you \
         really mean it."
    )]
    Root,
    #[error(
        "setup needs a terminal for this mode. Without one: `--mode new --yes` (the \
         phrase is never shown and stays unconfirmed), or `--mode restore --phrase-file \
         FILE` with a file readable only by you (mode 0600)."
    )]
    NoTty,
    #[error("could not read the free space of {0}; pass --quota-gb")]
    NoFreeSpaceInfo(PathBuf),
    #[error("quota must be at least 1 GB (0 means no limit and is not accepted): {0}")]
    InvalidQuota(f64),
    #[error("watch folder does not exist or is not a directory: {0}")]
    FolderMissing(PathBuf),
    #[error(
        "{0} already holds a Viaticum identity: restore would replace a live node. Use \
         another --data-dir, or remove this one with `viaticum --uninstall --purge` \
         (after the phrase is confirmed). Nothing was changed."
    )]
    DataDirHasIdentity(PathBuf),
    #[error(
        "the phrase file {0} is readable by other users (mode {1:04o}); it must be 0600 \
         (or stricter). Nothing was changed."
    )]
    PhraseFileMode(PathBuf, u32),
    #[error("disaster recovery failed: {0}")]
    Dr(String),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("config error: {0}")]
    Toml(String),
}

#[derive(Debug)]
pub struct SetupOptions {
    pub data_dir: PathBuf,
    pub mode: Option<SetupMode>,
    pub watch: Vec<PathBuf>,
    pub quota_gb: Option<f64>,
    pub seed: Vec<String>,
    pub phrase_file: Option<PathBuf>,
    pub yes: bool,
    pub skip_phrase_check: bool,
    pub allow_root: bool,
    pub json: bool,
}

/// What the installer reads from `--json` (and what the human summary repeats).
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct SetupReport {
    pub mode: String,
    pub data_dir: String,
    pub identity_pub: String,
    pub device_id: String,
    pub phrase_confirmed: bool,
    pub watch: Vec<String>,
    pub quota_gb: f64,
    pub reserve_gb: f64,
    pub web_port: u16,
    pub next: String,
}

const NEXT_NEW: &str =
    "start the Viaticum service (the installer does this), then run `viaticum open`";
const NEXT_RESTORE: &str =
    "start the service, then run `viaticum restore <folder>/`; files come back into staging";

/// `setup` entry point. Local only: no daemon, no service (R3c owns those).
pub async fn run_setup(opts: SetupOptions) -> Result<SetupReport, SetupError> {
    if root_refused(euid(), opts.allow_root) {
        return Err(SetupError::Root);
    }
    let tty = io::stdin().is_terminal() && io::stdout().is_terminal();
    let ui = Ui { json: opts.json };
    let mode = match opts.mode {
        Some(m) => m,
        None if tty => ask_mode(&ui)?,
        None => return Err(SetupError::NoTty),
    };

    std::fs::create_dir_all(&opts.data_dir)?;

    if mode == SetupMode::Restore {
        return run_restore(opts, tty, ui).await;
    }
    run_new(opts, tty, ui).await
}

async fn run_new(opts: SetupOptions, tty: bool, ui: Ui) -> Result<SetupReport, SetupError> {
    if !tty && !opts.yes {
        return Err(SetupError::NoTty);
    }
    let watch = resolve_watch(&opts, tty, &ui)?;
    let (free, size) = free_and_size(&opts.data_dir);
    let quota = resolve_quota(&opts, free, tty, &ui)?;
    let reserve = size.map(default_reserve_gb).unwrap_or(2.0);

    let keyfile = if opts.data_dir.join(KEYFILE_NAME).exists() {
        load_identity(&opts.data_dir)?
    } else {
        init_identity(&opts.data_dir)?
    };
    write_default_config_if_absent(&opts.data_dir)?;

    if !opts.skip_phrase_check && !crate::cli::phrase::is_confirmed(&opts.data_dir) {
        if tty {
            if let Some(grid) = phrase_grid_for_setup(tty, &keyfile.mnemonic) {
                ui.say("Your 24 recovery words. Write them on paper, in order, and keep the paper safe.");
                ui.say("Do not store them in a file, a photo or a password manager.");
                ui.say("");
                ui.raw(&grid);
                ui.say("");
                ui.wait_for_enter("Press Enter when you have written them down: ")?;
            }
            crate::cli::phrase::confirm_in_tty(&keyfile.mnemonic, None, None)
                .map_err(|e| SetupError::Io(io::Error::other(e)))?;
            crate::cli::phrase::mark_confirmed(&opts.data_dir)?;
        }
        // Without a tty the phrase is never printed and never confirmed: the
        // friend runs `viaticum phrase show` in a terminal (install-i2, N9).
    } else if opts.skip_phrase_check {
        crate::cli::phrase::mark_confirmed(&opts.data_dir)?;
    }

    finish(SetupMode::New, &opts, &watch, quota, reserve, &ui)
}

async fn run_restore(opts: SetupOptions, tty: bool, ui: Ui) -> Result<SetupReport, SetupError> {
    let identity_path = opts.data_dir.join(KEYFILE_NAME);
    if identity_path.exists() {
        return Err(SetupError::DataDirHasIdentity(opts.data_dir.clone()));
    }
    let phrase = match &opts.phrase_file {
        Some(path) => read_phrase_file(path)?,
        None if tty => ask_phrase(&ui)?,
        None => return Err(SetupError::NoTty),
    };
    let seeds = if opts.seed.is_empty() {
        viaticum_core::constants::DEFAULT_SEEDS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    } else {
        opts.seed.clone()
    };
    let dr = crate::daemon::dr::DrOptions {
        mnemonic: phrase,
        peers: seeds,
        data_dir: opts.data_dir.clone(),
        catalog: None,
    };
    crate::daemon::dr::run_dr(dr)
        .await
        .map_err(|e| SetupError::Dr(e.to_string()))?;
    crate::cli::phrase::mark_confirmed(&opts.data_dir)?;
    write_default_config_if_absent(&opts.data_dir)?;

    let watch = resolve_watch(&opts, tty, &ui)?;
    let (free, size) = free_and_size(&opts.data_dir);
    let quota = resolve_quota(&opts, free, tty, &ui)?;
    let reserve = size.map(default_reserve_gb).unwrap_or(2.0);
    finish(SetupMode::Restore, &opts, &watch, quota, reserve, &ui)
}

fn finish(
    mode: SetupMode,
    opts: &SetupOptions,
    watch: &[PathBuf],
    quota: f64,
    reserve: f64,
    ui: &Ui,
) -> Result<SetupReport, SetupError> {
    let config_path = opts.data_dir.join(CONFIG_FILE_NAME);
    let config_text = std::fs::read_to_string(&config_path)?;
    let listen_port = AppConfig::load(&config_path)
        .map_err(|e| SetupError::Toml(e.to_string()))?
        .network
        .listen_port;
    let existing_web_port = existing_web_port(&config_text).unwrap_or(0);
    let web_port = choose_web_port(existing_web_port, listen_port);
    let seeds = if opts.seed.is_empty() {
        None
    } else {
        Some(opts.seed.clone())
    };
    let answers = SetupAnswers {
        watch: watch.to_vec(),
        quota_gb: quota,
        reserve_gb: reserve,
        seeds,
        web_port,
    };
    let text = apply_setup_to_config(&config_text, &answers)?;
    write_config(&config_path, &text)?;

    let keyfile = load_identity(&opts.data_dir)?;
    let next = if mode == SetupMode::Restore {
        NEXT_RESTORE
    } else {
        NEXT_NEW
    };
    let report = SetupReport {
        mode: mode.as_str().to_string(),
        data_dir: opts.data_dir.display().to_string(),
        identity_pub: viaticum_core::types::hex_encode(&keyfile.identity_pub),
        device_id: viaticum_core::types::hex_encode(&keyfile.device_id),
        phrase_confirmed: crate::cli::phrase::is_confirmed(&opts.data_dir),
        watch: watch.iter().map(|p| p.display().to_string()).collect(),
        quota_gb: quota,
        reserve_gb: reserve,
        web_port,
        next: next.to_string(),
    };
    if opts.json {
        println!(
            "{}",
            serde_json::to_string(&report).expect("SetupReport is plain data")
        );
    } else {
        ui.say("Setup complete.");
        ui.say(&format!("  data directory: {}", report.data_dir));
        if report.watch.is_empty() {
            ui.say("  folders: none yet (add one in Settings)");
        } else {
            ui.say(&format!("  folders: {}", report.watch.join(", ")));
        }
        ui.say(&format!(
            "  space for friends: {:.1} GB (reserve {:.1} GB)",
            report.quota_gb, report.reserve_gb
        ));
        ui.say(&format!(
            "  Dashboard: http://127.0.0.1:{} (run `viaticum open`)",
            report.web_port
        ));
        if !report.phrase_confirmed {
            ui.say("  phrase NOT confirmed yet: run `viaticum phrase show` and `viaticum phrase check` in a terminal");
        }
        ui.say(&format!(
            "SETUP_OK mode={} data_dir={} web_port={}",
            report.mode, report.data_dir, report.web_port
        ));
        ui.say(&format!("Next: {}", report.next));
    }
    Ok(report)
}

// ─── Questions ───────────────────────────────────────────────────────────────

struct Ui {
    json: bool,
}

impl Ui {
    fn say(&self, text: &str) {
        if self.json {
            eprintln!("{text}");
        } else {
            println!("{text}");
        }
    }

    fn raw(&self, text: &str) {
        if self.json {
            eprint!("{text}");
        } else {
            print!("{text}");
        }
    }

    fn ask(&self, prompt: &str) -> io::Result<String> {
        if self.json {
            eprint!("{prompt}");
        } else {
            print!("{prompt}");
        }
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "no answer (stdin closed)",
            ));
        }
        Ok(line.trim().to_string())
    }

    fn wait_for_enter(&self, prompt: &str) -> Result<(), SetupError> {
        self.ask(prompt)?;
        Ok(())
    }
}

fn ask_mode(ui: &Ui) -> Result<SetupMode, SetupError> {
    ui.say("Is this a new installation, or are you restoring after losing a machine?");
    ui.say("  1) New installation — this machine has no Viaticum node yet; create a new identity.");
    ui.say(
        "  2) Restore from my 24 words — the old machine is gone; bring its catalog back first.",
    );
    loop {
        let answer = ui.ask("Choose 1 or 2 [1]: ")?;
        match answer.as_str() {
            "" | "1" | "new" | "n" => return Ok(SetupMode::New),
            "2" | "restore" | "r" => return Ok(SetupMode::Restore),
            _ => ui.say("Please answer 1 (new installation) or 2 (restore from 24 words)."),
        }
    }
}

fn ask_phrase(ui: &Ui) -> Result<String, SetupError> {
    ui.say("Enter your 24 recovery words, separated by spaces.");
    let phrase = ui.ask("Words: ")?;
    parse_mnemonic(&phrase).map_err(SetupError::Identity)?;
    Ok(phrase)
}

fn resolve_watch(opts: &SetupOptions, tty: bool, ui: &Ui) -> Result<Vec<PathBuf>, SetupError> {
    if !opts.watch.is_empty() {
        return validate_watch(opts.watch.clone());
    }
    let suggested = suggested_folders();
    if !tty {
        // A re-run without --watch keeps the folders already configured; a fresh
        // non-tty install starts from the suggestions (usually empty in CI).
        if let Some(existing) = configured_watch(&opts.data_dir) {
            return Ok(existing);
        }
        return Ok(suggested);
    }
    let default_text = if suggested.is_empty() {
        "none".to_string()
    } else {
        suggested
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    loop {
        let answer = ui.ask(&format!(
            "Folders to keep safe (comma-separated, empty = {default_text}): "
        ))?;
        let paths = if answer.is_empty() {
            suggested.clone()
        } else {
            answer
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| absolute_path(expand_watch_path(s)))
                .collect()
        };
        match validate_watch(paths) {
            Ok(paths) => return Ok(paths),
            Err(SetupError::FolderMissing(p)) => {
                ui.say(&format!(
                    "{} does not exist or is not a directory.",
                    p.display()
                ));
            }
            Err(e) => return Err(e),
        }
    }
}

fn validate_watch(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>, SetupError> {
    let mut out = Vec::new();
    for path in paths {
        let path = absolute_path(path);
        if !path.is_dir() {
            return Err(SetupError::FolderMissing(path));
        }
        if !out.contains(&path) {
            out.push(path);
        }
    }
    Ok(out)
}

fn absolute_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::path::absolute(&path).unwrap_or(path)
    }
}

/// Directories a friend is likely to want: only those that exist right now.
/// Sorted, deduplicated, absolute.
pub fn suggested_folders() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in [
        dirs::document_dir(),
        dirs::picture_dir(),
        dirs::desktop_dir(),
    ]
    .into_iter()
    .flatten()
    {
        let dir = absolute_path(dir);
        if dir.is_dir() && !out.contains(&dir) {
            out.push(dir);
        }
    }
    out
}

fn resolve_quota(
    opts: &SetupOptions,
    free: Option<u64>,
    tty: bool,
    ui: &Ui,
) -> Result<f64, SetupError> {
    if let Some(q) = opts.quota_gb {
        validate_quota(q)?;
        return Ok(q);
    }
    if !tty && let Some(q) = configured_quota(&opts.data_dir) {
        return Ok(q);
    }
    let default = free.map(default_quota_gb);
    if tty {
        loop {
            let prompt = match default {
                Some(d) => format!("Space to give friends on this disk, in GB [{d:.0}]: "),
                None => "Free space could not be read. Space to give friends, in GB (at least 1): "
                    .to_string(),
            };
            let answer = ui.ask(&prompt)?;
            if answer.is_empty() {
                if let Some(d) = default {
                    return Ok(d);
                }
                ui.say("Enter a number of GB, at least 1.");
                continue;
            }
            match answer.parse::<f64>() {
                Ok(q) => match validate_quota(q) {
                    Ok(()) => return Ok(q),
                    Err(e) => ui.say(&e.to_string()),
                },
                Err(_) => ui.say("Enter a number, for example 20."),
            }
        }
    }
    match default {
        Some(q) => Ok(q),
        None => Err(SetupError::NoFreeSpaceInfo(opts.data_dir.clone())),
    }
}

fn validate_quota(q: f64) -> Result<(), SetupError> {
    if !q.is_finite() || q < 1.0 {
        return Err(SetupError::InvalidQuota(q));
    }
    Ok(())
}

/// `max(1, floor(0.2 × free_gb))` (Р-11, install-i3).
pub fn default_quota_gb(free_bytes: u64) -> f64 {
    let free_gb = free_bytes as f64 / 1_073_741_824.0;
    (free_gb * 0.2).floor().max(1.0)
}

/// `clamp(0.1 × size_gb, 2, 20)` (Р-11).
pub fn default_reserve_gb(fs_size_bytes: u64) -> f64 {
    let size_gb = fs_size_bytes as f64 / 1_073_741_824.0;
    (size_gb * 0.1).clamp(2.0, 20.0)
}

/// Free bytes and filesystem size of the data directory via `statvfs` of the
/// path itself (F-Q, N3: a symlink is resolved by the kernel, not by us).
pub fn free_and_size(data_dir: &Path) -> (Option<u64>, Option<u64>) {
    (disk_available_bytes(data_dir), disk_size_bytes(data_dir))
}

// ─── Config ──────────────────────────────────────────────────────────────────

/// Apply setup answers to the `init` template with `toml_edit`, preserving
/// comments. Idempotent: applying the same answers twice yields the same text
/// and never duplicates `[[watch]]` (install-i3).
pub fn apply_setup_to_config(toml_text: &str, a: &SetupAnswers) -> Result<String, SetupError> {
    let mut doc: toml_edit::DocumentMut = toml_text
        .parse()
        .map_err(|e: toml_edit::TomlError| SetupError::Toml(e.to_string()))?;

    {
        let storage = table_mut(&mut doc, "storage");
        storage["soft_quota_gb"] = toml_edit::value(a.quota_gb);
        storage["disk_reserve_gb"] = toml_edit::value(a.reserve_gb);
    }
    if let Some(seeds) = &a.seeds {
        let mut arr = toml_edit::Array::new();
        for s in seeds {
            arr.push(s.as_str());
        }
        let network = table_mut(&mut doc, "network");
        network["kademlia_bootstrap_peers"] = toml_edit::value(arr);
    }
    {
        let web = table_mut(&mut doc, "web_api");
        web["enabled"] = toml_edit::value(true);
        web["bind"] = toml_edit::value(format!("127.0.0.1:{}", a.web_port));
    }

    let mut watches = toml_edit::ArrayOfTables::new();
    for path in &a.watch {
        let mut table = toml_edit::Table::new();
        table["path"] = toml_edit::value(path.to_string_lossy().to_string());
        watches.push(table);
    }
    doc.remove("watch");
    if !watches.is_empty() {
        doc.insert("watch", toml_edit::Item::ArrayOfTables(watches));
    }
    Ok(doc.to_string())
}

fn table_mut<'a>(doc: &'a mut toml_edit::DocumentMut, name: &str) -> &'a mut toml_edit::Table {
    if !doc.contains_key(name) {
        doc.insert(name, toml_edit::Item::Table(toml_edit::Table::new()));
    }
    doc[name]
        .as_table_mut()
        .expect("the table was just inserted")
}

fn configured_watch(data_dir: &Path) -> Option<Vec<PathBuf>> {
    let cfg = AppConfig::load(&data_dir.join(CONFIG_FILE_NAME)).ok()?;
    if cfg.watch.is_empty() {
        return None;
    }
    Some(
        cfg.watch
            .iter()
            .map(|w| absolute_path(expand_watch_path(&w.path)))
            .collect(),
    )
}

fn configured_quota(data_dir: &Path) -> Option<f64> {
    let cfg = AppConfig::load(&data_dir.join(CONFIG_FILE_NAME)).ok()?;
    (cfg.storage.soft_quota_gb >= 1.0).then_some(cfg.storage.soft_quota_gb)
}

fn existing_web_port(toml_text: &str) -> Option<u16> {
    let doc: toml_edit::DocumentMut = toml_text.parse().ok()?;
    let bind = doc.get("web_api")?.as_table()?.get("bind")?.as_str()?;
    bind.rsplit_once(':')?.1.parse().ok()
}

/// 7383 when it is free and not the libp2p port, else a random free TCP port on
/// loopback that differs from the libp2p one (two users on one machine). An
/// existing non-default web port is never rewritten (R3b brief).
pub fn choose_web_port(existing: u16, listen_port: u16) -> u16 {
    let default = crate::daemon::identity::DEFAULT_WEB_PORT;
    if existing != 0 && existing != default && existing != listen_port {
        return existing;
    }
    if existing == default && listen_port != default && tcp_free_on_loopback(default) {
        return default;
    }
    use crate::daemon::network::listen_port::{PortProtocols, pick_listen_port};
    let local = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    pick_listen_port(
        viaticum_core::constants::LISTEN_PORT_RANGE,
        &[listen_port, default],
        PortProtocols::Tcp,
        local,
    )
    .unwrap_or(default)
}

fn tcp_free_on_loopback(port: u16) -> bool {
    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok()
}

fn write_config(path: &Path, text: &str) -> Result<(), SetupError> {
    let tmp = path.with_extension("toml.setup-tmp");
    std::fs::write(&tmp, text)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

// ─── Phrase file ─────────────────────────────────────────────────────────────

/// Restore without a tty requires a 0600 phrase file. Anything outside 0600
/// (group/other access, or execute bits) is refused before DR touches anything.
pub fn check_phrase_file_mode(mode: u32) -> Result<(), SetupError> {
    if mode & !0o600 != 0 {
        return Err(SetupError::PhraseFileMode(PathBuf::new(), mode));
    }
    Ok(())
}

fn read_phrase_file(path: &Path) -> Result<String, SetupError> {
    let meta = std::fs::metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & !0o600 != 0 {
            return Err(SetupError::PhraseFileMode(path.to_path_buf(), mode));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = &meta;
    }
    let text = std::fs::read_to_string(path)?;
    let phrase = crate::daemon::identity::normalize_phrase(&text);
    if phrase.is_empty() {
        return Err(SetupError::Dr("the phrase file is empty".into()));
    }
    parse_mnemonic(&phrase).map_err(SetupError::Identity)?;
    Ok(phrase)
}

// ─── Small pure helpers (unit-tested) ────────────────────────────────────────

/// The phrase grid is shown only when the output is a tty (M3″, N9). `None`
/// means "print nothing": no log, no capture, no installer transcript.
pub fn phrase_grid_for_setup(is_tty: bool, mnemonic: &str) -> Option<String> {
    is_tty.then(|| crate::cli::phrase::format_grid(mnemonic))
}

/// Root is refused before the first write unless `--allow-root` (install-i8).
pub fn root_refused(euid: u32, allow_root: bool) -> bool {
    euid == 0 && !allow_root
}

#[cfg(unix)]
fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(not(unix))]
fn euid() -> u32 {
    1
}

/// The template DR/init wrote, for callers that need it before `setup` edits it.
pub fn base_config(listen_port: u16, seeds: &[&str]) -> String {
    default_config_toml(listen_port, seeds)
}
