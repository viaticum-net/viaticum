//! Token-based authentication for the web API.
//!
//! A daemon-local bearer token stored in `$DATA_DIR/api-token` (mode 0600
//! on unix). CLI and web UI both use this token; web UI receives it via
//! `/auth/start?token=<tok>` which sets an HTTP-only session cookie.

use std::io::Write;
use std::path::Path;

use rand::RngCore;

#[cfg(test)]
mod tests;

pub const TOKEN_FILENAME: &str = "api-token";
pub const PORT_FILENAME: &str = "api-port";
pub const SESSION_COOKIE_NAME: &str = "syncback_session";

/// Load an existing token from `$DATA_DIR/api-token`, or generate a new one
/// (32 random bytes → base64 URL-safe, no padding) and persist it.
pub fn load_or_create_token(data_dir: &Path) -> std::io::Result<String> {
    let path = data_dir.join(TOKEN_FILENAME);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    use base64::Engine as _;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    write_secure(&path, token.as_bytes())?;
    Ok(token)
}

/// Write the actual bound TCP port to `$DATA_DIR/api-port` with mode 0600.
pub fn write_port_file(data_dir: &Path, port: u16) -> std::io::Result<()> {
    let path = data_dir.join(PORT_FILENAME);
    write_secure(&path, port.to_string().as_bytes())
}

/// Read `(port, token)` from `$DATA_DIR`. Used by the CLI in local mode.
pub fn read_port_and_token(data_dir: &Path) -> std::io::Result<(u16, String)> {
    let port_str = std::fs::read_to_string(data_dir.join(PORT_FILENAME))?;
    let port: u16 = port_str
        .trim()
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let token = std::fs::read_to_string(data_dir.join(TOKEN_FILENAME))?
        .trim()
        .to_string();
    Ok((port, token))
}

/// Write `contents` to `path` with mode 0600 on unix. Creates parent dir.
fn write_secure(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.write_all(b"\n")?;
    Ok(())
}
