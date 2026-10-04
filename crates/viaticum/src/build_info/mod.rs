//! What build this binary is (install-i11, R3 Р-16).
//!
//! The release build (`packaging/build_release.sh`) compiles with
//! `VIATICUM_BUILD_ID=<version>+<rev7>`; `viaticum --version`, `status.daemon_version`
//! and `viaticum build-info` all report that one string, so "which version do you
//! run" names the exact revision. A build without the variable (cargo build, tests,
//! e2e) reports `<version>+dev`: never mistaken for a release. Cargo re-runs the
//! compile when the variable changes (`option_env!` is tracked in dep-info).

#[cfg(test)]
mod tests;

/// Compile-time variable carrying the release build id.
pub const BUILD_ID_ENV: &str = "VIATICUM_BUILD_ID";

/// Suffix of a build compiled without [`BUILD_ID_ENV`].
pub const DEV_SUFFIX: &str = "+dev";

/// This binary's build id: `<version>+<rev7>` for a release build, `<version>+dev`
/// otherwise.
pub const fn build_id() -> &'static str {
    match option_env!("VIATICUM_BUILD_ID") {
        Some(id) => id,
        None => concat!(env!("CARGO_PKG_VERSION"), "+dev"),
    }
}

/// Output of `viaticum build-info` (JSON). The release script compares
/// `web_ui_index_blake3` with the blake3 of the freshly built `web-ui/dist/index.html`:
/// a stale or foreign web UI embedded in the binary fails the release (N8).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BuildInfo {
    pub build_id: String,
    /// Hex blake3 of the embedded `index.html`; `None` if the binary embeds none.
    pub web_ui_index_blake3: Option<String>,
}

/// The build info of this binary.
pub fn build_info() -> BuildInfo {
    BuildInfo {
        build_id: build_id().to_string(),
        web_ui_index_blake3: crate::daemon::web_api::embedded_index_html_blake3(),
    }
}
