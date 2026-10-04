//! HTTP clients of the CLI and the metrics pusher.
//!
//! TLS is rustls with the `ring` crypto provider (install-i11, R3 Р-4′): reqwest is
//! built with `rustls-no-provider`, so no client may be built before a process-wide
//! default provider is installed — reqwest panics with "No provider set" otherwise.
//! Every client therefore starts from [`blocking_builder`] or [`async_builder`],
//! which install `ring` first. Clippy's `disallowed-methods` (`clippy.toml`) refuses
//! a direct `reqwest::…Client::builder()` / `new()` / `default()` and any named
//! `ClientBuilder` (`disallowed-types`) anywhere else.
//!
//! Why not reqwest's default provider: it is aws-lc-rs, a second large C crypto
//! library (`aws-lc-sys`) next to `ring`, which is already in the tree (snow,
//! hickory). One C crypto build less to cross-compile, audit and ship;
//! `packaging/build_release.sh` refuses a build that pulls `aws-lc-sys`.

#[cfg(test)]
mod tests;

/// Install `ring` as the process-wide rustls provider, unless one is installed.
/// Idempotent and race-free: a concurrent install by another thread wins, and the
/// only provider compiled into this binary is `ring`.
pub fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Err = another thread installed one between the check and here; fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

/// A blocking reqwest client builder with the crypto provider in place.
#[allow(clippy::disallowed_methods, clippy::disallowed_types)] // the one sanctioned site
pub fn blocking_builder() -> reqwest::blocking::ClientBuilder {
    install_crypto_provider();
    reqwest::blocking::Client::builder()
}

/// An async reqwest client builder with the crypto provider in place.
#[allow(clippy::disallowed_methods, clippy::disallowed_types)] // the one sanctioned site
pub fn async_builder() -> reqwest::ClientBuilder {
    install_crypto_provider();
    reqwest::Client::builder()
}
