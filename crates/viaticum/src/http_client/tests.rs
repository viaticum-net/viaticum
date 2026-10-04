use super::*;

fn suites(p: &rustls::crypto::CryptoProvider) -> Vec<rustls::CipherSuite> {
    p.cipher_suites.iter().map(|s| s.suite()).collect()
}

#[test]
fn install_crypto_provider_installs_ring_and_is_idempotent() {
    install_crypto_provider();
    install_crypto_provider();
    let installed = rustls::crypto::CryptoProvider::get_default()
        .expect("a provider is installed after install_crypto_provider");
    assert_eq!(
        suites(installed),
        suites(&rustls::crypto::ring::default_provider()),
        "the process-wide provider is ring"
    );
}

#[test]
fn blocking_builder_builds_a_client_without_panicking() {
    // With `rustls-no-provider` reqwest panics ("No provider set") at build() when
    // no provider is installed; the builder must have installed ring.
    let client = blocking_builder()
        .timeout(std::time::Duration::from_secs(5))
        .build();
    assert!(client.is_ok(), "blocking client: {:?}", client.err());
}

#[tokio::test]
async fn async_builder_builds_a_client_without_panicking() {
    let client = async_builder()
        .timeout(std::time::Duration::from_secs(5))
        .build();
    assert!(client.is_ok(), "async client: {:?}", client.err());
}

#[tokio::test]
async fn async_https_request_to_closed_port_is_an_error_not_a_panic() {
    // Port 1 on loopback: nothing listens. The request goes through the TLS
    // connector setup and ends in a connect error.
    let client = async_builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("client");
    let res = client.get("https://127.0.0.1:1/").send().await;
    let err = res.expect_err("nothing listens on 127.0.0.1:1");
    assert!(
        err.is_connect() || err.is_timeout(),
        "unexpected error: {err}"
    );
}
