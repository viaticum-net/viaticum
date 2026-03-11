//! Smoke tests for iroh connectivity — validates the API surface we depend on.

use iroh::endpoint::{Endpoint, RecvStream, SendStream};
use iroh::SecretKey;

const TEST_ALPN: &[u8] = b"syncback-test/0";

fn random_secret_key() -> SecretKey {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    SecretKey::from_bytes(&bytes)
}

/// Two iroh endpoints connect, exchange a message over a bidirectional stream.
#[tokio::test]
async fn two_endpoints_connect_and_exchange() {
    let ep_a = Endpoint::empty_builder(iroh::endpoint::RelayMode::Disabled)
        .secret_key(random_secret_key())
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await
        .expect("bind ep_a");

    let ep_b = Endpoint::empty_builder(iroh::endpoint::RelayMode::Disabled)
        .secret_key(random_secret_key())
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await
        .expect("bind ep_b");

    let addr_b = ep_b.addr();

    // Spawn accept loop on ep_b
    let accept_handle = tokio::spawn(async move {
        let incoming = ep_b.accept().await.expect("accept incoming");
        let conn = incoming.accept().expect("accept").await.expect("connecting");
        let (mut send, mut recv): (SendStream, RecvStream) =
            conn.accept_bi().await.expect("accept_bi");
        let msg = recv.read_to_end(64).await.expect("read");
        send.write_all(b"pong").await.expect("write pong");
        send.finish().expect("finish");
        send.stopped().await.expect("stopped");
        String::from_utf8(msg).expect("utf8")
    });

    // Connect from ep_a to ep_b
    let conn = ep_a
        .connect(addr_b, TEST_ALPN)
        .await
        .expect("connect a->b");
    let (mut send, mut recv): (SendStream, RecvStream) = conn.open_bi().await.expect("open_bi");
    send.write_all(b"ping").await.expect("write ping");
    send.finish().expect("finish");

    let reply = recv.read_to_end(64).await.expect("read reply");
    let reply = String::from_utf8(reply).expect("utf8");

    let received = accept_handle.await.expect("accept task");

    assert_eq!(received, "ping");
    assert_eq!(reply, "pong");

    ep_a.close().await;
}
