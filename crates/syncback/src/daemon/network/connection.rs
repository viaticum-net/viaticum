// Connection struct and framed message I/O.
//
// Wraps a single QUIC bidirectional stream (SendStream + RecvStream) that was
// opened during the SyncBack handshake. After handshake completion the same
// stream is reused for all protocol messages.
//
// Send and recv are behind separate Mutexes so that concurrent read and write
// operations don't block each other. This allows the read loop to wait for
// incoming messages while the handler sends responses on the same connection.
//
// NOTE: quinn::RecvStream has both its own `read_exact` (returns ReadExactError)
// and implements tokio::io::AsyncRead (via AsyncReadExt returns std::io::Error).
// We use quinn's native `read_exact` directly and convert ReadExactError
// to NetworkError to avoid ambiguity.

use iroh::endpoint::{ReadExactError, RecvStream, SendStream};
use syncback_core::constants::MAX_MESSAGE_SIZE;
use syncback_core::messages::{Message, MessageError, frame_message, from_cbor};
use syncback_core::types::IdentityPub;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::debug;

use crate::daemon::network::NetworkError;

/// A successfully authenticated direct connection to a peer.
///
/// Wraps one iroh QUIC bidirectional stream opened at handshake time.
/// All subsequent protocol messages share this single stream.
///
/// Send and recv are independently locked so that concurrent reads and writes
/// don't block each other.
pub struct Connection {
    /// Authenticated remote identity (from handshake sig — device-level key).
    pub peer_identity: IdentityPub,
    /// Peer's master identity (from device cert). Every node must present a cert,
    /// so this is always Some after a valid handshake. Trust, placement, and all
    /// protocol operations use this identity — never the device-level key.
    pub peer_master_identity: Option<IdentityPub>,
    /// iroh connection handle (kept alive so the connection does not close).
    #[allow(dead_code)]
    pub(crate) inner: iroh::endpoint::Connection,
    /// Write half of the bidirectional stream (independently locked).
    pub(crate) send: Mutex<SendStream>,
    /// Read half of the bidirectional stream (independently locked).
    pub(crate) recv: Mutex<RecvStream>,
}

impl Connection {
    /// Create a new Connection from handshake components.
    pub(crate) fn new(
        peer_identity: IdentityPub,
        peer_master_identity: Option<IdentityPub>,
        inner: iroh::endpoint::Connection,
        send: SendStream,
        recv: RecvStream,
    ) -> Self {
        Self {
            peer_identity,
            peer_master_identity,
            inner,
            send: Mutex::new(send),
            recv: Mutex::new(recv),
        }
    }

    /// The peer's master identity. All protocol operations (trust, placement,
    /// PoS) use this identity. Panics if the peer did not present a device cert —
    /// this should never happen because the handshake rejects cert-less peers.
    pub fn master_identity(&self) -> IdentityPub {
        self.peer_master_identity
            .expect("BUG: connection without device cert — handshake should have rejected")
    }

    /// Send a [`Message`] on this connection.
    ///
    /// Frames the message as `[u32 BE length][CBOR payload]` and writes it
    /// to the stream. The stream is flushed after each message because QUIC
    /// does not guarantee delivery until the flush completes.
    ///
    /// Only locks the send Mutex; recv can proceed concurrently.
    pub async fn send_message(&self, msg: &Message) -> Result<(), NetworkError> {
        let framed = frame_message(msg).map_err(NetworkError::Message)?;
        let mut send = self.send.lock().await;
        send.write_all(&framed)
            .await
            .map_err(|e| NetworkError::Io(std::io::Error::other(e.to_string())))?;
        send.flush()
            .await
            .map_err(|e| NetworkError::Io(std::io::Error::other(e.to_string())))?;
        debug!(
            peer = %self.peer_identity,
            bytes = framed.len(),
            "sent message"
        );
        Ok(())
    }

    /// Receive the next [`Message`] from this connection.
    ///
    /// Reads the 4-byte length prefix, validates against `MAX_MESSAGE_SIZE`,
    /// reads the CBOR payload, then deserializes.
    ///
    /// Only locks the recv Mutex; send can proceed concurrently.
    ///
    /// Returns [`NetworkError::ConnectionClosed`] on clean EOF.
    pub async fn recv_message(&self) -> Result<Message, NetworkError> {
        let mut recv = self.recv.lock().await;

        let mut len_buf = [0u8; 4];
        read_exact_from_stream(&mut recv, &mut len_buf).await?;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MESSAGE_SIZE as usize {
            return Err(NetworkError::Message(MessageError::TooLarge { size: len }));
        }

        let mut payload = vec![0u8; len];
        read_exact_from_stream(&mut recv, &mut payload).await?;

        let msg: Message = from_cbor(&payload).map_err(NetworkError::Message)?;
        debug!(
            peer = %self.peer_identity,
            bytes = len,
            "received message"
        );
        Ok(msg)
    }

    /// Finish the send stream (signal end of writing).
    pub fn finish_send(&self) {
        // try_lock to avoid blocking; if someone else has the lock, skip.
        if let Ok(mut send) = self.send.try_lock() {
            let _ = send.finish();
        }
    }
}

/// Read exactly `buf.len()` bytes from a quinn RecvStream.
///
/// Converts quinn's `ReadExactError` to `NetworkError`:
/// - `FinishedEarly` (stream closed before all bytes) → `ConnectionClosed`
/// - `ReadError` (QUIC error) → `Io` with error string
pub(crate) async fn read_exact_from_stream(
    recv: &mut RecvStream,
    buf: &mut [u8],
) -> Result<(), NetworkError> {
    recv.read_exact(buf).await.map_err(|e| match e {
        ReadExactError::FinishedEarly(_) => NetworkError::ConnectionClosed,
        ReadExactError::ReadError(re) => {
            NetworkError::Io(std::io::Error::other(re.to_string()))
        }
    })
}
