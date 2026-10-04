// pos-i4: a stale PoS verdict (answer or timeout) for a placement that holds no symbols
// (Offered, Accepted, Lost, Deleting) is written neither to the weekly PoS counters nor
// to trust; the log line says `stale=true`. Two sites: the mailbox response and the
// timeout.

use std::sync::Arc;

use viaticum_core::types::{PlacementStatus, Timestamp};

use super::{PosDropFixture, pos_drop_fixture};

const STALE: [PlacementStatus; 4] = [
    PlacementStatus::Offered,
    PlacementStatus::Accepted,
    PlacementStatus::Lost,
    PlacementStatus::Deleting,
];

/// Trust that a recalculation would visibly change (no weekly rows → P back to 0.5).
const TRUST_P: f64 = 0.93;
const TRUST_I: f64 = 0.77;

impl PosDropFixture {
    fn set_trust(&self) {
        let mut peer = self.db.get_peer(&self.holder).unwrap().unwrap();
        peer.trust_p = TRUST_P;
        peer.trust_i = TRUST_I;
        self.db.upsert_peer(&peer).unwrap();
    }

    fn trust(&self) -> (f64, f64) {
        let peer = self.db.get_peer(&self.holder).unwrap().unwrap();
        (peer.trust_p, peer.trust_i)
    }

    fn weekly_rows(&self) -> usize {
        self.db
            .list_pos_weekly_for_peer(&self.holder)
            .unwrap()
            .len()
    }

    /// The holder answers `challenge_id` with the right chain hash, correctly signed.
    async fn answer_right(&self, challenge_id: [u8; 16], expected: [u8; 32]) {
        let response = viaticum_core::messages::build_pos_hash_response(
            challenge_id,
            self.block,
            expected,
            Timestamp::now(),
            &self.holder_key,
        );
        self.scheduler
            .handle_pos_response_from_mailbox(response)
            .await
            .expect("the response resolves");
    }
}

#[derive(Clone, Default)]
struct LogBuf(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `fut` with an INFO log capture; returns its log.
pub(super) async fn logged<F: std::future::Future>(fut: F) -> (F::Output, String) {
    let buf = LogBuf::default();
    let writer = buf.clone();
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish(),
    );
    let out = tracing::instrument::WithSubscriber::with_subscriber(fut, dispatch).await;
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    (out, text)
}

/// pos-i4, the response site: an answer (right or wrong hash) to a challenge issued
/// before the placement stopped holding symbols changes neither the weekly counters nor
/// trust; the pending is consumed and the resolution line says `stale=true`. Premise: the
/// same answer for a held placement does write both.
#[tokio::test]
async fn stale_response_is_written_neither_to_weekly_nor_to_trust() {
    for (i, status) in STALE.into_iter().enumerate() {
        for right in [true, false] {
            let seed = 0x40 + (i as u8) * 4 + u8::from(right);
            let f = pos_drop_fixture(seed, status, 0, 0);
            f.set_trust();
            let (id, expected) = f.challenge(Timestamp::now(), seed).await;

            let ((), log) = logged(async {
                if right {
                    f.answer_right(id, expected).await
                } else {
                    f.answer_wrong(id).await
                }
            })
            .await;

            let case = format!("{status:?}, right hash = {right}");
            assert_eq!(f.weekly_rows(), 0, "{case}: no weekly PoS row");
            assert_eq!(f.trust(), (TRUST_P, TRUST_I), "{case}: trust untouched");
            assert!(
                f.pending.lock().await.is_empty(),
                "{case}: pending consumed"
            );
            assert_eq!(f.placement().status, status, "{case}: pos-i3");
            let line = log
                .lines()
                .find(|l| l.contains("mailbox PosResponse resolved"))
                .unwrap_or_else(|| panic!("{case}: no resolution line; log:\n{log}"));
            assert!(line.contains("stale=true"), "{case}: {line}");
        }
    }

    // Premise: a held placement's answer is counted (the observation works).
    let f = pos_drop_fixture(0x5F, PlacementStatus::Alive, 0, 0);
    f.set_trust();
    let (id, _) = f.challenge(Timestamp::now(), 0x5F).await;
    let ((), log) = logged(f.answer_wrong(id)).await;
    assert_eq!(f.weekly_rows(), 1, "a held placement's verdict is counted");
    assert_ne!(f.trust(), (TRUST_P, TRUST_I), "and recalculates trust");
    assert!(log.contains("stale=false"), "{log}");
}

/// pos-i4, the timeout site: the timeout of a challenge to a placement that holds no
/// symbols changes neither the weekly counters nor trust; the pending is removed and the
/// timeout line says `stale=true`. Premise: a held placement's timeout does write both.
#[tokio::test]
async fn stale_timeout_is_written_neither_to_weekly_nor_to_trust() {
    for (i, status) in STALE.into_iter().enumerate() {
        let seed = 0x60 + (i as u8) * 4;
        let f = pos_drop_fixture(seed, status, 0, 0);
        f.set_trust();
        f.challenge(Timestamp(0), seed).await;

        let (out, log) = logged(f.scheduler.check_timeouts()).await;
        out.expect("check_timeouts");

        let case = format!("{status:?}");
        assert_eq!(f.weekly_rows(), 0, "{case}: no weekly PoS row");
        assert_eq!(f.trust(), (TRUST_P, TRUST_I), "{case}: trust untouched");
        assert!(f.pending.lock().await.is_empty(), "{case}: pending removed");
        assert_eq!(f.placement().status, status, "{case}: pos-i3");
        let line = log
            .lines()
            .find(|l| l.contains("PoS challenge timed out"))
            .unwrap_or_else(|| panic!("{case}: no timeout line; log:\n{log}"));
        assert!(line.contains("stale=true"), "{case}: {line}");
    }

    // Premise: a held placement's timeout is counted (the observation works).
    let f = pos_drop_fixture(0x7F, PlacementStatus::Alive, 0, 0);
    f.set_trust();
    f.challenge(Timestamp(0), 0x7F).await;
    f.scheduler.check_timeouts().await.unwrap();
    assert_eq!(f.weekly_rows(), 1, "a held placement's timeout is counted");
    assert_ne!(f.trust(), (TRUST_P, TRUST_I), "and recalculates trust");
}
