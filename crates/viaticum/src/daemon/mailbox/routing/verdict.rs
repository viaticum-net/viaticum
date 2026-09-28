// What the postmen answered to one publication, and its verdict (CROWN-1 V.3, V.15.3).
//
// Pure: `PublishOutcome::verdict` only classifies the answers. Network errors (timeouts,
// unreachable postmen) never make an "all refused" verdict: a refusal is a postman's
// explicit answer.

use viaticum_core::mailbox::MailboxRejectReason;
use viaticum_core::types::DeviceId;

/// Every postman's answer to one store, as `MailboxRouter::publish_detailed` saw it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishOutcome {
    /// Postmen that acked (stored, replaced, or already held the same envelope).
    pub acks: Vec<DeviceId>,
    /// Postmen that refused, with their reason.
    pub rejects: Vec<(DeviceId, MailboxRejectReason)>,
    /// Postmen that did not answer (network error, timeout).
    pub errors: usize,
}

/// The publication's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishVerdict {
    /// At least one postman acked.
    Stored { acks: usize },
    /// No ack; every refusal was `ClockSkew` (this computer's clock looks wrong).
    AllClockSkew,
    /// No ack; every refusal was `Superseded` (friends hold a newer pointer of this
    /// place: the clock went back).
    AllSuperseded,
    /// No ack; every refusal was `QuotaExceeded` (for a SelfPointer: the address has
    /// no free place — 64 installations of this phrase).
    AllSlotsFull,
    /// No ack; refusals of different reasons.
    MixedRefusal {
        clock: usize,
        superseded: usize,
        slots_full: usize,
        other: usize,
    },
    /// No ack and no refusal: nobody answered (or nobody was asked).
    NoAck,
}

impl PublishOutcome {
    /// Classify the answers. "All*" = no ack, at least one refusal, and every refusal
    /// of that reason (network errors are not counted either way).
    pub fn verdict(&self) -> PublishVerdict {
        if !self.acks.is_empty() {
            return PublishVerdict::Stored {
                acks: self.acks.len(),
            };
        }
        if self.rejects.is_empty() {
            return PublishVerdict::NoAck;
        }
        let (mut clock, mut superseded, mut slots_full, mut other) = (0, 0, 0, 0);
        for (_, reason) in &self.rejects {
            match reason {
                MailboxRejectReason::ClockSkew => clock += 1,
                MailboxRejectReason::Superseded => superseded += 1,
                MailboxRejectReason::QuotaExceeded => slots_full += 1,
                _ => other += 1,
            }
        }
        let n = self.rejects.len();
        if clock == n {
            PublishVerdict::AllClockSkew
        } else if superseded == n {
            PublishVerdict::AllSuperseded
        } else if slots_full == n {
            PublishVerdict::AllSlotsFull
        } else {
            PublishVerdict::MixedRefusal {
                clock,
                superseded,
                slots_full,
                other,
            }
        }
    }
}
