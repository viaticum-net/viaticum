// Daemon-side mailbox module.
//
// T-2: candidate-set check (should_store).
// T-4: MailboxRouter (publish / poll / dr_collect_pointers).
// CROWN-1 C2: MailboxAddress targets, target_sig on store, fetch proofs.
// T-6: run_mailbox_poll — periodic poll + entry dispatch.
// T-11: cleanup — TTL sweep + membership-based self-cleanup.

pub mod candidate;
pub mod cleanup;
pub mod poll;
pub mod routing;

#[cfg(test)]
pub(crate) mod test_postman;

#[cfg(test)]
mod tests;
