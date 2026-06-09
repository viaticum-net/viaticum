// Daemon-side mailbox module.
//
// T-2: candidate-set check (should_store).
// T-4: MailboxRouter (publish / poll / dr_walk_for_pointer).
// T-6: run_mailbox_poll — periodic poll + entry dispatch.
// T-11: cleanup — TTL sweep + membership-based self-cleanup.

pub mod candidate;
pub mod cleanup;
pub mod poll;
pub mod routing;

#[cfg(test)]
mod tests;
