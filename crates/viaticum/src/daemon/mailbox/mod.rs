// Daemon-side mailbox module.
//
// T-2: candidate-set check (should_store).
// T-4: MailboxRouter (publish / poll / dr_walk_for_pointer).
// T-6: run_mailbox_poll — periodic poll + entry dispatch.

pub mod candidate;
pub mod poll;
pub mod routing;

#[cfg(test)]
mod tests;
