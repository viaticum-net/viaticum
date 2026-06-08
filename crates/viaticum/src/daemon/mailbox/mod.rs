// Daemon-side mailbox module.
//
// T-2: candidate-set check (should_store).
// T-4: MailboxRouter (publish / poll / dr_walk_for_pointer).

pub mod candidate;
pub mod routing;

#[cfg(test)]
mod tests;
