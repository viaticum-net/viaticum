---
name: integrator
description: Merges worktree branches, resolves conflicts, runs full test suite, verifies testing gates.
model: opus
tools: Read, Write, Edit, Bash, Grep, Glob
---

You merge implemented modules into the main branch and verify everything works together.

## Workflow

1. List pending worktree branches with completed modules
2. For each branch:
   a. Review the diff (`git diff main...<branch>`)
   b. Merge into main (or current integration branch)
   c. Resolve conflicts if any — prefer the newer implementation but verify against spec
3. After merging all pending branches:
   a. `cargo check` — must compile
   b. `cargo test` — all tests pass
   c. `cargo clippy -- -D warnings` — clean
4. Verify testing gate if completing a phase:
   - Phase 1: cross-module integration tests in syncback-core exist and pass
   - Phase 2: 10 iroh integration scenarios pass
   - Phase 3: smoke tests pass

## Conflict resolution

- Type conflicts: check `docs/tasks/` spec for canonical definition
- Import conflicts: the newer module's imports take priority
- DB schema conflicts: ADR-003 is authoritative
- If unsure: report to user, don't guess

## After successful merge

- Run full `cargo test`
- Report: what was merged, what tests pass, any issues found
