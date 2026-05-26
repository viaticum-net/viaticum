# Contributing to Viaticum

Viaticum is in pre-alpha and the bulk of architectural decisions are still being made by the original author. Contributions are welcome, but the project is not yet structured for many parallel hands. Read this document before opening a PR.

## Before you start

- Check `docs/features.md` and `docs/tech-debt.md` for what is planned and what is known to be wrong.
- For non-trivial changes, open an issue first to discuss approach. Substantial PRs without prior discussion may not be merged.
- Read `docs/overview.md` for the system shape and `docs/for_devs/logic.md` for the algorithms before touching protocol-level code.

## What we welcome

- Bug fixes with clear reproduction steps
- Test coverage for existing behavior
- Documentation improvements: typo fixes, clarifications, missing pieces
- Packaging contributions: NAS app catalog templates (TrueNAS SCALE, Unraid, OpenMediaVault), Yunohost manifests, Docker improvements
- Integration guides for self-hosted services (Immich, Nextcloud, Paperless-ngx, etc.)
- Translation of user-facing documentation

## What needs prior discussion

- Changes to the trust protocol or its parameters
- Changes to erasure coding or placement algorithms
- New cryptographic constructions
- Changes to wire-format messages
- New dependencies, particularly anything pulling in C/C++ libraries

## Development

The codebase is Rust. To build:

```
cargo build --workspace
cargo test --workspace
```

If you have access to a faster machine, `rbuild.sh` and `rtest.sh` build/test on a remote server. Configure with `VIATICUM_SERVER=user@host`.

## Style

- Code and code comments: English
- Conventions documented in the codebase itself (`Cargo.toml` workspace lints; `rustfmt`)
- Tests in separate `mod.rs` + `tests.rs` files, not inline `#[cfg(test)]`
- Errors via `thiserror` per module; no `anyhow` in core
- Newtypes for IDs, no string-typed identifiers

## License

By contributing, you agree that your contributions will be licensed under the project's [AGPL-3.0-only](LICENSE) license.

## Code of conduct

Be civil. Disagree about technical things, not about people. Don't be a jerk.

If you experience or witness behavior that violates this in any project space, contact the maintainer privately at `[your-email]`.
