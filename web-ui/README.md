# Viaticum Web UI

Browser-based interface for the Viaticum daemon. Talks to the daemon's local HTTP API (`viaticum init` configures `http://127.0.0.1:7383`; `viaticum open` opens it — see `crates/viaticum/src/daemon/web_api`). Built with Svelte 5 and Vite.

The daemon embeds the built `dist/` at compile time and serves it on its admin port, so end users don't run this separately — they open the browser at the daemon's URL. This directory is the source the daemon embeds.

## Panels

| Panel | Status | What it does |
|-------|--------|--------------|
| Connect | working | First-run flow: enter peer address to bootstrap into a swarm |
| Dashboard | working | System status, storage usage, peer count, recent events |
| Folders | working | Add/remove watched directories, see per-folder backup state |
| Files | working | Per-file status, restore actions, blocker explanations |
| Devices | working | List paired devices in the cluster, certificate state |
| Settings | working | Quota, disk reserve, daemon parameters; edit + save with `.bak` backup |

All panels are wired to real daemon endpoints. End-to-end flows work; visual polish, accessibility, mobile responsiveness, and i18n are pre-alpha.

## Build

```
npm install
npm run dev      # local dev server with HMR, proxies API to localhost:8765
npm run build    # produces dist/, picked up by the Rust build via include_dir!
```

The Rust build re-embeds `dist/` automatically when `crates/viaticum/build.rs` detects changes, so the standard workflow is `npm run build` then `cargo build` in the workspace root.

## Status

Prototype. Functional for everyday daemon use during development. Production hardening (a11y audit, mobile layouts, English+Italian translation, error UX, integration tests) is a Phase 3 deliverable.

## License

[AGPL-3.0-only](../LICENSE).
