# Porting Viaticum to macOS and Windows

*Status from the GitHub Actions runs of 2026-11-02. Linux is the reference platform; macOS and Windows are handed to developers who use them.*

This file says what works, what does not, why, what to fix first, and how to tell that a port is finished. Read [overview.md](../overview.md) for the system shape and [usage.md](../usage.md) for what the daemon does today.

## 1. Where the three platforms stand

| | Linux | macOS | Windows |
|---|---|---|---|
| **Builds** | `cargo build --workspace`; static musl binaries for x86_64 and aarch64 from `packaging/build_release.sh` | `cargo build --workspace --all-targets` in CI; passes | The last CI run stops in `cargo build --workspace --all-targets` because test modules use Unix-only APIs. The daemon itself may compile; that has not been checked separately. |
| **CI** | No Linux build or test workflow. `./rtest.sh --local` runs fmt, tests and clippy; plain `cargo test` runs the tests only. Multi-process end-to-end scripts live in `experiments/`. | `.github/workflows/macos.yml`, `macos-14`: build, test, clippy | `.github/workflows/windows.yml`, `windows-latest`: build, test, clippy |
| **Tests today** | Workspace tests plus the scripts in `experiments/` | 9 failed, 1986 passed, 1 ignored (run `41526134452`) | Not reached. The last run that reached tests was `36449003139` on 2026-09-28: 52 failed of 1130. |
| **Known broken** | None known on x86_64 | Deletion events and three test groups, see section 3 | Build of test targets; restore paths, importance classification, watcher error text, and (unconfirmed) DR on real data, see section 4 |
| **Never run** | Service unit and installer: neither is in this tree | launchd, installer, service start/stop, long paths, antivirus, two-process networking | Windows Service, installer, service start/stop, long paths, antivirus, two-process networking |

There is no install script and no service definition in this repository for any platform. There is no launchd plist and no Windows Service. `under_service_manager()` recognizes `VIATICUM_SUPERVISED=1`, or a systemd parent on Linux only (`crates/viaticum/src/daemon/restart/mod.rs:83-120`); on macOS and Windows the parent check returns `None`. Treat service integration as new work.

The CI workflows never start a second daemon and never install the product or a service. A green workflow is necessary but not sufficient.

## 2. Definition of done for a port

The port is done when:

1. The `macOS` or `Windows` workflow passes on `master`: `cargo build --workspace --all-targets`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`.
2. On a real machine of that OS, all of these pass by hand:
   - `viaticum daemon` starts, reports itself in `viaticum status`, and stops on Ctrl-C with exit code 0; the next start does not repair the database.
   - `viaticum open` opens the web UI; the dashboard answers and shows the node.
   - Two daemons on the same machine, or one on each of two machines, connect over libp2p (`viaticum connect <addr>` on both sides); each `viaticum status` shows the other.
   - The watcher sees create, modify, delete and rename in a watched folder, with no duplicate record for one file.
   - `viaticum restore <path>` returns the file or folder to staging; compare hashes with the originals.
   - `viaticum dr --mnemonic` with the 24 words recovers a lost node (the flag currently requires the value), then `viaticum restore` brings files back; compare hashes.
   - A folder path containing spaces works end to end, and a file path longer than 260 characters works on Windows (enable long path support first).
   - On Windows, Microsoft Defender is on: it does not quarantine the binary or the data directory, and it does not hold a file lock that breaks restore or DR.
   - If a service definition exists by then: the node starts at login or boot and survives logout; it stops cleanly.

If a check fails, record it in an issue with the details from section 6. Do not mark the port done from CI alone.

## 3. macOS

Run `41526134452`, 2026-11-02, `macos-14`: 9 failed, 1986 passed, 1 ignored. An earlier analysis of the 29 September runs described 21 failures out of 1183 on 2026-09-28. Most of those are gone; the groups below keep the old labels.

### Fix first

1. **Deletion is reported as a modification.** `watcher_detects_file_deletion` fails with `left: Modified, right: Deleted`. A deleted file is not marked deleted, and the backup handler then fails to read it. This is probably a product defect, but the mechanism is not confirmed: FSEvents may report a path with several flags at once (created, modified, removed), and `classify_event` takes one kind. The backup side re-checks a path that has gone (`crates/viaticum/src/daemon/backup/gone.rs`), so the user-visible effect may be smaller than the test suggests. The porter should confirm the event flags on a real Mac before changing code. See M-A.
2. The other eight failures are test-only. Fix them in the order M-D, M-C, M-A, because M-D blocks five tests with one helper and M-C is a platform assumption.

### M-A: watcher events

The earlier analysis had nine failing tests in `crates/viaticum/src/daemon/watcher/tests.rs`. All nine were blamed on FSEvents returning a canonical temporary path with an extra `/private` prefix where the test expected the plain path; the ninth also saw a pre-existing file reported again. Seven of the nine pass now. Two still fail, for different reasons.

- `daemon::watcher::tests::watcher_detects_file_deletion` (`tests.rs:179`). The path assertion now passes. The event kind does not: the run shows `left: Modified`, `right: Deleted`. Cause from the code: `classify_event` maps `Modify(Data | Any | Other)` to `Modified` (`crates/viaticum/src/daemon/watcher/mod.rs:492-494`), and `resolve()` emits that event without checking the disk (`crates/viaticum/src/daemon/watcher/event_loop.rs:285-292`). `handle_added_or_modified` then tries to read the path and returns an error when the read fails (`crates/viaticum/src/daemon/backup/events.rs:129-143`), which the backup loop logs and drops (`crates/viaticum/src/daemon/backup/mod.rs:770-773`). Class: **product**. First fix: on a `Modified` event, stat the path; if it is gone, take the deletion path already used for `Remove` and for a rename.
- `daemon::watcher::tests::watcher_keeps_watching_other_dirs_when_one_is_missing` (`tests.rs:947`). The run shows the second event is `before.txt`, the file that existed before the watch, while the test expects `after.txt`, created after it. Cause from the test and the run: the pre-existing file is reported a second time after the watch starts, and the test does not filter by path. Class: **test**. First fix: receive until the event path is the created one, or accept a duplicate event for the pre-existing file and ignore it.

The other seven old M-A tests now pass: `file_deleted_before_debounce_emits_deleted_event`, `debounce_multiple_changes_emit_one_event`, `large_file_generates_dirty_event`, `watcher_detects_file_creation`, `watcher_detects_file_modification`, `rapid_changes_no_panic`, `watcher_ignores_hidden_files`.

### M-B: canonical paths in `tests_exclude`

The earlier analysis had five failures in `crates/viaticum/src/daemon/watcher/tests_exclude.rs`, all from comparing a control path that FSEvents had canonicalized. They pass in the current run: `flush_drops_live_event_inside_data_dir`, `watcher_does_not_emit_live_event_from_hidden_subdir`, `watcher_does_not_emit_live_event_through_symlinked_directory`, `watcher_drops_live_event_of_file_symlink_into_data_dir`, and the control inside `watcher_marks_refused_config_folder_error_and_never_scans_it`. No action.

### M-B′: one file under two path forms

The earlier analysis said a file arrived once from the scan under the plain temporary path and once from a live event under the canonical one with the `/private` prefix, producing two catalog entries. The test `watcher_marks_refused_config_folder_error_and_never_scans_it` passes now, so the current path handling no longer produces that split in this case. No action.

### M-C: a watch that should fail

Two tests fail:

- `daemon::watcher::tests_exclude::watcher_scans_added_folder_whose_watch_failed`
- `daemon::watcher::tests_exclude::watcher_scans_config_folder_whose_watch_failed_and_keeps_error`

Both fail in `assert_error_status` (`tests_exclude.rs:632`) with `left: Idle`, `right: Error`. Cause from the code and the run: the test makes `home/locked` unreadable with mode `0o000`, then expects the watch on `home` to fail and the folder status to become `Error`. On this runner the watch was accepted and the status stayed `Idle`. The test assumes the inotify behaviour, where a watch on the unreadable directory is refused. Class: **test**, with a product question. First fix: make the failure injectable, or gate the expectation on Linux. Then decide separately whether an unreadable subdirectory should be visible as a scan error on macOS; today nothing tells the user about it.

### M-D: DR tests on APFS

Five tests fail before they reach their own logic:

- `daemon::dr::commit::tests::abort_does_not_remove_key_draft_written_by_other_dr`
- `daemon::dr::commit::tests::abort_does_not_remove_staging_claimed_by_other_dr`
- `daemon::dr::commit::tests::commit_refuses_staging_replaced_by_other_dr`
- `daemon::dr::commit::tests::commit_stops_in_progress_when_replacement_is_locked_by_other_dr`
- `daemon::dr::preflight::tests::owned_file_never_matches_a_file_recreated_at_its_path`

The failure is the control in `crates/viaticum/src/daemon/dr/preflight/test_disk.rs:44`:

```
CONTROL FAILED: the filesystem of .../target/dr-inode-tests/dr-... never reused a freed
inode number in 32 rounds of create/remove/create.
```

The run proves that the runner's filesystem under `target/` did not reuse a freed inode in 32 rounds; the earlier analysis attributes this to APFS. The control therefore refuses to let the test pass blind. Class: **test**. First fix: run the tests with `target/` on a filesystem that reuses inode numbers, or skip the control on macOS with a clear message. Do not make the control silently pass; the DR identity check is supposed to be exercised, and on a filesystem without reuse it cannot be.

## 4. Windows

Run `41526134282`, 2026-11-02, `windows-latest`: `Cargo build` failed, so `Cargo test` and `Cargo clippy` did not run. The same has happened in every Windows run since 2026-10-26.

### Fix first: the test build

Nine compile errors at seven sites, all in test modules:

- `crates/viaticum/src/daemon/scheduler/tests/issue_mem.rs:816` and `:839`: `use std::os::unix::fs::OpenOptionsExt;` (2 errors)
- `crates/viaticum/src/daemon/scheduler/tests/issue_mem.rs:822` and `:844`: `libc::O_NONBLOCK` (2 errors), and `custom_flags` on the same lines (2 errors)
- `crates/viaticum/src/daemon/backup/source_read/tests.rs:16`: `use std::os::unix::fs::PermissionsExt;` (1 error)
- `crates/viaticum/src/daemon/backup/source_read/tests.rs:23` and `:32`: `std::fs::Permissions::from_mode` (2 errors)

The scheduler helper `Unblock` uses a non-blocking open on a FIFO; the source-read test makes a file unreadable with mode `0o000`. Both are Unix ideas. First fix: gate with `#[cfg(unix)]`, or write a Windows equivalent. `Unblock` itself and its callers need the gate, not only the test functions, because the imports are inside `Unblock::now` and `Unblock::release_all`; `issue_batch.rs:814` also uses `Unblock`. A read-only attribute is not enough for the source-read test because it still allows reading; use an ACL that denies read, or a share lock. Gate the FIFO tests as well: they call `mkfifo` from `issue_mem.rs:869`, `:952` and `issue_batch.rs:808`, `:887`, and `mkfifo` does not exist on Windows. The point is to let the test target compile and the remaining tests run.

After that, rerun the workflow. The same log shows three `unused import` warnings in Windows-only builds of the test targets (`crates/viaticum/src/daemon/dr/commit/tests.rs:9` and `:13`, `crates/viaticum/src/daemon/watcher/event_loop.rs:49`); once the build passes, `clippy -D warnings` will stop on them, so remove or gate those imports too. The groups below are from the last run where tests started, `36449003139` on 2026-09-28: 52 failed of 1130. They are **not current**; the names are given so the porter can find the same tests after the build is fixed.

### W-A: restore rejects every Windows path (product)

Eleven tests:

- `daemon::restore::tests::restore_single_file_by_exact_path`
- `daemon::restore::tests::restore_latest_version_via_source_rebuild`
- `daemon::restore::tests::restore_does_not_change_local_state`
- `daemon::restore::tests::restore_of_deleted_file_keeps_delete_cooldown_running`
- `daemon::restore::tests::default_restore_writes_to_staging_not_origin`
- `daemon::restore::tests::restore_reconstructs_from_source_when_raw_missing`
- `daemon::restore::tests::restore_without_source_decodes_symbols_from_holders`
- `daemon::restore::tests::restore_without_source_when_all_placements_uncertain_fetches_from_them`
- `daemon::restore::tests::restore_without_source_when_all_placements_presumed_lost_fetches_from_them`
- `daemon::restore::tests::run_warns_at_once_when_staging_squeezes_holdings`
- `daemon::web_api::tests::restore_job_outlives_the_client_that_submitted_it`

The old failure was `PathUnsafe: drive letter in path component: "C:"`. The cause is still in the code. `validate_record_path` rejects a component that starts with a drive letter (`crates/viaticum-core/src/path_safety/mod.rs:133-140`) and any colon (`:142-145`). Catalog records are stored from a native path string (`crates/viaticum/src/daemon/backup/events.rs:359`), so on Windows they look like `C:\Users\me\Documents\a.txt`. Every record is validated before a file is written (`crates/viaticum/src/daemon/restore/decode.rs:452-457`). Result: a restore of files backed up on Windows returns no files. Class: **product**. This is the first product fix after the build. Fix: accept an absolute Windows path and turn it into a safe relative form under staging, such as `C/Users/me/...` (drive kept as one component) or `Users/me/...` (drive stripped), or store a record path relative to the watch root. Add a unit test with `C:\Users\me\Documents\a.txt`.

### W-B: a trailing slash from a Windows path (product, minor)

Five tests:

- `daemon::restore::tests::restore_pack_multiple_files_roundtrip`
- `daemon::restore::tests::restore_prefix_matches_multiple_files`
- `daemon::restore::tests::restore_deduplicates_source_blocks`
- `daemon::restore::tests::one_unrecoverable_block_does_not_abort_remaining_blocks`
- `daemon::restore::tests::restore_reports_not_backed_up_for_version_without_backup`

Cause: the tests append `/` to a native temporary path. `resolve_path` treats a trailing `/` as a literal prefix (`crates/viaticum/src/daemon/restore/mod.rs:651-656`), while the catalog records use `\`. A user who types `viaticum restore C:\Users\me\Documents/` gets nothing. Class: **product, minor**, plus a test that should use the native separator. First fix: normalize separators in `resolve_path` (strip a trailing `/` or `\`, then query both forms), and build test prefixes with `MAIN_SEPARATOR`.

### W-C: consequences of W-A and W-B

Eight tests:

- `daemon::restore::tests::restore_result_contains_staging_path`
- `daemon::restore::tests::restore_counts_restored_plus_failed_equal_files_total`
- `daemon::restore::tests::restore_records_progress_and_restored_paths_into_registered_job`
- `daemon::restore::tests::restore_cancelled_marks_remaining_files_interrupted_and_outcome_interrupted`
- `daemon::restore::tests::run_rewrites_job_marker_as_finished`
- `daemon::restore::tests::restore_writes_finished_job_record_with_restored_paths`
- `daemon::restore::no_answer::tests::restore_job_with_dead_holders_spends_one_budget_across_blocks`
- `daemon::restore::no_answer::tests::restore_cancel_during_pause_interrupts_job_at_once_and_pause_is_visible`

The old run shows a mix of `NothingRestored`, empty lists, an index out of bounds in the job record, and a missing pause line. Recheck all eight after W-A and W-B; do not work on them first.

### W-D: file locks in DR

Fifteen tests:

- `daemon::dr::commit::tests::commit_installs_staged_db_and_new_key_0600`
- `daemon::dr::commit::tests::commit_keeps_existing_matching_key_untouched`
- `daemon::dr::commit::tests::abort_removes_only_staging_created_by_this_run`
- `daemon::dr::commit::tests::commit_refuses_when_db_appeared_and_is_locked`
- `daemon::dr::commit::tests::commit_moves_old_db_to_dr_bak_with_same_bytes`
- `daemon::dr::commit::tests::commit_refuses_before_any_rename_when_identity_key_exists`
- `daemon::dr::commit::tests::commit_second_run_does_not_clobber_first_dr_bak`
- `daemon::dr::commit::tests::commit_stuck_install_does_not_abort_and_keeps_drafts`
- `daemon::dr::commit::tests::commit_stuck_key_install_names_files_and_keeps_them`
- `daemon::dr::commit::tests::commit_without_staged_db_changes_nothing`
- `daemon::dr::commit::tests::crash_between_two_renames_leaves_old_db_as_dr_bak`
- `daemon::dr::preflight::tests::preflight_refuses_when_db_locked_by_running_daemon`
- `daemon::dr::preflight::tests::staging_db_opens_on_file_locked_by_preflight`
- `daemon::dr::tests::network_phase_interrupt_aborts_and_removes_own_staging`
- `daemon::dr::tests::network_phase_error_aborts_and_removes_own_staging`

The old run has two kinds of Windows lock failure, both in test code:

- `DatabaseAlreadyOpen` from `Db::create_from_file` on the staging file. The product path unlocks the staging file on Windows before redb opens it (`crates/viaticum/src/daemon/dr/mod.rs:333-338`). The tests do not: `recovered_plan` takes `plan.staging.file` and calls `Db::create_from_file` directly (`crates/viaticum/src/daemon/dr/commit/tests.rs:51-59`, call at `:55`); the two network-phase tests do the same (`crates/viaticum/src/daemon/dr/tests.rs:93`, `:135`); `staging_db_opens_on_file_locked_by_preflight` also calls it without the unlock (`crates/viaticum/src/daemon/dr/preflight/tests.rs:329-336`).
- `os 33` from reading `db.redb` while a lock is held. `abort_removes_only_staging_created_by_this_run` calls `snapshot` while the plan still holds `plan.lock.db` (`crates/viaticum/src/daemon/dr/commit/tests.rs:268-278`). `preflight_refuses_when_db_locked_by_running_daemon` reads `db.redb` while the test daemon has it open (`crates/viaticum/src/daemon/dr/preflight/tests.rs:32-44`, `:196-207`). Windows locks are mandatory, so these reads fail.

Class: **test** as far as the code shows; **to be checked by the porter** after the build fix. First fix: put the Windows `unlock()` into the test helper the same way `recover_into_staging` does, and make the snapshots list names or metadata instead of reading a locked file. Then run. If DR still fails on Windows with a lock error in product code, the old product classification stands.

A Windows user cannot rely on disaster recovery until this is green. The failures in the old run came from the tests: the production path already calls `unlock()` before redb opens the staging file (`crates/viaticum/src/daemon/dr/mod.rs:333-338`). That the real recovery works on Windows has not been confirmed.

### W-G: importance classification never matches a Windows path (product)

Three tests:

- `daemon::backup::tests::watch_config_importance_applied_to_queued_file`
- `daemon::backup::tests::derive_file_importance_integration_photo_and_text_files_in_correct_order`
- `daemon::backup::tests::derive_file_importance_burst_downweight_integration`

Cause: `find_watch_config` builds the prefix as `base + "/"` and compares it with the file path as a string (`crates/viaticum-core/src/config/mod.rs:1019-1026`). On Windows the watch path is `C:\Users\...` and the file path is `C:\Users\...\photo.jpg`, so neither the prefix nor the equality check matches. Every file gets `DEFAULT_IMPORTANCE` 0.5 instead of the class and folder multiplier. Class: **product**. First fix: compare `Path` components, or normalize both sides to one separator before the prefix check. Add a test with a Windows path.

A Windows user does not lose files because of this, but files get the wrong redundancy and priority.

### W-E: directory mtime in staging tests

Five tests:

- `daemon::restore::cleanup::tests::startup_report_never_deletes_old_staging_dirs`
- `daemon::restore::cleanup::tests::hourly_check_warns_only_over_threshold_and_never_deletes`
- `daemon::restore::cleanup::tests::check_staging_returns_summary_without_side_effects`
- `daemon::restore::cleanup::tests::run_staging_monitor_refreshes_cache_from_startup_report`
- `daemon::restore::cleanup::tests::run_staging_monitor_ticks_refresh_cache_and_never_delete`

The old failure was `Access is denied` (os 5). Cause: `age_path` opens the path as a `File` and calls `set_modified` (`crates/viaticum/src/daemon/restore/cleanup/tests.rs:79-82`). In the failing run four tests fail at the `File::open` of a directory (`:81`, first call), and `startup_report_never_deletes_old_staging_dirs` fails at `set_modified` (`:81`, second call) on an ordinary file that `age_path` has opened read-only. Windows does not open a directory as a file this way, and `set_modified` needs write access. Class: **test**. First fix: open directories with a Windows-specific call (backup semantics) or skip the directory mtime there, and open ordinary files with write access before `set_modified`; the tests only need an old timestamp, not a specific API.

### W-F: a taken restore target

One test: `daemon::restore::tests::restore_with_taken_target_counts_only_published_files`. The old failure was `AlreadyExists` (os 183) while the test prepared an occupied target. Cause: the test strips only a leading `/` from the backed-up path (`b.trim_start_matches('/')`, `crates/viaticum/src/daemon/restore/tests.rs:751`) and joins the result to the job directory. On Windows `b` is `C:\...\b.txt`; `join` sees an absolute path and replaces the job directory with the original file, which already exists. Class: **test**. First fix: use `strip_prefix` on the temporary root, or build the relative path from components.

### W-H: Unix paths in fixtures

Three tests:

- `daemon::dispatch::tests::dispatch_status_reports_cached_restore_staging_summary`
- `daemon::handle::tests::disk_available_bytes_returns_positive_for_existing_path`
- `daemon::watch_admin::tests::add_watch_fails_with_not_a_directory_for_nonexistent_path`

- The dispatch test builds a test state with `data_dir = "/tmp"` and expects `restore_staging_path == "/tmp/restore"` (`crates/viaticum/src/daemon/dispatch/tests.rs:31`, `:1532`). On Windows the joined path uses the native separator (`/tmp\restore`), so the comparison with `/tmp/restore` fails. Class: **test**. Fix: use a temporary directory and compare with the path the code actually returns.
- The handle test calls `disk_available_bytes(Path::new("/"))` (`crates/viaticum/src/daemon/handle/tests.rs:34-40`). The earlier analysis said `/` has no drive on Windows. The current Windows branch uses `std::path::absolute` and `sysinfo` instead of `statvfs` (`crates/viaticum/src/daemon/handle/mod.rs:1597-1607`), so this may be fixed. **To be checked by the porter**; if it still fails, use the drive root from `std::env::temp_dir()`.
- The watch-admin test passes `/nonexistent/path/does/not/exist` and expects `NotADirectory` (`crates/viaticum/src/daemon/watch_admin/tests.rs:205-220`). On Windows that string is not absolute, so `add_watch` returns `NotAbsolute` first (`crates/viaticum/src/daemon/watch_admin/mod.rs:421-429`). Class: **test**. Fix: build a missing path under a real temporary root.

### W-I: watcher error text

One test: `daemon::watcher::tests::watcher_keeps_watching_other_dirs_when_one_is_missing`. The old run shows `left: Some("Input watch path is neither a file nor a directory.")`, `right: Some("folder does not exist")`. Cause: on Windows `notify` reports the missing path as `ErrorKind::Generic`; `describe_watch_error` maps only `PathNotFound` and `Io(NotFound)` to `folder does not exist`, and `Generic` falls through to `e.to_string()` (`crates/viaticum/src/daemon/watcher/mod.rs:507-521`, fallback at `:519`). Class: **product, minor**, as in the earlier analysis. First fix: check that the folder exists before calling `watch()`, or map the Generic message to `folder does not exist`. This test is the same one that fails for another reason on macOS (M-A); fix this one first on Windows, then look at the event order.

## 5. Building and running the tests

You need a working Rust toolchain and Node.js. `rust-toolchain.toml` pins Rust 1.95 with `rustfmt` and `clippy`; `Cargo.toml` lists 1.89 as the minimum.

The daemon embeds the built web UI at compile time. Build the UI first:

```sh
cd web-ui
npm ci
npm run build
cd ..
```

Then build and test:

```sh
cargo build --workspace --all-targets
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

The CI workflows run build, test and clippy in that order; `cargo fmt --all --check` is part of the local gate but not of CI. (`Cargo clippy` is skipped when an earlier step fails: tests on macOS, build on Windows.) The workflows build the UI with `npm ci && npm run build` too, and use a placeholder `dist/index.html` if `web-ui/package.json` is absent.

`rbuild.sh` and `rtest.sh` are the maintainers' convenience scripts. By default they try a remote build host and read its address from the gitignored `.env`; without that host they exit 9. A contributor should use plain `cargo`, or `./rtest.sh --local` if they have the checkout and want the same gate locally. The remote host is not required to port or test a build.

The end-to-end scripts in `experiments/` start several daemon processes and check backup, restore, trust and DR. They are Linux shell scripts; read one before adapting it to macOS or Windows. A port should add the manual checks from section 2 rather than pretend the Linux scripts prove the port.

## 6. Reporting back

Open an issue in the repository with:

- OS name and version, and the CPU architecture (for example `macOS 15.6 arm64`, `Windows 11 24H2 x86_64`).
- `rustc -V`, `node -v`, and `git rev-parse HEAD`.
- The GitHub Actions run link. If the failure is local, the exact command and its output.
- The failing test name and the panic or assertion line, copied from the log. For a build failure, the first `error[...]` block is enough.
- Whether the failure is in a test or in the product, if you can tell.
- For a manual check: what you did, what you expected, what happened, and whether it reproduced after a fresh start.
- For path problems: the exact path, including the drive letter and the trailing separator.
- For Windows Defender: the detection name and the file or directory it acted on.

Do not attach `identity.key`, the 24-word phrase, the database, or a copy of a watched folder. A log line with a file name is usually enough.
