#!/usr/bin/env python3
# Viaticum Polygon — per-node config.toml renderer + watch-dir seeder (L2 helper).
#
# WHY THIS MODULE EXISTS (intent / acceptance criteria — fixed before the code):
#   The polygon spins up a fleet of REAL viaticum daemons, each an independent
#   owner with its own archetype knobs (a free-rider needs a tiny soft_quota; a
#   "vault" node weights its files heavier via importance_multiplier; everyone
#   shares the canonical test surface — ephemeral web_api and a small
#   source_block_size so tiny test files still erasure-code; no [escrow] section:
#   v1 has no restore gate, restore-i6).
#   This module is the SINGLE PLACE that turns a NodePlan into the two on-disk
#   artifacts the fleet-manager writes per node: (1) the config.toml text and
#   (2) the seeded watch-dir files + their content-hash ledger.
#
#   It is observe-only / setup-only: it introduces NO new daemon Rust and must
#   emit ONLY config the daemon already accepts (verified against
#   crates/viaticum-core/src/config/mod.rs). Every rendered config must PASS the
#   daemon's own AppConfig::validate(), or the node refuses to start and the run
#   false-fails.
#
#   AC1 (valid config): render_config_toml() emits TOML that satisfies every
#        AppConfig::validate() constraint — source_block_size_mb is a power of
#        two >= 1; soft/hard/disk_reserve quotas >= 0 and (hard <= soft when both
#        non-zero); web_api.bind parses as a SocketAddr.
#   AC2 (free-rider via soft_quota, NOT hard_quota): a plan with a tiny
#        soft_quota_gb (~0.001) is rendered as storage.soft_quota_gb so the
#        GET-for-others ceiling is actually capped — the free-rider holds ~nothing
#        for others while still backing up its own data. hard_quota is a FLOOR and
#        must never be (mis)used for this.
#   AC3 (importance only when set): a [[watch]] block carrying
#        importance_multiplier is emitted ONLY when plan.importance_multiplier
#        differs from 1.0; otherwise we rely on the daemon's --watch-dir CLI flag
#        (default multiplier 1.0) and emit no [[watch]] block, so the two paths
#        never double-register the same directory.
#   AC4 (ground-truth ledger): seed_watch_dir() writes exactly the planned files
#        at exactly the planned sizes and returns (path, hash_hex) for each, so the
#        end-of-run restore oracle can compare restored content to the pre-backup
#        original — deletion/data-loss are judged against the hash, never against
#        the owner's optimistic view.
#
#   Determinism: file SIZES come from the NodePlan (already seeded upstream by
#   archetypes.build_node_plan); file CONTENT is drawn from the rng passed in, so
#   a fixed scenario seed reproduces byte-for-byte content run-to-run. The ledger
#   captures the actual on-disk hash regardless, so determinism is a convenience,
#   not a correctness dependency.
#
#   stdlib only (no third-party deps): os, hashlib, random typing.

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, List, Tuple

if TYPE_CHECKING:  # pragma: no cover - type hints only; avoids hard import at runtime
    import random as _random_mod

    from common import NodePlan

# ----------------------------------------------------------------------------
# Canonical test-config constants (shared by the whole fleet unless a plan or
# the scenario overrides them). Kept here so the config surface lives in ONE
# place. Every value is chosen to PASS AppConfig::validate().
# ----------------------------------------------------------------------------

# Loopback + OS-chosen ephemeral port. The daemon writes the real port to its
# api-port file; the fleet-manager reads `status` for it. Must parse as a
# SocketAddr (validate() enforces this when web_api.enabled = true).
DEFAULT_WEB_API_BIND = "127.0.0.1:0"

# Small source block so the polygon's tiny test files (KBs) still split into
# erasure-coded blocks across multiple holders (the multi-holder path we want
# to exercise). Must be a power of two and >= 1 MB.
DEFAULT_SOURCE_BLOCK_SIZE_MB = 1

# Multiplier value that means "no change"; matches DEFAULT_IMPORTANCE_MULTIPLIER
# in the daemon. A [[watch]] block is emitted only when a plan deviates from it.
NEUTRAL_IMPORTANCE_MULTIPLIER = 1.0

# Default chunk size when streaming random bytes to disk (keeps RAM flat even
# for the heaviest archetype's files).
_WRITE_CHUNK_BYTES = 1 << 20  # 1 MiB


# ----------------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------------


def _fmt_float(value: float) -> str:
    """Render a float for TOML.

    Always emits a decimal point (so the daemon's serde parses it as a float,
    not an integer) and avoids scientific notation for the tiny quotas (e.g.
    0.001), which `repr` would keep as a plain decimal anyway but we guard for
    very small magnitudes explicitly.
    """
    if value != value:  # NaN guard
        raise ValueError("config float cannot be NaN")
    if value in (float("inf"), float("-inf")):
        raise ValueError("config float cannot be infinite")
    # repr gives the shortest round-trippable decimal; force a '.0' when integral.
    text = repr(float(value))
    if "e" in text or "E" in text:
        # Expand scientific notation to a plain decimal TOML accepts.
        text = f"{value:.12f}".rstrip("0")
        if text.endswith("."):
            text += "0"
    if "." not in text:
        text += ".0"
    return text


def _toml_escape(s: str) -> str:
    """Escape a string for a TOML basic (double-quoted) string."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _scenario_value(plan: "NodePlan", attr: str, fallback):
    """Read a scenario-derived value.

    The documented render_config_toml signature takes only `plan`, but the
    config must carry the scenario-level source block size.
    The fleet-manager may attach these to the plan object (defensive getattr);
    otherwise we fall back to the canonical test default. Callers that thread
    the scenario explicitly should use the keyword args on render_config_toml.
    """
    val = getattr(plan, attr, None)
    return fallback if val is None else val


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------


def render_config_toml(
    plan: "NodePlan",
    *,
    source_block_size_mb: int | None = None,
    web_api_bind: str = DEFAULT_WEB_API_BIND,
) -> str:
    """Render a NodePlan into a per-node config.toml string.

    Emits, in this order:
      [web_api]  enabled = true, bind = <ephemeral loopback>
      [storage]  soft_quota_gb / hard_quota_gb / disk_reserve_gb from the plan
      [backup]   source_block_size_mb (scenario value, else canonical default)
      [[watch]]  ONLY when plan.importance_multiplier != 1.0 — otherwise the
                 fleet-manager relies on the daemon's --watch-dir CLI flag.

    source_block_size is scenario-level (not stored on the NodePlan dataclass),
    so it may be passed explicitly by the caller; if omitted, it is read off the
    plan when the fleet-manager attached it, and finally falls back to the
    canonical test default.

    The result always satisfies AppConfig::validate(): power-of-two block size,
    non-negative quotas with hard <= soft when both non-zero, and a parseable
    web_api.bind.
    """
    block_mb = (
        source_block_size_mb
        if source_block_size_mb is not None
        else _scenario_value(plan, "source_block_size_mb", DEFAULT_SOURCE_BLOCK_SIZE_MB)
    )

    soft = float(plan.soft_quota_gb)
    hard = float(plan.hard_quota_gb)
    reserve = float(plan.disk_reserve_gb)
    mult = float(plan.importance_multiplier)

    # Defensive validation that mirrors the daemon's AppConfig::validate(); a bad
    # plan should fail loudly HERE (at config render) rather than as a silent
    # daemon refusal that the oracle would misread as a crash.
    if int(block_mb) < 1:
        raise ValueError(f"backup.source_block_size_mb must be >= 1 (got {block_mb})")
    if int(block_mb) & (int(block_mb) - 1) != 0:
        raise ValueError(
            f"backup.source_block_size_mb must be a power of two (got {block_mb})"
        )
    if soft < 0.0 or hard < 0.0 or reserve < 0.0:
        raise ValueError(
            f"storage quotas must be >= 0 (soft={soft}, hard={hard}, reserve={reserve})"
        )
    if hard != 0.0 and soft != 0.0 and hard > soft:
        raise ValueError(
            f"storage.hard_quota_gb ({hard}) cannot exceed soft_quota_gb ({soft})"
        )

    lines: List[str] = []
    lines.append("# Auto-generated by viaticum polygon config_gen.py — do not hand-edit.")
    lines.append(f"# node: {plan.label}  archetype: {plan.archetype}")
    lines.append("")
    lines.append("[web_api]")
    lines.append("enabled = true")
    lines.append(f'bind = "{_toml_escape(web_api_bind)}"')
    lines.append("")
    lines.append("[storage]")
    lines.append(f"soft_quota_gb = {_fmt_float(soft)}")
    lines.append(f"hard_quota_gb = {_fmt_float(hard)}")
    lines.append(f"disk_reserve_gb = {_fmt_float(reserve)}")
    lines.append("")
    lines.append("[backup]")
    lines.append(f"source_block_size_mb = {int(block_mb)}")

    # A [[watch]] block is emitted ONLY when the archetype weights its files
    # away from the neutral 1.0 multiplier. Otherwise the daemon's --watch-dir
    # CLI flag registers the directory with the default multiplier, and we must
    # NOT also register it here (double-registration of the same path).
    if abs(mult - NEUTRAL_IMPORTANCE_MULTIPLIER) > 1e-9:
        watch_path = _watch_dir_for(plan)
        lines.append("")
        lines.append("[[watch]]")
        lines.append(f'path = "{_toml_escape(str(watch_path))}"')
        lines.append(f"importance_multiplier = {_fmt_float(mult)}")

    lines.append("")
    return "\n".join(lines)


def _watch_dir_for(plan: "NodePlan") -> str:
    """Path string the [[watch]] block should register.

    The fleet-manager launches the daemon with --watch-dir <data_dir>/files. When
    a plan needs a non-neutral importance multiplier we must name that same path
    in the [[watch]] block. The plan does not carry the absolute data_dir (that is
    the fleet-manager's concern), so we expose a relative-by-convention "files"
    sentinel that the fleet-manager rewrites to the absolute path before writing
    the config. The fleet-manager owns the absolute path; see seed_watch_dir,
    which is always handed the concrete files_dir.
    """
    return getattr(plan, "watch_path", "files")


def seed_watch_dir(
    files_dir: Path,
    plan: "NodePlan",
    rng: "_random_mod.Random",
) -> List[Tuple[Path, str]]:
    """Write the plan's watch files and return the (path, content-hash) ledger.

    Creates `files_dir` if absent, then for each (name, size_bytes) in
    plan.watch_files writes a file of EXACTLY that many random bytes (streamed in
    chunks so RAM stays flat) and computes its content hash. Returns a list of
    (absolute_path, hash_hex) tuples — the ground-truth ledger the end-of-run
    restore oracle compares restored content against.

    Determinism: content bytes are drawn from `rng`, so a fixed scenario seed
    reproduces byte-for-byte content run-to-run. Sizes come from the plan
    (already seeded upstream). The returned hash is the ACTUAL on-disk hash, so
    correctness never depends on determinism.
    """
    files_dir = Path(files_dir)
    files_dir.mkdir(parents=True, exist_ok=True)

    ledger: List[Tuple[Path, str]] = []
    for name, size_bytes in plan.watch_files:
        path = files_dir / name
        # Subdirectory support: a planned name may contain a relative subpath.
        path.parent.mkdir(parents=True, exist_ok=True)
        digest = _write_random_file(path, int(size_bytes), rng)
        ledger.append((path, digest))
    return ledger


def _write_random_file(path: Path, size_bytes: int, rng: "_random_mod.Random") -> str:
    """Write exactly `size_bytes` of rng-derived bytes to `path`; return md5 hex.

    Uses md5 to match the ground-truth hashing in the existing local_*_test.sh
    harnesses (md5sum). Streams in <=1 MiB chunks so even a large archetype file
    never materializes fully in RAM.
    """
    if size_bytes < 0:
        raise ValueError(f"watch file size must be >= 0 (got {size_bytes} for {path})")

    hasher = hashlib.md5()
    remaining = size_bytes
    with open(path, "wb") as fh:
        while remaining > 0:
            chunk_len = min(_WRITE_CHUNK_BYTES, remaining)
            # rng.randbytes is deterministic given a seeded rng (Python 3.9+).
            chunk = rng.randbytes(chunk_len)
            fh.write(chunk)
            hasher.update(chunk)
            remaining -= chunk_len
    return hasher.hexdigest()
