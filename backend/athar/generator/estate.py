"""The estate on disk (SPEC §4.7). This module owns every side effect in the generator lane.

    data/estate/seed-42/
      month-01/ … month-12/    aws/ azure/ gcp/ hr/   (the native exports of SPEC §4.6)
      events.jsonl             one line per simulated event — the causal history
      remediations.jsonl       applied remediations, replayed on every re-simulation (SPEC §11.5)
      ground_truth.json        what the simulator knows it did (SPEC §4.4)
      manifest.json            seed, months, identities, generator version, sha256 per file

Three rules govern this directory:

* **Idempotent.** `generate_estate` recognises its own output through the manifest and returns
  without writing a byte; a manifest describing a different estate is an error, never a clobber.
* **Forward only.** `advance_estate` re-simulates the same seed for one more month, proves months
  1..N are byte-identical to what is on disk, and only then writes month N+1.
* **Deterministic.** The same (seed, months, identities) always produces the same bytes: the
  writers are pure and every timestamp comes from `athar.clock`.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from athar.generator.ground_truth import GENERATOR_VERSION, build_ground_truth
from athar.generator.manifest import (
    MANIFEST_NAME,
    Manifest,
    ManifestError,
    hash_tree,
    manifest_path,
    read_manifest,
    write_manifest,
)
from athar.generator.simulator import simulate
from athar.generator.state import EstateState, RemediationSpec
from athar.generator.writers import dump_lines, dumps, month_files
from athar.hashing import sha256_hex
from athar.log import get_logger

log = get_logger(__name__)

EVENTS_FILE = "events.jsonl"
REMEDIATIONS_FILE = "remediations.jsonl"
GROUND_TRUTH_FILE = "ground_truth.json"
ESTATE_SUBDIR = "estate"
HISTORY_SAMPLE = 5  # mismatched paths named in an error before it says "and N more"


class EstateError(RuntimeError):
    """The estate on disk cannot serve the request (wrong estate, or history has changed)."""


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def estate_dir_for(data_dir: Path | str, seed: int) -> Path:
    """`<data_dir>/estate/seed-<seed>` (SPEC §4.7)."""
    return Path(data_dir) / ESTATE_SUBDIR / f"seed-{seed}"


def month_dir_for(estate_dir: Path | str, month: int) -> Path:
    return Path(estate_dir) / f"month-{month:02d}"


def load_manifest(estate_dir: Path | str) -> Manifest:
    return read_manifest(Path(estate_dir))


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _write_text(path: Path, text: str) -> str:
    """Write `text` (utf-8, unchanged files left alone) and return its sha256."""
    data = text.encode("utf-8")
    digest = sha256_hex(data)
    if path.is_file() and sha256_hex(path.read_bytes()) == digest:
        return digest
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return digest


def _prune(root: Path, keep: Iterable[str]) -> None:
    """Delete files under `root` the generator did not write (a leftover from another run), then
    the directories that became empty. Nothing outside `root` is touched."""
    expected = set(keep)
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_file():
            if path.relative_to(root).as_posix() not in expected:
                path.unlink()
        elif path.is_dir() and not any(path.iterdir()):
            path.rmdir()


def write_month(state: EstateState, month: int, month_dir: Path) -> dict[str, str]:
    """Write one month's native files; returns path → sha256, relative to `month_dir`."""
    files = month_files(state, state.snapshot(month))
    month_dir = Path(month_dir)
    month_dir.mkdir(parents=True, exist_ok=True)
    hashes = {name: _write_text(month_dir / name, text) for name, text in sorted(files.items())}
    _prune(month_dir, hashes)
    return hashes


def _write_registers(estate_dir: Path, state: EstateState) -> None:
    _write_text(estate_dir / EVENTS_FILE, dump_lines(event.as_json() for event in state.events))
    _write_text(estate_dir / GROUND_TRUTH_FILE, dumps(build_ground_truth(state)))
    if state.remediations:
        _write_text(estate_dir / REMEDIATIONS_FILE, dump_lines(r.as_json() for r in state.remediations))


def _write_estate(
    state: EstateState, estate_dir: Path, months: Sequence[int], horizon: int, *, prune: bool = False
) -> Manifest:
    estate_dir.mkdir(parents=True, exist_ok=True)
    written: set[str] = set()
    for month in months:
        hashes = write_month(state, month, month_dir_for(estate_dir, month))
        written.update(f"month-{month:02d}/{name}" for name in hashes)
    _write_registers(estate_dir, state)
    if prune:
        # A partial tree from an interrupted run must not survive into the manifest.
        _prune(estate_dir, written | {EVENTS_FILE, GROUND_TRUTH_FILE, REMEDIATIONS_FILE, MANIFEST_NAME})
    manifest = Manifest(
        seed=state.seed,
        months=state.months,
        identities=state.identities_target,
        generator_version=GENERATOR_VERSION,
        horizon=horizon,
        files=hash_tree(estate_dir),
    )
    write_manifest(estate_dir, manifest)
    return manifest


# ---------------------------------------------------------------------------
# History (SPEC §4.7: nothing rewrites the past)
# ---------------------------------------------------------------------------


def _assert_history(estate_dir: Path, state: EstateState, through: int) -> None:
    """Every file of months 1..`through`, and every earlier line of `events.jsonl`, must already be
    on disk with exactly the bytes this simulation produces."""
    changed: list[str] = []
    for month in range(1, through + 1):
        month_dir = month_dir_for(estate_dir, month)
        generated = month_files(state, state.snapshot(month))
        for name, text in sorted(generated.items()):
            path = month_dir / name
            on_disk = path.read_bytes() if path.is_file() else b""
            if on_disk != text.encode("utf-8"):
                changed.append(f"month-{month:02d}/{name}")
    events = estate_dir / EVENTS_FILE
    if events.is_file():
        existing = events.read_text(encoding="utf-8").splitlines()
        replayed = dump_lines(
            event.as_json() for event in state.events if event.month <= through
        ).splitlines()
        if existing[: len(replayed)] != replayed:
            changed.append(EVENTS_FILE)
    if changed:
        head = ", ".join(changed[:HISTORY_SAMPLE])
        more = f" (and {len(changed) - HISTORY_SAMPLE} more)" if len(changed) > HISTORY_SAMPLE else ""
        raise EstateError(
            f"re-simulating seed {state.seed} would change history in {estate_dir}: {head}{more}. "
            "The estate is forward-only (SPEC §4.7); regenerate it from scratch instead."
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_estate(seed: int, months: int, identities: int, out_dir: Path | str) -> Path:
    """Write `<out_dir>/seed-<seed>/…` and return it. Idempotent: an existing tree whose manifest
    matches (seed, identities, generator version) and already covers `months` is left untouched;
    a tree describing a different estate raises `EstateError` rather than overwriting it."""
    estate_dir = Path(out_dir) / f"seed-{seed}"
    if manifest_path(estate_dir).is_file():
        existing = read_manifest(estate_dir)
        if existing.matches(seed, months, identities):
            log.info(
                "estate already generated",
                extra={"dir": str(estate_dir), "seed": seed, "months": existing.months},
            )
            return estate_dir
        raise EstateError(
            f"{estate_dir} already holds a different estate ({existing.describe()}); "
            f"requested seed={seed} months={months} identities={identities} "
            f"generator_version={GENERATOR_VERSION}. Remove the directory to regenerate it."
        )
    state = simulate(seed, months, identities, horizon=months)
    manifest = _write_estate(state, estate_dir, range(1, months + 1), horizon=months, prune=True)
    log.info(
        "estate generated",
        extra={
            "dir": str(estate_dir),
            "seed": seed,
            "months": months,
            "identities": len(state.final.identities),
            "files": len(manifest.files),
        },
    )
    return estate_dir


def read_remediations(estate_dir: Path | str) -> list[RemediationSpec]:
    """Applied remediations in the order they were applied (SPEC §11.5)."""
    path = Path(estate_dir) / REMEDIATIONS_FILE
    if not path.is_file():
        return []
    out: list[RemediationSpec] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            data: Any = json.loads(line)
            if not isinstance(data, dict):
                raise TypeError("expected a JSON object")
            out.append(RemediationSpec.from_json(data))
        except (ValueError, KeyError, TypeError) as exc:
            raise EstateError(f"{path}: line {number} is not a remediation: {exc}") from exc
    return out


def advance_estate(estate_dir: Path | str) -> int:
    """Simulate one more month from the same seed and write `month-<N+1>/`. Months 1..N are proven
    byte-identical first; nothing already on disk is rewritten except the registers, whose earlier
    lines are unchanged. Returns the new current month."""
    estate_dir = Path(estate_dir)
    manifest = read_manifest(estate_dir)
    months, horizon = manifest.months, manifest.design_horizon
    remediations = read_remediations(estate_dir)
    state = simulate(manifest.seed, months + 1, manifest.identities, remediations, horizon)
    _assert_history(estate_dir, state, months)
    _write_estate(state, estate_dir, [months + 1], horizon=horizon)
    log.info("estate advanced", extra={"dir": str(estate_dir), "month": months + 1})
    return months + 1


def apply_remediation(estate_dir: Path | str, remediation: RemediationSpec) -> None:
    """Record an applied remediation and regenerate the CURRENT month's native files (SPEC §11.5).

    The remediation is appended to `remediations.jsonl`, replayed by every later simulation, and
    shows up as a `remediation` event in `events.jsonl`. Earlier months are never rewritten."""
    apply_remediations(estate_dir, [remediation])


def apply_remediations(
    estate_dir: Path | str, remediations: Sequence[RemediationSpec]
) -> list[RemediationSpec]:
    """`apply_remediation` for a batch, in one re-simulation (SPEC §11.5).

    Auto-remediation (SPEC §11.5, `services.remediation.auto_remediate`) disables every qualifying
    departed identity in one scan, and re-simulating the estate once per identity would cost a full
    simulation each. Specs already in `remediations.jsonl` are skipped, so a second run adds nothing
    and the estate on disk does not change. Returns the specs this call actually recorded.
    """
    estate_dir = Path(estate_dir)
    manifest = read_manifest(estate_dir)
    for rem in remediations:
        if rem.month != manifest.months:
            raise EstateError(
                f"remediation is for month {rem.month} but the estate's current month is "
                f"{manifest.months}; only the current month may be regenerated (SPEC §4.7)."
            )
    applied = read_remediations(estate_dir)
    fresh: list[RemediationSpec] = []
    for rem in remediations:
        if rem in applied or rem in fresh:
            log.info("remediation already applied", extra={"identity": rem.identity_id})
            continue
        fresh.append(rem)
    if not fresh:
        return []
    state = simulate(
        manifest.seed, manifest.months, manifest.identities, [*applied, *fresh], manifest.design_horizon
    )
    _assert_history(estate_dir, state, manifest.months - 1)
    _write_estate(state, estate_dir, [manifest.months], horizon=manifest.design_horizon)
    log.info(
        "remediations applied",
        extra={
            "dir": str(estate_dir),
            "month": manifest.months,
            "count": len(fresh),
            "actions": sorted({r.action for r in fresh}),
            "identities": sorted({r.identity_id for r in fresh}),
        },
    )
    return fresh


__all__ = [
    "EVENTS_FILE",
    "GROUND_TRUTH_FILE",
    "REMEDIATIONS_FILE",
    "EstateError",
    "Manifest",
    "ManifestError",
    "advance_estate",
    "apply_remediation",
    "apply_remediations",
    "estate_dir_for",
    "generate_estate",
    "load_manifest",
    "month_dir_for",
    "read_remediations",
    "write_month",
]
