"""The estate is mutable forward only (SPEC §4.7) and generating it twice is a no-op (CLAUDE.md 2).

`advance` simulates month N+1 from the same seed and must leave months 1..N exactly as they were;
`apply_remediation` (SPEC §11.5) rewrites only the current month's native files and appends an
event. Nothing rewrites history.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from athar.generator.estate import (
    EstateError,
    advance_estate,
    apply_remediation,
    estate_dir_for,
    generate_estate,
    load_manifest,
    read_remediations,
)
from athar.generator.simulator import simulate
from athar.generator.state import Grant, RemediationSpec

from tests.generator.conftest import SEED, SMALL_IDENTITIES, SMALL_MONTHS
from tests.generator.test_determinism import tree_digest


@pytest.fixture
def estate(tmp_path: Path) -> Path:
    return generate_estate(SEED, SMALL_MONTHS, SMALL_IDENTITIES, tmp_path)


def month_digests(estate: Path, through: int) -> dict[str, str]:
    return {f"month-{m:02d}": tree_digest(estate / f"month-{m:02d}") for m in range(1, through + 1)}


def test_estate_dir_for_follows_the_spec_layout(tmp_path: Path) -> None:
    assert estate_dir_for(tmp_path, 42) == tmp_path / "estate" / "seed-42"


def test_generating_twice_writes_nothing(estate: Path) -> None:
    before = tree_digest(estate)
    mtimes = {p: p.stat().st_mtime_ns for p in sorted(estate.rglob("*")) if p.is_file()}
    again = generate_estate(SEED, SMALL_MONTHS, SMALL_IDENTITIES, estate.parent)
    assert again == estate
    assert tree_digest(estate) == before
    assert {p: p.stat().st_mtime_ns for p in sorted(estate.rglob("*")) if p.is_file()} == mtimes


def test_a_different_estate_in_the_same_directory_is_refused(estate: Path) -> None:
    with pytest.raises(EstateError) as excinfo:
        generate_estate(SEED, SMALL_MONTHS, SMALL_IDENTITIES + 40, estate.parent)
    message = str(excinfo.value)
    assert str(SMALL_IDENTITIES) in message and str(SMALL_IDENTITIES + 40) in message


def test_advance_writes_the_next_month_and_leaves_history_alone(estate: Path) -> None:
    before = month_digests(estate, SMALL_MONTHS)
    events_before = (estate / "events.jsonl").read_text(encoding="utf-8").splitlines()

    month = advance_estate(estate)

    assert month == SMALL_MONTHS + 1
    assert month_digests(estate, SMALL_MONTHS) == before
    new_dir = estate / f"month-{month:02d}"
    assert (new_dir / "aws" / "authorization-details.json").is_file()
    manifest = load_manifest(estate)
    assert manifest.months == month
    assert manifest.design_horizon == SMALL_MONTHS  # the estate keeps the window it was designed for
    events_after = (estate / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert events_after[: len(events_before)] == events_before
    assert any(json.loads(line)["month"] == month for line in events_after)


def test_advance_is_recorded_in_the_manifest_hashes(estate: Path) -> None:
    month = advance_estate(estate)
    manifest = load_manifest(estate)
    assert f"month-{month:02d}/hr/employees.csv" in manifest.files
    from athar.generator.manifest import verify_manifest

    assert verify_manifest(estate) == []


# ---------------------------------------------------------------------------
# Applied remediation (SPEC §11.5)
# ---------------------------------------------------------------------------


def _revocable_grant(month: int) -> tuple[Grant, str]:
    """(grant, IAM UserName): an AWS managed-policy grant active at `month` on an unprotected
    identity — what an approver would revoke through the workflow."""
    state = simulate(SEED, month, SMALL_IDENTITIES, horizon=SMALL_MONTHS)
    snapshot = state.snapshot(month)
    for grant in sorted(snapshot.grants, key=lambda g: g.grant_ref):
        ident = snapshot.identities[grant.identity_id]
        if grant.cloud == "aws" and grant.kind == "aws_managed" and not ident.protected:
            return grant, ident.username
    raise AssertionError("no revocable AWS managed-policy grant in the estate")


def _revocation(grant: Grant) -> RemediationSpec:
    return RemediationSpec(
        month=SMALL_MONTHS,
        identity_id=grant.identity_id,
        action="revoke_grant",
        cloud="aws",
        grant_refs=({"grant_ref": grant.grant_ref},),
        credential_ref=None,
        note="approved in the ATHAR workflow (test)",
    )


def _attached(details: dict, username: str) -> set[str]:
    user = next(u for u in details["UserDetailList"] if u["UserName"] == username)
    return {policy["PolicyName"] for policy in user["AttachedManagedPolicies"]}


def test_apply_remediation_removes_the_grant_from_the_current_months_native_file(estate: Path) -> None:
    target, username = _revocable_grant(SMALL_MONTHS)
    history = month_digests(estate, SMALL_MONTHS - 1)
    current = estate / f"month-{SMALL_MONTHS:02d}" / "aws" / "authorization-details.json"
    assert target.name in _attached(json.loads(current.read_text(encoding="utf-8")), username)

    apply_remediation(estate, _revocation(target))

    assert target.name not in _attached(json.loads(current.read_text(encoding="utf-8")), username)
    assert month_digests(estate, SMALL_MONTHS - 1) == history, "earlier months were rewritten"


def test_apply_remediation_appends_an_event_and_a_remediation_line(estate: Path) -> None:
    target, _username = _revocable_grant(SMALL_MONTHS)
    remediation = _revocation(target)
    apply_remediation(estate, remediation)

    events = [json.loads(line) for line in (estate / "events.jsonl").read_text().splitlines()]
    applied = [e for e in events if e["kind"] == "remediation"]
    assert len(applied) == 1
    assert applied[0]["identity_id"] == target.identity_id
    assert applied[0]["action"] == "revoke_grant"
    assert applied[0]["grants_removed"]
    assert read_remediations(estate) == [remediation]

    # Idempotent: applying the same remediation again changes nothing.
    digest = tree_digest(estate)
    apply_remediation(estate, remediation)
    assert tree_digest(estate) == digest


def test_a_remediation_for_an_earlier_month_is_refused(estate: Path) -> None:
    target, _username = _revocable_grant(SMALL_MONTHS)
    stale = RemediationSpec(
        month=SMALL_MONTHS - 1,
        identity_id=target.identity_id,
        action="revoke_grant",
        cloud="aws",
        grant_refs=({"grant_ref": target.grant_ref},),
        credential_ref=None,
        note="too late",
    )
    with pytest.raises(EstateError):
        apply_remediation(estate, stale)


def test_a_remediation_survives_an_advance(estate: Path) -> None:
    target, _username = _revocable_grant(SMALL_MONTHS)
    remediation = _revocation(target)
    apply_remediation(estate, remediation)
    history = month_digests(estate, SMALL_MONTHS)

    month = advance_estate(estate)

    assert month == SMALL_MONTHS + 1
    assert month_digests(estate, SMALL_MONTHS) == history
    assert read_remediations(estate) == [remediation]
