"""The citizen-data guardrail is the estate's only `deny` (SPEC §5.2 `effect`).

`effect` has two values and, until this existed, the estate only ever produced one of them: deny
handling was proven by unit tests over hand-built rows and never by data a judge could open. The
guardrail is a customer-managed AWS policy holding a single explicit Deny over the citizen data
lake, attached to two identities whose role baseline still carries the matching `s3:*` allow. It
is the drift story in miniature -- nobody removed the allow, a deny was bolted on instead.

These tests run over a generated estate long enough to reach `CITIZEN_DENY_FROM_MONTH`, because
the shared small estate stops before it and so could never have seen any of this.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from athar.generator import catalogue as cat
from athar.generator.estate import generate_estate
from athar.normaliser.pipeline import normalise_month
from athar.scoring.graph import cancel_by_deny

from tests.generator.conftest import SEED

MONTHS = cat.CITIZEN_DENY_FROM_MONTH + 1
#: The guardrail attaches to real `citizen-data-lake` holders, and the shared 60-identity estate
#: has none: Data Services is too small at that scale for anyone to hold the data lake at all.
#: `generate_estate` also scales against the full design horizon rather than the months asked for,
#: so the population has to be near production size before Data Services is staffed enough to
#: matter. 300 is where holders appear and it still generates in a couple of seconds. This is why
#: the fixture here is not the shared `small_estate`.
IDENTITIES = 300


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """An estate that runs one month past the guardrail's start. Read-only."""
    out = tmp_path_factory.mktemp("guardrail")
    return generate_estate(SEED, MONTHS, IDENTITIES, out)


def _details(estate: Path, month: int) -> dict:
    path = estate / f"month-{month:02d}" / "aws" / "authorization-details.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _guardrail_document(estate: Path, month: int) -> dict | None:
    for policy in _details(estate, month)["Policies"]:
        if policy["PolicyName"] == cat.AWS_CITIZEN_DENY_POLICY:
            return policy
    return None


def test_the_guardrail_document_states_the_deny(estate: Path) -> None:
    """AWS states the effect in the document, so an attachment without one parses as an allow."""
    policy = _guardrail_document(estate, MONTHS)
    assert policy is not None, "the guardrail is attached; its document must be exported with it"
    statements = policy["PolicyVersionList"][0]["Document"]["Statement"]
    assert [s["Effect"] for s in statements] == ["Deny"]
    assert statements[0]["Action"] == "s3:*"


def test_the_deny_names_the_bucket_and_its_objects(estate: Path) -> None:
    """S3 scopes bucket operations and object operations with two different ARNs.

    A deny that names only one of them leaves the other half of the allow standing.
    """
    statements = _guardrail_document(estate, MONTHS)["PolicyVersionList"][0]["Document"]["Statement"]
    resources = statements[0]["Resource"]
    assert len(resources) == 2
    bucket, objects = sorted(resources, key=len)
    assert objects == f"{bucket}/*"
    assert not bucket.endswith("/*"), "the bucket ARN must not itself carry the object wildcard"


def test_it_is_absent_before_the_month_it_is_applied(estate: Path) -> None:
    assert _guardrail_document(estate, cat.CITIZEN_DENY_FROM_MONTH - 1) is None


def test_it_reaches_the_canonical_model_as_effect_deny(estate: Path) -> None:
    """The point of the whole exercise: `deny` rows exist in the CPM, not only in unit tests."""
    grants = normalise_month(estate, MONTHS).grants
    denies = [g for g in grants if g.effect == "deny"]
    assert denies, "the estate produced no deny rows at all"
    assert {g.granted_via for g in denies} == {f"managed_policy:{cat.AWS_CITIZEN_DENY_POLICY}"}
    assert {g.cloud for g in denies} == {"aws"}
    assert {g.service_category for g in denies} == {"storage"}


def test_at_most_the_capped_number_of_identities_carry_it(estate: Path) -> None:
    grants = normalise_month(estate, MONTHS).grants
    holders = {g.identity_id for g in grants if g.effect == "deny"}
    assert 0 < len(holders) <= cat.CITIZEN_DENY_IDENTITIES


def test_the_deny_actually_cancels_allows_in_the_graph(estate: Path) -> None:
    """`cancel_by_deny` is what makes the row mean anything; run it over the real rows."""
    grants = normalise_month(estate, MONTHS).grants
    principals = {g.principal_ref for g in grants if g.effect == "deny"}
    assert principals
    for principal in sorted(principals):
        mine = [g for g in grants if g.principal_ref == principal]
        allows = [g for g in mine if g.active and g.effect == "allow"]
        kept = cancel_by_deny(mine)
        assert len(kept) < len(allows), f"{principal}: the deny cancelled nothing"
        assert all(g.effect == "allow" for g in kept), "a deny row must never be returned as access"


def test_generating_twice_puts_the_guardrail_on_the_same_identities(
    tmp_path_factory: pytest.TempPathFactory, estate: Path
) -> None:
    """Determinism: the guardrail draws nothing from the RNG, so the pair never moves."""
    again = generate_estate(SEED, MONTHS, IDENTITIES, tmp_path_factory.mktemp("guardrail2"))
    first = {g.identity_id for g in normalise_month(estate, MONTHS).grants if g.effect == "deny"}
    second = {g.identity_id for g in normalise_month(again, MONTHS).grants if g.effect == "deny"}
    assert first == second


def test_it_draws_nothing_from_the_seeded_stream(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Adding the guardrail must not rewrite the estate around it.

    A deny grant that fed the per-grant usage draw in `_simulate_activity` would shift every later
    number the RNG produces, so switching the guardrail on would silently regenerate months four
    onwards — different activity, different credentials, a different ground truth. The comparison
    here is against the same seed with the guardrail disabled: everything but the files that carry
    it, or that derive a clock-time from a grant reference number, must be byte-identical.
    """
    import hashlib

    def digests(root: Path) -> dict[str, str]:
        return {
            str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest()
            for f in sorted(root.rglob("*"))
            if f.is_file() and f.name != ".DS_Store"
        }

    on = digests(generate_estate(SEED, MONTHS, IDENTITIES, tmp_path_factory.mktemp("on")))
    saved = cat.CITIZEN_DENY_IDENTITIES
    cat.CITIZEN_DENY_IDENTITIES = 0
    try:
        off = digests(generate_estate(SEED, MONTHS, IDENTITIES, tmp_path_factory.mktemp("off")))
    finally:
        cat.CITIZEN_DENY_IDENTITIES = saved

    assert set(on) == set(off), "the guardrail must not add or remove estate files"
    moved = sorted(k for k in on if on[k] != off[k])
    # The AWS exports carrying the attachment, the event log and the manifest. Anything beyond a
    # handful means the RNG stream shifted and the whole estate downstream of month four moved.
    assert len(moved) <= 8, f"the guardrail disturbed {len(moved)} files: {moved}"
    assert all("/gcp/" not in k for k in moved), "GCP has nothing to do with an AWS deny"
    assert any("aws/authorization-details.json" in k for k in moved), "the attachment must show up"


def test_no_activity_is_recorded_through_a_deny(estate: Path) -> None:
    """Nothing is ever *used* through an explicit deny, so the usage draw is not made for one."""
    from athar.generator import catalogue as catalogue_mod
    from athar.generator.simulator import simulate

    state = simulate(SEED, MONTHS, IDENTITIES, horizon=MONTHS)
    denies = [g for g in state.final.grants if not g.is_allow]
    assert denies, "the estate under test has no deny grant, so this proves nothing"
    for grant in denies:
        for service in grant.services:
            key = (grant.identity_id, grant.cloud, service)
            record = state.final.activity.get(key)
            if record is None:
                continue
            # The identity may legitimately use s3 through the allow the deny sits over; what must
            # not happen is the deny itself manufacturing a usage record where there was none.
            allows = [
                g
                for g in state.final.grants
                if g.identity_id == grant.identity_id and g.is_allow and service in g.services
            ]
            assert allows, f"{key} has activity but no allow grant that could have produced it"
    assert catalogue_mod.CITIZEN_DENY_IDENTITIES > 0
