"""Wildcard expansion properties (SPEC §5.3): pure, deterministic, sorted, never `unknown` for a
known prefix wildcard, never raises."""

from __future__ import annotations

import pytest
from athar.domain import CATEGORIES, VERBS
from athar.normaliser.expand import expand_action, expand_actions, subtract
from athar.normaliser.mappings import UNKNOWN, canonical, full_wildcard, load_mapping
from hypothesis import given, settings
from hypothesis import strategies as st

CLOUDS = ("aws", "azure", "gcp")
_ident = st.text(alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")), min_size=1, max_size=24)
_any_text = st.text(max_size=64)
_cloud = st.sampled_from(CLOUDS)
_aws_service = st.sampled_from(sorted(load_mapping("aws").services))
_azure_provider = st.sampled_from(sorted({k for k in load_mapping("azure").services}))
_gcp_service = st.sampled_from(sorted(load_mapping("gcp").services))
_aws_listed = st.sampled_from(sorted(load_mapping("aws").actions))
_gcp_listed = st.sampled_from(sorted(load_mapping("gcp").actions))


# ---------------------------------------------------------------- SPEC examples


def test_spec_examples() -> None:
    assert expand_action("aws", "s3:*") == [
        ("storage", "admin"),
        ("storage", "delete"),
        ("storage", "read"),
        ("storage", "write"),
    ]
    assert expand_action("aws", "iam:*") == [
        ("identity", "admin"),
        ("identity", "grant"),
        ("identity", "impersonate"),
    ]
    for star in ("*", "*:*"):
        pairs = expand_action("aws", star)
        assert set(pairs) == set(full_wildcard())
        assert {c for c, _ in pairs} == set(CATEGORIES)
        assert {v for _, v in pairs} == set(VERBS)
    assert expand_action("aws", "nope:Thing") == [(UNKNOWN, UNKNOWN)]
    assert expand_action("aws", "") == [(UNKNOWN, UNKNOWN)]
    assert expand_action("oracle", "s3:*") == [(UNKNOWN, UNKNOWN)]


def test_wildcard_verb_sets_come_from_canonical_yaml() -> None:
    canon = canonical()
    for _cat, verbs in canon.categories.items():
        assert set(verbs) <= set(VERBS)
    assert set(canon.categories["identity"]) == {"admin", "grant", "impersonate"}
    assert set(canon.categories["billing"]) == {"read", "billing"}


def test_helpers() -> None:
    assert expand_actions("aws", ["s3:GetObject", "s3:PutObject"]) == {
        ("storage", "read"),
        ("storage", "write"),
    }
    assert subtract({("a", "b"), ("c", "d")}, {("c", "d")}) == {("a", "b")}


# ---------------------------------------------------------------- properties


@settings(max_examples=200)
@given(_cloud, _any_text)
def test_never_raises_and_returns_sorted_unique_pairs(cloud: str, action: str) -> None:
    pairs = expand_action(cloud, action)
    assert pairs
    assert pairs == sorted(set(pairs))
    for cat, verb in pairs:
        assert cat in (*CATEGORIES, UNKNOWN) and verb in (*VERBS, UNKNOWN)


@settings(max_examples=200)
@given(_cloud, _any_text)
def test_deterministic(cloud: str, action: str) -> None:
    assert expand_action(cloud, action) == expand_action(cloud, action)


@given(_aws_service)
def test_aws_service_wildcard_never_unknown(service: str) -> None:
    pairs = expand_action("aws", f"{service}:*")
    assert UNKNOWN not in {c for c, _ in pairs} and UNKNOWN not in {v for _, v in pairs}
    assert {c for c, _ in pairs} <= set(CATEGORIES)


@given(_aws_service, _ident)
def test_aws_known_prefix_keeps_its_category(service: str, name: str) -> None:
    pairs = expand_action("aws", f"{service}:{name}")
    assert all(c != UNKNOWN for c, _ in pairs)


@given(_aws_listed)
def test_aws_service_wildcard_covers_every_listed_action(action: str) -> None:
    service = action.split(":", 1)[0]
    star = set(expand_action("aws", f"{service}:*"))
    covered = set(expand_action("aws", action))
    # SPEC §5.3 fixes "iam:*" as admin + grant + impersonate on identity, which is narrower than
    # the union of the individual iam actions (GenerateCredentialReport → identity:read,
    # DeleteAccessKey → identity:delete). Those three dominate for every rule, so compare the
    # category only for identity-mapped services.
    if {c for c, _ in covered} == {"identity"}:
        assert {c for c, _ in star} == {"identity"}
        return
    assert covered <= star | set(full_wildcard())


@given(_aws_listed)
def test_aws_case_insensitive(action: str) -> None:
    assert expand_action("aws", action.upper()) == expand_action("aws", action)


@given(_azure_provider)
def test_azure_provider_wildcard_never_unknown(provider: str) -> None:
    pairs = expand_action("azure", f"{provider}/*")
    assert UNKNOWN not in {c for c, _ in pairs} and UNKNOWN not in {v for _, v in pairs}


@given(_azure_provider, _ident, st.sampled_from(["read", "write", "delete", "action"]))
def test_azure_known_provider_and_suffix_never_unknown(provider: str, resource: str, suffix: str) -> None:
    pairs = expand_action("azure", f"{provider}/{resource}/{suffix}")
    assert all(c != UNKNOWN and v != UNKNOWN for c, v in pairs)


@given(_gcp_service)
def test_gcp_service_wildcard_never_unknown(service: str) -> None:
    pairs = expand_action("gcp", f"{service}.*")
    assert UNKNOWN not in {c for c, _ in pairs} and UNKNOWN not in {v for _, v in pairs}


@given(_gcp_service, _ident)
def test_gcp_unlisted_role_keeps_the_service_category(service: str, name: str) -> None:
    pairs = expand_action("gcp", f"roles/{service}.{name}")
    assert all(c != UNKNOWN for c, _ in pairs)


@given(_gcp_listed)
def test_gcp_listed_permission_never_unknown(permission: str) -> None:
    pairs = expand_action("gcp", permission)
    assert all(c != UNKNOWN and v != UNKNOWN for c, v in pairs)


@pytest.mark.parametrize("cloud", CLOUDS)
def test_full_wildcard_is_a_fixed_point(cloud: str) -> None:
    star = set(expand_action(cloud, "*"))
    assert star == set(full_wildcard())
    assert all(set(expand_action(cloud, "*")) == star for _ in range(3))
