"""Same inputs → identical strings; arbitrary inputs never raise (CLAUDE.md non-negotiables 3 and 4)."""

from __future__ import annotations

from athar.detection.facts import RULE_SLOTS, required_slots
from athar.narrative.examples import example_causal, example_facts, example_score
from athar.narrative.templates import render_all, render_evidence, render_explanation, render_headline
from hypothesis import given, settings
from hypothesis import strategies as st

RULE_IDS = sorted(RULE_SLOTS, key=lambda r: int(r[1:]))

_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-5, max_value=100_000),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=40),
    st.lists(st.text(max_size=12), max_size=4),
    st.dictionaries(st.text(max_size=8), st.text(max_size=8), max_size=3),
)


@st.composite
def facts_for(draw: st.DrawFn, rule_id: str) -> dict[str, object]:
    keys = list(required_slots(rule_id))
    present = draw(st.lists(st.sampled_from(keys), unique=True, max_size=len(keys)))
    return {k: draw(_scalar) for k in present}


@given(rule_id=st.sampled_from(RULE_IDS), data=st.data())
@settings(max_examples=150, deadline=None)
def test_random_facts_never_raise(rule_id: str, data: st.DataObject):
    facts = data.draw(facts_for(rule_id))
    assert render_headline(rule_id, facts).endswith(".")
    assert render_explanation(
        rule_id, facts, first_seen_month=data.draw(st.one_of(st.none(), st.integers(1, 12)))
    )
    assert "text" in render_evidence(rule_id, facts)


@given(rule_id=st.sampled_from(RULE_IDS))
@settings(max_examples=len(RULE_IDS), deadline=None)
def test_same_inputs_yield_identical_strings(rule_id: str):
    kwargs = dict(score=example_score(), causal=example_causal(), first_seen_month=5, leaf="0x" + "ab" * 32)
    first = render_all(rule_id, example_facts(rule_id), **kwargs).as_dict()
    second = render_all(rule_id, example_facts(rule_id), **kwargs).as_dict()
    assert first == second


def test_rendering_does_not_mutate_facts():
    facts = example_facts("R3")
    before = dict(facts)
    render_all("R3", facts, score=example_score(), causal=example_causal())
    assert facts == before
