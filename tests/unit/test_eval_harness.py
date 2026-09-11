"""Evaluation arithmetic (SPEC §17) on a hand-built ground truth and hand-built drafts.

No generator, no database, no estate on disk: these tests pin the definitions the Evaluation page
reports — flagged at High+, the per-rule confusion, the decoy rule ("not flagged above Medium"),
and the two-register sentences — so a change to any of them is deliberate.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from athar.detection.base import EvidenceRef, FindingDraft
from athar.eval import harness

# R1 High · R3 Critical · R2 Medium · R7 Low (SPEC §7 severities, asserted below)
POSITIVES: dict[str, list[str]] = {
    "emp-0001": ["R3", "R1"],  # High+ positive
    "emp-0002": ["R1"],  # High+ positive
    "emp-0003": ["R2"],  # Medium-only positive: not a High+ positive
    "emp-0004": ["R1", "R2"],  # High+ positive, missed below
}
DECOYS: list[dict[str, Any]] = [
    {"identity_id": "emp-0010", "looks_like": ["R1"], "why_legitimate": "register entry break-glass"},
    {"identity_id": "emp-0011", "looks_like": ["R2"], "why_legitimate": "register entry dr-failover"},
]
GROUND_TRUTH: dict[str, Any] = {
    "seed": 7,
    "months": 6,
    "thresholds": {"dormant_days": 45, "stale_key_days": 200, "approved_regions": ["me-central-1"]},
    "positives": [
        {"identity_id": k, "rules": v, "since_month": 2, "reason": "seeded"} for k, v in POSITIVES.items()
    ],
    "decoys": DECOYS,
}


def draft(identity_id: str, rule_id: str, severity: str) -> FindingDraft:
    return FindingDraft(
        rule_id=rule_id,
        identity_id=identity_id,
        severity=severity,
        evidence=[EvidenceRef(kind="grant", ref=f"grant-{identity_id}")],
    )


#: tp emp-0001, emp-0002 · fp emp-0005 (nothing in the ground truth) · fn emp-0004
DRAFTS: list[FindingDraft] = [
    draft("emp-0001", "R3", "Critical"),
    draft("emp-0001", "R1", "High"),
    draft("emp-0002", "R1", "High"),
    draft("emp-0003", "R2", "Medium"),  # correct, but below the threshold on both sides
    draft("emp-0005", "R1", "High"),  # false positive
    draft("emp-0010", "R2", "Medium"),  # decoy, correctly kept below High
]


def result() -> harness.EvalResult:
    return harness.build_result(
        seed=7,
        months=6,
        ground_truth=GROUND_TRUTH,
        drafts=DRAFTS,
        names={"emp-0010": "Ahmed Al Mansoori", "emp-0011": "svc-dr-failover-a"},
        identities=11,
        generated_from="hand-built",
        held_out=True,
    )


def test_rule_severities_are_what_this_test_assumes() -> None:
    assert harness.expected_severity("R3") == "Critical"
    assert harness.expected_severity("R1") == "High"
    assert harness.expected_severity("R2") == "Medium"
    assert harness.expected_severity("R99") == "Low"  # unknown rule never counts as High+


def test_flagged_severity_keeps_the_worst_rule() -> None:
    assert harness.flagged_severity(DRAFTS)["emp-0001"] == "Critical"
    assert harness.flagged_severity(DRAFTS)["emp-0003"] == "Medium"
    assert "emp-0004" not in harness.flagged_severity(DRAFTS)


def test_positives_are_thresholded_by_rule_severity() -> None:
    at_threshold = harness.high_plus_positives(POSITIVES)
    assert at_threshold == {"emp-0001", "emp-0002", "emp-0004"}
    assert "emp-0003" not in at_threshold, "a Medium-only positive is not a High+ positive"


def test_precision_recall_f1_at_high_plus() -> None:
    r = result()
    assert (r.tp, r.fp, r.fn) == (2, 1, 1)
    assert r.precision == pytest.approx(2 / 3, abs=1e-4)
    assert r.recall == pytest.approx(2 / 3, abs=1e-4)
    assert r.f1 == pytest.approx(2 / 3, abs=1e-4)
    assert r.positives_total == 4
    assert r.positives_at_threshold == 3
    assert r.flagged_total == 3
    # recall against every positive, including the Medium-only one, is the stricter number
    assert r.recall_all_positives == pytest.approx(0.5, abs=1e-4)


def test_score_metrics_never_divides_by_zero() -> None:
    assert harness.score_metrics(set(), set()) == (0, 0, 0, 0.0, 0.0, 0.0)
    assert harness.score_metrics({"a"}, set()) == (0, 1, 0, 0.0, 0.0, 0.0)
    assert harness.score_metrics(set(), {"a"}) == (0, 0, 1, 0.0, 0.0, 0.0)
    assert harness.score_metrics({"a"}, {"a"}) == (1, 0, 0, 1.0, 1.0, 1.0)


def test_per_rule_confusion_counts_identities() -> None:
    rows = {r.rule_id: r for r in result().per_rule}
    assert (rows["R1"].tp, rows["R1"].fp, rows["R1"].fn) == (2, 1, 1)  # 0001,0002 hit; 0005 fp; 0004 fn
    assert (rows["R3"].tp, rows["R3"].fp, rows["R3"].fn) == (1, 0, 0)
    assert (rows["R2"].tp, rows["R2"].fp, rows["R2"].fn) == (1, 1, 1)  # decoy 0010 is an R2 fp
    assert rows["R1"].precision == pytest.approx(2 / 3, abs=1e-3)
    assert rows["R4"].tp == 0 and rows["R4"].precision is None  # a rule that never fired
    assert [r.rule_id for r in result().per_rule][:3] == ["R0", "R1", "R2"], "rows are in rule order"


def test_decoy_is_handled_when_nothing_above_medium_fired() -> None:
    decoys = {d.identity_id: d for d in result().decoys}
    assert decoys["emp-0010"].flagged_at == "Medium"
    assert decoys["emp-0010"].correctly_handled is True
    assert decoys["emp-0010"].display_name == "Ahmed Al Mansoori"
    assert decoys["emp-0010"].why_legitimate.startswith("register entry")
    assert decoys["emp-0011"].flagged_at is None
    assert decoys["emp-0011"].correctly_handled is True


def test_decoy_flagged_at_high_is_not_handled_and_counts_as_a_recognised_fp() -> None:
    drafts = [*DRAFTS, draft("emp-0011", "R1", "High")]
    r = harness.build_result(
        seed=7,
        months=6,
        ground_truth=GROUND_TRUTH,
        drafts=drafts,
        names={},
        identities=11,
        generated_from="hand-built",
        held_out=True,
    )
    decoys = {d.identity_id: d for d in r.decoys}
    assert decoys["emp-0011"].correctly_handled is False
    assert r.fp == 2, "the flagged decoy is a false positive"
    assert r.decoys_recognised == 1
    assert r.decoys_recognised <= r.fp, "build_director_sentence rejects more decoys than fp"


def test_two_register_sentences_report_the_same_numbers() -> None:
    r = result()
    assert r.director_sentence == (
        "Of 3 accounts flagged, 2 are verified genuine risks; 1 is still under analyst review."
    )
    assert r.engineer_sentence == "precision 0.67 / recall 0.67 at High+ on held-out seed 7"
    assert r.held_out is True
    assert r.threshold == "High"
    assert "flagged" in r.definition and "decoy" in r.definition


def test_the_tuning_seed_is_not_labelled_held_out() -> None:
    """SPEC §8.3: only `ATHAR_EVAL_SEED` is held out; `results-42.json` used to claim it was too."""
    r = harness.build_result(
        seed=42,
        months=6,
        ground_truth=GROUND_TRUTH,
        drafts=DRAFTS,
        names={},
        identities=11,
        generated_from="hand-built",
        held_out=False,
    )
    assert r.held_out is False
    assert r.engineer_sentence.endswith("on tuning seed 42")
    assert "held-out" not in r.engineer_sentence


def test_evaluate_takes_the_held_out_fact_from_the_configured_eval_seed(monkeypatch, tmp_path) -> None:
    """`evaluate` is the caller that knows which seed is which, so it resolves `held_out` itself.

    Everything expensive is stubbed: this test is about one decision — that the flag comes from
    `ATHAR_EVAL_SEED` and not from an assumption inside the sentence builder.
    """
    from types import SimpleNamespace

    from athar.config import get_settings

    eval_seed = get_settings().athar_eval_seed
    seen: list[bool] = []

    monkeypatch.setattr(harness, "ensure_estate", lambda *a, **k: tmp_path)
    monkeypatch.setattr(harness, "load_ground_truth", lambda p: {"positives": [], "decoys": []})
    monkeypatch.setattr(harness, "_months_on_disk", lambda p: [1])
    monkeypatch.setattr(harness, "normalise_all", lambda p, m, w: SimpleNamespace(identities={}))
    monkeypatch.setattr(harness, "run_all", lambda estate, rules: [])
    monkeypatch.setattr(harness, "build_graph", lambda estate: object())
    monkeypatch.setattr(harness, "score_all", lambda *a, **k: {})

    real_build = harness.build_result

    def spy(**kwargs: object) -> harness.EvalResult:
        seen.append(bool(kwargs["held_out"]))
        return real_build(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(harness, "build_result", spy)

    assert harness.evaluate(eval_seed, months=1, data_dir=tmp_path, write=False).held_out is True
    assert harness.evaluate(eval_seed + 1, months=1, data_dir=tmp_path, write=False).held_out is False
    # An explicit argument still wins over the default, for a third seed that is neither.
    assert harness.evaluate(99, months=1, data_dir=tmp_path, write=False, held_out=True).held_out is True
    assert seen == [True, False, True]


def test_thresholds_come_from_the_ground_truth_document() -> None:
    t = harness.thresholds_from(GROUND_TRUTH)
    assert (t.dormant_days, t.stale_key_days) == (45, 200)
    assert t.approved_regions == ("me-central-1",)
    fallback = harness.thresholds_from({})
    assert fallback.dormant_days == 90 and fallback.stale_key_days == 180


def test_result_round_trips_through_the_results_file(tmp_path) -> None:
    r = result()
    path = harness.save_result(r, tmp_path)
    assert path == harness.results_path(7, tmp_path)
    assert path.name == "results-7.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["precision"] == r.precision and document["decoys"][0]["identity_id"] == "emp-0010"
    loaded = harness.load_result(7, tmp_path)
    assert loaded is not None and loaded.model_dump() == r.model_dump()


def test_load_result_is_none_when_nothing_was_computed(tmp_path) -> None:
    assert harness.load_result(999, tmp_path) is None


def test_load_result_is_none_when_the_file_is_corrupt(tmp_path) -> None:
    path = harness.results_path(5, tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    assert harness.load_result(5, tmp_path) is None


def test_missing_ground_truth_is_a_clear_error(tmp_path) -> None:
    with pytest.raises(harness.EvalError, match=r"ground_truth\.json"):
        harness.load_ground_truth(tmp_path)


def test_empty_estate_scores_zero_rather_than_raising() -> None:
    r = harness.build_result(
        seed=1,
        months=1,
        ground_truth={"positives": [], "decoys": []},
        drafts=[],
        names={},
        identities=0,
        generated_from="empty",
        held_out=False,
    )
    assert (r.tp, r.fp, r.fn, r.precision, r.recall, r.f1) == (0, 0, 0, 0.0, 0.0, 0.0)
    assert r.director_sentence == "No accounts were flagged at High or above."


class TestProvenanceIsNotAHostPath:
    """`GET /eval` must not disclose the API host's filesystem layout (CLAUDE.md).

    `EvalResult.generated_from` is an absolute path because the harness writes it for whoever runs
    `athar eval` at a shell. `DbRepo` reduces it to the estate's own name before serving it.
    """

    def test_an_absolute_estate_path_becomes_the_estate_name(self) -> None:
        from athar.services.repo import _provenance

        assert _provenance("/srv/athar/data/estate/seed-7") == "seed-7"
        assert _provenance("/Users/someone/Downloads/gisec/data/estate/seed-42") == "seed-42"

    def test_a_windows_path_is_reduced_too(self) -> None:
        from athar.services.repo import _provenance

        assert _provenance(r"C:\\srv\\athar\\data\\estate\\seed-7") == "seed-7"

    def test_sentinels_and_bare_names_pass_through(self) -> None:
        from athar.services.repo import _provenance

        assert _provenance("mock") == "mock"
        assert _provenance("not computed") == "not computed"
        assert _provenance("seed-7") == "seed-7"

    def test_an_empty_or_slash_only_value_is_not_turned_into_nothing(self) -> None:
        from athar.services.repo import _provenance

        assert _provenance("") == ""
        assert _provenance("/") == "/"

    def test_no_directory_separator_survives_any_absolute_input(self) -> None:
        from athar.services.repo import _provenance

        for raw in ("/a/b/c/seed-1", "/data/estate/seed-99", r"D:\\x\\y\\seed-3"):
            assert "/" not in _provenance(raw) and "\\" not in _provenance(raw)


class TestAnAdvancedEstateIsJudgedAtItsFinalMonth:
    """The truth file always describes the estate's last month, so the harness must read that far.

    A user who advances the dashboard one month has a thirteen-month estate and a thirteen-month
    truth. Reading only the configured twelve compared old findings against a newer truth and
    reported misses that were not there.
    """

    class _StopError(Exception):
        """Raised by the fake normaliser once it has seen which months it was asked for."""

    def _months_requested(
        self, monkeypatch: pytest.MonkeyPatch, on_disk: list[int], configured: int
    ) -> list[int]:
        from pathlib import Path

        from athar.eval import harness

        seen: list[int] = []
        monkeypatch.setattr(harness, "ensure_estate", lambda *a, **k: Path("/nowhere"))
        monkeypatch.setattr(harness, "load_ground_truth", lambda p: {"positives": [], "decoys": []})
        monkeypatch.setattr(harness, "_months_on_disk", lambda p: on_disk)
        monkeypatch.setattr(harness, "get_settings", lambda: type("S", (), {"athar_eval_seed": 7})())

        def capture(path: Path, months: list[int], warnings: list[str]) -> None:
            seen.extend(months)
            raise self._StopError()

        monkeypatch.setattr(harness, "normalise_all", capture)
        with pytest.raises(self._StopError):
            harness.evaluate(42, months=configured, write=False)
        return seen

    def test_reads_past_the_configured_horizon(self, monkeypatch: pytest.MonkeyPatch) -> None:
        got = self._months_requested(monkeypatch, on_disk=list(range(1, 14)), configured=12)
        assert got == list(range(1, 14)), "month 13 is on disk and the truth describes it"

    def test_a_shorter_estate_is_read_whole_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert self._months_requested(monkeypatch, on_disk=[1, 2, 3], configured=12) == [1, 2, 3]
