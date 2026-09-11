"""Evaluation harness: precision / recall / F1 against ground truth (SPEC §17).

`evaluate(seed, …)` generates (or loads) the estate for `seed`, normalises every month **in
memory** — no database, no ledger, no LLM — runs the rule engine and the scorer on the final
month, and compares what fired with `ground_truth.json`. It writes `eval/results-<seed>.json`;
`GET /eval` reads the held-out result through :func:`load_result`.

Tuning vs reporting (SPEC §17): constants are tuned on `ATHAR_SEED` and reported on
`ATHAR_EVAL_SEED`, which the constants never saw. This module is the one that knows which is
which, so it decides `EvalResult.held_out` and passes it to the sentence builder rather than
letting the sentence assume it — `results-42.json` used to describe the tuning seed as held out,
which is the claim SPEC §8.3 exists to prevent. Nothing here writes to the database, so the
module imports (and this file's metric arithmetic is unit-testable) without Postgres, without
Anvil and without the generator.

**What "flagged at ≥ High" compares.** Both sides of the comparison are held to the same
threshold: an identity is *flagged* when a rule fired on it at High or Critical, and a ground-truth
positive counts as a High+ positive when at least one of the rules the simulator recorded for it is
a High/Critical rule. `recall_all_positives` reports recall against *every* positive (including the
Low/Medium-only ones) so the stricter number is always visible in the result file.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from athar.config import get_settings
from athar.detection.base import FindingDraft
from athar.detection.registry import all_rules, get_rule, run_all
from athar.domain import SEVERITY_RANK, EstateView, Thresholds
from athar.export.summary import build_director_sentence, build_engineer_sentence
from athar.log import get_logger
from athar.scoring.constants import DEFAULT, ScoringConstants
from athar.scoring.graph import build_graph
from athar.scoring.score import score_all
from athar.scoring.types import ScoreResult

log = get_logger(__name__)

GROUND_TRUTH_FILE = "ground_truth.json"
RESULTS_DIR = "eval"
THRESHOLD = "High"
HIGH_PLUS: frozenset[str] = frozenset({"High", "Critical"})
#: A decoy is correctly handled when nothing above Medium fired on it (SPEC §4.3, §17).
DECOY_MAX_RANK = SEVERITY_RANK["Medium"]

DEFINITION = (
    "flagged = a rule fired at High or Critical; positive = a ground-truth identity whose recorded "
    "rules include a High or Critical rule; decoy handled = nothing above Medium fired"
)

#: What the headline numbers do and do not evidence. Rendered wherever they are (SPEC §17).
WHAT_IT_MEASURES = (
    "This measures whether the rule engine recovers, from the written provider exports, what the "
    "simulator recorded doing. Ground truth is derived from the simulator's own bookkeeping in the "
    "same canonical vocabulary the rules use, so the two sides agree by construction on definitions "
    "and disagree only where the pipeline loses or distorts something — a writer, a mapping, the "
    "linker or a rule. It is a pipeline-recovery check, not evidence of accuracy on a real estate. "
    "The decoys are the part that tests judgement: eleven identities built to trip a naive detector, "
    "legitimate only through the governance register."
)


class EvalError(RuntimeError):
    """The estate for this seed is neither on disk nor buildable."""


class RuleConfusion(BaseModel):
    rule_id: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float | None = None
    recall: float | None = None


class DecoyOutcome(BaseModel):
    identity_id: str
    display_name: str = ""
    looks_like: list[str] = Field(default_factory=list)
    why_legitimate: str = ""
    flagged_at: str | None = None
    correctly_handled: bool = True


class EvalResult(BaseModel):
    """`eval/results-<seed>.json` (SPEC §17). Every number the Evaluation page shows."""

    seed: int
    months: int
    identities: int
    threshold: str = THRESHOLD
    definition: str = DEFINITION
    generated_at: str = ""
    generated_from: str = ""
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    decoys_recognised: int = 0
    positives_total: int = 0
    positives_at_threshold: int = 0
    flagged_total: int = 0
    recall_all_positives: float = 0.0
    #: Whether `seed` is `ATHAR_EVAL_SEED` — the seed the scoring constants never saw (SPEC §8.3).
    #: Recorded in the file so a reader of `eval/results-<seed>.json` does not have to know the
    #: environment it was produced in. Defaults to False: an unlabelled result is not held out.
    held_out: bool = False
    per_rule: list[RuleConfusion] = Field(default_factory=list)
    decoys: list[DecoyOutcome] = Field(default_factory=list)
    director_sentence: str = ""
    engineer_sentence: str = ""
    warnings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------


def estate_dir(seed: int, data_dir: Path) -> Path:
    return Path(data_dir) / "estate" / f"seed-{seed}"


def results_path(seed: int, data_dir: Path) -> Path:
    return Path(data_dir) / RESULTS_DIR / f"results-{seed}.json"


# ---------------------------------------------------------------------------
# estate loading (generator imported lazily: this module must import without it)
# ---------------------------------------------------------------------------


def _months_on_disk(path: Path) -> list[int]:
    from athar.services.ingest import months_on_disk

    return months_on_disk(path)


def ensure_estate(seed: int, months: int, identities: int, data_dir: Path) -> Path:
    """The estate directory for `seed`, generating it when it is not on disk yet (SPEC §4.7)."""
    path = estate_dir(seed, data_dir)
    if (path / GROUND_TRUTH_FILE).is_file() and _months_on_disk(path):
        return path
    try:
        from athar.generator.estate import generate_estate
    except ImportError as exc:  # another lane owns the generator; say so plainly
        raise EvalError(
            f"no estate at {path} and the generator (athar.generator.estate) is not available: {exc}"
        ) from exc
    out = generate_estate(seed=seed, months=months, identities=identities, out_dir=Path(data_dir) / "estate")
    return Path(out)


def load_ground_truth(path: Path) -> dict[str, Any]:
    file = path / GROUND_TRUTH_FILE
    if not file.is_file():
        raise EvalError(f"no {GROUND_TRUTH_FILE} in {path}")
    data = json.loads(file.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise EvalError(f"{file} is not a ground-truth document")
    return data


def thresholds_from(ground_truth: dict[str, Any]) -> Thresholds:
    """The thresholds the ground truth was written with, so both sides read the same rules."""
    raw = ground_truth.get("thresholds")
    if not isinstance(raw, dict):
        return Thresholds()
    regions = raw.get("approved_regions")
    return Thresholds(
        dormant_days=int(raw.get("dormant_days", Thresholds().dormant_days)),
        stale_key_days=int(raw.get("stale_key_days", Thresholds().stale_key_days)),
        approved_regions=tuple(str(r) for r in regions)
        if isinstance(regions, list)
        else Thresholds().approved_regions,
    )


def normalise_all(path: Path, months: Sequence[int], warnings: list[str]) -> EstateView:
    """Normalise every month in memory (no DB) and return the final month's view."""
    from athar.normaliser.pipeline import normalise_month, to_estate_view

    view: EstateView | None = None
    for month in months:
        normalised = normalise_month(path, month)
        warnings.extend(f"month {month}: {w}" for w in normalised.warnings[:5])
        view = to_estate_view(normalised)
    if view is None:
        raise EvalError(f"no months to normalise under {path}")
    return view


# ---------------------------------------------------------------------------
# metrics (pure — unit-tested without a generator or a database)
# ---------------------------------------------------------------------------


def expected_severity(rule_id: str) -> str:
    try:
        return get_rule(rule_id).severity
    except KeyError:
        return "Low"


def flagged_severity(drafts: Sequence[FindingDraft]) -> dict[str, str]:
    """identity → the worst severity that fired on it."""
    out: dict[str, str] = {}
    for draft in drafts:
        current = out.get(draft.identity_id)
        if current is None or SEVERITY_RANK.get(draft.severity, 0) > SEVERITY_RANK.get(current, 0):
            out[draft.identity_id] = draft.severity
    return out


def positives_from(ground_truth: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for entry in ground_truth.get("positives", []):
        if not isinstance(entry, dict):
            continue
        identity_id = str(entry.get("identity_id", ""))
        if identity_id:
            out[identity_id] = [str(r) for r in entry.get("rules", [])]
    return out


def high_plus_positives(positives: dict[str, list[str]]) -> set[str]:
    return {
        identity_id
        for identity_id, rules in positives.items()
        if any(expected_severity(rule) in HIGH_PLUS for rule in rules)
    }


def per_rule_confusion(
    positives: dict[str, list[str]], drafts: Sequence[FindingDraft]
) -> list[RuleConfusion]:
    """One confusion row per registered rule, over identities (not per finding instance)."""
    fired: dict[str, set[str]] = defaultdict(set)
    for draft in drafts:
        fired[draft.rule_id].add(draft.identity_id)
    expected: dict[str, set[str]] = defaultdict(set)
    for identity_id, rules in positives.items():
        for rule in rules:
            expected[rule].add(identity_id)
    rule_ids = sorted({r.id for r in all_rules()} | set(fired) | set(expected), key=_rule_order)
    rows: list[RuleConfusion] = []
    for rule_id in rule_ids:
        got, want = fired.get(rule_id, set()), expected.get(rule_id, set())
        tp, fp, fn = len(got & want), len(got - want), len(want - got)
        rows.append(
            RuleConfusion(
                rule_id=rule_id,
                tp=tp,
                fp=fp,
                fn=fn,
                precision=round(tp / (tp + fp), 3) if tp + fp else None,
                recall=round(tp / (tp + fn), 3) if tp + fn else None,
            )
        )
    return rows


def _rule_order(rule_id: str) -> tuple[int, str]:
    body = rule_id[1:]
    return (int(body) if body.isdigit() else 99, rule_id)


def decoy_outcomes(
    ground_truth: dict[str, Any], flagged: dict[str, str], names: dict[str, str]
) -> list[DecoyOutcome]:
    out: list[DecoyOutcome] = []
    for entry in sorted(
        (e for e in ground_truth.get("decoys", []) if isinstance(e, dict)),
        key=lambda e: str(e.get("identity_id", "")),
    ):
        identity_id = str(entry.get("identity_id", ""))
        at = flagged.get(identity_id)
        out.append(
            DecoyOutcome(
                identity_id=identity_id,
                display_name=names.get(identity_id, identity_id),
                looks_like=[str(r) for r in entry.get("looks_like", [])],
                why_legitimate=str(entry.get("why_legitimate", "")),
                flagged_at=at,
                correctly_handled=at is None or SEVERITY_RANK.get(at, 0) <= DECOY_MAX_RANK,
            )
        )
    return out


def score_metrics(predicted: set[str], actual: set[str]) -> tuple[int, int, int, float, float, float]:
    """(tp, fp, fn, precision, recall, f1). Empty predictions score 0, never divide by zero."""
    tp = len(predicted & actual)
    fp = len(predicted - actual)
    fn = len(actual - predicted)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return tp, fp, fn, round(precision, 4), round(recall, 4), round(f1, 4)


def build_result(
    *,
    seed: int,
    months: int,
    ground_truth: dict[str, Any],
    drafts: Sequence[FindingDraft],
    names: dict[str, str],
    identities: int,
    generated_from: str,
    held_out: bool,
    warnings: Sequence[str] = (),
) -> EvalResult:
    """Assemble the result document from ground truth and what the rule engine produced. Pure.

    `held_out` says whether `seed` is the reporting seed (`ATHAR_EVAL_SEED`) or the tuning seed
    (`ATHAR_SEED`). It is a parameter rather than a comparison made here so that the function
    stays pure, and it is required rather than defaulted so that a new caller has to decide:
    labelling the tuning seed "held-out" is exactly the claim SPEC §8.3 forbids.
    """
    positives = positives_from(ground_truth)
    at_threshold = high_plus_positives(positives)
    flagged = flagged_severity(drafts)
    flagged_high = {i for i, severity in flagged.items() if severity in HIGH_PLUS}
    tp, fp, fn, precision, recall, f1 = score_metrics(flagged_high, at_threshold)

    decoys = decoy_outcomes(ground_truth, flagged, names)
    decoy_ids = {d.identity_id for d in decoys}
    recognised = min(len(flagged_high & decoy_ids), fp)
    all_recall = len(flagged_high & set(positives)) / len(positives) if positives else 0.0

    return EvalResult(
        seed=seed,
        months=months,
        identities=identities,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        generated_from=generated_from,
        tp=tp,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        decoys_recognised=recognised,
        positives_total=len(positives),
        positives_at_threshold=len(at_threshold),
        flagged_total=len(flagged_high),
        recall_all_positives=round(all_recall, 4),
        per_rule=per_rule_confusion(positives, drafts),
        decoys=decoys,
        held_out=held_out,
        director_sentence=build_director_sentence(tp, fp, recognised),
        engineer_sentence=build_engineer_sentence(
            precision, recall, threshold=THRESHOLD, seed=seed, held_out=held_out
        ),
        warnings=list(warnings),
    )


# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------


def evaluate(
    seed: int,
    *,
    months: int = 12,
    identities: int = 500,
    data_dir: Path | str = "data",
    thresholds: Thresholds | None = None,
    constants: ScoringConstants | None = None,
    write: bool = True,
    held_out: bool | None = None,
) -> EvalResult:
    """Run the pipeline for `seed` in memory and score it against its ground truth (SPEC §17).

    `held_out` defaults to `seed == ATHAR_EVAL_SEED`, which is the only place that fact lives.
    Pass it explicitly to evaluate a seed that is neither the tuning nor the reporting one.
    """
    if held_out is None:
        held_out = seed == get_settings().athar_eval_seed
    root = Path(data_dir)
    path = ensure_estate(seed, months, identities, root)
    ground_truth = load_ground_truth(path)
    # Every month on disk, not the first `months` of them. `ground_truth.json` is rewritten each
    # time the estate changes and always describes its *final* month, so an estate that has been
    # advanced past ATHAR_MONTHS — one click of "advance" in the dashboard — must be judged at that
    # month. Capping at `months` compared month-12 findings against a month-13 truth and reported
    # four misses that did not exist. `months` governs generation only, when nothing is on disk yet.
    available = _months_on_disk(path)
    if not available:
        raise EvalError(f"no month directories under {path}")
    warnings: list[str] = []
    estate = normalise_all(path, available, warnings)
    rules = thresholds or thresholds_from(ground_truth)

    drafts = run_all(estate, rules)
    by_identity: dict[str, list[FindingDraft]] = defaultdict(list)
    for draft in drafts:
        by_identity[draft.identity_id].append(draft)
    scores: dict[str, ScoreResult] = score_all(estate, by_identity, build_graph(estate), constants or DEFAULT)

    result = build_result(
        seed=seed,
        months=max(available),
        ground_truth=ground_truth,
        drafts=drafts,
        names={i: row.display_name for i, row in estate.identities.items()},
        identities=len(estate.identities),
        generated_from=str(path),
        held_out=held_out,
        warnings=warnings,
    )
    log.info(
        "evaluation complete",
        extra={
            "seed": seed,
            "precision": result.precision,
            "recall": result.recall,
            "f1": result.f1,
            "flagged": result.flagged_total,
            "scored": len(scores),
        },
    )
    if write:
        save_result(result, root)
    return result


def save_result(result: EvalResult, data_dir: Path | str) -> Path:
    path = results_path(result.seed, Path(data_dir))
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    path.write_text(payload, encoding="utf-8")
    return path


def load_result(seed: int, data_dir: Path | str = "data") -> EvalResult | None:
    """The stored result for `seed`, or None when it has not been computed (or is unreadable)."""
    path = results_path(seed, Path(data_dir))
    if not path.is_file():
        return None
    try:
        return EvalResult.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("eval result unreadable", extra={"seed": seed, "error": type(exc).__name__})
        return None
