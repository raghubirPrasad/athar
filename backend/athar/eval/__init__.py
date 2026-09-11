"""Evaluation harness (SPEC §17): precision / recall / F1 against the generator's ground truth.

Importable without a database, without the ledger and without the generator — the CLI
(`athar eval`), the API (`GET /eval`) and the exports all read through these names.
"""

from athar.eval.harness import (
    DEFINITION,
    THRESHOLD,
    DecoyOutcome,
    EvalError,
    EvalResult,
    RuleConfusion,
    evaluate,
    load_result,
    results_path,
    save_result,
)

__all__ = [
    "DEFINITION",
    "THRESHOLD",
    "DecoyOutcome",
    "EvalError",
    "EvalResult",
    "RuleConfusion",
    "evaluate",
    "load_result",
    "results_path",
    "save_result",
]
