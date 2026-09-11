"""`athar eval` takes its seeds from the environment, so `make eval` follows `.env` (SPEC §17).

The Makefile used to pass `--seed $${ATHAR_EVAL_SEED:-7}`, a *shell* variable that nothing sets,
so it evaluated the default whatever `.env` said. Someone who changed `ATHAR_EVAL_SEED`, ran
`make eval` and reloaded the Evaluation page saw the same numbers and, reasonably, concluded the
page was broken. The seeds now come from `Settings`, which reads `.env`, through `--held-out`.

`evaluate` is stubbed: what is under test is which seed the command resolves, not the harness.
"""

from __future__ import annotations

from typing import Any

import pytest
from athar import cli
from athar.eval import harness
from typer.testing import CliRunner


class _Result:
    precision = recall = f1 = 1.0
    tp, fp, fn = 5, 0, 0
    held_out = True
    decoys_recognised = 11


@pytest.fixture
def evaluated(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    seen: list[int] = []

    def fake(seed: int, **kwargs: Any) -> _Result:
        seen.append(seed)
        return _Result()

    monkeypatch.setattr(harness, "evaluate", fake)
    monkeypatch.setenv("ATHAR_SEED", "42")
    monkeypatch.setenv("ATHAR_EVAL_SEED", "3")
    from athar.config import get_settings

    get_settings.cache_clear()
    yield seen
    get_settings.cache_clear()


def test_no_flags_evaluates_the_tuning_seed_from_the_environment(evaluated: list[int]) -> None:
    result = CliRunner().invoke(cli.app, ["eval"])
    assert result.exit_code == 0, result.output
    assert evaluated == [42]


def test_held_out_evaluates_the_eval_seed_from_the_environment(evaluated: list[int]) -> None:
    result = CliRunner().invoke(cli.app, ["eval", "--held-out"])
    assert result.exit_code == 0, result.output
    assert evaluated == [3], "this is the seed a `.env` edit must reach"


def test_an_explicit_seed_still_wins(evaluated: list[int]) -> None:
    result = CliRunner().invoke(cli.app, ["eval", "--seed", "99"])
    assert result.exit_code == 0, result.output
    assert evaluated == [99]


def test_held_out_with_an_explicit_seed_is_refused(evaluated: list[int]) -> None:
    """Two answers to "which seed" is a mistake, not a preference; say so rather than pick one."""
    result = CliRunner().invoke(cli.app, ["eval", "--held-out", "--seed", "99"])
    assert result.exit_code == 2
    assert "do not also pass --seed" in result.output
    assert evaluated == []
