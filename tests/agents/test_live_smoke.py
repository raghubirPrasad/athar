"""Manual smoke test against a real provider. Skipped unless RUN_LIVE_LLM=1 and a Gemini key is set.

    RUN_LIVE_LLM=1 GEMINI_API_KEY=... uv run pytest ../tests/agents/test_live_smoke.py -q -s

Never part of CI (`make test` runs with LLM_PROVIDER=none and no key).
"""

from __future__ import annotations

import os
from datetime import date

import pytest
from athar.agents.inputs import build_investigate_input, build_plan_input
from athar.agents.investigate import investigate
from athar.agents.llm_client import LlmClient
from athar.agents.remediate import PlanEngine, plan_remediation
from athar.config import Settings
from athar.detection.base import FindingDraft
from athar.domain import EstateView

from tests.agents.conftest import rule_spec

_KEY = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""
pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE_LLM") != "1" or not _KEY,
    reason="live LLM smoke test: set RUN_LIVE_LLM=1 and GEMINI_API_KEY",
)


@pytest.mark.slow
def test_live_gemini_investigate_and_plan(r3_estate: EstateView, r3_draft: FindingDraft) -> None:
    settings = Settings(_env_file=None, LLM_PROVIDER="gemini", GEMINI_API_KEY=_KEY)
    client = LlmClient(settings)
    spec = rule_spec("R3", "Orphaned access")

    inv = investigate(build_investigate_input(r3_estate, r3_draft, None, [], {}, spec), client, None)
    assert inv.meta.generated_by == "model", "provider chain fell through to the template"
    assert inv.output.recommended_action in spec.allowed_actions
    assert "ignore previous instructions" not in inv.output.hypothesis.lower()

    plan = plan_remediation(
        build_plan_input(r3_estate, r3_draft, None, spec, as_of=date(2026, 8, 31)),
        client,
        None,
        engine=PlanEngine.proportional(0.5, 3),
    )
    assert plan.output.action in spec.allowed_actions
