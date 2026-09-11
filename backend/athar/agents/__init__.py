"""Agent layer (SPEC §11): the rule engine decides, agents explain.

Public surface:
  - `LlmClient`, `TemplateFallback`, `LlmResult`   (llm_client)
  - `CacheStore`, `InMemoryCacheStore`, `DbCacheStore` (cache)
  - `sanitize_untrusted`, `validate_output`          (guard)
  - `build_investigate_input`, `build_plan_input`, `build_summary_input` (inputs)
  - `investigate`, `plan_remediation`, `executive_summary` (agents)
"""

from athar.agents.cache import CacheStore, DbCacheStore, InMemoryCacheStore
from athar.agents.guard import sanitize_untrusted, validate_output
from athar.agents.inputs import build_investigate_input, build_plan_input, build_summary_input
from athar.agents.investigate import InvestigateResult, investigate
from athar.agents.llm_client import LlmClient, LlmResult, TemplateFallback
from athar.agents.remediate import PlanEngine, PlanResult, plan_remediation
from athar.agents.summarise import SummaryResult, executive_summary

__all__ = [
    "CacheStore",
    "DbCacheStore",
    "InMemoryCacheStore",
    "InvestigateResult",
    "LlmClient",
    "LlmResult",
    "PlanEngine",
    "PlanResult",
    "SummaryResult",
    "TemplateFallback",
    "build_investigate_input",
    "build_plan_input",
    "build_summary_input",
    "executive_summary",
    "investigate",
    "plan_remediation",
    "sanitize_untrusted",
    "validate_output",
]
