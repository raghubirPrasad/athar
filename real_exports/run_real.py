"""Ingest a REAL `aws iam get-account-authorization-details` export through ATHAR's
own normaliser + rule engine and print what fires.

This is the SAME `normalise_provider(...)` the `/ingest/upload` API endpoint calls, run
without a database, ledger, LLM or HR feed (`hr=None`). It exists to answer the jury's one
open question: how the pipeline behaves on real cloud IAM data rather than the synthetic estate.

Run from the repo root:

    PYTHONPATH=backend python real_exports/run_real.py real_exports/aws-authorization-details.json
"""

from __future__ import annotations

import collections
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "backend"))

from athar.detection.registry import get_rule, run_all  # noqa: E402
from athar.domain import Thresholds  # noqa: E402
from athar.normaliser.pipeline import (  # noqa: E402
    normalise_provider,
    provider_rows_to_month,
    to_estate_view,
)


def main() -> None:
    src = Path(sys.argv[1] if len(sys.argv) > 1 else REPO / "real_exports/aws-authorization-details.json")
    data = src.read_bytes()

    # hr=None: no ownership feed, so every principal is unlinked (this is what makes R10 fire on
    # all of them). Real deployments supply an HR/ownership feed; the point here is the cloud side.
    rows = normalise_provider("aws", 1, {"authorization-details.json": data}, hr=None)
    print(f"== INGESTED REAL EXPORT: {src.name} ({len(data):,} bytes) ==")
    print(f"principals parsed : {len(rows.principals)}")
    print(f"canonical grants  : {len(rows.grants)}")
    print(f"unmapped actions  : {len(rows.unmapped)}  (real AWS has thousands of actions; mapping")
    print("                     coverage is the concrete real-data work item, surfaced as R0)")

    estate = to_estate_view(provider_rows_to_month(rows))
    drafts = run_all(estate, Thresholds())

    by_rule = collections.Counter(d.rule_id for d in drafts)
    by_ident = {d.identity_id for d in drafts}
    print(f"\n== FINDINGS: {len(drafts)} across {len(by_ident)} real principals ==")
    for rid in sorted(by_rule, key=lambda r: (int(r[1:]) if r[1:].isdigit() else 99)):
        spec = get_rule(rid)
        print(f"  {rid:4} {spec.severity:8} {by_rule[rid]:4}  {spec.name}")

    high = [d for d in drafts if get_rule(d.rule_id).severity in ("High", "Critical")]
    print(f"\n== {len(high)} HIGH/CRITICAL findings — sample principals ==")
    seen: set[str] = set()
    for d in high:
        name = d.identity_id.split("/")[-1].split(":")[-1]
        if name in seen:
            continue
        seen.add(name)
        print(f"  [{d.rule_id}] {name}")
        if len(seen) >= 12:
            break


if __name__ == "__main__":
    main()
