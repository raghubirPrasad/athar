"""ATHAR-MCP — a Model Context Protocol adapter over the ATHAR governance engine.

Any MCP-speaking AI (Claude Desktop, a SOC copilot, an IDE assistant) can ask ATHAR
"who can do what", "why is identity X a 100", "propose least-privilege for X" — and every
answer comes back deterministic and proof-bound from the rule engine. The model never
decides and never acts: the tools here are READ-ONLY plus one PROPOSE tool whose output
still requires human approval in the dashboard. Nothing here can approve, apply, advance,
re-score or write settings — those stay human-in-the-UI.

Run:  ATHAR_MCP_PASSWORD=... python mcp_server/server.py     (stdio transport)
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from client import AtharClient  # noqa: E402  (sibling module, run as a script)

mcp = FastMCP("athar")
_api = AtharClient()


# --------------------------------------------------------------------------- read
@mcp.tool()
def list_identities(
    sort: str = "-score",
    cloud: str | None = None,
    department: str | None = None,
    limit: int = 20,
) -> Any:
    """List identities ranked by risk. `sort` is a field name; prefix with '-' for descending
    (default '-score'). Filter by `cloud` (aws|azure|gcp) or `department`.

    Each row carries the identity's risk score (measured blast radius), department and the
    clouds it holds power in. Use this to find the estate's highest-risk identities."""
    return _api.get("/identities", {"sort": sort, "cloud": cloud, "department": department, "limit": limit})


@mcp.tool()
def get_identity(identity_id: str) -> Any:
    """Full drill-down for one identity: its grants across every cloud, its score line-items,
    the findings open against it, and its cross-cloud links. `identity_id` comes from
    list_identities."""
    return _api.get(f"/identities/{identity_id}")


@mcp.tool()
def list_findings(
    severity: str | None = None,
    rule: str | None = None,
    cloud: str | None = None,
    department: str | None = None,
    limit: int = 25,
) -> Any:
    """List findings. Filter by `severity` (Low|Medium|High|Critical), `rule` (R0..R10),
    `cloud` or `department`. Returns finding keys for explain_finding."""
    return _api.get(
        "/findings",
        {"severity": severity, "rule": rule, "cloud": cloud, "department": department, "limit": limit},
    )


@mcp.tool()
def explain_finding(finding_key: str) -> Any:
    """Why a finding fired, at three altitudes: a one-line headline, the explanation (rule,
    since when, measured blast radius, what changes if remediated) and the evidence (raw
    provider JSON → canonical rows → score line-items → escalation chain → Merkle leaf and
    inclusion proof). This is the proof-bound answer: the engine decided, here is the receipt."""
    return _api.get(f"/findings/{finding_key}")


@mcp.tool()
def estate_summary() -> Any:
    """Estate-wide rollup: identity and finding counts, severity breakdown, current month."""
    return _api.get("/estate/summary")


@mcp.tool()
def department_halflife() -> Any:
    """Permission Half-Life per department — the median grant→revoke interval, a process
    finding. A department reading 'Never' has a broken offboarding process, not just risky
    people."""
    return _api.get("/departments/halflife")


@mcp.tool()
def evaluation() -> Any:
    """Precision / recall / F1 at High+ on the held-out seed, per-rule confusion and the decoy
    table. Read the definition it returns: on the synthetic estate this is a pipeline-recovery
    check against the generator's own ground truth, not an accuracy claim on a real estate."""
    return _api.get("/eval")


@mcp.tool()
def verify_scan(scan_id: int) -> Any:
    """Recompute a scan's Merkle root from the database and compare it with the root committed
    on-chain. Returns whether the anchored record still matches — the audit check a regulator
    can run without trusting us."""
    return _api.get(f"/ledger/scans/{scan_id}/verify")


# ------------------------------------------------------------------------ propose
@mcp.tool()
def propose_remediation(finding_key: str) -> Any:
    """Draft a least-privilege remediation PLAN for a finding (a policy diff + the privilege
    reduction it achieves). This only proposes: the plan is validated against the rules and
    still requires a human approver to approve and apply it in the dashboard. This tool cannot
    approve, apply or change anything in the estate."""
    return _api.post(f"/agent/plan/{finding_key}")


if __name__ == "__main__":
    mcp.run()
