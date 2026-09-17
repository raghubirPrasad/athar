# ATHAR-MCP

A Model Context Protocol adapter over the ATHAR governance engine. Any MCP-speaking AI —
Claude Desktop, a SOC copilot, an IDE assistant — connects and asks *"who can do what"*,
*"why is identity X a 100"*, *"propose least-privilege for X"*. Every answer comes back
deterministic and **proof-bound** from the rule engine.

## The fence

The model never decides and never acts. Tools are **read-only** plus one **propose** tool whose
output still requires a human approver in the dashboard. There is deliberately no tool to approve,
apply, advance the month, re-score, or write settings — those stay human-in-the-UI. The engine
decides; MCP only surfaces the answer and its evidence.

| Tool | Kind | Backs onto |
|---|---|---|
| `list_identities` | read | `GET /identities` |
| `get_identity` | read | `GET /identities/{id}` |
| `list_findings` | read | `GET /findings` |
| `explain_finding` | read | `GET /findings/{key}` (3 altitudes + evidence + Merkle leaf) |
| `estate_summary` | read | `GET /estate/summary` |
| `department_halflife` | read | `GET /departments/halflife` |
| `evaluation` | read | `GET /eval` |
| `verify_scan` | read | `GET /ledger/scans/{id}/verify` |
| `propose_remediation` | propose | `POST /agent/plan/{key}` (plan only, no apply) |

It talks HTTP to the running API (`/api/v1`), so it inherits ATHAR's RBAC, evidence and ledger
logic unchanged and shares nothing with the database directly.

## Run

The API must be up (`make demo`). Then:

```bash
python -m venv .venv && ./.venv/bin/pip install -r requirements.txt
export ATHAR_MCP_PASSWORD='<the analyst password from .env DEMO_ANALYST_PASSWORD>'
./.venv/bin/python server.py        # stdio transport
```

Environment:

| Var | Default | Meaning |
|---|---|---|
| `ATHAR_API` | `http://localhost:8000/api/v1` | API base |
| `ATHAR_MCP_EMAIL` | `analyst@athar.local` | account the adapter logs in as |
| `ATHAR_MCP_PASSWORD` | — | that account's password (required) |

Use `judge@athar.local` (viewer) to expose read-only tools only; `propose_remediation` then
returns a permission error, which is the fence doing its job.

## Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "athar": {
      "command": "/absolute/path/to/mcp_server/.venv/bin/python",
      "args": ["/absolute/path/to/mcp_server/server.py"],
      "env": {
        "ATHAR_API": "http://localhost:8000/api/v1",
        "ATHAR_MCP_EMAIL": "analyst@athar.local",
        "ATHAR_MCP_PASSWORD": "<analyst password>"
      }
    }
  }
}
```

Then in Claude: *"Using athar, show the three highest-risk identities and explain the top
finding."*
