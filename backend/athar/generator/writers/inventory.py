"""ATHAR-side resource inventories (`{aws,azure,gcp}/resources.json`). Pure.

These three files are the only ones in a month directory that are NOT a provider export. A real
deployment builds them from **AWS Config** (`ListDiscoveredResources` / an aggregator query),
**Azure Resource Graph** (`resources | project id, type, location, tags`) and **GCP Cloud Asset
Inventory** (`gcloud asset search-all-resources`), then classifies each row's sensitivity from
the data-classification register. ATHAR reads them for the region and sensitivity of a scope
(SPEC §5.1 `resources`), which is what R7/R8 cite; the generator emits them so the simulated
estate carries the same inputs a real one would.

Row shape (SPEC §4.6): AWS `{arn, service, region, sensitivity, project}`, Azure and GCP
`{ref, service, region, sensitivity, project}`.

# SPEC? §4.6 names the `project` field but not what it holds. It is written here as the cloud's
# own container — the AWS account id, the Azure subscription scope, the GCP projectId — because
# that is what the normaliser derives from a resource reference anyway (`parse_inventory` overrides
# an AWS row's project with the ARN's account), so the two agree instead of disagreeing per service.
"""

from __future__ import annotations

import re
from typing import Any

from athar.generator.state import EstateState, MonthSnapshot, Resource

_SUBSCRIPTION = re.compile(r"^/subscriptions/([^/]+)")


def _sorted(cloud: str, snapshot: MonthSnapshot) -> list[Resource]:
    return sorted((r for r in snapshot.resources if r.cloud == cloud), key=lambda r: r.ref)


def aws_resources(state: EstateState, snapshot: MonthSnapshot) -> list[dict[str, Any]]:
    account = state.constants.aws_account_id
    return [
        {
            "arn": res.ref,
            "service": res.service,
            "region": res.region,
            "sensitivity": res.sensitivity,
            "project": account,
        }
        for res in _sorted("aws", snapshot)
    ]


def azure_resources(state: EstateState, snapshot: MonthSnapshot) -> list[dict[str, Any]]:
    default_scope = state.constants.azure_subscription_scope
    out: list[dict[str, Any]] = []
    for res in _sorted("azure", snapshot):
        match = _SUBSCRIPTION.match(res.ref)
        out.append(
            {
                "ref": res.ref,
                "service": res.service,
                "region": res.region,
                "sensitivity": res.sensitivity,
                "project": f"/subscriptions/{match.group(1)}" if match else default_scope,
            }
        )
    return out


def gcp_resources(state: EstateState, snapshot: MonthSnapshot) -> list[dict[str, Any]]:
    return [
        {
            "ref": res.ref,
            "service": res.service,
            "region": res.region,
            "sensitivity": res.sensitivity,
            "project": res.project_ref,
        }
        for res in _sorted("gcp", snapshot)
    ]
