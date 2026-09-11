"""Upload validation happy paths (SPEC §15.2). Rejections live in tests/robustness."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from athar.normaliser.schemas import (
    MAX_JSON_DEPTH,
    ValidatedFile,
    canonical_filename,
    json_depth,
    known_files,
    validate_upload,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "native" / "month-01"
LIMIT = 10 * 1024 * 1024


def _fixture_files() -> list[tuple[str, str, Path]]:
    out: list[tuple[str, str, Path]] = []
    for provider_dir in sorted(FIXTURES.iterdir()):
        for path in sorted(provider_dir.rglob("*")):
            if path.is_file():
                out.append((provider_dir.name, path.relative_to(provider_dir).as_posix(), path))
    return out


@pytest.mark.parametrize(
    ("provider", "name", "path"), _fixture_files(), ids=lambda x: str(x) if isinstance(x, str) else ""
)
def test_every_fixture_file_validates(provider: str, name: str, path: Path) -> None:
    vf = validate_upload(provider, name, path.read_bytes(), LIMIT)
    assert isinstance(vf, ValidatedFile)
    assert vf.provider == provider and vf.filename == name
    assert vf.size == path.stat().st_size and len(vf.sha256) == 64
    assert vf.kind == ("csv" if name.endswith(".csv") else "json")
    assert vf.warnings == []


def test_canonical_filename_strips_directories_but_keeps_gcp_project() -> None:
    assert canonical_filename("aws", "exports/aws/authorization-details.json") == "authorization-details.json"
    assert (
        canonical_filename("gcp", "gcp/nda-analytics-prod/iam-policy.json")
        == "nda-analytics-prod/iam-policy.json"
    )
    assert canonical_filename("gcp", "x\\nda-x\\roles.json") == "nda-x/roles.json"
    assert canonical_filename("gcp", "iam-policy.json") == "iam-policy.json"
    assert canonical_filename("hr", "../../employees.csv") == "employees.csv"
    assert canonical_filename("hr", "") == ""


def test_json_depth_is_iterative_and_exact() -> None:
    assert json_depth(1) == 1
    assert json_depth({}) == 1
    assert json_depth({"a": [1]}) == 3
    deep: object = 0
    for _ in range(5000):
        deep = [deep]
    assert json_depth(deep) == 5001  # no RecursionError
    assert MAX_JSON_DEPTH == 32


def test_graph_paged_value_wrapper_is_unwrapped() -> None:
    body = json.dumps(
        {"value": [{"id": "aaaaaaaa-0001-4000-8000-000000000001", "userPrincipalName": "a@nda.example"}]}
    ).encode()
    vf = validate_upload("azure", "entra-users.json", body, LIMIT)
    assert isinstance(vf.content, list) and vf.content[0]["id"].startswith("aaaaaaaa")


def test_extra_fields_are_allowed_and_retained() -> None:
    body = json.dumps(
        {
            "UserDetailList": [
                {"UserName": "u", "Arn": "arn:aws:iam::123456789012:user/u", "FutureField": {"x": 1}}
            ],
            "Filler": True,
        }
    ).encode()
    vf = validate_upload("aws", "authorization-details.json", body, LIMIT)
    assert vf.content["UserDetailList"][0]["FutureField"] == {"x": 1}
    assert vf.content["Filler"] is True


def test_duplicate_principals_are_tolerated_and_reported() -> None:
    body = json.dumps(
        [{"id": "x", "userPrincipalName": "a@nda.example"}, {"id": "x", "userPrincipalName": "b@nda.example"}]
    ).encode()
    vf = validate_upload("azure", "entra-users.json", body, LIMIT)
    assert len(vf.content) == 2
    assert vf.warnings == ["entra-users.json: duplicate id x (last wins)"]


def test_csv_content_shape_by_provider() -> None:
    report = b"user,arn,mfa_active\nu,arn:aws:iam::123456789012:user/u,true\n"
    vf = validate_upload("aws", "credential-report.csv", report, LIMIT)
    assert vf.content == [{"user": "u", "arn": "arn:aws:iam::123456789012:user/u", "mfa_active": "true"}]
    employees = b"# SYNTHETIC\nemployee_id,email,display_name,department,employment_type,status\ne1,a@nda.example,A,Finance,staff,active\n"
    vf = validate_upload("hr", "employees.csv", employees, LIMIT)
    assert isinstance(vf.content, str) and vf.content.startswith("# SYNTHETIC")
    assert any("optional column(s) absent" in w for w in vf.warnings)


def test_known_files_per_provider() -> None:
    assert "authorization-details.json" in known_files("aws")
    assert "role-assignments.json" in known_files("azure")
    assert "iam-policy.json" in known_files("gcp")
    assert known_files("hr") == ("employees.csv", "projects.csv", "exceptions.csv")
    assert known_files("oracle") == ()
