"""Unexpected input never kills the process (CLAUDE.md non-negotiable 3, SPEC §15.2).

One fixture per input class in `fixtures/`. Every one either validates cleanly, or raises
`UploadValidationError` with a stable machine-readable code — never another exception type,
never a stack trace reaching a client.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from athar.normaliser.expand import expand_action
from athar.normaliser.schemas import UploadValidationError, validate_upload

FIXTURES = Path(__file__).parent / "fixtures"
MAX_BYTES = 10 * 1024 * 1024


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def expect_rejection(provider: str, filename: str, data: bytes, *, max_bytes: int = MAX_BYTES) -> str:
    """Validate and assert the only thing raised is a coded UploadValidationError."""
    try:
        validate_upload(provider, filename, data, max_bytes)
    except UploadValidationError as exc:
        assert exc.code.startswith("upload."), exc.code
        assert exc.detail, "a rejection must say what was wrong"
        assert "Traceback" not in exc.detail
        assert "/Users/" not in exc.detail and "\\Users\\" not in exc.detail
        return exc.code
    raise AssertionError(f"{filename} was accepted but should have been rejected")


# --- rejected input classes ---------------------------------------------------


@pytest.mark.parametrize(
    ("provider", "filename", "fixture"),
    [
        ("aws", "authorization-details.json", "empty.json"),
        ("aws", "credential-report.csv", "empty.csv"),
        ("aws", "authorization-details.json", "malformed.json"),
        ("aws", "authorization-details.json", "wrong-shape.json"),
        ("aws", "authorization-details.json", "non-utf8.json"),
        ("aws", "authorization-details.json", "too-deep.json"),
        ("azure", "role-assignments.json", "missing-field-role-assignments.json"),
    ],
)
def test_bad_input_is_a_coded_rejection(provider: str, filename: str, fixture: str) -> None:
    expect_rejection(provider, filename, load(fixture))


def test_wrong_provider_is_named_as_such() -> None:
    code = expect_rejection("aws", "role-assignments.json", load("azure-role-assignments.json"))
    assert code in {"upload.wrong_provider", "upload.unknown_file"}


def test_unknown_provider_is_rejected() -> None:
    assert expect_rejection("oracle", "whatever.json", b"{}") == "upload.unknown_provider"


def test_oversize_upload_is_rejected_without_reading_it_all() -> None:
    body = b'{"UserDetailList": []}' + b" " * 4096
    code = expect_rejection("aws", "authorization-details.json", body, max_bytes=1024)
    assert code == "upload.too_large"


def test_a_20_mib_file_is_rejected() -> None:
    """Generated, never committed: a 20 MiB fixture in git would be absurd."""
    body = b"[" + b'{"a":1},' * 2_700_000 + b"{}]"
    assert len(body) > 20 * 1024 * 1024
    assert expect_rejection("aws", "authorization-details.json", body) == "upload.too_large"


# --- tolerated input classes --------------------------------------------------


def test_unknown_fields_are_tolerated() -> None:
    validated = validate_upload(
        "aws", "authorization-details.json", load("extra-fields-authorization-details.json"), MAX_BYTES
    )
    assert validated.provider == "aws"
    assert validated.content["UserDetailList"][0]["UserName"] == "a.person"


def test_duplicate_principals_do_not_crash() -> None:
    validated = validate_upload(
        "aws",
        "authorization-details.json",
        load("duplicate-principals-authorization-details.json"),
        MAX_BYTES,
    )
    assert len(validated.content["UserDetailList"]) == 2


def test_absent_and_nan_dates_are_tolerated() -> None:
    validated = validate_upload(
        "aws", "credential-report.csv", load("nan-dates-credential-report.csv"), MAX_BYTES
    )
    assert validated.kind == "csv"
    row = validated.content[0]
    assert row["user"] == "a.person"
    assert row["password_last_used"] in {"N/A", ""}


def test_formula_injection_in_hr_is_data_not_an_error() -> None:
    """The CSV *exporter* escapes leading = + - @ (SPEC §15.2); the importer must not choke."""
    validated = validate_upload("hr", "employees.csv", load("formula-injection-employees.csv"), MAX_BYTES)
    text = validated.content if isinstance(validated.content, str) else str(validated.content)
    assert "HYPERLINK" in text


@pytest.mark.parametrize(
    ("cloud", "action"),
    [
        ("gcp", "roles/nonexistent.customThing"),
        ("gcp", "organizations/1234/roles/CustomBillingReader"),
        ("aws", "quantumledger:Frobnicate"),
        ("azure", "Microsoft.Nonexistent/things/frobnicate"),
        ("aws", ""),
        ("aws", "no-colon-here"),
    ],
)
def test_unknown_actions_become_unknown_not_an_exception(cloud: str, action: str) -> None:
    """Mapping misses are finding R0 (SPEC §5.3), never a crash."""
    pairs = expand_action(cloud, action)
    assert pairs, "expansion always returns at least one pair"
    assert all(isinstance(p, tuple) and len(p) == 2 for p in pairs)
    assert any(verb == "unknown" or category == "unknown" for category, verb in pairs)


def test_unknown_gcp_roles_validate_and_survive_expansion() -> None:
    validated = validate_upload(
        "gcp", "nda-sandbox/iam-policy.json", load("unknown-role-iam-policy.json"), MAX_BYTES
    )
    roles = [b["role"] for b in validated.content["bindings"]]
    for role in roles:
        assert expand_action("gcp", role)
