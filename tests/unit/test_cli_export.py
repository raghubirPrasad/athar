"""`athar export` writes the findings.json sidecar beside the CSV (SPEC §16).

The footer of every PDF page, the README and docs/DEMO.md all tell the reader to verify with
`athar verify --csv findings.csv --json findings.json`. That instruction is only true if the
sidecar exists next to the CSV the reader was handed, so the CSV export writes it.

No database: `session_scope` and `DbRepo` are stubbed, because what is under test is the CLI's
file handling, not the queries (those have their own tests in tests/integration/).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from athar import cli
from typer.testing import CliRunner

CSV = b"finding_key,rule_id\nabc,R1\n"
JSON = b'{"findings": [], "merkle_root": "0x00"}\n'
PDF = b"%PDF-1.4 stub\n"


class _Repo:
    """Stands in for DbRepo: returns fixed bytes per format, and counts the calls."""

    calls: list[str] = []

    def __init__(self, session: Any, settings: Any) -> None:
        pass

    def export_csv(self, filters: Any) -> bytes:
        _Repo.calls.append("csv")
        return CSV

    def export_json(self, filters: Any) -> bytes:
        _Repo.calls.append("json")
        return JSON

    def export_pdf(self, filters: Any) -> bytes:
        _Repo.calls.append("pdf")
        return PDF


@contextmanager
def _no_session() -> Iterator[None]:
    yield None


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> CliRunner:
    import athar.db.session as session_mod
    import athar.services.repo as repo_mod

    _Repo.calls = []
    monkeypatch.setattr(repo_mod, "DbRepo", _Repo)
    monkeypatch.setattr(session_mod, "session_scope", _no_session)
    return CliRunner()


def _run(runner: CliRunner, *args: str) -> Any:
    result = runner.invoke(cli.app, ["export", *args])
    assert result.exit_code == 0, result.output
    return result


def test_csv_export_writes_the_sidecar_beside_it(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "findings.csv"
    result = _run(runner, "--format", "csv", "--out", str(out))
    sidecar = tmp_path / "findings.json"
    assert out.read_bytes() == CSV
    assert sidecar.exists() and sidecar.read_bytes() == JSON
    assert str(sidecar) in result.output
    assert _Repo.calls == ["csv", "json"]


def test_sidecar_lands_next_to_a_renamed_csv(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "reports" / "month-12.csv"
    _run(runner, "--format", "csv", "--out", str(out))
    assert (tmp_path / "reports" / "month-12.json").read_bytes() == JSON


def test_json_export_writes_only_the_named_file(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "findings.json"
    _run(runner, "--format", "json", "--out", str(out))
    assert out.read_bytes() == JSON
    assert list(tmp_path.iterdir()) == [out]
    assert _Repo.calls == ["json"]


def test_pdf_export_writes_only_the_named_file(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "findings.pdf"
    _run(runner, "--format", "pdf", "--out", str(out))
    assert out.read_bytes() == PDF
    assert list(tmp_path.iterdir()) == [out]
    assert _Repo.calls == ["pdf"]


def test_csv_export_never_clobbers_a_json_out_path(runner: CliRunner, tmp_path: Path) -> None:
    """`--format csv --out …/findings.json` must not overwrite the CSV with the sidecar."""
    out = tmp_path / "findings.json"
    result = _run(runner, "--format", "csv", "--out", str(out))
    assert out.read_bytes() == CSV
    assert "not writing a sidecar" in result.output


def test_writing_twice_is_idempotent(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "findings.csv"
    _run(runner, "--format", "csv", "--out", str(out))
    first = (out.read_bytes(), (tmp_path / "findings.json").read_bytes())
    _run(runner, "--format", "csv", "--out", str(out))
    assert (out.read_bytes(), (tmp_path / "findings.json").read_bytes()) == first


def test_scan_option_is_refused_rather_than_ignored(runner: CliRunner, tmp_path: Path) -> None:
    """`--scan` used to be accepted and silently dropped; a mislabelled export is worse than none."""
    out = tmp_path / "findings.csv"
    result = runner.invoke(cli.app, ["export", "--format", "csv", "--scan", "3", "--out", str(out)])
    assert result.exit_code == 2
    assert "not supported" in result.output
    assert not out.exists() and _Repo.calls == []


def test_unknown_format_is_rejected_without_writing(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "findings.csv"
    result = runner.invoke(cli.app, ["export", "--format", "xml", "--out", str(out)])
    assert result.exit_code == 2
    assert not out.exists() and _Repo.calls == []


def test_a_directory_out_path_names_the_file_rather_than_raising(runner: CliRunner, tmp_path: Path) -> None:
    """`--out data/exports` used to raise IsADirectoryError and print a traceback.

    The README, docs/DEMO.md and `make export` all describe the exports as landing "in
    data/exports/", so passing the directory is the documented mental model rather than a mistake.
    """
    result = _run(runner, "--format", "csv", "--out", str(tmp_path))
    assert (tmp_path / "findings.csv").read_bytes() == CSV
    assert (tmp_path / "findings.json").read_bytes() == JSON, "the sidecar still lands beside it"
    assert "Traceback" not in result.output


def test_a_directory_out_path_works_for_every_format(runner: CliRunner, tmp_path: Path) -> None:
    for fmt, body in (("json", JSON), ("pdf", PDF)):
        target = tmp_path / fmt
        target.mkdir()
        _run(runner, "--format", fmt, "--out", str(target))
        assert (target / f"findings.{fmt}").read_bytes() == body


def test_an_unwritable_destination_is_reported_without_a_traceback(runner: CliRunner, tmp_path: Path) -> None:
    """Robustness (CLAUDE.md): unexpected input never kills the process with a stack trace."""
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        result = runner.invoke(cli.app, ["export", "--format", "pdf", "--out", str(locked / "f.pdf")])
    finally:
        locked.chmod(0o700)
    assert result.exit_code == 2
    assert "could not write" in result.output
    assert "Traceback" not in result.output
