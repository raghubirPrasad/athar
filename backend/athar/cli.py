"""ATHAR CLI (SPEC §2). Every pipeline stage is runnable on its own; `athar seed` is the judge path.

Orchestration only: each subcommand calls into a service and prints a short human line. Anything
that could fail because an optional component is missing (the generator, the ledger, an LLM) is
imported lazily so the rest of the CLI keeps working.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import typer

from athar import __version__
from athar.config import APP_NAME, Settings, get_settings

app = typer.Typer(help=f"{APP_NAME} — multi-cloud access governance", no_args_is_help=True)
agent_app = typer.Typer(help="Run the fenced agents over open findings (cache-aware)")
app.add_typer(agent_app, name="agent")


def _settings() -> Settings:
    from athar import log

    settings = get_settings()
    log.configure(settings.log_level)
    return settings


def _estate_dir(settings: Settings, seed: int | None = None) -> Path:
    from athar.services.ingest import estate_dir_for

    return estate_dir_for(settings, seed)


def _ledger_client(settings: Settings, *, resolve: bool = False, address: str | None = None) -> Any:
    """A read-only client (deploy check, verify). Only `LedgerWriter` ever signs (SPEC §12.4).

    With `resolve`, the contract address comes from `ledger_meta` when the environment does not
    name one — the normal case, since the contract is deployed on first use and recorded there.
    """
    from athar.ledger.client import LedgerClient

    address = address or settings.ledger_contract_address
    if resolve and not address:
        from athar.db import models as m
        from athar.db.session import session_scope

        with session_scope() as session:
            meta = session.get(m.LedgerMeta, 1)
            address = meta.contract_address if meta else ""
    return LedgerClient(settings.ledger_rpc_url, settings.ledger_private_key, address)


def _writer(settings: Settings) -> Any:
    """The single ledger writer, or None when the chain is off or unreachable (SPEC §12.4)."""
    if not settings.ledger_enabled:
        return None
    try:
        from athar.db.session import session_scope
        from athar.ledger.client import ensure_deployed
        from athar.ledger.writer import get_writer

        writer = get_writer(settings)
        client = _ledger_client(settings)
        with session_scope() as session:
            meta = ensure_deployed(client, session, settings)
        # The writer's own client is the only thing that signs; point it at the resolved address.
        setattr(writer.client, "contract_address", meta.contract_address)  # noqa: B010
        return writer
    except Exception as exc:  # the ledger never blocks the pipeline
        typer.secho(f"  ledger unavailable ({type(exc).__name__}); scans will be unanchored", fg="yellow")
        return None


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(f"{APP_NAME} {__version__}")


@app.command()
def generate(
    seed: Annotated[int | None, typer.Option(help="Estate seed; defaults to ATHAR_SEED")] = None,
    months: Annotated[int | None, typer.Option(help="Months to simulate; defaults to ATHAR_MONTHS")] = None,
    identities: Annotated[int | None, typer.Option(help="Identity count at the final month")] = None,
    advance: Annotated[bool, typer.Option("--advance", help="Simulate one more month instead")] = False,
) -> None:
    """Simulate the estate and write native provider exports (SPEC §4)."""
    settings = _settings()
    from athar.generator.estate import advance_estate, generate_estate

    seed = seed if seed is not None else settings.athar_seed
    out = Path(settings.data_dir) / "estate"
    if advance:
        month = advance_estate(_estate_dir(settings, seed))
        typer.echo(f"advanced to month {month}")
        return
    path = generate_estate(
        seed=seed,
        months=months if months is not None else settings.athar_months,
        identities=identities if identities is not None else settings.athar_identities,
        out_dir=out,
    )
    typer.echo(f"estate ready at {path}")


@app.command()
def ingest(
    month: Annotated[int | None, typer.Option(help="One month; omit for every month on disk")] = None,
    latest: Annotated[bool, typer.Option("--latest", help="Only the newest month directory")] = False,
    seed: Annotated[int | None, typer.Option(help="Estate seed; defaults to ATHAR_SEED")] = None,
) -> None:
    """Normalise native exports into the Canonical Permission Model (SPEC §5, §6)."""
    settings = _settings()
    from athar.db.session import session_scope
    from athar.services.ingest import ingest_all, months_on_disk

    estate = _estate_dir(settings, seed)
    months = [month] if month else ([max(months_on_disk(estate))] if latest else None)
    with session_scope() as session:
        for result in ingest_all(session, estate, months=months):
            s = result.stats
            typer.echo(
                f"month {result.month:>2}: {s.identities} identities, {s.principals} principals, "
                f"{s.grants} grants, {s.credentials} credentials, {result.unmapped} unmapped actions"
            )


def _current_month(session: Any) -> int:
    from athar.db import models as m

    clock = session.get(m.EstateClock, 1)
    return clock.current_month if clock is not None and clock.current_month else 1


@app.command()
def scan(
    month: Annotated[int | None, typer.Option(help="Snapshot month; defaults to the current one")] = None,
    all_months: Annotated[bool, typer.Option("--all", help="Scan every ingested month")] = False,
) -> None:
    """Diff, apply rules, score, narrate and anchor one month (SPEC §7, §8, §12)."""
    settings = _settings()
    from sqlalchemy import select

    from athar.db import models as m
    from athar.db.session import session_scope
    from athar.services.scan import run_scan

    writer = _writer(settings)
    with session_scope() as session:
        months = (
            sorted(session.scalars(select(m.Snapshot.snapshot_month)))
            if all_months
            else [month or _current_month(session)]
        )
        for target in months:
            outcome = run_scan(session, settings, target, writer=writer)
            typer.echo(
                f"scan {outcome.scan_id} month {target:>2}: {outcome.finding_count} findings, "
                f"root {outcome.merkle_root[:14]}… {outcome.detail}"
            )


@app.command()
def seed(
    seed_value: Annotated[int | None, typer.Option("--seed", help="Defaults to ATHAR_SEED")] = None,
    months: Annotated[int | None, typer.Option(help="Defaults to ATHAR_MONTHS")] = None,
    identities: Annotated[int | None, typer.Option(help="Defaults to ATHAR_IDENTITIES")] = None,
) -> None:
    """The judge path: migrate, seed users, generate, ingest every month, scan and anchor each."""
    settings = _settings()
    from athar.db.migrate import upgrade_head
    from athar.db.session import session_scope
    from athar.generator.estate import generate_estate
    from athar.security.users import seed_users
    from athar.services.ingest import ingest_all
    from athar.services.scan import run_scan

    upgrade_head()
    with session_scope() as session:
        typer.echo(f"users seeded: {seed_users(session, settings)} changed")

    value = seed_value if seed_value is not None else settings.athar_seed
    path = generate_estate(
        seed=value,
        months=months if months is not None else settings.athar_months,
        identities=identities if identities is not None else settings.athar_identities,
        out_dir=Path(settings.data_dir) / "estate",
    )
    typer.echo(f"estate: {path}")

    writer = _writer(settings)
    with session_scope() as session:
        results = ingest_all(session, path)
        typer.echo(f"ingested {len(results)} months")
        for result in results:
            outcome = run_scan(session, settings, result.month, writer=writer)
            typer.echo(
                f"month {result.month:>2}: {outcome.finding_count:>3} findings · "
                f"root {outcome.merkle_root[:14]}… · {outcome.detail}"
            )


@agent_app.command("run")
def agent_run(
    limit: Annotated[int, typer.Option(help="Findings to investigate and plan for")] = 10,
    regenerate: Annotated[bool, typer.Option("--regenerate", help="Bypass the LLM cache")] = False,
    summary: Annotated[bool, typer.Option("--summary/--no-summary")] = True,
) -> None:
    """Investigate and plan remediation for the highest-scoring open findings (SPEC §11)."""
    settings = _settings()
    from sqlalchemy import select

    from athar.db import models as m
    from athar.db.session import session_scope
    from athar.services.agents import estate_summary_paragraph, investigate_finding, plan_for_finding

    with session_scope() as session:
        scan = session.scalars(select(m.Scan).order_by(m.Scan.scan_id.desc())).first()
        if scan is None:
            typer.secho("no scan yet — run `athar scan` first", fg="red")
            raise typer.Exit(1)
        rows = list(
            session.scalars(
                select(m.Finding)
                .where(m.Finding.scan_id == scan.scan_id)
                .order_by(m.Finding.score.desc(), m.Finding.finding_key)
                .limit(limit)
            )
        )
        for row in rows:
            inv = investigate_finding(session, settings, row, regenerate=regenerate)
            plan = plan_for_finding(session, settings, row, regenerate=regenerate)
            typer.echo(
                f"{row.rule_id} {row.identity_id}: {inv.generated_by} investigation, "
                f"plan {plan.action} (−{plan.privilege_reduction_pct:.0f}% privilege)"
            )
        if summary:
            out = estate_summary_paragraph(session, settings, scan, regenerate=regenerate)
            typer.echo(f"\nexecutive summary ({out['generated_by']}, {out['model_id']}):")
            typer.echo(f"  {out['summary_paragraph']}")


@app.command()
def verify(
    scan_id: Annotated[
        int | None, typer.Option("--scan", help="Scan to verify; defaults to the latest")
    ] = None,
    csv_path: Annotated[Path | None, typer.Option("--csv", help="An exported findings.csv")] = None,
    json_path: Annotated[Path | None, typer.Option("--json", help="Its findings.json sidecar")] = None,
) -> None:
    """Recompute the Merkle root and compare it with the chain (SPEC §12.6)."""
    settings = _settings()
    from sqlalchemy import select

    from athar.db import models as m
    from athar.db.session import session_scope
    from athar.ledger import verify as ledger_verify
    from athar.services import queries

    if csv_path or json_path:
        sidecar = json_path or (csv_path.with_suffix(".json") if csv_path else None)
        if sidecar is None or not sidecar.exists():
            typer.secho("pass --json pointing at the findings.json sidecar", fg="red")
            raise typer.Exit(2)
        from athar.export.json_export import read_findings_json

        parsed = read_findings_json(sidecar.read_bytes())
        claimed = parsed.merkle_root or ""
        if not claimed:
            typer.secho("the sidecar carries no Merkle root", fg="red")
            raise typer.Exit(2)
        index = parsed.scan.ledger_scan_index if parsed.scan else None
        if index is None:
            typer.secho(
                "the sidecar names no on-chain commit, so nothing here can be checked against the chain",
                fg="red",
            )
            raise typer.Exit(2)
        # The root MUST come from the chain. Verifying the rows against the root the report carries
        # would only prove the report is internally consistent — delete a finding, recompute the
        # root and the proofs, and a forged report would pass (SPEC §12.6).
        chain_client = _ledger_client(settings, address=parsed.contract_address)
        try:
            commit = chain_client.get_commit(index)
        except Exception as exc:
            typer.secho(
                f"could not read commit {index} from the chain ({type(exc).__name__}); nothing was verified",
                fg="red",
            )
            raise typer.Exit(2) from None
        root = commit.findings_root
        if root.lower() != claimed.lower():
            typer.secho(f"FAIL: the report claims root {claimed}", fg="red")
            typer.secho(f"      the chain holds    {root}", fg="red")
            raise typer.Exit(1)
        rows = ledger_verify.rows_from_sidecar(parsed.findings)
        results = ledger_verify.verify_rows(rows, root)
        bad = [r for r in results if not r.passed]
        for r in bad[:10]:
            typer.secho(f"  FAIL {r.finding_key}: {r.detail}", fg="red")
        if len(results) != commit.finding_count:
            typer.secho(
                f"FAIL: the chain committed {commit.finding_count} findings, the report carries {len(results)}",
                fg="red",
            )
            raise typer.Exit(1)
        typer.secho(
            f"{len(results) - len(bad)}/{len(results)} rows verify against the on-chain root {root[:14]}…",
            fg="red" if bad else "green",
        )
        raise typer.Exit(1 if bad else 0)

    client = _ledger_client(settings, resolve=True)
    with session_scope() as session:
        scan = (
            session.get(m.Scan, scan_id)
            if scan_id
            else session.scalars(select(m.Scan).order_by(m.Scan.scan_id.desc())).first()
        )
        if scan is None:
            typer.secho("no scan to verify", fg="red")
            raise typer.Exit(1)
        # Recomputed from the rows as they stand now, not read back from `instance_hash`:
        # verification has to catch an edit to the stored finding (SPEC §12.6).
        hashes = queries.instance_hashes_for_scan(session, scan.scan_id)
        if scan.ledger_scan_index is None:
            typer.secho(f"scan {scan.scan_id} was never anchored ({scan.ledger_status})", fg="yellow")
            raise typer.Exit(1)
        result = ledger_verify.verify_scan(hashes, scan.ledger_scan_index, client)
    typer.secho(
        f"scan {scan.scan_id} month {scan.snapshot_month}: {'PASS' if result.passed else 'FAIL'} — {result.detail}",
        fg="green" if result.passed else "red",
    )
    typer.echo(f"  recomputed {result.computed_root}")
    typer.echo(f"  on chain   {result.chain_root}")
    raise typer.Exit(0 if result.passed else 1)


@app.command()
def export(
    fmt: Annotated[str, typer.Option("--format", help="csv | json | pdf")] = "csv",
    out: Annotated[Path, typer.Option("--out", help="Destination file")] = Path("data/exports/findings.csv"),
    scan_id: Annotated[
        int | None, typer.Option("--scan", help="Not yet supported; exports always cover the latest scan")
    ] = None,
) -> None:
    """Write the findings export carrying the ledger reference (SPEC §16).

    `--format csv` also writes the `findings.json` sidecar beside the CSV, because the footer of
    every report tells the reader to verify with `--csv findings.csv --json findings.json` and
    that has to be true of the file they were just handed.
    """
    settings = _settings()
    from athar.api.schemas import ListFilters
    from athar.db.session import session_scope
    from athar.services.repo import DbRepo

    if scan_id is not None:
        # The option was accepted and silently ignored; an export labelled with the wrong scan is
        # worse than a refusal. Selecting a scan needs a filter the list schema does not carry yet.
        typer.secho(
            f"--scan {scan_id} is not supported: the export always covers the latest scan",
            fg="red",
        )
        raise typer.Exit(2)

    with session_scope() as session:
        repo = DbRepo(session, settings)
        filters = ListFilters(limit=500, offset=0)
        writers = {"csv": repo.export_csv, "json": repo.export_json, "pdf": repo.export_pdf}
        if fmt not in writers:
            typer.secho(f"unknown format {fmt!r}; use csv, json or pdf", fg="red")
            raise typer.Exit(2)
        data = writers[fmt](filters)
        sidecar = repo.export_json(filters) if fmt == "csv" else None
    if out.is_dir():
        # README, DEMO.md and `make export` all describe the exports as landing "in data/exports/",
        # so a reader naturally passes the directory. That used to raise IsADirectoryError and print
        # a traceback carrying internal paths; name the file for them instead.
        out = out / f"findings.{fmt}"
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        out.write_bytes(data)
    except OSError as exc:  # unwritable path, bad filename, full disk: say so, never traceback
        typer.secho(f"could not write {out}: {exc.strerror or exc}", fg="red")
        raise typer.Exit(2) from exc
    typer.echo(f"wrote {out} ({len(data):,} bytes)")
    if sidecar is not None:
        sidecar_path = out.with_suffix(".json")
        if sidecar_path == out:  # `--format csv --out …/findings.json`; never clobber the CSV
            typer.secho(f"  not writing a sidecar: {out} is already the .json path", fg="yellow")
            return
        sidecar_path.write_bytes(sidecar)
        typer.echo(f"wrote {sidecar_path} ({len(sidecar):,} bytes) — the sidecar `athar verify --json` reads")


@app.command("seed-users")
def seed_users_cmd() -> None:
    """Create or update the three demo accounts (SPEC §15.1)."""
    settings = _settings()
    from athar.db.migrate import upgrade_head
    from athar.db.session import session_scope
    from athar.security.users import seed_users

    upgrade_head()
    with session_scope() as session:
        changed = seed_users(session, settings)
    typer.echo(f"users seeded ({changed} changed)")


@app.command("eval")
def eval_cmd(
    seed_value: Annotated[int | None, typer.Option("--seed", help="Estate seed to evaluate")] = None,
    sample: Annotated[
        int | None,
        typer.Option("--sample", help="Rebuild the small CI estate for this seed under data/sample"),
    ] = None,
    gate: Annotated[bool, typer.Option("--gate", help="Exit non-zero below the SPEC §17 thresholds")] = False,
    report: Annotated[bool, typer.Option("--report", help="Print the two-register sentences")] = False,
    held_out: Annotated[
        bool, typer.Option("--held-out", help="Evaluate ATHAR_EVAL_SEED, the seed the constants never saw")
    ] = False,
) -> None:
    """Precision / recall against ground truth (SPEC §17). Tuned on ATHAR_SEED, reported on the held-out seed.

    With no `--seed`, evaluates ATHAR_SEED; with `--held-out`, ATHAR_EVAL_SEED. Both come from the
    environment (`.env`), so `make eval` follows an edit there without anyone retyping a number —
    the Makefile used to read the seeds from the shell instead, where they are never set, and so
    always evaluated the defaults whatever `.env` said.
    """
    settings = _settings()
    from athar.eval.harness import evaluate

    if held_out and seed_value is not None:
        typer.secho("--held-out names the seed itself; do not also pass --seed", fg="red")
        raise typer.Exit(2)
    if sample is not None:
        value = sample
    elif seed_value is not None:
        value = seed_value
    elif held_out:
        value = settings.athar_eval_seed
    else:
        value = settings.athar_seed
    result = evaluate(
        value,
        months=6 if sample is not None else settings.athar_months,
        identities=120 if sample is not None else settings.athar_identities,
        data_dir=Path(settings.data_dir) / "sample" if sample is not None else Path(settings.data_dir),
    )
    typer.echo(
        f"seed {value}: precision {result.precision:.2f} recall {result.recall:.2f} "
        f"F1 {result.f1:.2f} (tp {result.tp} fp {result.fp} fn {result.fn}) at High+"
    )
    if report:
        from athar.export.summary import build_director_sentence, build_engineer_sentence

        # `result.held_out` is the harness's own answer, and it is the whole point of the field:
        # printing "on seed 7" throws away the one thing SPEC §8.3 asks this line to say.
        typer.echo(
            "  "
            + build_engineer_sentence(result.precision, result.recall, seed=value, held_out=result.held_out)
        )
        typer.echo("  " + build_director_sentence(result.tp, result.fp, result.decoys_recognised))
    if gate and (result.precision < 0.80 or result.recall < 0.90):
        typer.secho("  below the SPEC §17 gate (precision ≥ 0.80, recall ≥ 0.90)", fg="red")
        raise typer.Exit(1)


@app.command()
def tamper(
    finding: Annotated[str, typer.Option("--finding", help="Finding key to alter")],
    severity: Annotated[str, typer.Option(help="New severity")] = "Low",
    scan_id: Annotated[
        int | None,
        typer.Option("--scan", help="Scan to alter; defaults to the latest one carrying the finding"),
    ] = None,
) -> None:
    """DEV ONLY — edit a stored severity so `athar verify` fails (the demo's tamper beat, SPEC §12.6).

    Exactly one scan is altered. A finding key is stable across months (SPEC §10.1), so altering
    every row would break verification for every scan the finding appears in, while `athar scan`
    only restores the month it re-runs — leaving the others failing with no hint why.
    """
    settings = _settings()
    if not settings.athar_dev:
        typer.secho("refusing to tamper outside ATHAR_DEV", fg="red")
        raise typer.Exit(2)
    from sqlalchemy import select

    from athar.db import models as m
    from athar.db.session import session_scope
    from athar.services.scan import restorable_scan

    with session_scope() as session:
        stmt = select(m.Finding).where(m.Finding.finding_key == finding)
        if scan_id is not None:
            stmt = stmt.where(m.Finding.scan_id == scan_id)
        row = session.scalars(stmt.order_by(m.Finding.scan_id.desc())).first()
        if row is None:
            where = f" in scan {scan_id}" if scan_id is not None else ""
            typer.secho(f"no finding {finding}{where}", fg="red")
            raise typer.Exit(1)
        # Only a scan the current snapshot can reproduce is restorable by re-scanning. Tampering
        # one that a later ingest has superseded would leave it failing with no way back.
        restorable = restorable_scan(session, settings, row.scan_id)
        if restorable is None:
            typer.secho(
                f"scan {row.scan_id} cannot be rebuilt from the estate on disk, so a tamper there "
                "could not be undone; re-scan the month first",
                fg="red",
            )
            raise typer.Exit(2)
        if restorable != row.scan_id:
            typer.secho(
                f"scan {row.scan_id} has been superseded; tampering scan {restorable} instead, "
                "which `athar scan` can restore",
                fg="yellow",
            )
            row = session.scalars(
                select(m.Finding).where(m.Finding.finding_key == finding, m.Finding.scan_id == restorable)
            ).first()
            if row is None:
                typer.secho(f"{finding} is not in scan {restorable}", fg="red")
                raise typer.Exit(1)
        target, previous = row.scan_id, row.severity
        if previous == severity:
            # Otherwise the demo beat silently does nothing and `verify` still passes.
            typer.secho(
                f"{finding} in scan {target} is already {severity}; pass a different --severity",
                fg="red",
            )
            raise typer.Exit(2)
        scan_row = session.get(m.Scan, target)
        month = scan_row.snapshot_month if scan_row is not None else None
        row.severity = severity
    typer.secho(
        f"tampered scan {target}: {finding} {previous} → {severity} (that scan only).",
        fg="yellow",
    )
    typer.echo(f"  `athar verify --scan {target}` should now FAIL.")
    if month is not None:
        typer.echo(f"  restore with: athar scan --month {month}")


@app.command()
def serve(
    reload: Annotated[bool, typer.Option("--reload", help="Development auto-reload")] = False,
) -> None:
    """Run the API (migrations, user seeding and the ledger deploy happen on startup)."""
    settings = _settings()
    from athar.api.serve import run

    run(settings, app="athar.services.wiring:create_app", reload=reload)


if __name__ == "__main__":  # pragma: no cover
    app()
