"""`.env.example` documents every variable the code or compose reads (SPEC §18.2).

SPEC §18.2 makes `.env.example` the one place a variable is documented, and CLAUDE.md makes
`config.py` the one place it is declared. Two things can therefore drift apart from the file:

1. a new aliased field on :class:`athar.config.Settings`, and
2. a new `${VAR}` substitution in `docker-compose.yml`.

Both happened (`GOOGLE_API_KEY`, `ATHAR_API_MOCK`, the four `*_HOST_PORT` variables and
`PUBLIC_HOSTNAME` were all live and undocumented), so this test walks both sources and fails on
anything that has no assignment line in `.env.example`.

**Nothing is excluded today**, and :data:`INTERNAL` is deliberately empty: every setting the code
reads is one an operator may legitimately need to change, and every compose substitution is a
knob on the deployment. The set exists so that a genuinely internal variable — one an operator
must never set, such as a value compose injects into a container for another container to read —
has an obvious home with a written reason, rather than being silently dropped from the check.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from athar.config import REPO_ROOT, Settings

ENV_EXAMPLE = REPO_ROOT / ".env.example"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"

#: Variables intentionally left out of `.env.example`, each with the reason it is not an operator
#: knob. Empty on purpose — see the module docstring before adding to it.
INTERNAL: frozenset[str] = frozenset()

#: `NAME=` at the start of a line. A mention inside a comment does not count as documentation:
#: an operator copies this file to `.env` and edits assignments.
_ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)=", re.MULTILINE)

#: `${NAME}`, `${NAME:-default}`, `${NAME-default}`, `$NAME`.
_SUBSTITUTION = re.compile(r"\$\{?([A-Z][A-Z0-9_]*)[}:\-]")


def documented() -> set[str]:
    return set(_ASSIGNMENT.findall(ENV_EXAMPLE.read_text(encoding="utf-8")))


def settings_aliases() -> set[str]:
    """Every env var `Settings` reads, taken from the field aliases rather than a hand-kept list."""
    names = {
        field.alias
        for field in Settings.model_fields.values()
        if field.alias is not None and field.alias.isupper()
    }
    assert names, "Settings declares no aliased fields — the walk is broken, not the file"
    return names


def compose_substitutions() -> set[str]:
    """Every `${VAR}` compose interpolates, including the profile-only services."""
    return set(_SUBSTITUTION.findall(COMPOSE_FILE.read_text(encoding="utf-8")))


def test_env_example_is_readable() -> None:
    assert ENV_EXAMPLE.is_file() and COMPOSE_FILE.is_file()
    assert len(documented()) > 20, "parsed almost nothing — the assignment pattern is wrong"


@pytest.mark.parametrize("alias", sorted(settings_aliases()))
def test_every_setting_is_documented(alias: str) -> None:
    """A field on `Settings` an operator cannot discover from `.env.example` is a documentation bug."""
    if alias in INTERNAL:
        pytest.skip(f"{alias} is documented as internal in tests/unit/test_env_example.py")
    assert alias in documented(), (
        f"{alias} is read by athar.config.Settings but has no `{alias}=` line in .env.example "
        "(SPEC §18.2: .env.example documents every variable)"
    )


@pytest.mark.parametrize("name", sorted(compose_substitutions()))
def test_every_compose_variable_is_documented(name: str) -> None:
    """A `${VAR}` in compose with no `.env.example` line silently falls back to its default."""
    if name in INTERNAL:
        pytest.skip(f"{name} is documented as internal in tests/unit/test_env_example.py")
    assert name in documented(), (
        f"docker-compose.yml interpolates ${{{name}}} but .env.example has no `{name}=` line, so "
        "an operator setting it in .env has no way to know it exists"
    )


def test_public_hostname_reaches_caddy() -> None:
    """The `public` profile's whole point: `deploy/Caddyfile` reads `PUBLIC_HOSTNAME` (SPEC §18.5).

    The Caddyfile's site block is `{$PUBLIC_HOSTNAME:localhost}`, which Caddy resolves from the
    *container's* environment. Compose passing the variable into the service is what makes
    docs/DEPLOY.md's "set PUBLIC_HOSTNAME in .env" true instead of always serving `localhost`.
    """
    compose = COMPOSE_FILE.read_text(encoding="utf-8")
    caddy_block = compose.split("  caddy:", 1)[1]
    assert "PUBLIC_HOSTNAME" in caddy_block.split("\nvolumes:", 1)[0]
    caddyfile = (REPO_ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    assert "{$PUBLIC_HOSTNAME" in caddyfile


def test_env_example_has_no_duplicate_assignments() -> None:
    """Two lines for one variable means the second silently wins; an operator edits the first."""
    names = _ASSIGNMENT.findall(ENV_EXAMPLE.read_text(encoding="utf-8"))
    duplicates = sorted({n for n in names if names.count(n) > 1})
    assert not duplicates, f"duplicated in .env.example: {', '.join(duplicates)}"


def test_paths_are_the_repository_root_ones() -> None:
    """Guards the walk itself: a wrong REPO_ROOT would make every assertion vacuously pass."""
    assert Path(REPO_ROOT, ".env.example") == ENV_EXAMPLE
    assert "ATHAR_SEED" in documented()
