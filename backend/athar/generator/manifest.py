"""Estate manifest (SPEC §4.7 `manifest.json`). Pure except for the two file helpers.

The manifest is what makes `make seed` idempotent (CLAUDE.md non-negotiable 2): it records the
inputs the tree was generated from — seed, months written so far, identity target, the window the
estate was designed for, and the generator version — plus the sha256 of every file in the tree.
A second `generate` with the same inputs recognises its own output and writes nothing; an
`advance` uses the hashes to prove months 1..N are untouched before it writes month N+1.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from athar.generator.ground_truth import GENERATOR_VERSION
from athar.hashing import sha256_hex

MANIFEST_NAME = "manifest.json"


class ManifestError(ValueError):
    """The manifest is missing, unreadable or does not describe this estate."""


@dataclass(frozen=True)
class Manifest:
    seed: int
    months: int
    identities: int
    generator_version: str = GENERATOR_VERSION
    horizon: int = 0  # the window the estate was designed for; 0 == "same as months"
    files: dict[str, str] = field(default_factory=dict)  # relative posix path → sha256

    @property
    def design_horizon(self) -> int:
        return self.horizon or self.months

    def as_json(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "months": self.months,
            "identities": self.identities,
            "generator_version": self.generator_version,
            "horizon": self.design_horizon,
            "files": dict(sorted(self.files.items())),
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Manifest:
        try:
            files = {str(k): str(v) for k, v in dict(data.get("files") or {}).items()}
            return cls(
                seed=int(data["seed"]),
                months=int(data["months"]),
                identities=int(data["identities"]),
                generator_version=str(data.get("generator_version") or ""),
                horizon=int(data.get("horizon") or 0),
                files=files,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ManifestError(f"{MANIFEST_NAME} is missing a required field: {exc}") from exc

    def describe(self) -> str:
        return (
            f"seed={self.seed} months={self.months} identities={self.identities} "
            f"generator_version={self.generator_version}"
        )

    def matches(self, seed: int, months: int, identities: int, version: str = GENERATOR_VERSION) -> bool:
        """True when this tree already satisfies the request. An estate advanced past `months`
        still contains the requested window (SPEC §4.7 is forward-only), so it counts as a match."""
        return (
            self.seed == seed
            and self.identities == identities
            and self.generator_version == version
            and self.months >= months
        )


def hash_tree(root: Path, exclude: tuple[str, ...] = (MANIFEST_NAME,)) -> dict[str, str]:
    """sha256 of every file under `root`, keyed by its posix path relative to `root`."""
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in exclude:
            continue
        out[relative] = sha256_hex(path.read_bytes())
    return dict(sorted(out.items()))


def manifest_path(estate_dir: Path) -> Path:
    return Path(estate_dir) / MANIFEST_NAME


def write_manifest(estate_dir: Path, manifest: Manifest) -> Path:
    path = manifest_path(estate_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest.as_json(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def read_manifest(estate_dir: Path) -> Manifest:
    path = manifest_path(estate_dir)
    if not path.is_file():
        raise ManifestError(f"no {MANIFEST_NAME} in {estate_dir}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ManifestError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{path} must contain a JSON object")
    return Manifest.from_json(data)


def verify_manifest(estate_dir: Path, manifest: Manifest | None = None) -> list[str]:
    """Paths whose bytes on disk disagree with the manifest (missing, changed or unexpected)."""
    manifest = manifest or read_manifest(estate_dir)
    actual = hash_tree(Path(estate_dir))
    return sorted({p for p in set(actual) | set(manifest.files) if actual.get(p) != manifest.files.get(p)})
