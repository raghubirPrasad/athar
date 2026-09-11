"""Two-register evaluation sentences (SPEC §17). Pure string helpers for the Evaluation page.

Same numbers, two readers: directors get counts in plain language, engineers get precision/recall.
"""

from __future__ import annotations


def _plural(n: int, singular: str, plural: str) -> str:
    return singular if n == 1 else plural


def build_director_sentence(tp: int, fp: int, decoys_recognised: int) -> str:
    """E.g. "Of 47 accounts flagged, 41 are verified genuine risks; 6 are known exceptions the system now recognises."

    `tp` + `fp` = accounts flagged at High or above. `decoys_recognised` is the part of `fp` that is
    a seeded decoy / registered exception the system now suppresses; any remainder is reported as
    still under review rather than hidden.
    """
    if min(tp, fp, decoys_recognised) < 0:
        raise ValueError("counts must be non-negative")
    if decoys_recognised > fp:
        raise ValueError("decoys_recognised cannot exceed fp")
    flagged = tp + fp
    if flagged == 0:
        return "No accounts were flagged at High or above."
    parts = [
        f"Of {flagged} {_plural(flagged, 'account', 'accounts')} flagged, "
        f"{tp} {_plural(tp, 'is a verified genuine risk', 'are verified genuine risks')}"
    ]
    if decoys_recognised:
        parts.append(
            f"; {decoys_recognised} {_plural(decoys_recognised, 'is a known exception', 'are known exceptions')}"
            " the system now recognises"
        )
    remaining = fp - decoys_recognised
    if remaining:
        parts.append(f"; {remaining} {_plural(remaining, 'is', 'are')} still under analyst review")
    return "".join(parts) + "."


def build_engineer_sentence(
    precision: float,
    recall: float,
    *,
    threshold: str = "High",
    seed: int | None = None,
    held_out: bool | None = None,
) -> str:
    """E.g. "precision 0.87 / recall 0.95 at High+ on held-out seed 7".

    `held_out` is the caller's fact, not an assumption: which seed is held out is
    `ATHAR_EVAL_SEED`, and only the caller knows whether the numbers it is about to print came
    from that seed or from the tuning seed (SPEC §8.3, §17). Passing `True` gives "held-out
    seed N", `False` gives "tuning seed N", and leaving it `None` says only "seed N" — because
    calling the tuning seed held out is the one claim this sentence must never make. It would
    describe the constants as reported on an estate they were fitted to, which is the rubric's
    train/test leakage line.
    """
    for name, value in (("precision", precision), ("recall", recall)):
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"{name} must be within [0, 1]")
    sentence = f"precision {precision:.2f} / recall {recall:.2f} at {threshold}+"
    if seed is not None:
        provenance = "" if held_out is None else ("held-out " if held_out else "tuning ")
        sentence += f" on {provenance}seed {seed}"
    return sentence
