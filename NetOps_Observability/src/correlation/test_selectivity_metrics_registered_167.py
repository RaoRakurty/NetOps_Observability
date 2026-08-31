"""Tracker 167 — the selectivity counters must actually reach the exposition.

`scoring.py` shipped `corr_template_scored_total` / `corr_template_candidates_total`
(and the tracker-157 `corr_template_ungrounded_total` beside them) in 3001d440,
but the REGISTRATION in `_metrics_text()` was deferred to a later change. A
counter nobody can scrape is not a counter: the whole point of the pair is the
ratio `scored / candidates` — how much of the catalog the kind index elides per
`rank()` — and that ratio is unreadable from inside the process.

This is the wiring test, and only the wiring test: what the counters MEAN is
pinned next to them in `test_template_index_167.py`. Deleting the
`*template_scoring_metric_lines(),` splice from `_metrics_text()` must go red
here.
"""
from __future__ import annotations

import asyncio

import main
import scoring


def _exposition() -> str:
    resp = asyncio.run(main.metrics_exposition())
    return resp.body.decode() if hasattr(resp, "body") else str(resp)


def _samples(body: str) -> dict[str, str]:
    """Name → value for every SAMPLE line. HELP/TYPE comments mention the name
    too, so matching the raw text would pass on a build that exports the header
    and drops the number."""
    return {ln.split(" ", 1)[0]: ln.split(" ", 1)[1]
            for ln in body.splitlines()
            if ln and not ln.startswith("#") and " " in ln}


def test_the_selectivity_counters_are_registered_in_the_exposition():
    samples = _samples(_exposition())
    for series in ("corr_template_scored_total",
                   "corr_template_candidates_total",
                   "corr_template_ungrounded_total"):
        assert series in samples, (
            f"{series} has no sample line — `*template_scoring_metric_lines(),` "
            f"is missing from _metrics_text()")
        int(samples[series])              # and it must carry a parsable count


def test_the_exposition_reports_what_scoring_is_actually_counting():
    """Registered is not the same as CORRECT: the numbers must come from the
    live counters, not from a constant somebody typed into main.py."""
    before = scoring.template_scoring_stats()
    samples = _samples(_exposition())
    after = scoring.template_scoring_stats()
    for series, key in (("corr_template_scored_total", "scored"),
                        ("corr_template_candidates_total", "candidates"),
                        ("corr_template_ungrounded_total", "ungrounded")):
        # `rank()` may run on another test's behalf between the two reads, so
        # the exposed value is bracketed rather than pinned to one snapshot.
        assert before[key] <= int(samples[series]) <= after[key], (
            f"{series} does not track scoring.{key}")


def test_the_metric_names_are_owned_by_the_module_that_counts():
    """main.py splices the lines in whole; it must not re-declare a name of its
    own, or the two can drift apart silently."""
    body = _exposition()
    for line in scoring.template_scoring_metric_lines():
        if line.startswith(("# TYPE", "# HELP")):
            assert line in body, f"{line!r} is not in the exposition"
    assert body.count("# TYPE corr_template_scored_total counter") == 1
    assert body.count("# TYPE corr_template_candidates_total counter") == 1
