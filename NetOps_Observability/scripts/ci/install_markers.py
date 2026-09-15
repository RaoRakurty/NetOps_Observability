# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Read install.py's `@CX@ {json}` progress markers out of a captured log.

install.py (run with --progress-json) prints one marker per stage transition:
  @CX@ {"kind":"stage","id":"up-a","title":"...","status":"start"}
  @CX@ {"kind":"stage","id":"up-a","title":"...","status":"ok","elapsed_s":1.2}
  @CX@ {"kind":"result","status":"ok",...}

Two CI checks are built on them (installer self-healing FMEA 2026-09-15 §5):

  check        one run: a terminal `result` ok, no stage failed, every stage
               that started also closed, and at least one marker at all (a log
               without markers means --progress-json was not passed, and a check
               over nothing proves nothing).
  check-rerun  a second install over the first must not regress:
               * the second run passes `check`;
               * WITHOUT an install journal, it runs exactly the stage sequence
                 the first run ran (a missing stage is an early exit, an extra
                 one is a changed plan);
               * WITH a journal (data/.install-journal.json, FMEA §4.1 — not built
                 yet, so this branch activates when it lands), stages may be
                 skipped, but no stage the first run did not know may appear, the
                 `bundle` stage — if the first run loaded one — must be absent or
                 reported `skipped`, and `kafka-acls` is never skippable (§4.1
                 rule 1: cheap, and the store can be wiped).

Exit codes: 0 pass · 1 fail · 2 could not assess (unreadable input).
Standard library only; tested by tests/test_ci_install_markers.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

MARKER = "@CX@ "
CLOSED = ("ok", "fail", "skipped")
# FMEA §4.1 rule 1: never skipped on a re-run, journal or not.
NEVER_SKIPPED = ("kafka-acls",)


def parse_marker_line(line: str) -> dict | None:
    """The marker object on this line, or None. Tolerates a prefix (a log
    timestamp, or another stream's partial line) before the marker."""
    i = line.find(MARKER)
    if i < 0:
        return None
    try:
        obj = json.loads(line[i + len(MARKER):].strip())
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def parse_markers(lines: Iterable[str]) -> list[dict]:
    return [m for m in (parse_marker_line(ln) for ln in lines) if m is not None]


@dataclass
class Occurrence:
    id: str
    status: str  # start (never closed) | ok | fail | skipped


@dataclass
class RunSummary:
    stages: list[Occurrence] = field(default_factory=list)
    result: str = ""
    marker_count: int = 0

    @property
    def ids(self) -> list[str]:
        return [o.id for o in self.stages]


def summarize(markers: Sequence[dict]) -> RunSummary:
    s = RunSummary(marker_count=len(markers))
    for m in markers:
        kind = m.get("kind")
        if kind == "result":
            s.result = str(m.get("status") or "")
            continue
        if kind != "stage":
            continue
        sid = str(m.get("id") or "")
        status = str(m.get("status") or "")
        if status == "start":
            s.stages.append(Occurrence(sid, "start"))
        elif status in CLOSED:
            open_occ = next((o for o in reversed(s.stages)
                             if o.id == sid and o.status == "start"), None)
            if open_occ is not None:
                open_occ.status = status
            else:
                # A stage reported without a start (e.g. a journal "skipped"
                # marker) is still an occurrence of that stage.
                s.stages.append(Occurrence(sid, status))
    return s


def check_single(s: RunSummary, label: str = "run") -> list[str]:
    problems: list[str] = []
    if s.marker_count == 0:
        return [f"{label}: no @CX@ markers in the log — was --progress-json passed?"]
    if s.result != "ok":
        problems.append(f"{label}: terminal result is {s.result or 'missing'!r}, "
                        "expected 'ok'")
    for o in s.stages:
        if o.status == "fail":
            problems.append(f"{label}: stage {o.id} failed")
        elif o.status == "start":
            problems.append(f"{label}: stage {o.id} started and never closed")
    return problems


def check_rerun(first: RunSummary, second: RunSummary,
                journal: dict | None) -> tuple[list[str], list[str]]:
    """(problems, notes) for a second install run over the first."""
    problems = check_single(second, "re-run")
    notes: list[str] = []
    if first.result != "ok":
        notes.append("first run did not finish ok, so the re-run is judged on its "
                     "own (no stage-sequence comparison)")
        return problems, notes

    if journal is None:
        notes.append("no install journal: the re-run must repeat the first run's "
                     "stage sequence exactly")
        if second.ids != first.ids:
            problems.append("re-run stage sequence differs from the first run:\n"
                            f"  first:  {' '.join(first.ids)}\n"
                            f"  re-run: {' '.join(second.ids)}")
        return problems, notes

    notes.append("install journal present: stages may be skipped; bundle must be "
                 "skipped when the first run loaded one")
    known = set(first.ids)
    for o in second.stages:
        if o.id not in known:
            problems.append(f"re-run: stage {o.id} did not exist in the first run")
    if "bundle" in known:
        ran = [o for o in second.stages if o.id == "bundle" and o.status != "skipped"]
        if ran:
            problems.append("re-run: the bundle stage ran again although the journal "
                            "records it as done (expected absent or 'skipped')")
    for sid in NEVER_SKIPPED:
        if sid in known and not any(o.id == sid and o.status == "ok"
                                    for o in second.stages):
            problems.append(f"re-run: stage {sid} must run on every install, "
                            "journal or not")
    return problems, notes


def _load(path: str) -> RunSummary:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return summarize(parse_markers(fh))


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    one = sub.add_parser("check")
    one.add_argument("--log", required=True)
    two = sub.add_parser("check-rerun")
    two.add_argument("--first", required=True)
    two.add_argument("--second", required=True)
    two.add_argument("--journal", default=None,
                     help="path to a COPY of the install journal; a path that "
                          "does not exist means no journal")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "check":
            s = _load(args.log)
            print(f"stages: {' '.join(f'{o.id}={o.status}' for o in s.stages)}")
            problems, notes = check_single(s), []
        else:
            first, second = _load(args.first), _load(args.second)
            journal = None
            if args.journal and Path(args.journal).exists():
                doc = json.loads(Path(args.journal).read_text(encoding="utf-8"))
                if not isinstance(doc, dict):
                    print("install journal is not a JSON object", file=sys.stderr)
                    return 2
                journal = doc
            print(f"first:  {' '.join(f'{o.id}={o.status}' for o in first.stages)}")
            print(f"re-run: {' '.join(f'{o.id}={o.status}' for o in second.stages)}")
            problems, notes = check_rerun(first, second, journal)
    except (OSError, ValueError) as e:
        print(f"could not read the install log/journal: {e}", file=sys.stderr)
        return 2
    for n in notes:
        print(f"note: {n}")
    for p in problems:
        print(f"FAIL  {p}")
    print("PASS" if not problems else "FAIL")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
