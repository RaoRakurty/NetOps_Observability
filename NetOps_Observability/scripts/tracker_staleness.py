#!/usr/bin/env python3
"""
tracker_staleness.py — flag TRACKER.md items whose status has gone STALE.

Why this exists
---------------
The tracker's status column lags reality: an item ships in code/commits but its
status is never flipped from open → done. A stale "🔜 NEXT / 🟡 in progress"
entry is a trap — it can send someone to rebuild work that already exists (the
2026-06-23 G2/G3 episode). This is a mechanical cross-check: for every item still
marked OPEN, does git history already show shipping commits that reference it?

What it CATCHES
    "Shipped-but-still-marked-open": an item with an open-status glyph that has
    feat()/fix() commits referencing its id. → likely needs a status flip.

What it does NOT catch (be honest)
    "Premise drift": an item that became MOOT with no commit at all — the gap it
    described stopped being real because reality/data moved (G2/G3). Nothing in
    git signals it. That class needs the *verify-before-building* habit (grep the
    live code + query the running system BEFORE building), not a script. See
    docs/design/correlation-engine.md §4.2 and the verify-before-building rule.

Usage
    python3 scripts/tracker_staleness.py                 # report, exit 1 if any stale
    python3 scripts/tracker_staleness.py --quiet          # only the stale ones
    python3 scripts/tracker_staleness.py --json           # machine-readable
Pure stdlib + `git`; no running stack required. Safe to run in CI.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TRACKER = os.path.join(ROOT, "docs", "TRACKER.md")

# Status glyphs that mean "not finished". ✅ = done, 👤 = waiting on user (excluded:
# a user-action item is correctly open until the user acts).
OPEN_GLYPHS = ("🔜", "🟡", "⏳", "🔬", "🧪", "📋")
# Open-status WORDS, matched in the status cell only (not the description prose).
OPEN_WORDS = re.compile(r"\b(in progress|not started|not begun|queued|building|partial|next)\b", re.IGNORECASE)
# "NOT-STARTED" status — these should have NO shipping commits. A shipping commit
# here is a HIGH-confidence stale flag (the dangerous direction: looks untouched but
# was built — exactly what sends someone to rebuild it). 🟡/in-progress/partial/"N of
# M"/phase items are EXPECTED to have per-phase commits → INFO only, not a red flag.
NOTSTARTED_GLYPHS = ("🔜", "⏳", "📋")
NOTSTARTED_WORDS = re.compile(r"\b(not started|not begun|queued|next)\b", re.IGNORECASE)
PROGRESS_WORDS = re.compile(r"\b(in progress|partial|building|phase|\d+\s+of\s+\d+)\b", re.IGNORECASE)
# A commit subject that represents SHIPPED work (vs docs/chore/test-only).
SHIPPED_KIND = re.compile(r"^(feat|fix)\b", re.IGNORECASE)


def sh(*args: str) -> str:
    try:
        return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=30, check=False).stdout
    except Exception:  # noqa: BLE001 — best-effort: empty git output degrades to "no data"
        return ""


def parse_tracker() -> list[dict]:
    """Each table row → {id, title, status}. Only numeric-id rows are checkable
    (an id we can grep commits for); '—' rows are skipped."""
    items = []
    with open(TRACKER, encoding="utf-8") as fh:
        for line in fh:
            if not line.startswith("|"):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) < 4:
                continue
            rid = cells[0]
            if not rid.isdigit():
                continue
            title = re.sub(r"\*\*|`", "", cells[1])[:70]
            items.append({"id": rid, "title": title, "status": cells[-1]})
    return items


def is_open(status: str) -> bool:
    return any(g in status for g in OPEN_GLYPHS) or bool(OPEN_WORDS.search(status))


def severity(status: str) -> str:
    """HIGH = status implies not-started yet has shipping commits (dangerous: looks
    untouched but was built). INFO = actively-in-progress/partial (commits expected)."""
    notstarted = any(g in status for g in NOTSTARTED_GLYPHS) or bool(NOTSTARTED_WORDS.search(status))
    if notstarted and not PROGRESS_WORDS.search(status):
        return "HIGH"
    return "INFO"


def shipping_commits(item_id: str) -> list[str]:
    """feat()/fix() commit subjects that reference (#<id>) with a real word boundary
    (so #7 does not match #79)."""
    out = sh("git", "log", "--all", "--oneline", "--no-color", f"--grep=#{item_id}", "-E")
    hits = []
    pat = re.compile(rf"#{item_id}(?![0-9])")
    for ln in out.splitlines():
        subj = ln.split(" ", 1)[1] if " " in ln else ""
        if pat.search(ln) and SHIPPED_KIND.search(subj):
            hits.append(ln.strip())
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="Flag stale TRACKER.md statuses.")
    ap.add_argument("--quiet", action="store_true", help="print only stale items")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if not os.path.exists(TRACKER):
        print(f"tracker not found: {TRACKER}", file=sys.stderr)
        return 2

    stale, checked = [], 0
    for it in parse_tracker():
        if not is_open(it["status"]):
            continue
        checked += 1
        commits = shipping_commits(it["id"])
        if commits:
            stale.append({**it, "commits": commits, "severity": severity(it["status"])})

    high = [s for s in stale if s["severity"] == "HIGH"]
    info = [s for s in stale if s["severity"] == "INFO"]

    if args.json:
        print(json.dumps({"checked_open": checked, "stale": stale}, indent=2, ensure_ascii=False))
        return 1 if high else 0

    def show(group: list[dict]) -> None:
        for it in group:
            print(f"  #{it['id']}  [{it['status'][:46]}]  {it['title']}")
            for c in it["commits"][:4]:
                print(f"        ↳ {c}")
            print()

    if high:
        print(f"⚠ HIGH — {len(high)} item(s) marked NOT-STARTED but with shipping commits "
              f"(rebuild risk — flip the status):\n")
        show(high)
    if info and not args.quiet:
        print(f"ℹ INFO — {len(info)} in-progress/partial item(s) with commits (expected; "
              f"verify the status text still matches):\n")
        show(info)
    if not high and not info:
        print(f"✅ no stale tracker statuses ({checked} open items cross-checked vs git).")
    if not args.quiet:
        print("NOTE: catches shipped-but-not-marked-done only. It does NOT catch 'premise went\n"
              "moot with no commit' (the G2/G3 class) — that needs verify-before-building.")
    # CI signal: fail only on HIGH (a not-started item that was actually shipped).
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
