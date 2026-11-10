#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Record each new vendor-pack fixture into the parser's golden corpus (tracker 387).

`src/correlation/fixtures/parser_golden_corpus.jsonl` freezes what the parser produced,
so a later change that moves a signal's identity is red. A pack's lines belong there too,
and adding a vendor must stay data work, so this script appends them. It only ever adds:
an entry already in the corpus keeps the output it recorded, which is the whole point.

    python3 telemetry-catalog/record_pack_corpus.py          # append what is missing
    python3 telemetry-catalog/record_pack_corpus.py --check  # exit 1 if anything is

Run it after the bake, deliberately: a recorded line states what the parser now does.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
CORRELATION = os.path.abspath(os.path.join(HERE, "..", "src", "correlation"))
sys.path.insert(0, CORRELATION)
sys.path.insert(0, os.path.join(CORRELATION, "fixtures"))

import bake_rules
import parser_branch_baseline as frozen
import producers as P

GOLDEN = os.path.join(CORRELATION, "fixtures", "parser_golden_corpus.jsonl")
#: The corpus replays every entry at this instant (test_parser_provenance_w1b.T0).
T0 = datetime(2026, 9, 2, 10, 0, 0, tzinfo=timezone.utc)
TS = "2026-09-02T10:00:00.000Z"
PROVENANCE_KEYS = frozenset({"rule_id", "parser_rev", "rules_hash", "fidelity"})
BASELINE_REASON = (
    "tracker 387: a vendor-pack line. The frozen pre-A3 branch code has no pack, so it "
    "cannot answer for this line the way the pack does. Pinned by this entry's recorded "
    "`out`, which the byte-identical replay still checks, and by the pack's own fixture.")


def _shot(sig: object) -> dict | None:
    """The comparison surface of test_parser_provenance_w1b._shot."""
    if sig is None:
        return None
    attrs = sig.attrs if isinstance(sig.attrs, dict) else {}
    return {
        "kind": sig.kind,
        "entity_type": sig.entity_type.value,
        "entity_id": sig.entity_id,
        "state": str(attrs.get("state", "")),
        "tokens": list(sig.entity_tokens),
        "native_id": sig.native_id,
        "signal_id": str(sig.signal_id),
        "severity": sig.severity.value,
        "metric_name": sig.metric_name,
        "modality_class": sig.modality_class.value,
        "attrs": {k: v for k, v in sorted(attrs.items()) if k not in PROVENANCE_KEYS},
    }


def engine_event(fx: dict) -> dict:
    """The event as the engine reads it: Stage B has already run."""
    raw = {"hostname": fx.get("hostname", "spine1"), "appname": fx.get("appname", "unknown"),
           "severity": fx.get("severity", "notice"), "message": fx["message"],
           "timestamp": TS}
    if "msgid" in fx:
        raw["msgid"] = fx["msgid"]
    ev = {**raw, **P._PACKS.parse(raw)}
    # Stage B's envelope fallback: MSGID is the event_type when no grammar stated one.
    if fx.get("msgid") and fx["msgid"] != "-" and "event_type" not in ev:
        ev["event_type"] = str(fx["msgid"]).lower()
    return ev


def entry_for(pack: str, fx: dict) -> dict | None:
    """A corpus entry, or None for a line no rule reaches."""
    ev = engine_event(fx)
    before = dict(P.KNOWN_BENIGN_HITS)
    sig = P.syslog_control_signal(dict(ev), "t1", T0)
    benign = P.KNOWN_BENIGN_HITS != before
    if sig is None and not benign:
        return None
    entry: dict = {
        "ev": ev,
        "lane": "syslog",
        "origin": f"pack:{pack}",
        "out": {"port_event_signal": _shot(P.port_event_signal(dict(ev), "t1", T0)),
                "syslog_control_signal": _shot(sig)},
    }
    # An entry leaves the frozen-code parity run only when the two really differ. A line
    # that reaches the generic net agrees with it, and stays in the run.
    if (_shot(frozen.syslog_control_signal(dict(ev), "t1", T0))
            != entry["out"]["syslog_control_signal"]):
        entry["baseline"] = "absent"
        entry["baseline_reason"] = BASELINE_REASON
    return entry


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="exit 1 if a fixture is unrecorded")
    args = ap.parse_args(argv)
    with open(GOLDEN, encoding="utf-8") as fh:
        have = {json.dumps(json.loads(ln)["ev"], sort_keys=True) for ln in fh if ln.strip()}
    missing: list[dict] = []
    for pack in bake_rules.load_packs():
        for fx in pack["fixtures"]:
            entry = entry_for(pack["pack"], fx)
            if entry is not None and json.dumps(entry["ev"], sort_keys=True) not in have:
                missing.append(entry)
    if args.check:
        if missing:
            print(f"{len(missing)} pack fixture(s) are not in the corpus: run "
                  "telemetry-catalog/record_pack_corpus.py", file=sys.stderr)
            return 1
        return 0
    with open(GOLDEN, "a", encoding="utf-8") as fh:
        for entry in missing:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    print(f"recorded {len(missing)} pack fixture(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
