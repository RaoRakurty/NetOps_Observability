#!/usr/bin/env python3
"""Event parser engine — applies the event/parser catalog (events.yaml) to a raw
syslog event and yields a canonical event sharing the SAME identity model as the
metric plane (so events ⨝ metrics on device/ifName/peer).

A3 — ONE GRAMMAR, TWO READERS. This file used to carry its own interpreter over
a per-family `match_tag` / `grammars` / `state` block, which was a SECOND copy of
the regexes `src/correlation/producers.py` classified with. It no longer does:
both read the `rules:` rows of `events.yaml`, through the same compiler
(`rule_model`). What differs is only what they BUILD from a matched rule — a
canonical event here, a correlation `Signal` there.

    events.yaml rules[]  --rule_model.compile_rule-->  guard / extract / emit
              |                                              |
              +--> parse_event()  → canonical event          |
              +--> producers.classify() → Signal  <----------+

A rule with no `family` (the FHRP/VTEP/EVPN grammars, the generic-alarm nets) is
skipped here: it makes no canonical-event claim, so the catalog has nothing to
say about it — exactly the behaviour the old family loop had.

A raw syslog event (as delivered by the Vector syslog source) looks like:
    {"hostname": "leaf1", "appname": "%BGP-5-ADJCHANGE",
     "message": "peer 10.0.0.1 (AS 65001) old state Established new state Idle",
     "timestamp": "2026-06-13T20:00:00Z"}

parse_event(ev, cat) -> CanonicalEvent | None (None = not a recognized family).
"""
from __future__ import annotations

import os
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "src", "correlation")))

from rule_model import Ctx, Rule

# `load` validates the rows and fills their defaults — the SAME normalization the
# bake applies, so the conformance reader can never see a shape the runtime
# would not.
from bake_rules import load

# The lanes that produce a canonical EVENT: the correlation engine's own syslog
# rules plus the catalog-only rows (firewall families no correlation lane
# consumes yet). Trap and port rows are a different plane and have no canonical
# syslog-event form.
EVENT_LANES = ("syslog", "catalog")


def _no_severity(ctx: Ctx) -> None:
    """The severity-floor guard belongs to the generic-alarm nets, which carry
    no family and are skipped before their guard is ever evaluated."""


class EventCatalog:
    """The event families plus the compiled rules that produce them."""

    def __init__(self, families: dict, rules: list[Rule] | None = None) -> None:
        self.families = families
        self.rules: list[Rule] = list(rules or [])

    @classmethod
    def load(cls, path: str | None = None) -> EventCatalog:
        data, rows = load(path or os.path.join(HERE, "events.yaml"))
        rules = [r for r in (compile_row(row) for row in rows)
                 if r.lane in EVENT_LANES and r.fidelity_key is not None]
        return cls(data.get("families") or {}, rules)


def compile_row(row: dict) -> Rule:
    from rule_model import compile_rule
    return compile_rule(row)


def parse_event(ev: dict, cat: EventCatalog | None = None) -> dict[str, Any] | None:
    cat = cat or EventCatalog.load()
    host = str(ev.get("hostname") or "")
    if not host or host == "unknown":
        return None
    tag = str(ev.get("appname") or "").upper()
    msg = str(ev.get("message") or "")
    # The SAME classification token the correlation lane builds (#31 envelope):
    # Cisco/Arista carry the family token in appname (%FAC-SEV-MNEMONIC), Nokia
    # SR Linux leaves appname nil ('-') and carries its structured eventType
    # (isisAdjacencyChange, remotePeerRemoved, …) in the message, so the guards
    # span both.
    ctoken = (tag + " " + str(ev.get("facility") or "") + " "
              + str(ev.get("event_type") or "")).upper()
    ctx = Ctx(
        {"ev": ev, "msg": msg, "tag": tag, "ctoken": ctoken},
        {"host": host, "ts_ms": 0, "tag": tag, "msg": msg},
        _no_severity,
        # CONFORMANCE reading: honours a `target_scope: catalog` transition
        # target the executable rule deliberately does not consult. Exactly one
        # rule declares that today (bgp_adjacency_change) and events.yaml
        # records why.
        catalog=True,
    )
    for rule in cat.rules:
        ctx.enter(rule.extract)
        ctx.vars["kind"] = rule.kind
        if rule.guard is None or not rule.guard(ctx):
            continue
        if rule.shadow:
            # A shadow row is measured, never believed — the same semantics the
            # runtime gives it.
            continue
        fam = cat.families.get(rule.fidelity_key or "", {})
        state = str(ctx.var("state")) if "state" in rule.extract else "unknown"
        assert rule.emit is not None
        severity = rule.emit.severity(ctx).value
        # Canonical labels from the family's label spec: `hostname`, or the name
        # of a var the rule extracts.
        labels: dict[str, str] = {}
        for canon_key, src in (fam.get("labels") or {}).items():
            if src == "hostname":
                labels[canon_key] = host
                continue
            if src not in rule.extract:
                continue
            v = ctx.var(src)
            if v:
                labels[canon_key] = str(v)
        return {
            "event_type": rule.fidelity_key,
            "rule_id": rule.rule_id,
            "labels": labels,
            "state": state,
            "severity": severity,
            "raw_ts": ev.get("timestamp"),
            "message": msg,
            "correlates_with": fam.get("correlates_with"),
            "join_on": fam.get("join_on", []),
        }
    return None
