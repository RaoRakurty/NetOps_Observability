#!/usr/bin/env python3
"""Event parser engine — applies the event/parser catalog (events.yaml) to a raw
syslog event and yields a canonical event sharing the SAME identity model as the
metric plane (so events ⨝ metrics on device/ifName/peer).

Code-owned and unit-tested — the authoritative spec for the correlation engine's
src/correlation/producers.py syslog parsing. A raw syslog event (as delivered by
the Vector syslog source) looks like:
    {"hostname": "leaf1", "appname": "%BGP-5-ADJCHANGE",
     "message": "peer 10.0.0.1 (AS 65001) old state Established new state Idle",
     "timestamp": "2026-06-13T20:00:00Z"}

parse_event(ev, cat) -> CanonicalEvent | None (None = not a recognized family).
"""
from __future__ import annotations

import os
import re

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))


class EventCatalog:
    def __init__(self, families: dict):
        self.families = families
        self._tag_re = {n: re.compile(f["match_tag"], re.IGNORECASE)
                        for n, f in families.items()}

    @classmethod
    def load(cls, path: str | None = None) -> "EventCatalog":
        data = yaml.safe_load(open(path or os.path.join(HERE, "events.yaml")))
        return cls(data.get("families") or {})


def _first_group(pattern: str, text: str) -> str:
    if not pattern:
        return ""
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1) if m else ""


def _classify(token: str, state_cfg: dict) -> str:
    """First DECLARED state whose regex hits, in declaration order.

    Every family declared `{down: ..., up: ...}` until tracker 184, and those two
    still resolve down-before-up because that is the order they are written in.
    Iterating the declaration instead of hard-coding the pair is what lets a
    family name a state its phenomenon actually has — a MAC that is `flapping`
    or `moved`, a BGP session in `churn` — instead of being forced to call it
    "down" (a teardown that did not happen) or "" (no health claim at all, the
    defect tracker 184 records for mac_flap).
    """
    for name, pattern in state_cfg.items():
        if pattern and re.search(pattern, token, re.IGNORECASE):
            return str(name)
    return "unknown"


def _state_of(msg: str, state_cfg: dict, target_re: str | None) -> str:
    """Prefer the TRANSITION TARGET (e.g. token after 'new state' / 'to') so a flap
    INTO Established reads 'up' despite an 'old state Idle' down-token. Falls back
    to a whole-message down-beats-up scan when no explicit target is present."""
    if target_re:
        tgt = _first_group(target_re, msg)
        if tgt:
            cls = _classify(tgt, state_cfg)
            if cls != "unknown":
                return cls
    return _classify(msg, state_cfg)


def parse_event(ev: dict, cat: EventCatalog | None = None) -> dict | None:
    cat = cat or EventCatalog.load()
    host = str(ev.get("hostname") or "")
    if not host or host == "unknown":
        return None
    tag = str(ev.get("appname") or "")
    msg = str(ev.get("message") or "")
    # Cisco/Arista carry the family token in appname (%FAC-SEV-MNEMONIC); Nokia SR
    # Linux leaves appname nil ('-') and carries its structured eventType
    # (isisAdjacencyChange, remotePeerRemoved, ...) in the message. Match across
    # both so one grammar set is multi-vendor.
    matchtext = tag + " " + msg

    for fname, fam in cat.families.items():
        if not cat._tag_re[fname].search(matchtext):
            continue

        # try each vendor grammar in order; first whose required regexes hit wins
        extracted: dict[str, str] = {}
        for gram in fam.get("grammars", []):
            cand = {}
            for k, pat in gram.items():
                if k.endswith("_re"):
                    cand[k] = _first_group(pat, msg)
            # a grammar matches if its peer_re/ifname_re (whichever it declares) hit
            keyfields = [k for k in cand if k in ("peer_re", "ifname_re")]
            if keyfields:
                if all(cand[k] for k in keyfields):
                    extracted = cand
                    break
                continue
            # A vendor grammar with no peer/ifname requirement (the STP-instance
            # and PAN-CSV shapes). Accept it — but a LATER sibling that extracts
            # nothing must not overwrite one that did: that is how the MST0 TCN
            # lost its instance to the PVST grammar (tracker 184).
            if not extracted or any(cand.values()):
                extracted = cand
            if any(cand.values()):
                break
        # fall back to last grammar's (possibly partial) extraction
        if not extracted and fam.get("grammars"):
            g = fam["grammars"][-1]
            extracted = {k: _first_group(p, msg) for k, p in g.items() if k.endswith("_re")}

        state = _state_of(msg, fam.get("state", {}), fam.get("target_state_re"))
        sev = fam.get("severity", {}).get(state, "warn")

        # build canonical labels from the label spec (hostname or an *_re result)
        labels: dict[str, str] = {}
        for canon_key, src in fam.get("labels", {}).items():
            if src == "hostname":
                labels[canon_key] = host
            else:
                v = extracted.get(src, "")
                if v:
                    labels[canon_key] = v

        return {
            "event_type": fname,
            "labels": labels,
            "state": state,
            "severity": sev,
            "raw_ts": ev.get("timestamp"),
            "message": msg,
            "correlates_with": fam.get("correlates_with"),
            "join_on": fam.get("join_on", []),
        }
    return None
