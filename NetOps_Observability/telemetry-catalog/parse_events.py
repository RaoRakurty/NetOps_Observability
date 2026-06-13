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
    if re.search(state_cfg.get("down", r"(?!)"), token, re.IGNORECASE):
        return "down"
    if re.search(state_cfg.get("up", r"(?!)"), token, re.IGNORECASE):
        return "up"
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

    for fname, fam in cat.families.items():
        if not cat._tag_re[fname].search(tag):
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
            if keyfields and all(cand[k] for k in keyfields):
                extracted = cand
                break
            if not keyfields:  # vendor with no extraction reqs (rare) — accept
                extracted = cand
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
