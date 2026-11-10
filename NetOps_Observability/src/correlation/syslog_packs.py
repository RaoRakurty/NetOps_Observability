# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Vendor-pack syslog grammars: the engine's executor (tracker 387, plan §5.1, §6a).

A vendor pack is DATA (`telemetry-catalog/vendor-packs/<pack>.yaml`): envelope and
body grammars, a severity map, rule rows and fixtures. `bake_rules.py` compiles the
grammars into `parser_rules.py`, and `scripts/gen-syslog-packs.py` compiles the same
rows into the aggregator's VRL. There is ONE grammar with TWO executors, so Vector
and the engine cannot disagree about a line; the generated `vector test` suite pins
this module's answers against the shipped transform.

This module names no vendor and knows no message format. Adding a vendor adds a YAML
file; it changes nothing here.

STAGE [1] ONLY. Two questions are answered for `producers`:

  severity  What severity does the line's own TEXT state? Some platforms carry the
            real severity only there.
  floor     May that severity alarm on its own? `alarm_floor` is the pack's answer.
            Reading a severity correctly is not a licence to open an object (owner
            D3, "ingestion is not incident creation"): a line worse than the floor
            reaches the engine only through a typed rule, at the severity the rule
            states.

`parse` is the Python statement of what the aggregator's Stage B writes onto the
document. The engine never calls it on the ingest path: Vector already did the work.
It exists so that the generator can state the expected answer for every fixture, and
so a test can replay real lines without a running Vector.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

#: Mirrors the aggregator's keyword ladder (Stage B, "Severity reconcile"), which
#: tests/test_ingest_contract.py pins. Anything else reads as info.
_PRI_RANK: dict[str, int] = {
    "emergency": 2, "emerg": 2, "panic": 2, "alert": 2, "critical": 2, "crit": 2,
    "error": 3, "err": 3, "warning": 4, "warn": 4, "notice": 5, "debug": 7,
}
_NO_SEVERITY = 99
_TEMPLATE_RE = re.compile(r"\{(\w+)\}")


def normalized_label(rank: int) -> str:
    """The aggregator's `.normalized_severity` for an effective rank."""
    if rank <= 2:
        return "critical"
    if rank == 3:
        return "error"
    if rank == 4:
        return "warning"
    if rank == 5:
        return "notice"
    return "info"


class Grammar:
    """One baked body grammar, compiled once at import."""

    __slots__ = (
        "alarm_floor", "apps", "category", "event_type", "facility", "grammar_id",
        "literal", "native_code", "native_text", "pack", "parser_id", "regex",
        "sev_digit", "sev_map", "sev_word", "summary", "vendor", "with_msgid",
    )

    def __init__(self, row: Mapping[str, Any]) -> None:
        self.pack = str(row["pack"])
        self.vendor = str(row.get("vendor") or "")
        self.grammar_id = str(row["id"])
        self.parser_id = str(row["parser_id"])
        self.literal = str(row["literal"])
        self.apps = frozenset(str(a) for a in row.get("apps") or ())
        self.regex = re.compile(str(row["pattern"]))
        self.facility = str(row.get("facility") or "")
        self.event_type = str(row.get("event_type") or "")
        self.summary = str(row.get("summary") or "")
        self.sev_digit = str(row.get("sev_digit") or "")
        self.sev_word = str(row.get("sev_word") or "")
        self.sev_map: dict[str, int] = dict(row.get("sev_map") or {})
        self.native_text = str(row.get("native_text") or "")
        self.native_code = str(row.get("native_code") or "")
        floor = row.get("alarm_floor")
        self.alarm_floor = int(floor) if floor is not None else None
        self.category = str(row.get("category") or "")
        self.with_msgid = bool(row.get("with_msgid"))

    def haystack(self, msg: str, ev: Mapping[str, Any]) -> str:
        """The text this row reads: `<MSGID>: <message>` for a `with_msgid` row when the
        frame carries one (RFC 5424; `-` is its nil value), else the message."""
        if self.with_msgid:
            mid = str(ev.get("msgid") or "")
            if mid and mid != "-":
                return mid + ": " + msg
        return msg

    @property
    def reads_severity(self) -> bool:
        return bool(self.sev_digit or self.sev_word)

    def applies(self, msg: str, app: str, inventory_vendor: str) -> bool:
        """The cheap gates, in the order the generated VRL tests them."""
        if self.vendor and inventory_vendor and inventory_vendor != self.vendor:
            return False
        if self.literal not in msg:
            return False
        return not self.apps or app in self.apps

    def severity_of(self, m: re.Match[str]) -> int | None:
        if self.sev_digit:
            raw = m.group(self.sev_digit)
            return int(raw) if raw and raw.isdigit() else None
        if self.sev_word:
            return self.sev_map.get(m.group(self.sev_word) or "")
        return None


def _render(template: str, m: re.Match[str]) -> str:
    return _TEMPLATE_RE.sub(lambda v: m.group(v.group(1)) or "", template)


def _inventory_vendor(ev: Mapping[str, Any]) -> str:
    """The vendor the record's INVENTORY states. A vendor stamped by format
    matching is not a fact about the device, so it never narrows the grammars."""
    if ev.get("vendor_source") == "inventory":
        return str(ev.get("vendor") or "")
    return ""


class PackTable:
    """The baked pack rows, ready to run."""

    __slots__ = ("envelopes", "grammars", "severity_grammars")

    def __init__(self, grammars: Iterable[Mapping[str, Any]],
                 envelopes: Iterable[Mapping[str, Any]]) -> None:
        self.grammars = tuple(Grammar(g) for g in grammars)
        self.severity_grammars = tuple(g for g in self.grammars if g.reads_severity)
        self.envelopes = tuple(
            (str(e["literal"]), re.compile(str(e["pattern"])), e)
            for e in envelopes)

    def severity_hit(self, ev: Mapping[str, Any], msg: str) -> tuple[int, int] | None:
        """(embedded severity, alarm floor) from the first grammar that matches
        the message and states a known severity. None otherwise.

        On the ingest path for every line, so the common case is one substring
        test per severity grammar and nothing else.
        """
        for g in self.severity_grammars:
            if g.literal not in msg:
                continue
            app = str(ev.get("appname") or "").lower()
            if not g.applies(msg, app, _inventory_vendor(ev)):
                continue
            m = g.regex.search(msg)
            if m is None:
                continue
            n = g.severity_of(m)
            if n is not None and g.alarm_floor is not None:
                return n, g.alarm_floor
        return None

    def strip_envelope(self, msg: str) -> tuple[str, dict[str, str]]:
        """(message, fields to set) after the first envelope rule that matches."""
        for literal, regex, spec in self.envelopes:
            if literal not in msg:
                continue
            m = regex.search(msg)
            if m is None:
                continue
            fields = {str(spec["preserve_as"]): msg}
            skip = set(spec.get("skip_values") or ())
            for field, group in (spec.get("lift") or {}).items():
                v = m.group(group) or ""
                if v and v not in skip:
                    fields[str(field)] = v
            clean = m.group(spec["message"]) or ""
            fields["message"] = clean
            return clean, fields
        return msg, {}

    def parse(self, ev: Mapping[str, Any], inventory_vendor: str = "") -> dict[str, Any]:
        """The document fields Stage B sets for this raw event.

        `ev` carries `hostname`, `appname`, `message`, `severity` as the aggregator
        receives them. Only keys Stage B writes for a pack hit appear; an empty
        dict means no pack has an opinion and Stage B's other parsers run.
        """
        msg, out = self.strip_envelope(str(ev.get("message") or ""))
        app = str(ev.get("appname") or "unknown").lower()
        for g in self.grammars:
            text = g.haystack(msg, ev)
            if not g.applies(text, app, inventory_vendor):
                continue
            m = g.regex.search(text)
            if m is None:
                continue
            out["parser_id"] = g.parser_id
            out["parser_status"] = "parsed"
            for key, template in (("facility", g.facility),
                                  ("event_type", g.event_type),
                                  ("summary", g.summary)):
                text = _render(template, m) if template else ""
                if text:
                    out[key] = text.lower() if key == "event_type" else text
            if g.vendor and not inventory_vendor:
                out["vendor"] = g.vendor
                out["vendor_source"] = "format"
            if g.native_text and m.group(g.native_text):
                out["severity_native_text"] = m.group(g.native_text)
            if g.native_code and m.group(g.native_code):
                out["severity_native_code"] = m.group(g.native_code)
            if g.category:
                out["event_category"] = g.category
                out["dedup_key"] = "|".join((
                    str(ev.get("hostname") or "unknown"),
                    str(ev.get("appname") or "unknown"),
                    str(out.get("event_type") or ""),
                ))
            embedded = g.severity_of(m)
            pri = _PRI_RANK.get(str(ev.get("severity") or "info").lower(), 6)
            eff = pri if embedded is None or embedded >= pri else embedded
            out["normalized_severity"] = normalized_label(eff)
            return out
        return out
