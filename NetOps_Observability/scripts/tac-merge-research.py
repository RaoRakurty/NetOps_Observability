#!/usr/bin/env python3
"""tac-merge-research.py — merge vendor TAC research into the escalation taxonomy.

    Research  ai/tac/research/<vendor>.yaml   (INPUT, written by the research pass)
    Taxonomy  ai/tac/classes.yaml             (the closed class list + intent vocabulary)
    Plans     ai/tac/plans/<dialect>.yaml     (per-dialect intent -> command bindings)

The schema for all three is `ai/tac/README.md`; this script is that document made
executable. It is the ONLY sanctioned way research reaches the shipped data,
because it is the only path that applies the four rules the data rests on:

  1. AN UNKNOWN FIELD IS A REFUSAL, not silence. A typo in a research file must
     fail the merge, not quietly drop the value it carried.
  2. A COMMAND THAT IS NOT A READ-ONLY SHOW NEVER LANDS. Same closed grammar the
     Go loader and the live SSH runner apply — lead token in show/display/get/
     info, display-only pipe filters, no chaining/redirection/substitution, and
     only the six documented placeholders.
  3. A DETECTION RULE MAY NOT NAME SOMETHING THAT DOES NOT EXIST. Alert names,
     signature ids, issue ids and skill ids are checked against this repository;
     an id that is not there is DROPPED with a reason on stdout, never merged.
  4. NOTHING IS OVERWRITTEN SILENTLY. An existing binding is only replaced when
     the new record is `verified: capture` and the old one was `doc_claimed` —
     i.e. only when evidence replaces documentation. Anything else is reported
     and skipped.

It is IDEMPOTENT: running it twice changes nothing, which is what makes
`--check` (the CI mode) meaningful — it exits non-zero if a merge would change
the checked-in data, so what ships is always the merged result.

Standard library only (CLAUDE.md §6). The YAML subset it reads and writes is the
one internal/tac/yamlmin.go parses; nothing here emits a construct that parser
would refuse, and the Go loader is the real gate either way — this script's own
validation exists so a bad merge fails HERE, with a filename and a line, rather
than at api boot.

Usage:
    python3 scripts/tac-merge-research.py           # merge and write
    python3 scripts/tac-merge-research.py --check   # fail if a merge would change anything
    python3 scripts/tac-merge-research.py --vendor cisco
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Any

# ── locations ────────────────────────────────────────────────────────────────

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)                       # NetOps_Observability/
TAC = os.path.join(REPO, "src", "backend", "ai", "tac")
RESEARCH_DIR = os.path.join(TAC, "research")
CLASSES = os.path.join(TAC, "classes.yaml")
PLANS_DIR = os.path.join(TAC, "plans")
BACKEND = os.path.join(REPO, "src", "backend")
CONFIG = os.path.join(REPO, "src", "config")
CORRELATION = os.path.join(REPO, "src", "correlation")

# ── the closed grammars (kept in lockstep with internal/tac) ──────────────────

def _load_intent_areas() -> set:
    """The closed area set, read from internal/tac/tac.go.

    There is ONE authority for what an intent area may be, and it is the Go
    engine that enforces it. Re-typing the list here would guarantee drift: this
    script would merge an area the loader then refuses, and the failure would
    land at api boot instead of at merge time.
    """
    src = _read(os.path.join(BACKEND, "internal", "tac", "tac.go"))
    block = src[src.index("var intentAreas = map[string]struct{}{"):]
    block = block[:block.index("\n}")]
    return set(re.findall(r'"([a-z][a-z0-9-]*)":', block))


CLASS_PROTOCOLS = {
    "bgp", "ospf", "isis", "interface", "l2", "overlay", "mpls", "qos",
    "hardware", "system", "config", "generic",
}
PLACEHOLDERS = {"{if}", "{peer}", "{prefix}", "{vrf-scope}", "{rid}", "{area}",
                "{vlan}", "{vni}"}
READ_ONLY_LEAD = {"show", "display", "get", "info"}
READ_ONLY_FILTER = {
    "include", "i", "exclude", "e", "begin", "b", "section", "count",
    "match", "except", "find", "last", "first", "trim", "display", "no-more",
}
FORBIDDEN_CHARS = [";", "\n", "\r", "&", "`", "$(", "${", ">", "<", "!"]
VERIFIED = {"capture", "doc_claimed"}

SLUG_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
INTENT_RE = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z0-9][a-z0-9_-]*){1,3}$")

class Refusal(Exception):
    """A refusal is a first-class outcome: it names the file, the record and why."""


# ── a minimal YAML reader, matching internal/tac/yamlmin.go ───────────────────
#
# Python's standard library has no YAML parser and PyYAML is not on the
# dependency allowlist, so the same subset the Go side reads is parsed here:
# block mappings, block sequences, quoted scalars, block scalars, flow
# sequences/mappings, comments, space indentation. Anything else RAISES rather
# than being guessed at — a parser that skips what it does not understand turns a
# typo into missing data.


def _strip_comment(text: str) -> str:
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
    return text


def _unquote(value: str, line: int) -> str:
    value = value.strip()
    if not value:
        return ""
    if value[0] == "'":
        end = value.rfind("'")
        if end == 0:
            raise Refusal("line %d: unterminated single-quoted scalar" % line)
        return value[1:end].replace("''", "'")
    if value[0] == '"':
        end = value.rfind('"')
        if end == 0:
            raise Refusal("line %d: unterminated double-quoted scalar" % line)
        body = value[1:end]
        if "\\" in body:
            try:
                return body.encode().decode("unicode_escape")
            except (UnicodeDecodeError, UnicodeEncodeError):
                return body
        return body
    return _strip_comment(value).strip()


def _split_flow(text: str) -> list:
    """Split a flow collection on commas that are outside quotes AND outside a
    nested bracket. `{cmd: "x", intent: y, params: [peer, if]}` has three
    entries, not four — a depth-blind split silently corrupts the last one."""
    out, buf, quote, depth = [], [], "", 0
    for ch in text:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch in "[{":
            depth += 1
            buf.append(ch)
        elif ch in "]}":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    out.append("".join(buf))
    return out


def _split_key(text: str):
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "#":
            return None
        elif ch == ":" and (i + 1 == len(text) or text[i + 1] == " "):
            key = text[:i].strip()
            if not key:
                return None
            try:
                key = _unquote(key, 0)
            except Refusal:
                pass
            return key, text[i + 1:].strip()
    return None


def _scan(src: str) -> list:
    lines = []
    for n, raw in enumerate(src.replace("\r\n", "\n").split("\n"), start=1):
        indent = len(raw) - len(raw.lstrip(" "))
        if "\t" in raw[:indent]:
            raise Refusal("line %d: tab in indentation" % n)
        body = raw[indent:]
        if not body or body.startswith("#"):
            continue
        if body.startswith("---") or body.startswith("..."):
            if body.strip() == "---" and not lines:
                continue
            raise Refusal("line %d: multiple documents are not supported" % n)
        lines.append((indent, body, n))
    return lines


def _inline(value: str, line: int):
    value = value.strip()
    if value.startswith("["):
        if not value.endswith("]"):
            raise Refusal("line %d: unterminated flow sequence" % line)
        out = []
        for part in _split_flow(value[1:-1]):
            part = part.strip()
            if not part:
                continue
            if part.startswith("{") or part.startswith("["):
                raise Refusal("line %d: nested flow collections are not supported" % line)
            out.append(_unquote(part, line))
        return out
    if value.startswith("{"):
        if not value.endswith("}"):
            raise Refusal("line %d: unterminated flow mapping" % line)
        out = {}
        for part in _split_flow(value[1:-1]):
            part = part.strip()
            if not part:
                continue
            kv = _split_key(part)
            if kv is None:
                raise Refusal("line %d: flow entry %r is not `key: value`" % (line, part))
            k, v = kv
            v = v.strip()
            if v.startswith("["):
                if not v.endswith("]"):
                    raise Refusal("line %d: unterminated flow sequence" % line)
                out[k] = [_unquote(x, line) for x in _split_flow(v[1:-1]) if x.strip()]
                continue
            if v.startswith("{"):
                raise Refusal("line %d: nested flow collections are not supported" % line)
            out[k] = _unquote(v, line)
        return out
    return _unquote(value, line)


def _parse_block(lines: list, pos: int, indent: int):
    if pos >= len(lines):
        return {}, pos
    if lines[pos][1].startswith("- ") or lines[pos][1] == "-":
        return _parse_seq(lines, pos, indent)
    return _parse_map(lines, pos, indent)


def _parse_value(rest: str, lines: list, pos: int, indent: int, num: int):
    rest = rest.strip()
    if rest in ("|", "|-", ">", ">-", "|+", ">+"):
        body, base = [], -1
        while pos < len(lines) and lines[pos][0] > indent:
            if base < 0:
                base = lines[pos][0]
            body.append(" " * (lines[pos][0] - base) + lines[pos][1])
            pos += 1
        sep = " " if rest.startswith(">") else "\n"
        return sep.join(body), pos
    if rest:
        return _inline(rest, num), pos
    if pos >= len(lines):
        return "", pos
    nxt_indent, nxt_body, _ = lines[pos]
    if nxt_indent > indent:
        return _parse_block(lines, pos, nxt_indent)
    if nxt_indent == indent and (nxt_body.startswith("- ") or nxt_body == "-"):
        return _parse_seq(lines, pos, indent)
    return "", pos


def _parse_map(lines: list, pos: int, indent: int):
    out = {}
    while pos < len(lines):
        cur_indent, body, num = lines[pos]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise Refusal("line %d: unexpected indentation in mapping" % num)
        if body.startswith("- ") or body == "-":
            break
        kv = _split_key(body)
        if kv is None:
            raise Refusal("line %d: expected `key: value`, got %r" % (num, body))
        key, rest = kv
        if key in out:
            raise Refusal("line %d: duplicate key %r" % (num, key))
        pos += 1
        out[key], pos = _parse_value(rest, lines, pos, indent, num)
    return out, pos


def _parse_seq(lines: list, pos: int, indent: int):
    out = []
    while pos < len(lines):
        cur_indent, body, num = lines[pos]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise Refusal("line %d: unexpected indentation in sequence" % num)
        if not (body.startswith("- ") or body == "-"):
            break
        item_body = "" if body == "-" else body[2:].strip()
        pos += 1
        kv = None if item_body.startswith("{") else _split_key(item_body)
        if kv is not None:
            item_indent = cur_indent + 2
            item = {}
            key, rest = kv
            item[key], pos = _parse_value(rest, lines, pos, item_indent, num)
            while pos < len(lines) and lines[pos][0] == item_indent and not (
                lines[pos][1].startswith("- ") or lines[pos][1] == "-"
            ):
                k2 = _split_key(lines[pos][1])
                if k2 is None:
                    raise Refusal("line %d: expected `key: value`" % lines[pos][2])
                if k2[0] in item:
                    raise Refusal("line %d: duplicate key %r" % (lines[pos][2], k2[0]))
                n2 = lines[pos][2]
                pos += 1
                item[k2[0]], pos = _parse_value(k2[1], lines, pos, item_indent, n2)
            out.append(item)
            continue
        if item_body == "":
            if pos >= len(lines) or lines[pos][0] <= cur_indent:
                raise Refusal("line %d: empty sequence item" % num)
            sub, pos = _parse_block(lines, pos, lines[pos][0])
            out.append(sub)
            continue
        out.append(_inline(item_body, num))
    return out, pos


def parse_yaml(src: str):
    lines = _scan(src)
    if not lines:
        return {}
    doc, pos = _parse_block(lines, 0, lines[0][0])
    if pos != len(lines):
        raise Refusal("line %d: unexpected indentation" % lines[pos][2])
    return doc


# ── emitting the subset back out ─────────────────────────────────────────────

_PLAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/+-]*$")


def emit_scalar(value) -> str:
    value = "" if value is None else str(value)
    if value == "":
        return "''"
    if _PLAIN_RE.match(value) and not value.endswith(" "):
        return value
    return "'" + value.replace("'", "''") + "'"


def emit_block(value: str, indent: str) -> list:
    """Render a long scalar as a folded block so a line stays readable and the
    Go reader's line-length assumptions hold."""
    words, line, lines = str(value).split(), "", []
    for w in words:
        if line and len(line) + 1 + len(w) > 74:
            lines.append(indent + line)
            line = w
        else:
            line = (line + " " + w).strip()
    if line:
        lines.append(indent + line)
    return lines


# ── repository fact lookups ──────────────────────────────────────────────────


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as err:
        # An unreadable fact source is NOT "assume the id is fine": it is a hard
        # stop, because merging on an empty allowlist would drop every cue.
        raise Refusal("cannot read %s: %s" % (path, err)) from err


def repo_facts() -> dict:
    alerts = set()
    for name in ("rules.yaml", "rules-scale-slo.yaml"):
        alerts |= set(re.findall(r"(?m)^\s*-?\s*alert:\s*([A-Za-z0-9_]+)",
                                 _read(os.path.join(CONFIG, name))))
    hyps = set(re.findall(r"sig\.ent\.[a-z0-9][a-z0-9.-]*[a-z0-9]",
                          _read(os.path.join(CORRELATION, "catalog.py"))))
    sigs = set(re.findall(r'ID:\s*"([a-z0-9-]+)"',
                          _read(os.path.join(BACKEND, "internal", "protocoldiag", "analyze.go"))))
    issues = set(re.findall(r'ID:\s*"([a-z0-9-]+)"',
                            _read(os.path.join(BACKEND, "internal", "protocoldiag", "catalog.go"))))
    skills_dir = os.path.join(BACKEND, "ai", "skills")
    skills = {e for e in os.listdir(skills_dir) if os.path.isdir(os.path.join(skills_dir, e))}
    return {"alerts": alerts, "hypotheses": hyps, "signatures": sigs,
            "issues": issues, "skills": skills}


# ── validation ───────────────────────────────────────────────────────────────


def only_fields(record: dict, allowed: set, what: str) -> None:
    unknown = sorted(set(record) - allowed)
    if unknown:
        raise Refusal("%s: unknown field(s) %s (allowed: %s)"
                      % (what, ", ".join(unknown), ", ".join(sorted(allowed))))


def validate_command(command: str, what: str) -> str:
    """The read-only grammar, byte-for-byte the one internal/tac applies."""
    cmd = " ".join(command.split())
    if not cmd:
        raise Refusal("%s: empty command" % what)
    for bad in FORBIDDEN_CHARS:
        if bad in cmd:
            raise Refusal("%s: command contains the disallowed metacharacter %r" % (what, bad))
    segments = cmd.split("|")
    lead = segments[0].split()
    if not lead or lead[0].lower() not in READ_ONLY_LEAD:
        raise Refusal("%s: %r does not lead with a read-only verb (%s)"
                      % (what, cmd, "/".join(sorted(READ_ONLY_LEAD))))
    for seg in segments[1:]:
        toks = seg.split()
        if not toks:
            raise Refusal("%s: empty pipe segment in %r" % (what, cmd))
        if toks[0].lower() not in READ_ONLY_FILTER:
            raise Refusal("%s: pipe filter %r is not a display-only filter" % (what, toks[0]))
    return cmd


# ── the shipped data, read back in ───────────────────────────────────────────


def load_classes() -> dict:
    doc = parse_yaml(_read(CLASSES))
    if not isinstance(doc, dict):
        raise Refusal("classes.yaml: document must be a mapping")
    doc.setdefault("intents", [])
    doc.setdefault("classes", [])
    return doc


def load_plan(slug: str):
    path = os.path.join(PLANS_DIR, slug + ".yaml")
    if not os.path.exists(path):
        return None
    doc = parse_yaml(_read(path))
    doc.setdefault("bindings", {})
    doc.setdefault("baseline", [])
    doc.setdefault("sources", [])
    return doc


# ── writers ──────────────────────────────────────────────────────────────────


def render_classes(doc: dict) -> str:
    out = []
    out.append("# classes.yaml — the TAC escalation issue-class taxonomy and intent vocabulary.")
    out.append("#")
    out.append("# Schema, closed enums and the rules for adding to this file: ai/tac/README.md.")
    out.append("# Every id under `detect:` is REAL and is proven so by")
    out.append("# internal/tac/reference_test.go, which greps this repo for each one. Never")
    out.append("# invent a name here — an invented detection rule is a rule that can never fire.")
    out.append("#")
    out.append("# MACHINE-MERGED from ai/tac/research/*.yaml by scripts/tac-merge-research.py.")
    out.append("# Edit the research file or the script, not this file: a hand edit here is")
    out.append("# reverted the next time the merge runs, and `--check` fails in CI meanwhile.")
    out.append("schema_version: 1")
    out.append("version: " + emit_scalar(doc.get("version", "")))
    out.append("")
    out.append("# ── the closed intent vocabulary ───────────────────────────────────────────")
    out.append("# An intent is a vendor-neutral command CONCEPT. Plans bind intents to actual")
    out.append("# commands per dialect; an intent a dialect does not bind is shown to the")
    out.append("# operator as unbound, never guessed.")
    out.append("intents:")
    for intent in doc["intents"]:
        out.append("  - id: " + intent["id"])
        out.append("    area: " + intent["area"])
        out.append("    title: " + emit_scalar(intent.get("title", "")))
        if intent.get("note"):
            out.append("    note: " + emit_scalar(intent["note"]))
    out.append("")
    out.append("# ── the issue-class taxonomy ───────────────────────────────────────────────")
    out.append("classes:")
    for cls in doc["classes"]:
        out.append("  - id: " + cls["id"])
        out.append("    title: " + emit_scalar(cls.get("title", "")))
        out.append("    protocol: " + cls.get("protocol", "generic"))
        for key in ("summary", "tac_first_look"):
            if cls.get(key):
                out.append("    %s: >-" % key)
                out += emit_block(cls[key], "      ")
        detect = cls.get("detect") or {}
        if detect:
            out.append("    detect:")
            for key in ("alerts", "hypotheses", "signatures", "skills", "issues", "log_regex"):
                values = detect.get(key) or []
                if not values:
                    continue
                out.append("      %s:" % key)
                for value in values:
                    out.append("        - " + emit_scalar(value))
        intents = cls.get("intents") or []
        if intents:
            out.append("    intents:")
            for intent in intents:
                out.append("      - " + intent)
        else:
            out.append("    intents: []")
        if cls.get("sources"):
            out.append("    sources:")
            for src in cls["sources"]:
                out.append("      - title: " + emit_scalar(src["title"]))
                out.append("        url: " + src["url"])
                if src.get("retrieved"):
                    out.append("        retrieved: " + src["retrieved"])
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def render_plan(doc: dict) -> str:
    out = []
    out.append("# plans/%s.yaml — the %s command plan for the TAC escalation pack."
               % (doc["dialect"], doc.get("display", doc["dialect"])))
    out.append("#")
    out.append("# Schema: ai/tac/README.md §4. Every command here is a READ-ONLY show, proven")
    out.append("# by the loader (protocoldiag.ValidateReadOnly) and again by the runner. An")
    out.append("# intent this dialect does not bind is simply ABSENT — the plan preview shows")
    out.append("# it as unbound rather than rendering another vendor's command at this device.")
    out.append("#")
    out.append("# `verified: doc_claimed` means the vendor documents the command and Correlix")
    out.append("# has not run it on this platform. `consent: true` marks a command the vendor")
    out.append("# says is NOT routine (a core dump, a control-plane load, a file written on the")
    out.append("# device): it never runs by default and never sits in a baseline.")
    out.append("# `read_only_exception` is a CITED documented-status read whose text carries a")
    out.append("# token the grammar refuses on sight.")
    out.append("#")
    out.append("# MACHINE-MERGED from ai/tac/research/*.yaml by scripts/tac-merge-research.py.")
    out.append("schema_version: 1")
    out.append("dialect: " + doc["dialect"])
    out.append("profile: " + doc["profile"])
    out.append("display: " + emit_scalar(doc.get("display", "")))
    out.append("version: " + emit_scalar(doc.get("version", "")))
    if doc.get("sources"):
        out.append("")
        out.append("# The dialect's default citation set. A doc_claimed binding inherits it.")
        out.append("sources:")
        for src in doc["sources"]:
            out.append("  - title: " + emit_scalar(src["title"]))
            out.append("    url: " + src["url"])
            if src.get("retrieved"):
                out.append("    retrieved: " + src["retrieved"])
    out.append("")
    out.append("# baseline — collected for EVERY class: the vendor-standard set a TAC engineer")
    out.append("# opens before anything issue-specific.")
    out.append("baseline:")
    for intent in doc["baseline"]:
        out.append("  - " + intent)
    if doc.get("optional"):
        out.append("")
        out.append("# optional — off by default: large and slow captures the operator opts into.")
        out.append("optional:")
        for intent in doc["optional"]:
            out.append("  - " + intent)
    out.append("")
    out.append("bindings:")
    for intent in doc["bindings"]:
        binding = doc["bindings"][intent]
        out.append("  %s:" % intent)
        out.append("    command: " + emit_scalar(binding["command"]))
        out.append("    verified: " + binding.get("verified", "doc_claimed"))
        if binding.get("consent") == "true":
            out.append("    consent: true")
            out.append("    consent_note: >-")
            out += emit_block(binding.get("consent_note", ""), "      ")
        if binding.get("read_only_exception"):
            out.append("    read_only_exception: >-")
            out += emit_block(binding["read_only_exception"], "      ")
        if binding.get("sources"):
            out.append("    sources:")
            for src in binding["sources"]:
                out.append("      - title: " + emit_scalar(src["title"]))
                out.append("        url: " + src["url"])
                if src.get("retrieved"):
                    out.append("        retrieved: " + src["retrieved"])
        for key in ("max_bytes", "timeout_s"):
            if binding.get(key):
                out.append("    %s: %s" % (key, binding[key]))
    return "\n".join(out).rstrip() + "\n"


# ── the research schema (as actually written) ────────────────────────────────
#
# The research files predate ai/tac/README.md and use the brief's schema. That
# is the input of record, so this script reads THAT and translates:
#
#   vendor:            a DIALECT slug ("cisco-iosxe"), not a vendor id
#   sources:           [{title, url}]  — the file's citation set
#   tac_baseline:      {commands: [...], notes, sources}
#   issues: [{id, class, proposed_class?, title, symptoms, log_signatures,
#             likely_causes, commands: [{cmd, intent, params?, writes_file?}],
#             tac_first_look, sources}]
#
# and a command entry may also be a bare string (the Cisco baseline).

RESEARCH_TOP_FIELDS = {"vendor", "dialect", "sources", "tac_baseline", "issues",
                       "schema_version", "notes"}
BASELINE_FIELDS = {"commands", "notes", "sources"}
ISSUE_FIELDS = {"id", "key", "class", "proposed_class", "title", "symptoms",
                "log_signatures", "likely_causes", "commands", "tac_first_look",
                "sources", "notes"}
COMMAND_FIELDS = {"cmd", "command", "intent", "params", "writes_file", "notes",
                  "verified", "sources", "read_only_exception", "consent_note"}
SOURCE_FIELDS = {"title", "url", "retrieved"}

# ── dialect slug → vendorprofile id + label ──────────────────────────────────
#
# A research file may name a dialect that has no plan file yet. Rather than
# refusing 40 cited issues to protect an empty directory, the merge CREATES the
# plan from this table — which is the same slug↔profile join internal/tac's
# DialectSlug performs, written down once so the two cannot drift.
DIALECT_PROFILES = {
    "cisco-iosxe": ("cisco/ios_xe", "Cisco IOS-XE"),
    "cisco-ios": ("cisco/ios", "Cisco IOS"),
    "cisco-iosxr": ("cisco/ios_xr", "Cisco IOS-XR"),
    "cisco-nxos": ("cisco/nx-os", "Cisco NX-OS"),
    "cisco-asa": ("cisco/asa", "Cisco ASA"),
    "arista-eos": ("arista/eos", "Arista EOS"),
    "juniper-junos": ("juniper/junos", "Juniper Junos"),
    "nokia-sros": ("nokia/sros", "Nokia SR OS"),
    "nokia-srlinux": ("nokia/srlinux", "Nokia SR Linux"),
    "huawei-vrp": ("huawei/vrp", "Huawei VRP"),
    "fortinet-fortios": ("fortinet/fortios", "Fortinet FortiOS"),
    "paloalto-panos": ("paloalto/pan-os", "Palo Alto PAN-OS"),
    "mikrotik-routeros": ("mikrotik/routeros", "MikroTik RouterOS"),
}


# ── (1) cross-vendor class synonyms ──────────────────────────────────────────
#
# Ten concepts were named differently by different research passes
# (README-nokia-huawei-fortinet-paloalto.md, "Cross-file synonyms to normalise").
# One name wins per row, and the winner is the one already in the §2 taxonomy
# where there is one — `environment` folds into `hardware-fault` rather than
# becoming a second name for it.
CANONICAL_CLASS = {
    "lacp-bundle": "lag-lacp",
    "port-channel-lacp": "lag-lacp",
    "snmp-agent": "snmp",
    "bfd-session": "bfd",
    "acl-drops": "acl",
    "mpls-rsvp": "mpls-rsvp-te",
    "mpls-te": "mpls-rsvp-te",
    "l3vpn-vprn": "mpls-l3vpn",
    "l3vpn": "mpls-l3vpn",
    "logging-pipeline": "logging",
    "process-crash": "process-health",
    "software-install": "software-upgrade",
    "environment": "hardware-fault",
}

# ── placeholder normalisation ────────────────────────────────────────────────
#
# The research writes `<peer>`; the command table matches `{peer}`. The names
# also vary by vendor for the same concept, so they are folded onto the six (now
# eight) Correlix can actually FILL from an incident.
#
# A placeholder that is NOT in this map is a value Correlix has no source for —
# an IOS-XR `<loc>`, a `<slot>`, an NPU id, a process id. Binding a command whose
# argument can never be supplied would render it in an unscoped form that is
# either invalid or fleet-wide. Those records are REFUSED and listed, which is
# the honest outcome: the command is real, and Correlix cannot yet run it.
PLACEHOLDER_ALIASES = {
    "if": "{if}", "interface": "{if}", "interface-name": "{if}", "intf": "{if}",
    "port-id": "{if}", "port": "{if}", "ifname": "{if}",
    "peer": "{peer}", "neighbor": "{peer}", "neighbor-address": "{peer}",
    "neighbour": "{peer}", "peer-address": "{peer}",
    "prefix": "{prefix}", "destination-prefix": "{prefix}", "network": "{prefix}",
    "ip-prefix": "{prefix}", "route": "{prefix}",
    "vrf": "{vrf-scope}", "vrf-name": "{vrf-scope}", "instance": "{vrf-scope}",
    "routing-instance": "{vrf-scope}", "routing-instance-name": "{vrf-scope}",
    "virtual-router": "{vrf-scope}", "logical-router": "{vrf-scope}",
    "ni": "{vrf-scope}", "network-instance": "{vrf-scope}",
    "vsys": "{vrf-scope}", "vdom": "{vrf-scope}",
    "rid": "{rid}", "router-id": "{rid}",
    "area": "{area}",
    "vlan": "{vlan}", "vlan-id": "{vlan}",
    "vni": "{vni}",
}

# ── (2) the documented-status-read allowlist ─────────────────────────────────
#
# The read-only grammar judges a command by its LEAD TOKEN. Several vendors
# spell a pure status print with a token that reads like an action, and refusing
# those on the word alone would drop evidence the vendor's own TAC asks for
# first. The allowlist is therefore EXPLICIT, per dialect, EXACT-MATCH (no
# prefixes, no wildcards) and CITED — the citation travels into the binding and
# the loader refuses an exception that carries none.
#
# Everything not listed here still fails closed.
READ_ONLY_EXCEPTIONS = {
    "fortinet-fortios": {
        "diagnose debug crashlog read":
            "a status print of the stored crash log; it reads, it does not enable debugging",
        "diagnose debug config-error-log read":
            "a status print of the configuration-error log",
        "diagnose debug rating":
            "prints the FortiGuard server ratings this unit is using",
        "diagnose debug fsso-polling detail":
            "prints the FSSO polling state",
        "diagnose debug fsso-polling summary":
            "prints the FSSO polling summary",
        "diagnose debug fsso-polling user":
            "prints the FSSO polled user list",
        "diagnose debug authd fsso list":
            "prints the authd FSSO logon list",
        "diagnose debug authd fsso server-status":
            "prints the authd FSSO server status",
    },
    "huawei-vrp": {
        "dir": "lists the storage device so the operator can confirm a diagnostic "
               "file was written; Huawei's own collection procedure uses it",
    },
}
EXCEPTION_SOURCE = {
    "fortinet-fortios": ("FortiOS CLI troubleshooting cheat sheet",
                         "https://docs.fortinet.com/document/fortigate/7.4.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet"),
    "huawei-vrp": ("Huawei VRP — collecting fault information",
                   "https://support.huawei.com/enterprise/en/doc/EDOC1100280260/c4073c75/collecting-fault-information"),
}

# ── (4) the explicit refusals ────────────────────────────────────────────────
#
# Each is a documented command that this collector will NOT run in W1, with the
# reason. They are listed in the merge report rather than silently dropped: the
# point of the report is that an operator can see what Correlix decided not to
# do and why.
EXPLICIT_REFUSALS = [
    (re.compile(r"^\s*test\s+authentication\b.*\bpassword\b", re.I),
     "takes a cleartext credential on the command line; an evidence collector must never "
     "put a password on a device's command line or in an audit record"),
    (re.compile(r"^\s*(scp|tftp|ftp)\s+export\b", re.I),
     "pushes a file to an arbitrary external host instead of returning output over Correlix's "
     "own SSH channel; that is a different trust model from a read"),
    (re.compile(r"^\s*diagnose\s+sniffer\s+packet\b", re.I),
     "is a live packet capture with an operator-supplied BPF; it belongs behind the Packet "
     "Capture module's existing closed BPF grammar, not the read-only command table"),
    (re.compile(r"^\s*diagnose\s+test\s+application\b", re.I),
     "selects a daemon debug LEVEL, and some levels restart the daemon; it needs a per-daemon, "
     "per-level allowlist, not a prefix match"),
    (re.compile(r"^\s*diagnose\s+test\s+authserver\b", re.I),
     "takes a cleartext credential on the command line"),
    (re.compile(r"^\s*diagnose\s+sys\s+session\s+filter\b", re.I),
     "sets daemon-side read scope; it changes no configuration and clears nothing, but it does "
     "leave state behind on the device — pending a product decision on scope-setters"),
    (re.compile(r"^\s*execute\s+log\s+filter\b", re.I),
     "sets daemon-side read scope; pending the same product decision as the session filter"),
    (re.compile(r"^\s*(ping|traceroute|tracert|tracepath)\b", re.I),
     "transmits from the device rather than reading it. W1's collector reads state; an active "
     "probe is a different act with a different blast radius and needs its own consent path"),
    (re.compile(r"^\s*(clear|reload|reset|restart|write|copy|delete|erase|configure|conf)\b", re.I),
     "is a state-changing command; it can never be part of a read-only collection"),
]

# Commands whose vendor documentation says they are NOT routine. They bind, but
# with consent: true and the vendor's own caveat, and they are never in a
# baseline. `writes_file: true` in the research is the primary signal; these
# patterns catch the ones whose caveat is about load or authorisation instead.
CONSENT_PATTERNS = [
    (re.compile(r"^\s*admin\s+tech-support\b", re.I),
     "Nokia's own reference says this creates a system CORE DUMP and should only be used with "
     "authorised direction of Nokia support. It is not a routine collector."),
    (re.compile(r"^\s*display\s+diagnostic-information\b", re.I),
     "Huawei warns that this markedly raises CPU and degrades device performance, and that its "
     "output contains personal data (MAC addresses) that must be deleted after use."),
    (re.compile(r"^\s*tech-support\b", re.I),
     "SR Linux pauses while every application dumps its report and WRITES A ZIP on the device "
     "under /tmp."),
    (re.compile(r"^\s*show\s+tech-support\b", re.I),
     "The vendor's full support bundle: output can be tens of megabytes and take minutes on a "
     "loaded box."),
    (re.compile(r"^\s*execute\s+tac\s+report\b", re.I),
     "Fortinet documents this as running the whole diagnostic battery; the output is very large."),
]


class Report:
    """One research file's outcome. Refusals are the point, not an afterthought."""

    def __init__(self, name: str, dialect: str) -> None:
        self.name = name
        self.dialect = dialect
        self.plan_created = False
        self.issues_seen = 0
        self.issues_merged = 0
        self.classes_added: list[str] = []
        self.classes_normalised: list[str] = []
        self.intents_added = 0
        self.bindings_added: list[str] = []
        self.bindings_conflicted = 0
        self.consent_bindings: list[str] = []
        self.exception_bindings: list[str] = []
        self.refused: dict[str, list[str]] = {}
        self.dropped_cues: list[str] = []

    def refuse(self, reason: str, what: str) -> None:
        self.refused.setdefault(reason, []).append(what)

    def refused_count(self) -> int:
        return sum(len(v) for v in self.refused.values())

    def render(self, verbose: bool = False) -> str:
        lines = ["  %-22s dialect %s%s" % (self.name, self.dialect or "(none)",
                                           "  [plan file created]" if self.plan_created else ""),
                 "    issues            : %d merged of %d" % (self.issues_merged, self.issues_seen),
                 "    classes added     : %s" % (", ".join(self.classes_added) or "none"),
                 "    classes normalised: %s" % (", ".join(sorted(set(self.classes_normalised))) or "none"),
                 "    intents added     : %d" % self.intents_added,
                 "    bindings added    : %d" % len(self.bindings_added),
                 "    consent bindings  : %d" % len(self.consent_bindings),
                 "    cited exceptions  : %d" % len(self.exception_bindings),
                 "    binding conflicts : %d (existing binding kept)" % self.bindings_conflicted,
                 "    commands refused  : %d" % self.refused_count()]
        for reason in sorted(self.refused):
            examples = self.refused[reason]
            shown = ", ".join(sorted(set(examples))[:4])
            lines.append("      · %d × %s" % (len(examples), reason))
            lines.append("        e.g. %s" % shown)
        if self.dropped_cues:
            lines.append("    detection cues dropped (no such id in this repo): %d" % len(self.dropped_cues))
            for d in sorted(set(self.dropped_cues))[:6]:
                lines.append("      - " + d)
        return "\n".join(lines)


def normalise_command(raw: str, params, what: str) -> str:
    """Turn a research `cmd` into a command-table template.

    `<x>` becomes `{x}` for the placeholders Correlix can fill; any other
    `<...>` is a value Correlix has no source for and the record is refused.
    """
    cmd = " ".join(str(raw).split())
    if not cmd:
        raise Refusal("%s: empty command" % what)
    if len(cmd) > 512:
        raise Refusal("%s: command longer than 512 characters" % what)

    def sub(m):
        name = m.group(1).lower()
        token = PLACEHOLDER_ALIASES.get(name)
        if token is None:
            raise Refusal("%s: placeholder <%s> is a value Correlix cannot supply from an "
                          "incident, so the command could only be run unscoped" % (what, name))
        return token
    cmd = re.sub(r"<([A-Za-z0-9_.-]+)>", sub, cmd)
    # Some research files already write `{peer}`; the same alias table applies,
    # so a vendor's own name for a concept lands on the token Correlix fills.
    def sub_brace(m):
        raw = m.group(1)
        token = "{%s}" % raw.lower()
        if token in PLACEHOLDERS:
            return token
        mapped = PLACEHOLDER_ALIASES.get(raw.lower())
        if mapped is None:
            raise Refusal("%s: placeholder {%s} is a value Correlix cannot supply from an "
                          "incident, so the command could only be run unscoped" % (what, raw))
        return mapped
    cmd = re.sub(r"\{([A-Za-z0-9_.-]+)\}", sub_brace, cmd)
    if "<" in cmd or ">" in cmd:
        raise Refusal("%s: unbalanced or unsupported placeholder syntax" % what)
    # Any {token} that survived must be in the closed set.
    for tok in cmd.split():
        if tok.startswith("{"):
            if not tok.endswith("}"):
                raise Refusal("%s: malformed placeholder %r" % (what, tok))
            if tok not in PLACEHOLDERS:
                raise Refusal("%s: placeholder %r is outside the closed substitution grammar"
                              % (what, tok))
    if params:
        declared = {PLACEHOLDER_ALIASES.get(str(p).lower()) for p in params}
        present = {t for t in cmd.split() if t.startswith("{")}
        if None not in declared and declared != present and present:
            # A params list that disagrees with the command is a research bug, not
            # something to guess at.
            raise Refusal("%s: `params` %s does not match the placeholders in the command %s"
                          % (what, sorted(x for x in declared if x), sorted(present)))
    return cmd


def classify_command(cmd: str, dialect: str, writes_file: bool):
    """Decide what happens to one command.

    Returns (verdict, detail) where verdict is one of:
        "ok"        — binds normally
        "consent"   — binds, but needs the operator's explicit approval (detail = caveat)
        "exception" — binds under a cited read-only exception (detail = reason)
        "refuse"    — never binds (detail = why)
    """
    for pattern, reason in EXPLICIT_REFUSALS:
        if pattern.search(cmd):
            return "refuse", reason
    exceptions = READ_ONLY_EXCEPTIONS.get(dialect, {})
    if cmd in exceptions:
        return "exception", exceptions[cmd]
    try:
        validate_command(cmd, "command")
    except Refusal as err:
        return "refuse", str(err).split(": ", 1)[-1]
    for pattern, caveat in CONSENT_PATTERNS:
        if pattern.search(cmd):
            return "consent", caveat
    if writes_file:
        return "consent", ("the vendor documents this command as writing a file on the device; "
                           "it is not a plain read")
    return "ok", ""


def merge_vendor(path: str, classes_doc: dict, plans: dict, facts: dict) -> Report:
    name = os.path.basename(path)
    doc = parse_yaml(_read(path))
    if not isinstance(doc, dict):
        raise Refusal("%s: document must be a mapping" % name)
    only_fields(doc, RESEARCH_TOP_FIELDS, name)
    dialect = str(doc.get("dialect") or doc.get("vendor") or "").strip()
    rep = Report(name, dialect)
    if dialect not in plans:
        profile = DIALECT_PROFILES.get(dialect)
        if profile is None:
            raise Refusal("%s: `%s` is not a dialect this platform recognises — add it to "
                          "DIALECT_PROFILES and to internal/vendorprofile first" % (name, dialect))
        plans[dialect] = {
            "dialect": dialect, "profile": profile[0], "display": profile[1],
            "version": "correlix-tac-plan-%s-2026-09-05" % dialect,
            "sources": [], "baseline": [], "bindings": {},
        }
        rep.plan_created = True
    plan = plans[dialect]
    file_sources = normalise_sources(doc.get("sources"), name)

    intent_areas = _load_intent_areas()
    intents_by_id = {i["id"]: i for i in classes_doc["intents"]}
    classes_by_id = {c["id"]: c for c in classes_doc["classes"]}

    def ensure_intent(intent_id: str, what: str) -> bool:
        if intent_id in intents_by_id:
            return True
        if not INTENT_RE.match(intent_id):
            rep.refuse("intent id does not match the intent grammar", intent_id)
            return False
        area = intent_id.split(".")[0]
        if area not in intent_areas:
            rep.refuse("intent area %r is outside the closed area set (adding an area is a "
                       "reviewed code change)" % area, intent_id)
            return False
        record = {"id": intent_id, "area": area, "title": intent_title(intent_id)}
        classes_doc["intents"].append(record)
        intents_by_id[intent_id] = record
        rep.intents_added += 1
        return True

    def bind(intent_id, cmd, verdict, detail, sources, what):
        existing = plan["bindings"].get(intent_id)
        record = {"command": cmd, "verified": "doc_claimed"}
        if verdict == "consent":
            record["consent"] = "true"
            record["consent_note"] = detail
        if verdict == "exception":
            record["read_only_exception"] = detail
            title, url = EXCEPTION_SOURCE.get(dialect, ("vendor documentation", ""))
            if url and not sources:
                sources = [{"title": title, "url": url, "retrieved": ""}]
        if sources:
            record["sources"] = sources
        if existing is None:
            plan["bindings"][intent_id] = record
            rep.bindings_added.append(intent_id)
            if verdict == "consent":
                rep.consent_bindings.append(intent_id)
            if verdict == "exception":
                rep.exception_bindings.append(intent_id)
            return
        if existing.get("command") == cmd:
            return
        rep.bindings_conflicted += 1
        rep.refuse("intent already bound to a different command on this dialect; the existing "
                   "binding is kept", "%s (%r vs %r)" % (intent_id, existing.get("command"), cmd))

    def handle_commands(entries, cls, what_prefix):
        """Fold one issue's (or the baseline's) command list into the data."""
        bound_intents = []
        for entry in entries or []:
            if isinstance(entry, str):
                # The Cisco baseline lists bare command strings with no intent.
                rep.refuse("baseline command carries no intent, so it cannot be bound to a "
                           "vendor-neutral concept", entry)
                continue
            if not isinstance(entry, dict):
                rep.refuse("command entry is neither a string nor a mapping", str(entry)[:60])
                continue
            try:
                only_fields(entry, COMMAND_FIELDS, "%s command" % what_prefix)
            except Refusal as err:
                rep.refuse("unknown field in a command entry", str(err))
                continue
            raw = entry.get("cmd") or entry.get("command") or ""
            intent_id = str(entry.get("intent", "")).strip()
            what = "%s %s" % (what_prefix, intent_id or raw)
            if not intent_id:
                rep.refuse("command carries no intent", str(raw)[:70])
                continue
            writes_file = str(entry.get("writes_file", "")).lower() == "true"
            try:
                cmd = normalise_command(raw, entry.get("params"), what)
            except Refusal as err:
                msg = str(err)
                reason = msg.split(": ", 1)[-1] if ": " in msg else msg
                rep.refuse(reason, str(raw)[:70])
                continue
            verdict, detail = classify_command(cmd, dialect, writes_file)
            if verdict == "refuse":
                rep.refuse(detail, cmd)
                continue
            if not ensure_intent(intent_id, what):
                continue
            srcs = normalise_sources(entry.get("sources"), what) or []
            bind(intent_id, cmd, verdict, detail, srcs, what)
            bound_intents.append(intent_id)
            if cls is not None and intent_id in plan["bindings"] and intent_id not in cls["intents"]:
                cls["intents"].append(intent_id)
        return bound_intents

    # ── the vendor's own TAC data-collection baseline ────────────────────────
    baseline = doc.get("tac_baseline")
    if isinstance(baseline, dict):
        try:
            only_fields(baseline, BASELINE_FIELDS, "%s tac_baseline" % name)
        except Refusal as err:
            rep.refuse("unknown field in tac_baseline", str(err))
        bound = handle_commands(baseline.get("commands"), None, "baseline")
        for intent_id in bound:
            record = plan["bindings"].get(intent_id) or {}
            if record.get("consent") == "true":
                continue  # never in a baseline that runs by default
            if intent_id not in plan["baseline"]:
                plan["baseline"].append(intent_id)

    # ── the issues ──────────────────────────────────────────────────────────
    for issue in doc.get("issues") or []:
        if not isinstance(issue, dict):
            rep.refuse("issue entry is not a mapping", str(issue)[:60])
            continue
        rep.issues_seen += 1
        issue_id = str(issue.get("id") or issue.get("key") or "").strip()
        what = "issue %s" % (issue_id or "?")
        try:
            only_fields(issue, ISSUE_FIELDS, what)
        except Refusal as err:
            rep.refuse("unknown field in an issue", str(err))
            continue

        raw_class = str(issue.get("class", "")).strip()
        if not raw_class:
            rep.refuse("issue names no class", issue_id)
            continue
        class_id = CANONICAL_CLASS.get(raw_class, raw_class)
        if class_id != raw_class:
            rep.classes_normalised.append("%s → %s" % (raw_class, class_id))
        if not SLUG_RE.match(class_id):
            rep.refuse("class id is not a kebab slug", raw_class)
            continue

        issue_sources = normalise_sources(issue.get("sources"), what)
        cls = classes_by_id.get(class_id)
        if cls is None:
            proposed = str(issue.get("proposed_class", "")).lower() == "true"
            if not proposed:
                rep.refuse("class does not exist in the taxonomy and the issue does not mark it "
                           "`proposed_class: true`", class_id)
                continue
            cls = {"id": class_id, "title": issue.get("title") or class_id,
                   "protocol": protocol_for_class(class_id), "detect": {},
                   "intents": [], "sources": list(issue_sources)}
            classes_doc["classes"].append(cls)
            classes_by_id[class_id] = cls
            rep.classes_added.append(class_id)
        cls.setdefault("detect", {})
        cls.setdefault("intents", [])
        cls.setdefault("sources", [])

        if class_id == "generic":
            # The fallback class is what "nothing matched" MEANS. Giving it a
            # detection rule would make it match, and the honest "Correlix did
            # not classify this" answer would silently disappear.
            rep.refuse("issue is filed against the `generic` fallback class, which must carry no "
                       "detection rules; re-file it under a real class or propose one", issue_id)
            continue
        for signature in issue.get("log_signatures") or []:
            text = str(signature).strip()
            if not text or len(text) > 300:
                continue
            pattern = "(?i)" + re.escape(text)
            bucket = cls["detect"].setdefault("log_regex", [])
            if pattern not in bucket and len(bucket) < 40:
                bucket.append(pattern)

        handle_commands(issue.get("commands"), cls, what)

        for src in issue_sources:
            add_source(cls["sources"], src)
        if not cls["sources"]:
            cls.pop("sources")
        rep.issues_merged += 1

    for src in file_sources:
        add_source(plan.setdefault("sources", []), src, cap=24)
    return rep


def add_source(bucket: list, src: dict, cap: int = 12) -> None:
    """Add a citation to a list, DEDUPED BY URL.

    Identity is the url, not the whole record: a source read back out of the
    merged file has a quoted title and no `retrieved` key, so comparing dicts
    would re-add the same page on every run and the merge would never be
    idempotent. That bug is invisible in one run and obvious only in a diff.
    """
    url = src.get("url", "")
    if not url:
        return
    for have in bucket:
        if have.get("url") == url:
            return
    if len(bucket) >= cap:
        return
    bucket.append({"title": src.get("title") or url, "url": url,
                   "retrieved": src.get("retrieved", "")})


def normalise_sources(raw, what: str) -> list[dict]:
    """Accept both source shapes the research uses: a bare URL string, or a
    {title, url} mapping. A non-https url is refused, not silently kept."""
    if not raw:
        return []
    if not isinstance(raw, list):
        raise Refusal("%s: `sources` must be a list" % what)
    out = []
    for src in raw:
        if isinstance(src, str):
            url = src.strip()
            title = url
        elif isinstance(src, dict):
            only_fields(src, SOURCE_FIELDS, "%s source" % what)
            url = str(src.get("url", "")).strip()
            title = str(src.get("title", "")).strip() or url
        else:
            raise Refusal("%s: a source must be a url or a {title, url} mapping" % what)
        if not url.startswith("https://"):
            raise Refusal("%s: source url %r must be https" % (what, url))
        out.append({"title": title, "url": url, "retrieved": ""})
    return out


def intent_title(intent_id: str) -> str:
    """A readable title for a machine-derived intent. It is deliberately plain:
    a generated title that pretended to be authored prose would be worse than one
    that reads like what it is."""
    return intent_id.replace(".", " ").replace("-", " ").replace("_", " ")


# Which taxonomy `protocol` group a proposed class belongs to. It only groups the
# class in the UI; a class whose area is not obvious is grouped `system` rather
# than guessed into a protocol it has nothing to do with.
PROTOCOL_HINTS = [
    (("ospf",), "ospf"), (("isis",), "isis"), (("bgp",), "bgp"),
    (("mpls", "ldp", "rsvp", "l3vpn", "segment-routing", "sr-"), "mpls"),
    (("evpn", "vxlan", "overlay"), "overlay"),
    (("lag", "lacp", "stp", "vlan", "l2vpn", "vpls", "arp", "nd", "mac", "stack"), "l2"),
    (("qos", "shaping", "policing"), "qos"),
    (("optic", "interface", "link", "cable", "port"), "interface"),
    (("hardware", "environment", "fan", "power", "temperature"), "hardware"),
    (("config", "commit"), "config"),
]


def protocol_for_class(class_id: str) -> str:
    for needles, proto in PROTOCOL_HINTS:
        for n in needles:
            if n in class_id:
                return proto
    return "system"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if a merge would change the checked-in data (CI mode)")
    ap.add_argument("--vendor", action="append", default=None,
                    help="merge only this vendor's research file (repeatable)")
    args = ap.parse_args()

    if not os.path.isdir(RESEARCH_DIR):
        print("no research directory at %s — nothing to merge" % RESEARCH_DIR)
        return 0
    files = sorted(f for f in os.listdir(RESEARCH_DIR) if f.endswith(".yaml"))
    if args.vendor:
        wanted = {v + ".yaml" for v in args.vendor}
        files = [f for f in files if f in wanted]
    if not files:
        print("no research files to merge (%s)" % RESEARCH_DIR)
        return 0

    try:
        facts = repo_facts()
        classes_doc = load_classes()
        plan_slugs = sorted(f[:-5] for f in os.listdir(PLANS_DIR) if f.endswith(".yaml"))
        plans = {slug: load_plan(slug) for slug in plan_slugs}
    except Refusal as err:
        print("REFUSED: %s" % err, file=sys.stderr)
        return 2

    before = {CLASSES: render_classes(classes_doc)}
    for slug, plan in plans.items():
        before[os.path.join(PLANS_DIR, slug + ".yaml")] = render_plan(plan)

    reports: list[Report] = []
    failed = False
    for name in files:
        path = os.path.join(RESEARCH_DIR, name)
        try:
            reports.append(merge_vendor(path, classes_doc, plans, facts))
        except Refusal as err:
            print("REFUSED %s: %s" % (name, err), file=sys.stderr)
            failed = True

    # A class every one of whose commands was refused would be dead data: it can
    # neither fire nor collect anything beyond the baseline, and the Go loader
    # refuses it. Prune it here, loudly, rather than shipping a taxonomy the
    # engine will not load.
    pruned = []
    kept = []
    for cls in classes_doc["classes"]:
        empty_detect = not any((cls.get("detect") or {}).get(k) for k in
                               ("alerts", "hypotheses", "signatures", "skills", "issues", "log_regex"))
        if cls["id"] != "generic" and empty_detect and not cls.get("intents"):
            pruned.append(cls["id"])
            continue
        kept.append(cls)
    classes_doc["classes"] = kept

    after = {CLASSES: render_classes(classes_doc)}
    for slug, plan in plans.items():
        after[os.path.join(PLANS_DIR, slug + ".yaml")] = render_plan(plan)

    changed = [p for p in after if after[p] != before.get(p)]

    print("tac-merge-research: %d research file(s)" % len(files))
    for rep in reports:
        print(rep.render())
    if pruned:
        print("  classes pruned (every command refused, so nothing to collect): %s"
              % ", ".join(sorted(pruned)))
    if changed:
        print("  files changed: %s" % ", ".join(os.path.relpath(p, REPO) for p in sorted(changed)))
    else:
        print("  files changed: none (already merged)")

    refused = sum(len(r.refused) for r in reports)
    dropped = sum(len(r.dropped_cues) for r in reports)
    if refused or dropped:
        # Refusals are REPORTED, not fatal: a research file may legitimately
        # carry a command a vendor documents that is not a read-only show, and
        # that record must simply never land. Silence would be the bug.
        print("  %d record(s) refused and %d detection cue(s) dropped — they will NEVER merge; "
              "fix or remove them in the research file." % (refused, dropped))

    if args.check:
        if changed:
            print("\n--check: the checked-in taxonomy is NOT the merged result. "
                  "Run scripts/tac-merge-research.py and commit the result.", file=sys.stderr)
            return 1
        return 2 if failed else 0

    for path in changed:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(after[path])
    if failed:
        # A partial merge is written (the records that passed are real work), but
        # the run is LOUD: a refusal is never a silent skip.
        print("\nsome research files were refused — see above", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
