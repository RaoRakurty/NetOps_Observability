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
import json
import os
import re
import sys

# scripts/ is not a package, so make the sibling module importable however this
# file is loaded: run directly, or read through importlib by the purge script
# and by tests/test_tac_merge_research.py.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# The OUTPUT-ONLY command policy (ai/tac/forbidden.yaml) and the bounded-probe
# grammar, shared with scripts/tac-purge-forbidden.py so there is one matcher.
import tac_forbidden

# ── locations ────────────────────────────────────────────────────────────────

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)                       # NetOps_Observability/
TAC = os.path.join(REPO, "src", "backend", "ai", "tac")
RESEARCH_DIR = os.path.join(TAC, "research")
CLASSES = os.path.join(TAC, "classes.yaml")
FORBIDDEN = os.path.join(TAC, "forbidden.yaml")
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
PLACEHOLDERS = {"{if}", "{peer}", "{prefix}", "{vrf-scope}", "{vrf-name}",
                "{rid}", "{area}", "{vlan}", "{vni}"}
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
            raise Refusal(f"line {line}: unterminated single-quoted scalar")
        return value[1:end].replace("''", "'")
    if value[0] == '"':
        end = value.rfind('"')
        if end == 0:
            raise Refusal(f"line {line}: unterminated double-quoted scalar")
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
            raise Refusal(f"line {n}: tab in indentation")
        body = raw[indent:]
        if not body or body.startswith("#"):
            continue
        if body.startswith(("---", "...")):
            if body.strip() == "---" and not lines:
                continue
            raise Refusal(f"line {n}: multiple documents are not supported")
        lines.append((indent, body, n))
    return lines


def _inline(value: str, line: int):
    value = value.strip()
    if value.startswith("["):
        if not value.endswith("]"):
            raise Refusal(f"line {line}: unterminated flow sequence")
        out = []
        for part in _split_flow(value[1:-1]):
            part = part.strip()
            if not part:
                continue
            if part.startswith(("{", "[")):
                raise Refusal(f"line {line}: nested flow collections are not supported")
            out.append(_unquote(part, line))
        return out
    if value.startswith("{"):
        if not value.endswith("}"):
            raise Refusal(f"line {line}: unterminated flow mapping")
        out = {}
        for part in _split_flow(value[1:-1]):
            part = part.strip()
            if not part:
                continue
            kv = _split_key(part)
            if kv is None:
                raise Refusal(f"line {line}: flow entry {part!r} is not `key: value`")
            k, v = kv
            v = v.strip()
            if v.startswith("["):
                if not v.endswith("]"):
                    raise Refusal(f"line {line}: unterminated flow sequence")
                out[k] = [_unquote(x, line) for x in _split_flow(v[1:-1]) if x.strip()]
                continue
            if v.startswith("{"):
                raise Refusal(f"line {line}: nested flow collections are not supported")
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
            raise Refusal(f"line {num}: unexpected indentation in mapping")
        if body.startswith("- ") or body == "-":
            break
        kv = _split_key(body)
        if kv is None:
            raise Refusal(f"line {num}: expected `key: value`, got {body!r}")
        key, rest = kv
        if key in out:
            raise Refusal(f"line {num}: duplicate key {key!r}")
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
            raise Refusal(f"line {num}: unexpected indentation in sequence")
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
                    raise Refusal(f"line {lines[pos][2]}: expected `key: value`")
                if k2[0] in item:
                    raise Refusal(f"line {lines[pos][2]}: duplicate key {k2[0]!r}")
                n2 = lines[pos][2]
                pos += 1
                item[k2[0]], pos = _parse_value(k2[1], lines, pos, item_indent, n2)
            out.append(item)
            continue
        if item_body == "":
            if pos >= len(lines) or lines[pos][0] <= cur_indent:
                raise Refusal(f"line {num}: empty sequence item")
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
        raise Refusal(f"line {lines[pos][2]}: unexpected indentation")
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
        raise Refusal(f"cannot read {path}: {err}") from err


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
        raise Refusal("{}: unknown field(s) {} (allowed: {})".format(what, ", ".join(unknown), ", ".join(sorted(allowed))))


def validate_command(command: str, what: str) -> str:
    """The read-only grammar, byte-for-byte the one internal/tac applies.

    A BOUNDED REACHABILITY PROBE is the one shape that is not a read and is
    still allowed (owner, 2026-09-05). It has its own grammar rather than a hole
    in this one, and every count, size, timeout and hop must be inside the bound.
    """
    cmd = " ".join(command.split())
    if not cmd:
        raise Refusal(f"{what}: empty command")
    if tac_forbidden.is_probe_command(cmd):
        try:
            return tac_forbidden.validate_bounded_probe(cmd)
        except tac_forbidden.ProbeRefusal as err:
            raise Refusal(f"{what}: probe is outside the bounded-probe grammar — {err}") from err
    for bad in FORBIDDEN_CHARS:
        if bad in cmd:
            raise Refusal(f"{what}: command contains the disallowed metacharacter {bad!r}")
    segments = cmd.split("|")
    lead = segments[0].split()
    if not lead or lead[0].lower() not in READ_ONLY_LEAD:
        raise Refusal("{}: {!r} does not lead with a read-only verb ({})".format(what, cmd, "/".join(sorted(READ_ONLY_LEAD))))
    for seg in segments[1:]:
        toks = seg.split()
        if not toks:
            raise Refusal(f"{what}: empty pipe segment in {cmd!r}")
        if toks[0].lower() not in READ_ONLY_FILTER:
            raise Refusal(f"{what}: pipe filter {toks[0]!r} is not a display-only filter")
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
    # A citation is identified by the PAGE IT POINTS AT. Earlier merges appended
    # the research file's whole citation set on every run without comparing, so
    # nokia-srlinux carried the same 61 pages six times over (366 entries) and
    # every binding inherited all of them. Fold them on the way in, so a re-merge
    # writes the deduped set and the escalation preview stops rendering the pool.
    doc["sources"] = dedupe_sources(doc["sources"])
    for binding in doc["bindings"].values():
        if isinstance(binding, dict) and binding.get("sources"):
            binding["sources"] = dedupe_sources(binding["sources"])[:MAX_BINDING_SOURCES]
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
                out.append(f"    {key}: >-")
                out += emit_block(cls[key], "      ")
        detect = cls.get("detect") or {}
        if detect:
            out.append("    detect:")
            for key in ("alerts", "hypotheses", "signatures", "skills", "issues", "log_regex"):
                values = detect.get(key) or []
                if not values:
                    continue
                out.append(f"      {key}:")
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
    out.append("# plans/{}.yaml — the {} command plan for the TAC escalation pack.".format(doc["dialect"], doc.get("display", doc["dialect"])))
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
        out.append("# The dialect's BIBLIOGRAPHY — the pages this file was built from. A binding")
        out.append("# cites its own page(s) below; this list never rides on a plan step.")
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
        out.append(f"  {intent}:")
        out.append("    command: " + emit_scalar(binding["command"]))
        out.append("    verified: " + binding.get("verified", "doc_claimed"))
        if binding.get("consent") == "true":
            out.append("    consent: true")
            out.append("    consent_note: >-")
            out += emit_block(binding.get("consent_note", ""), "      ")
        if binding.get("read_only_exception"):
            out.append("    read_only_exception: >-")
            out += emit_block(binding["read_only_exception"], "      ")
        if binding.get("teardown"):
            out.append("    teardown: " + emit_scalar(binding["teardown"]))
        if binding.get("sources"):
            out.append("    sources:")
            for src in binding["sources"]:
                out.append("      - title: " + emit_scalar(src["title"]))
                out.append("        url: " + src["url"])
                if src.get("retrieved"):
                    out.append("        retrieved: " + src["retrieved"])
        for key in ("max_bytes", "timeout_s"):
            if binding.get(key):
                out.append(f"    {key}: {binding[key]}")
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
    # The VRF concept. `<vrf-name>` is written by research that spells the
    # command with the name AFTER a word that is not the dialect's scoping
    # keyword ("show route extensive table <vrf-name>"), so it folds onto the
    # BARE token; everything else takes the keyword-emitting one and
    # shape_vrf_scope() below decides which of the two the command needs.
    #
    # `instance` is DELIBERATELY ABSENT. It is the most overloaded word in the
    # corpus — an EIGRP instance tag, an MST instance id, an OSPF process tag
    # and an IS-IS instance name are all written `<instance>` by the research,
    # and NONE of them is a VRF. Folding it onto the VRF token scoped those
    # commands by the wrong value (tracker row 261); Correlix has no source for
    # any of them, so the record is REFUSED and the honest unscoped command is
    # authored by hand instead. A research file that really means the VRF says
    # `<routing-instance>`, `<network-instance>` or `<vrf>`.
    "vrf": "{vrf-scope}", "vrf-name": "{vrf-name}",
    "routing-instance": "{vrf-scope}", "routing-instance-name": "{vrf-scope}",
    "virtual-router": "{vrf-scope}", "logical-router": "{vrf-scope}",
    "ni": "{vrf-scope}", "network-instance": "{vrf-scope}",
    "vsys": "{vrf-scope}", "vdom": "{vrf-scope}",
    "rid": "{rid}", "router-id": "{rid}",
    "area": "{area}",
    "vlan": "{vlan}", "vlan-id": "{vlan}",
    "vni": "{vni}",
}

# ── the VRF-scoping contract (ai/tac/README.md §2, tracker row 261) ──────────
#
# `{vrf-scope}` EMITS the dialect's scoping keyword ahead of the instance name.
# A template must therefore NOT spell that keyword itself, or a scoped
# collection renders `show ip route vrf vrf CUST-A` — a command every one of
# those devices rejects. Vendor research is written the way the vendor's own
# reference PRINTS the command, keyword and all, so the shaping happens HERE,
# once, on the way in; row 261 is what a merge without it produced.
#
# The keyword is not this script's to invent. It is `dialect.vrf_scope_keyword`
# in internal/vendorprofile/profiles/<vendor>.json — the same field internal/tac
# resolves onto the plan at load. Re-typing it here would guarantee drift
# between what the merge writes and what the engine renders.

VENDORPROFILE_DIR = os.path.join(BACKEND, "internal", "vendorprofile", "profiles")

# The scoping words the corpus spells. A literal from this set immediately
# before the placeholder is a qualifier the research wrote out; anything else is
# part of the command's name.
VRF_QUALIFIER_WORDS = {
    "vrf", "instance", "vpn-instance", "routing-instance", "network-instance",
    "logical-router", "virtual-router",
}

_VRF_KEYWORDS: dict = {}


def vrf_scope_keyword(dialect: str) -> str:
    """The keyword `{vrf-scope}` emits on this dialect, read from the registry.

    An EMPTY string is an authored answer, not a missing one: SR Linux, SR OS
    and PAN-OS carry their own word in the command and take the bare name.
    """
    if dialect in _VRF_KEYWORDS:
        return _VRF_KEYWORDS[dialect]
    profile = DIALECT_PROFILES.get(dialect)
    if profile is None:
        raise Refusal(f"{dialect}: not a dialect this platform recognises, so its VRF "
                      "scoping keyword cannot be resolved")
    vendor = profile[0].split("/", 1)[0]
    path = os.path.join(VENDORPROFILE_DIR, vendor + ".json")
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as err:
        raise Refusal(f"{dialect}: vendor profile {vendor}.json is unreadable ({err}); the "
                      "VRF scoping keyword is registry data and cannot be guessed") from err
    kw = str((doc.get("dialect") or {}).get("vrf_scope_keyword", "") or "").strip()
    _VRF_KEYWORDS[dialect] = kw
    return kw


def shape_vrf_scope(cmd: str, dialect: str) -> str:
    """Apply the contract to one normalised command.

    Three cases, in order:

      1. the dialect's OWN keyword sits immediately before `{vrf-scope}` — the
         placeholder emits it, so the literal is DROPPED;
      2. some OTHER scoping word sits there (`display bgp instance <name>` on
         VRP, whose keyword is `vpn-instance`) — the command carries its own
         word, so the placeholder becomes the BARE `{vrf-name}`;
      3. the keyword is still standing as a literal elsewhere in the command
         (`show ip vrf detail <name>`), which means it is part of the command's
         NAME rather than a qualifier — the placeholder becomes `{vrf-name}`.

    A dialect whose authored keyword is empty is returned untouched: its
    `{vrf-scope}` already renders the bare name.
    """
    kw = vrf_scope_keyword(dialect)
    if not kw or "{vrf-scope}" not in cmd:
        return cmd
    out: list = []
    for tok in cmd.split():
        if tok == "{vrf-scope}" and out:
            prev = out[-1].lower()
            if prev == kw:
                out.pop()
                out.append(tok)
                continue
            if prev in VRF_QUALIFIER_WORDS:
                out.append("{vrf-name}")
                continue
        out.append(tok)
    toks = [t.lower() for t in out]
    if "{vrf-scope}" in out and kw in toks:
        out = ["{vrf-name}" if t == "{vrf-scope}" else t for t in out]
    return " ".join(out)


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

# ── (3a) the OUTPUT-ONLY command policy ──────────────────────────────────────
#
# Owner decision, 2026-09-05: a command that changes configuration, that restarts
# or reboots, or that touches a daemon must not merely be refused — it must not
# be KNOWN to Correlix at all. ai/tac/forbidden.yaml is that vocabulary; this
# merge applies it AT THE DOOR, before anything else, and reports ONLY A COUNT
# PER FAMILY. The command text is never printed, never written and never kept:
# the count is known, the command is not.
#
# The corpus itself is kept clean by scripts/tac-purge-forbidden.py, so in a
# healthy tree these counters read zero. They are still here because a research
# file added tomorrow may carry one, and it must die at this door rather than in
# a code review.

_POLICY = None


def policy() -> tac_forbidden.Policy:
    """The compiled command policy, read once.

    A policy that will not load is a HARD STOP: merging against no policy would
    silently admit exactly the commands the owner's rule excludes.
    """
    global _POLICY
    if _POLICY is None:
        try:
            _POLICY = tac_forbidden.load_policy(parse_yaml(_read(FORBIDDEN)))
        except tac_forbidden.PolicyError as err:
            raise Refusal(f"forbidden.yaml: {err}") from err
    return _POLICY


# ── (4) the explicit refusals ────────────────────────────────────────────────
#
# Each is a documented command that this collector will NOT run in W1, with the
# reason. They are listed in the merge report rather than silently dropped: the
# point of the report is that an operator can see what Correlix decided not to
# do and why.
#
# The config / restart / daemon families are NOT here: they are the policy above,
# which refuses them earlier and reports them without their text.
EXPLICIT_REFUSALS = [
    (re.compile(r"^\s*test\s+authentication\b.*\bpassword\b", re.IGNORECASE),
     ("takes a cleartext credential on the command line; an evidence collector must never "
     "put a password on a device's command line or in an audit record")),
    (re.compile(r"^\s*(scp|tftp|ftp)\s+export\b", re.IGNORECASE),
     ("pushes a file to an arbitrary external host instead of returning output over Correlix's "
     "own SSH channel; that is a different trust model from a read")),
    (re.compile(r"^\s*diagnose\s+sniffer\s+packet\b", re.IGNORECASE),
     ("is a live packet capture with an operator-supplied BPF; it belongs behind the Packet "
     "Capture module's existing closed BPF grammar, not the read-only command table")),
    (re.compile(r"^\s*diagnose\s+test\s+authserver\b", re.IGNORECASE),
     "takes a cleartext credential on the command line"),
]

# Commands whose vendor documentation says they are NOT routine. They bind, but
# with consent: true and the vendor's own caveat, and they are never in a
# baseline. `writes_file: true` in the research is the primary signal; these
# patterns catch the ones whose caveat is about load or authorisation instead.
CONSENT_PATTERNS = [
    (re.compile(r"^\s*admin\s+tech-support\b", re.IGNORECASE),
     ("Nokia's own reference says this creates a system CORE DUMP and should only be used with "
     "authorised direction of Nokia support. It is not a routine collector.")),
    (re.compile(r"^\s*display\s+diagnostic-information\b", re.IGNORECASE),
     ("Huawei warns that this markedly raises CPU and degrades device performance, and that its "
     "output contains personal data (MAC addresses) that must be deleted after use.")),
    (re.compile(r"^\s*tech-support\b", re.IGNORECASE),
     ("SR Linux pauses while every application dumps its report and WRITES A ZIP on the device "
     "under /tmp.")),
    (re.compile(r"^\s*show\s+tech-support\b", re.IGNORECASE),
     ("The vendor's full support bundle: output can be tens of megabytes and take minutes on a "
     "loaded box.")),
    (re.compile(r"^\s*execute\s+tac\s+report\b", re.IGNORECASE),
     "Fortinet documents this as running the whole diagnostic battery; the output is very large."),
]


def _families_line(counts: dict) -> str:
    """`N (config a · restart b · daemon c)` — counts only, never a command."""
    total = sum(counts.get(f, 0) for f in tac_forbidden.FAMILIES)
    detail = " · ".join(f"{f} {counts.get(f, 0)}" for f in tac_forbidden.FAMILIES)
    return f"{total} ({detail})"


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
        self.scoped_bindings: list[str] = []
        # Excluded by the owner's output-only policy. A COUNT PER FAMILY and
        # nothing else — the command text is deliberately not held here.
        self.excluded = tac_forbidden.empty_counts()

    def refuse(self, reason: str, what: str) -> None:
        self.refused.setdefault(reason, []).append(what)

    def exclude(self, family: str) -> None:
        self.excluded[family] = self.excluded.get(family, 0) + 1

    def excluded_count(self) -> int:
        return sum(self.excluded.values())

    def refused_count(self) -> int:
        return sum(len(v) for v in self.refused.values())

    def render(self, verbose: bool = False) -> str:
        created = "  [plan file created]" if self.plan_created else ""
        lines = [f"  {self.name:<22} dialect {self.dialect or '(none)'}{created}",
                 f"    issues            : {self.issues_merged} merged of {self.issues_seen}",
                 f"    classes added     : {', '.join(self.classes_added) or 'none'}",
                 f"    classes normalised: {', '.join(sorted(set(self.classes_normalised))) or 'none'}",
                 f"    intents added     : {self.intents_added}",
                 f"    bindings added    : {len(self.bindings_added)}",
                 f"    consent bindings  : {len(self.consent_bindings)}",
                 f"    cited exceptions  : {len(self.exception_bindings)}",
                 f"    scoped setters    : {len(self.scoped_bindings)} (each with its teardown)",
                 f"    binding conflicts : {self.bindings_conflicted} (existing binding kept)",
                 "    excluded by policy: " + _families_line(self.excluded),
                 f"    commands refused  : {self.refused_count()}"]
        for reason in sorted(self.refused):
            examples = self.refused[reason]
            shown = ", ".join(sorted(set(examples))[:4])
            lines.append(f"      · {len(examples)} × {reason}")
            lines.append(f"        e.g. {shown}")
        if self.dropped_cues:
            lines.append(f"    detection cues dropped (no such id in this repo): {len(self.dropped_cues)}")
            for d in sorted(set(self.dropped_cues))[:6]:
                lines.append("      - " + d)
        return "\n".join(lines)


def normalise_command(raw: str, params, what: str, dialect: str) -> str:
    """Turn a research `cmd` into a command-table template.

    `<x>` becomes `{x}` for the placeholders Correlix can fill; any other
    `<...>` is a value Correlix has no source for and the record is refused.
    The VRF placeholder is then SHAPED to the contract for this dialect
    (shape_vrf_scope): the vendor's own keyword is spelled by exactly one of the
    template and the placeholder, never by both.
    """
    cmd = " ".join(str(raw).split())
    if not cmd:
        raise Refusal(f"{what}: empty command")
    if len(cmd) > 512:
        raise Refusal(f"{what}: command longer than 512 characters")

    def sub(m):
        name = m.group(1).lower()
        token = PLACEHOLDER_ALIASES.get(name)
        if token is None:
            raise Refusal(f"{what}: placeholder <{name}> is a value Correlix cannot supply from an "
                          "incident, so the command could only be run unscoped")
        return token
    cmd = re.sub(r"<([A-Za-z0-9_.-]+)>", sub, cmd)
    # Some research files already write `{peer}`; the same alias table applies,
    # so a vendor's own name for a concept lands on the token Correlix fills.
    def sub_brace(m):
        raw = m.group(1)
        token = f"{{{raw.lower()}}}"
        if token in PLACEHOLDERS:
            return token
        mapped = PLACEHOLDER_ALIASES.get(raw.lower())
        if mapped is None:
            raise Refusal(f"{what}: placeholder {{{raw}}} is a value Correlix cannot supply from an "
                          "incident, so the command could only be run unscoped")
        return mapped
    cmd = re.sub(r"\{([A-Za-z0-9_.-]+)\}", sub_brace, cmd)
    if "<" in cmd or ">" in cmd:
        raise Refusal(f"{what}: unbalanced or unsupported placeholder syntax")
    cmd = shape_vrf_scope(cmd, dialect)
    # Any {token} that survived must be in the closed set.
    for tok in cmd.split():
        if tok.startswith("{"):
            if not tok.endswith("}"):
                raise Refusal(f"{what}: malformed placeholder {tok!r}")
            if tok not in PLACEHOLDERS:
                raise Refusal(f"{what}: placeholder {tok!r} is outside the closed substitution grammar")
    if params:
        # `{vrf-name}` and `{vrf-scope}` are ONE concept in two renderings (the
        # bare instance name, with or without the dialect's keyword in front),
        # and which one a command needs is decided by shape_vrf_scope, not by
        # the research. Comparing them apart would refuse a correctly shaped
        # command for disagreeing with its own `params` list.
        def vrf_fold(tokens):
            return {"{vrf-scope}" if t == "{vrf-name}" else t for t in tokens}
        declared = vrf_fold({PLACEHOLDER_ALIASES.get(str(p).lower()) for p in params})
        present = vrf_fold({t for t in cmd.split() if t.startswith("{")})
        if None not in declared and declared != present and present:
            # A params list that disagrees with the command is a research bug, not
            # something to guess at.
            raise Refusal(f"{what}: `params` {sorted(x for x in declared if x)} does not match the placeholders in the command {sorted(present)}")
    return cmd


def classify_command(cmd: str, dialect: str, writes_file: bool):
    """Decide what happens to one command.

    Returns (verdict, detail) where verdict is one of:
        "ok"        — binds normally
        "consent"   — binds, but needs the operator's explicit approval (detail = caveat)
        "exception" — binds under a cited read-only exception (detail = reason)
        "scoped"    — a session-scoped setter; binds WITH its teardown (detail = teardown)
        "refuse"    — never binds (detail = why)
        "forbidden" — the owner's output-only policy excludes it (detail = family);
                      it is counted and NEVER named
    """
    # (0) THE OWNER'S RULE, first and without appeal. A config / restart /
    # daemon command is not knowledge Correlix carries, so it is not merged, not
    # reported by name and not kept — only counted, by family.
    rule = policy().match(dialect, cmd)
    if rule is not None:
        return "forbidden", rule.family
    for pattern, reason in EXPLICIT_REFUSALS:
        if pattern.search(cmd):
            return "refuse", reason
    # A documented SESSION-SCOPED SETTER narrows what a read prints and dies with
    # the CLI session: no configuration change, nothing cleared. It binds with
    # the teardown the policy documents, which the collector always runs.
    scope = policy().session_scope(dialect, cmd)
    if scope is not None:
        return "scoped", scope.teardown
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
        raise Refusal(f"{name}: document must be a mapping")
    only_fields(doc, RESEARCH_TOP_FIELDS, name)
    dialect = str(doc.get("dialect") or doc.get("vendor") or "").strip()
    rep = Report(name, dialect)
    if dialect not in plans:
        profile = DIALECT_PROFILES.get(dialect)
        if profile is None:
            raise Refusal(f"{name}: `{dialect}` is not a dialect this platform recognises — add it to "
                          "DIALECT_PROFILES and to internal/vendorprofile first")
        plans[dialect] = {
            "dialect": dialect, "profile": profile[0], "display": profile[1],
            "version": f"correlix-tac-plan-{dialect}-2026-09-05",
            "sources": [], "baseline": [], "bindings": {},
        }
        rep.plan_created = True
    plan = plans[dialect]
    file_sources = normalise_sources(doc.get("sources"), name)
    # The research files cite an issue with a bare url; the file's own `sources:`
    # block is where those urls have TITLES. A citation whose title is its url is
    # a link with nothing to read, so give it the file's title when there is one.
    title_by_url = {src["url"]: src["title"] for src in file_sources if src["title"] != src["url"]}

    def titled(sources: list[dict]) -> list[dict]:
        out = []
        for src in sources:
            known = title_by_url.get(src["url"])
            out.append(dict(src, title=known) if known and src["title"] == src["url"] else src)
        return out

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
            rep.refuse(f"intent area {area!r} is outside the closed area set (adding an area is a "
                       "reviewed code change)", intent_id)
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
        if verdict == "scoped":
            # The teardown is what makes the setter allowed at all, so it is
            # written into the binding, not left to the runner to remember.
            record["teardown"] = detail
        if sources:
            record["sources"] = sources
        if existing is None:
            plan["bindings"][intent_id] = record
            rep.bindings_added.append(intent_id)
            if verdict == "consent":
                rep.consent_bindings.append(intent_id)
            if verdict == "exception":
                rep.exception_bindings.append(intent_id)
            if verdict == "scoped":
                rep.scoped_bindings.append(intent_id)
            return
        if existing.get("command") == cmd:
            # Same command, already merged. A citation is the one thing that may
            # still be filled in: it adds provenance and changes nothing that
            # runs, so it is not the silent overwrite rule 4 forbids.
            if sources and not existing.get("sources"):
                existing["sources"] = dedupe_sources(sources)[:MAX_BINDING_SOURCES]
            return
        rep.bindings_conflicted += 1
        rep.refuse("intent already bound to a different command on this dialect; the existing "
                   "binding is kept", "{} ({!r} vs {!r})".format(intent_id, existing.get("command"), cmd))

    def handle_commands(entries, cls, what_prefix, default_sources=()):
        """Fold one issue's (or the baseline's) command list into the data.

        `default_sources` are the pages the ISSUE (or the baseline block) was
        read from. A command with no citation of its own inherits THOSE — the
        pages that actually establish it — never the file-wide bibliography."""
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
                only_fields(entry, COMMAND_FIELDS, f"{what_prefix} command")
            except Refusal as err:
                rep.refuse("unknown field in a command entry", str(err))
                continue
            raw = entry.get("cmd") or entry.get("command") or ""
            intent_id = str(entry.get("intent", "")).strip()
            what = f"{what_prefix} {intent_id or raw}"
            if not intent_id:
                rep.refuse("command carries no intent", str(raw)[:70])
                continue
            writes_file = str(entry.get("writes_file", "")).lower() == "true"
            try:
                cmd = normalise_command(raw, entry.get("params"), what, dialect)
            except Refusal as err:
                msg = str(err)
                reason = msg.split(": ", 1)[-1] if ": " in msg else msg
                rep.refuse(reason, str(raw)[:70])
                continue
            verdict, detail = classify_command(cmd, dialect, writes_file)
            if verdict == "forbidden":
                # COUNTED, NEVER NAMED. Printing the command here would defeat
                # the point of the purge: the owner's rule is that Correlix does
                # not know it, and a merge report is knowledge.
                rep.exclude(detail)
                continue
            if verdict == "refuse":
                rep.refuse(detail, cmd)
                continue
            if not ensure_intent(intent_id, what):
                continue
            own = dedupe_sources(titled(normalise_sources(entry.get("sources"), what)))
            if own:
                srcs = own[:MAX_BINDING_SOURCES]
            else:
                # INHERITED, so ONE page. The issue's citation set belongs to the
                # issue; handing all of it to every command the issue names
                # recreates the pool a step down. One page answers "where did
                # this command come from"; the rest is the pack's bibliography.
                srcs = titled(dedupe_sources(default_sources))[:1]
            bind(intent_id, cmd, verdict, detail, srcs, what)
            bound_intents.append(intent_id)
            if cls is not None and intent_id in plan["bindings"] and intent_id not in cls["intents"]:
                cls["intents"].append(intent_id)
        return bound_intents

    # ── the vendor's own TAC data-collection baseline ────────────────────────
    baseline = doc.get("tac_baseline")
    if isinstance(baseline, dict):
        try:
            only_fields(baseline, BASELINE_FIELDS, f"{name} tac_baseline")
        except Refusal as err:
            rep.refuse("unknown field in tac_baseline", str(err))
        try:
            baseline_sources = normalise_sources(baseline.get("sources"), f"{name} tac_baseline")
        except Refusal as err:
            rep.refuse("unusable `sources` in tac_baseline", str(err))
            baseline_sources = []
        bound = handle_commands(baseline.get("commands"), None, "baseline", baseline_sources)
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
            rep.classes_normalised.append(f"{raw_class} → {class_id}")
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

        handle_commands(issue.get("commands"), cls, what, issue_sources)

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


# A binding cites the pages that bind THAT intent, and at most this many. The
# dialect-wide pool is the file's bibliography, not a per-command citation: an
# escalation preview that repeated it under every step rendered 8,418 links.
MAX_BINDING_SOURCES = 2


def dedupe_sources(sources) -> list[dict]:
    """The same list, one entry per url, first occurrence kept."""
    out: list[dict] = []
    for src in sources or []:
        if not isinstance(src, dict):
            continue
        url = str(src.get("url", "")).strip()
        if not url or any(have.get("url") == url for have in out):
            continue
        out.append(src)
    return out


def normalise_sources(raw, what: str) -> list[dict]:
    """Accept both source shapes the research uses: a bare URL string, or a
    {title, url} mapping. A non-https url is refused, not silently kept."""
    if not raw:
        return []
    if not isinstance(raw, list):
        raise Refusal(f"{what}: `sources` must be a list")
    out = []
    for src in raw:
        if isinstance(src, str):
            url = src.strip()
            title = url
        elif isinstance(src, dict):
            only_fields(src, SOURCE_FIELDS, f"{what} source")
            url = str(src.get("url", "")).strip()
            title = str(src.get("title", "")).strip() or url
        else:
            raise Refusal(f"{what}: a source must be a url or a {{title, url}} mapping")
        if not url.startswith("https://"):
            raise Refusal(f"{what}: source url {url!r} must be https")
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
        print(f"no research directory at {RESEARCH_DIR} — nothing to merge")
        return 0
    files = sorted(f for f in os.listdir(RESEARCH_DIR) if f.endswith(".yaml"))
    if args.vendor:
        wanted = {v + ".yaml" for v in args.vendor}
        files = [f for f in files if f in wanted]
    if not files:
        print(f"no research files to merge ({RESEARCH_DIR})")
        return 0

    try:
        facts = repo_facts()
        classes_doc = load_classes()
        plan_slugs = sorted(f[:-5] for f in os.listdir(PLANS_DIR) if f.endswith(".yaml"))
        plans = {slug: load_plan(slug) for slug in plan_slugs}
    except Refusal as err:
        print(f"REFUSED: {err}", file=sys.stderr)
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
            print(f"REFUSED {name}: {err}", file=sys.stderr)
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

    print(f"tac-merge-research: {len(files)} research file(s)")
    for rep in reports:
        print(rep.render())
    if pruned:
        print("  classes pruned (every command refused, so nothing to collect): {}".format(", ".join(sorted(pruned))))
    if changed:
        print("  files changed: {}".format(", ".join(os.path.relpath(p, REPO) for p in sorted(changed))))
    else:
        print("  files changed: none (already merged)")

    refused = sum(len(r.refused) for r in reports)
    dropped = sum(len(r.dropped_cues) for r in reports)
    excluded = sum(r.excluded_count() for r in reports)
    if excluded:
        by_family = " · ".join(
            f"{f} {sum(r.excluded.get(f, 0) for r in reports)}"
            for f in tac_forbidden.FAMILIES)
        print(f"  {excluded} record(s) excluded by the output-only command policy ({by_family}). "
              "They are counted, never named: run scripts/tac-purge-forbidden.py to take them "
              "out of the research corpus as well.")
    if refused or dropped:
        # Refusals are REPORTED, not fatal: a research file may legitimately
        # carry a command a vendor documents that is not a read-only show, and
        # that record must simply never land. Silence would be the bug.
        print(f"  {refused} record(s) refused and {dropped} detection cue(s) dropped — they will NEVER merge; "
              "fix or remove them in the research file.")

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
