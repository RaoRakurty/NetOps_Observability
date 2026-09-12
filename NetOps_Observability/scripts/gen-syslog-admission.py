#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""gen-syslog-admission.py — compile the correlation engine's syslog admission
screen into VRL the aggregator can run, so the bus can carry a PRE-SCREENED
copy of the syslog lane (topic `netops.syslog.control`).

WHY THIS EXISTS (A4 Phase 1).
`src/correlation/producers.syslog_promotable` is a NECESSARY condition for a
raw syslog line to become correlation evidence. Today the engine consumes the
WHOLE firehose from `netops.syslog` and applies that screen in-process — on
storm-s11, 900,001 lines in, 54,767 passed, 845,234 rejected. 94 % of the
decode + dispatch work is spent proving a line is uninteresting. Moving the
screen upstream to the aggregator lets the engine subscribe to a topic that
carries only the 6 %.

That is only safe if the two screens are the SAME screen. So the VRL is
GENERATED FROM THE PYTHON, never hand-written: this script imports `producers`,
reads `ALARM_SEVERITY_FLOOR` and the literal set the screen tests, and emits

  deployment/docker/vector/generated/syslog-admission.vrl   the program
  deployment/docker/vector/tests/syslog-admission.yaml      its `vector test`s
  deployment/docker/vector/vector.yaml                      the spliced copy

`--check` re-renders all three in memory and exits 1 on any difference, so a
rule change in `producers.py` that is not re-generated is RED in CI (the drift
test in tests/test_syslog_admission.py runs exactly that).

THE PREDICATE (identical to `syslog_promotable`, in the same order):

    tag = upcase(appname)
    sev = min(severity-keyword lookup, %FAC-N-MNEMONIC tag digit)   # 99 = none
    if sev <= ALARM_SEVERITY_FLOOR            -> admit, by = "severity"
    hay = downcase(message + " " + tag + " " + facility + " " + event_type)
    if any screen literal is a substring of hay -> admit, by = "marker"
    otherwise                                  -> leave .cx_admission unset

FAIL-OPEN PARITY. `_build_syslog_screen()` returns None when a guard pattern
cannot be screened soundly; `syslog_promotable` then admits everything. The
generated VRL mirrors that exactly: it admits every line (`by = "unscreenable"`
where severity did not already answer) and the header says UNSCREENABLE. The
optimization is lost, never a signal.

WHY `source:` AND NOT `file:`. The .vrl artifact below is the source of truth
and is what `vector test` exercises, but vector.yaml carries a SPLICED copy
rather than `file: …`, for two reasons: (1) `scripts/preflight-configs.sh`
fresh-loads the committed aggregator config with ONLY vector.yaml mounted, so a
`file:` reference would make every preflight run fail on a missing path — and
that script is the gate, not a thing to weaken; (2) a runtime file dependency
turns a missing/unmounted generated file into a boot failure of the whole
syslog tier (`Could not open vrl program …` → exit before sinks connect), which
for the highest-value evidence class is a total loss. Byte-equality between the
two copies is pinned by `--check`, so they cannot drift.

Usage:
    python3 scripts/gen-syslog-admission.py            # write the artifacts
    python3 scripts/gen-syslog-admission.py --check    # exit 1 if stale
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
CORRELATION_DIR = os.path.join(REPO_ROOT, "src", "correlation")

VECTOR_DIR = os.path.join(REPO_ROOT, "deployment", "docker", "vector")
VRL_PATH = os.path.join(VECTOR_DIR, "generated", "syslog-admission.vrl")
TESTS_PATH = os.path.join(VECTOR_DIR, "tests", "syslog-admission.yaml")
CONFIG_PATH = os.path.join(VECTOR_DIR, "vector.yaml")
FIXTURES_PATH = os.path.join(REPO_ROOT, "telemetry-catalog", "fixtures",
                             "syslog_events.jsonl")

# The container path the vector-aggregator sees (the service mounts ./vector at
# /etc/vector/conf, F-51 directory mount) — used by the generated test config,
# which DOES load the .vrl by file (we own that docker command).
VRL_CONTAINER_PATH = "/etc/vector/conf/generated/syslog-admission.vrl"

BEGIN_MARK = "  # >>> BEGIN GENERATED-SYSLOG-ADMISSION (scripts/gen-syslog-admission.py)"
END_MARK = "  # <<< END GENERATED-SYSLOG-ADMISSION"

# No severity derivable. Must stay ABOVE any plausible ALARM_SEVERITY_FLOOR so
# `sev <= floor` is false — the VRL equivalent of Python's `min([]) -> None`.
# Asserted against the real floor in `read_screen()`.
NO_SEVERITY = 99

# The Cisco %FACILITY-N-MNEMONIC tag-digit regex. Copied from
# `producers._TAG_SEV_RE` and pinned equal to it at generation time, so the
# copy cannot drift (the same both-directions pin `_CP_GUARD_PATTERNS` uses).
TAG_SEV_PATTERN = r"%[A-Z0-9_]+-(\d)-[A-Z0-9_]+"

# The SAME pattern with the digit group named, which is how VRL's parse_regex
# returns it. DERIVED from TAG_SEV_PATTERN rather than written out a second
# time: a hand-kept copy is one escaping slip away from emitting `\\d` (a
# literal backslash) instead of `\d`, which would silently switch off the
# tag-digit severity path — admitting fewer lines than the Python screen, in
# the one direction the contract forbids.
VRL_TAG_SEV_PATTERN = TAG_SEV_PATTERN.replace(r"(\d)", r"(?P<d>\d)")
assert VRL_TAG_SEV_PATTERN != TAG_SEV_PATTERN, "digit group could not be named"

# Literals are pasted into a VRL regex alternation and into `r'…'`, so they must
# carry no regex metacharacter and no quote. This is a REFUSAL, not an escape:
# a literal outside this class means the screen grew a shape this generator was
# never designed for, and silently escaping it would be a guess.
SAFE_LITERAL_RE = re.compile(r"^[a-z0-9_ .:/-]+$")


class GenerationError(RuntimeError):
    """The screen could not be compiled faithfully — never emit a guess."""


# ── reading the Python screen ────────────────────────────────────────────────

def load_producers() -> Any:
    """Import `src/correlation/producers` (its siblings import flat, so the
    package dir itself goes on sys.path). Read-only: this script never writes
    into src/correlation."""
    if CORRELATION_DIR not in sys.path:
        sys.path.insert(0, CORRELATION_DIR)
    # Imported here, not at module scope: sys.path has to carry
    # src/correlation before the import can resolve.
    import producers
    return producers


def read_screen(producers: Any) -> tuple[int, tuple[str, ...] | None]:
    """(ALARM_SEVERITY_FLOOR, literals-or-None).

    `producers` exposes no public accessor for the screen, so this reads the
    module global `_SYSLOG_SCREEN_LITERALS` — the value `syslog_promotable`
    ACTUALLY tests — and cross-checks it against a fresh `_build_syslog_screen()`
    call. A disagreement means the module global was patched or the build is
    non-deterministic; either way generating from it would be a lie.
    """
    floor = producers.ALARM_SEVERITY_FLOOR
    if not isinstance(floor, int) or not 0 <= floor <= 7:
        raise GenerationError(
            f"ALARM_SEVERITY_FLOOR is not an RFC5424 severity: {floor!r}")
    if floor >= NO_SEVERITY:
        raise GenerationError(
            f"ALARM_SEVERITY_FLOOR {floor} collides with the no-severity "
            f"sentinel {NO_SEVERITY} — the generated VRL would admit "
            f"severity-less lines that the Python screen rejects")

    live = producers._SYSLOG_SCREEN_LITERALS
    rebuilt = producers._build_syslog_screen()
    if live is None or rebuilt is None:
        if live is not rebuilt:
            raise GenerationError(
                "screen disagreement: _SYSLOG_SCREEN_LITERALS is "
                f"{'None' if live is None else 'built'} but _build_syslog_screen() "
                f"returned {'None' if rebuilt is None else 'a screen'}")
        return floor, None
    if tuple(live) != tuple(rebuilt):
        raise GenerationError(
            "screen disagreement: _SYSLOG_SCREEN_LITERALS is not what "
            "_build_syslog_screen() produces — refusing to generate from a "
            "patched or non-deterministic screen")
    for lit in live:
        if lit != lit.lower():
            raise GenerationError(f"screen literal is not lower-cased: {lit!r}")
        if not SAFE_LITERAL_RE.match(lit):
            raise GenerationError(
                f"screen literal {lit!r} carries a character this generator "
                "cannot compile into VRL soundly (regex metacharacter or "
                "quote) — extend SAFE_LITERAL_RE deliberately, never blindly")
    return floor, tuple(live)


def read_severity_map(producers: Any) -> dict[str, int]:
    sevmap = producers._SEVERITY_NUM
    if not isinstance(sevmap, dict) or not sevmap:
        raise GenerationError("producers._SEVERITY_NUM is not a non-empty dict")
    for kw, num in sevmap.items():
        if not isinstance(kw, str) or kw != kw.lower():
            raise GenerationError(f"severity keyword not lower-cased: {kw!r}")
        if not SAFE_LITERAL_RE.match(kw):
            raise GenerationError(f"severity keyword not VRL-safe: {kw!r}")
        if not isinstance(num, int) or not 0 <= num <= 7:
            raise GenerationError(f"severity {kw!r} maps to {num!r}, not 0..7")
    return dict(sevmap)


def check_tag_regex(producers: Any) -> None:
    """The tag-digit regex is COPIED into the VRL; pin the copy to the source."""
    live = producers._TAG_SEV_RE.pattern
    if live != TAG_SEV_PATTERN:
        raise GenerationError(
            f"producers._TAG_SEV_RE changed to {live!r}; the generated VRL "
            f"still compiles {TAG_SEV_PATTERN!r}. Update TAG_SEV_PATTERN (and "
            "re-verify the Rust-regex semantics match Python's) deliberately.")


def rules_hash(floor: int, literals: tuple[str, ...] | None) -> str:
    """sha256 over the SCREEN, not over the rendered text.

    Domain-separated, newline-framed, literals sorted (the tuple's longest-first
    order is a lookup optimization, not part of the screen's meaning), so the
    hash changes exactly when the admission DECISION can change.
    """
    h = hashlib.sha256()
    h.update(b"cx-syslog-admission-v1\n")
    h.update(f"floor={floor}\n".encode())
    if literals is None:
        h.update(b"screen=UNSCREENABLE\n")
    else:
        h.update(f"literals={len(literals)}\n".encode())
        for lit in sorted(literals):
            h.update(lit.encode() + b"\n")
    return h.hexdigest()


# ── the decision, in Python (the golden side of the equality) ────────────────

def expected_by(ev: dict, floor: int,
                literals: tuple[str, ...] | None) -> str | None:
    """`.cx_admission.by` the generated VRL must produce for `ev`.

    A re-statement of `syslog_promotable` that also names WHICH gate answered.
    `emit_tests` asserts `(expected_by(...) is not None) == syslog_promotable(ev)`
    for every case it writes, so this function can never drift from the screen
    without the generation itself failing.
    """
    tag = str(ev.get("appname") or "").upper()
    sev = _severity_num(ev, tag)
    if sev is not None and sev <= floor:
        return "severity"
    if literals is None:
        return "unscreenable"
    hay = " ".join((
        str(ev.get("message") or ""),
        tag,
        str(ev.get("facility") or ""),
        str(ev.get("event_type") or ""),
    )).lower()
    for lit in literals:
        if lit in hay:
            return "marker"
    return None


def _severity_num(ev: dict, tag: str) -> int | None:
    """Deferred to `producers.syslog_severity_num` — there is no second copy of
    the severity derivation in this repo, and there will not be one."""
    return _PRODUCERS.syslog_severity_num(ev, tag)


# ── VRL rendering ────────────────────────────────────────────────────────────

def _vrl_severity_branches(sevmap: dict[str, int], indent: str) -> list[str]:
    """`includes([...], kw)` branches, one per distinct severity NUMBER — the
    same table as `producers._SEVERITY_NUM`, grouped so the diff is readable."""
    by_num: dict[int, list[str]] = {}
    for kw, num in sevmap.items():
        by_num.setdefault(num, []).append(kw)
    out: list[str] = []
    for i, num in enumerate(sorted(by_num)):
        kws = json.dumps(sorted(by_num[num]))
        kw_op = "if" if i == 0 else "} else if"
        out.append(f"{indent}{kw_op} includes({kws}, cx_kw) {{")
        out.append(f"{indent}  cx_sev = {num}")
    out.append(f"{indent}}}")
    return out


def render_vrl(floor: int, literals: tuple[str, ...] | None,
               sevmap: dict[str, int], digest: str) -> str:
    short = digest[:12]
    screen_state = "UNSCREENABLE" if literals is None else f"{len(literals)} literals"
    lines: list[str] = [
        "# syslog-admission.vrl — GENERATED by scripts/gen-syslog-admission.py.",
        "# DO NOT EDIT BY HAND: re-run the generator, or CI's drift test fails.",
        "#",
        "# Compiled from src/correlation/producers.py — the same screen the",
        "# correlation engine applies in-process (`syslog_promotable`). Sets",
        "# `.cx_admission = {\"v\": <rules_hash prefix>, \"by\": <gate>}` on a line",
        "# the engine COULD promote, and leaves the field unset otherwise. It",
        "# never drops, rewrites or reorders anything: the stamp is additive.",
        "#",
        f"#   rules_hash : {digest}",
        f"#   v          : {short}",
        f"#   floor      : ALARM_SEVERITY_FLOOR = {floor}",
        f"#   screen     : {screen_state}",
        "#",
    ]
    if literals is None:
        lines += [
            "# SCREEN STATE: UNSCREENABLE. `_build_syslog_screen()` returned None —",
            "# a classifier guard could not be screened soundly, so the Python",
            "# screen FAILS OPEN and admits every line. This program does the same",
            "# (`by` = \"unscreenable\"): the pre-filter is inert, not wrong. The",
            "# control topic then carries the full firehose, which is a lost",
            "# optimization and never a lost signal.",
            "#",
        ]
    lines += [
        "# Field parity: this runs immediately after `syslog_normalized`, so it",
        "# reads exactly the document `kafka_syslog` serializes onto",
        "# netops.syslog — the same dict `syslog_promotable` receives.",
        "",
        "# ── severity (producers.syslog_severity_num) ────────────────────────",
        f"# `{NO_SEVERITY}` is the no-severity sentinel: Python's `min([]) -> None`,",
        "# which never satisfies the floor. Keyword AND tag digit are both read;",
        "# the MOST severe (numerically smallest) of the two wins.",
        f"cx_sev = {NO_SEVERITY}",
        "cx_kw = downcase(strip_whitespace(string(.severity) ?? \"\"))",
    ]
    lines += _vrl_severity_branches(sevmap, "")
    lines += [
        "",
        "cx_tag = upcase(string(.appname) ?? \"\")",
        f"cx_tag_sev = {NO_SEVERITY}",
        f"cx_m = parse_regex(cx_tag, r'{VRL_TAG_SEV_PATTERN}') ?? {{}}",
        "if is_string(cx_m.d) {",
        f"  cx_tag_sev = to_int(cx_m.d) ?? {NO_SEVERITY}",
        "}",
        "if cx_tag_sev < cx_sev {",
        "  cx_sev = cx_tag_sev",
        "}",
        "",
        "# ── gate 1: the device called it warning-or-worse ───────────────────",
        f"if cx_sev <= {floor} {{",
        f'  .cx_admission = {{ "v": "{short}", "by": "severity" }}',
        "}",
    ]
    if literals is None:
        lines += [
            "",
            "# ── gate 2: UNSCREENABLE — fail open, exactly like the Python ───────",
            "if !exists(.cx_admission) {",
            f'  .cx_admission = {{ "v": "{short}", "by": "unscreenable" }}',
            "}",
        ]
    else:
        alternation = "|".join(literals)  # longest-first: presentation only
        lines += [
            "",
            "# ── gate 2: a known typed symptom marker, at any severity ───────────",
            "# The haystack is `message + \" \" + upcase(appname) + \" \" + facility +",
            "# \" \" + event_type`, lower-cased — byte-for-byte the join",
            "# `syslog_promotable` builds. The alternation below is the screen's",
            f"# {len(literals)} literals (longest first, as in the Python tuple); Rust's",
            "# regex compiles an alternation of plain literals into a literal-set",
            "# matcher, so this is one pass, not 61 substring searches.",
            "if !exists(.cx_admission) {",
            "  cx_hay = downcase(",
            "    (string(.message) ?? \"\") + \" \" + cx_tag + \" \" +",
            "    (string(.facility) ?? \"\") + \" \" + (string(.event_type) ?? \"\"))",
            f"  if match(cx_hay, r'{alternation}') {{",
            f'    .cx_admission = {{ "v": "{short}", "by": "marker" }}',
            "  }",
            "}",
        ]
    lines += [
        "",
        "# The scratch locals never reach the wire (VRL locals are not fields).",
        "",
    ]
    return "\n".join(lines)


# ── vector.yaml splice ───────────────────────────────────────────────────────

def render_config_block(vrl: str) -> str:
    body = "\n".join(("      " + ln).rstrip() for ln in vrl.rstrip("\n").split("\n"))
    lines = [
        BEGIN_MARK,
        "  # The admission stamp. GENERATED — edit scripts/gen-syslog-admission.py",
        "  # (or the screen in src/correlation/producers.py) and re-run it; the",
        "  # drift test in tests/test_syslog_admission.py fails on a stale copy.",
        "  #",
        "  # Additive and non-filtering: every line leaves this transform, so",
        "  # kafka_syslog still carries the WHOLE lane. Only the `syslog_admission`",
        "  # route below narrows, and only onto the opt-in control topic.",
        "  syslog_admission_stamp:",
        "    type: remap",
        "    inputs: [syslog_normalized]",
        "    source: |",
        body,
        END_MARK,
    ]
    return "\n".join(lines) + "\n"


def splice_config(existing: str, block: str) -> str:
    start = existing.find(BEGIN_MARK)
    end = existing.find(END_MARK)
    if start < 0 or end < 0:
        raise GenerationError(
            f"vector.yaml carries no generated block: expected the markers\n"
            f"  {BEGIN_MARK}\n  {END_MARK}\n"
            "Add them (with the hand-written route + sink below) before "
            "generating.")
    if end < start:
        raise GenerationError("vector.yaml generated markers are inverted")
    end_line = existing.find("\n", end)
    if end_line < 0:
        raise GenerationError("vector.yaml END marker is not newline-terminated")
    return existing[:start] + block + existing[end_line + 1:]


# ── vector unit tests ────────────────────────────────────────────────────────

# Six hand cases the fixture corpus does not (or cannot) cover. The
# UNSCREENABLE case is NOT here: fail-open is a different generated program, so
# it is proven by generating it — see tests/test_syslog_admission.py.
HAND_CASES: tuple[tuple[str, dict], ...] = (
    ("severity-floor line with no marker admits by severity",
     {"hostname": "core1", "appname": "sshd", "severity": "warning",
      "message": "session opened for user netops"}),
    ("notice line with a typed marker admits by marker",
     {"hostname": "leaf3", "appname": "LINK", "severity": "notice",
      "message": "Interface Ethernet1/3 changed state UPDOWN"}),
    ("notice line with no marker is not admitted",
     {"hostname": "leaf3", "appname": "sshd", "severity": "notice",
      "message": "accepted publickey for netops from 10.9.9.9"}),
    ("severity derived from the %FAC-N-MNEMONIC appname tag alone",
     {"hostname": "edge2", "appname": "%SYS-3-CPUHOG",
      "message": "task ran too long"}),
    ("no severity anywhere and no marker is not admitted",
     {"hostname": "edge2", "appname": "cron",
      "message": "run-parts finished daily"}),
    ("marker found in facility / event_type, not in the message",
     {"hostname": "spine1", "appname": "eos", "severity": "info",
      "message": "state change", "facility": "local7",
      "event_type": "lldp_neighbor_change"}),
)

TEST_FIELDS = ("message", "appname", "severity", "facility", "event_type",
               "hostname")


def load_fixture_corpus() -> list[dict]:
    if not os.path.exists(FIXTURES_PATH):
        raise GenerationError(f"fixture corpus missing: {FIXTURES_PATH}")
    out: list[dict] = []
    with open(FIXTURES_PATH, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise GenerationError(
                    f"{FIXTURES_PATH}:{lineno} is not JSON: {exc}") from exc
            if not isinstance(ev, dict):
                raise GenerationError(f"{FIXTURES_PATH}:{lineno} is not an object")
            out.append({k: v for k, v in ev.items() if k in TEST_FIELDS})
    if not out:
        raise GenerationError(f"fixture corpus is empty: {FIXTURES_PATH}")
    return out


def _yaml_str(value: object) -> str:
    """JSON is a YAML subset for scalars — and json.dumps is the escaper we
    already trust everywhere else in this repo."""
    return json.dumps(value if isinstance(value, str) else str(value))


def render_tests(producers: Any, floor: int,
                 literals: tuple[str, ...] | None, digest: str) -> str:
    cases: list[tuple[str, dict]] = [
        (f"fixture {i:02d}: {ev.get('appname', '?')}", ev)
        for i, ev in enumerate(load_fixture_corpus(), 1)
    ]
    cases += list(HAND_CASES)

    # Decide EVERY case first (and prove the equality) so the header can state
    # the admitted/rejected split — a suite where nothing is rejected would be
    # a suite that proves nothing, and the number says so at a glance.
    decided: list[tuple[str, dict, str | None]] = []
    for name, ev in cases:
        want = expected_by(ev, floor, literals)
        promotable = producers.syslog_promotable(ev)
        if (want is not None) != promotable:
            raise GenerationError(
                f"GOLDEN EQUALITY BROKEN before it was even written: case "
                f"{name!r} -> expected_by={want!r} but "
                f"syslog_promotable={promotable} (event: {ev!r})")
        decided.append((name, ev, want))
    n_admit = sum(1 for _, _, want in decided if want is not None)

    # A suite that never rejects would pass against a VRL that admits
    # unconditionally, and one that never exercises a gate proves nothing about
    # it. Both are refused HERE rather than caught later: the screen moves, and
    # when it moves out from under a hand case the fix is to add a hand case,
    # not to ship a suite that quietly stopped testing something.
    gates = {want for _, _, want in decided}
    required = {"severity", None} | ({"unscreenable"} if literals is None
                                     else {"marker"})
    missing = required - gates
    if missing:
        raise GenerationError(
            f"the generated suite would not exercise {sorted(map(str, missing))} "
            f"— add a HAND_CASES entry that lands on it (the screen changed "
            f"under the existing ones)")

    short = digest[:12]
    body: list[str] = [
        "# syslog-admission.yaml — GENERATED by scripts/gen-syslog-admission.py.",
        "# DO NOT EDIT BY HAND.",
        "#",
        "# `vector test` proof of the GOLDEN EQUALITY: for every case below the",
        "# expected `.cx_admission.by` was computed by calling",
        "# `producers.syslog_promotable` (and its severity/marker gates) on the",
        "# SAME event at generation time — the generator refuses to write a case",
        "# whose two sides disagree. So a green run here means the VRL and the",
        "# Python screen admit exactly the same lines.",
        "#",
        f"#   rules_hash : {digest}",
        (f"#   cases      : {len(cases)} ({len(cases) - len(HAND_CASES)} "
         f"fixture corpus + {len(HAND_CASES)} hand)"),
        (f"#   admitted   : {n_admit} / {len(cases)} "
         f"({len(cases) - n_admit} correctly rejected)"),
        "#",
        "# Run (from the repo root). Keep every dollar sign out of this file:",
        "# Vector interpolates environment variables in the raw config TEXT,",
        "# comments included, and an unset one is a hard load error.",
        "#   docker run --rm --entrypoint vector \\",
        "#     -v ./deployment/docker/vector:/etc/vector/conf:ro \\",
        "#     timberio/vector:0.40.0-alpine \\",
        "#     test /etc/vector/conf/tests/syslog-admission.yaml",
        "",
        "# The transform under test loads the GENERATED PROGRAM BY FILE, so this",
        "# suite exercises the artifact itself; vector.yaml's spliced copy is",
        "# pinned byte-identical to it by `gen-syslog-admission.py --check`.",
        "transforms:",
        "  syslog_admission_stamp:",
        "    type: remap",
        "    inputs: []",
        f"    file: {VRL_CONTAINER_PATH}",
        "",
        "tests:",
    ]

    for name, ev, want in decided:
        body.append(f"  - name: {_yaml_str(name)}")
        body.append("    inputs:")
        body.append("      - insert_at: syslog_admission_stamp")
        body.append("        type: log")
        body.append("        log_fields:")
        for key in TEST_FIELDS:
            if key in ev:
                body.append(f"          {key}: {_yaml_str(ev[key])}")
        body.append("    outputs:")
        body.append("      - extract_from: syslog_admission_stamp")
        body.append("        conditions:")
        body.append("          - type: vrl")
        if want is None:
            body.append("            source: |")
            body.append("              assert_eq!(.cx_admission, null, "
                        '"expected NO admission stamp")')
        else:
            body.append("            source: |")
            body.append(f"              assert_eq!(.cx_admission.by, "
                        f'{_yaml_str(want)}, "wrong admission gate")')
            body.append(f"              assert_eq!(.cx_admission.v, "
                        f'{_yaml_str(short)}, "wrong rules_hash stamp")')
    return "\n".join(body) + "\n"


# ── driver ───────────────────────────────────────────────────────────────────

_PRODUCERS: Any = None


def build() -> dict[str, str]:
    """Render every artifact in memory. Returns {path: content}."""
    global _PRODUCERS
    _PRODUCERS = producers = load_producers()
    floor, literals = read_screen(producers)
    sevmap = read_severity_map(producers)
    check_tag_regex(producers)
    digest = rules_hash(floor, literals)

    vrl = render_vrl(floor, literals, sevmap, digest)
    tests = render_tests(producers, floor, literals, digest)
    with open(CONFIG_PATH, encoding="utf-8") as fh:
        config = splice_config(fh.read(), render_config_block(vrl))
    return {VRL_PATH: vrl, TESTS_PATH: tests, CONFIG_PATH: config}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Compile the correlation syslog screen into aggregator VRL.")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if any checked-in artifact is stale (CI/drift)")
    args = ap.parse_args(argv)

    try:
        artifacts = build()
    except GenerationError as exc:
        print(f"gen-syslog-admission: {exc}", file=sys.stderr)
        return 2

    stale: list[str] = []
    for path, content in artifacts.items():
        rel = os.path.relpath(path, REPO_ROOT)
        current = None
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                current = fh.read()
        if current == content:
            if not args.check:
                print(f"gen-syslog-admission: {rel} up to date")
            continue
        if args.check:
            stale.append(rel)
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"gen-syslog-admission: wrote {rel}")

    if args.check:
        if stale:
            print("gen-syslog-admission: STALE — re-run "
                  "`python3 scripts/gen-syslog-admission.py`:", file=sys.stderr)
            for rel in stale:
                print(f"  - {rel}", file=sys.stderr)
            return 1
        print("gen-syslog-admission: all artifacts match the Python screen")
    return 0


if __name__ == "__main__":
    sys.exit(main())
