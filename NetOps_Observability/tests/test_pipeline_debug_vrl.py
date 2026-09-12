# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""W2 pipeline-debugger — the VRL parser/router DECISION HOOK.

WHAT IS BEING PINNED. `correlix-debug trace` collects the parser and router
stages with `vector tap --outputs-of <transform>`. A tap shows the EVENT, never
the DECISION PATH — which vendor branch matched, whether the device→tenant
registry answered, which body parser ran, and WHY a record ends up unattributed,
unadmitted or without a usable event time. Wave 2 owes that path, and the four
Vector transforms that make those decisions now write it down:

  aggregator   syslog_normalized, snmptrap_normalized
  router       the shared &log_lane anchor (syslog_tagged / snmptrap_tagged /
               applogs_tagged / cloudlogs_tagged / security_tagged) and
               flows_decoded  (+ a log-only hook on the pass-through flows_rekey)

Three properties have to hold, and only the REAL RUNTIME can prove them, which
is what these tests run:

  1. a record carrying the debugger's `cx_debug=<ulid>` marker gets a
     `.cx_parse_trace` naming the branch that matched;
  2. an ordinary record does not get the field AT ALL — the guard is one
     `contains()` (one `exists()` on the flow lane, which has no free text) and
     unmarked traffic pays nothing else;
  3. every miss / refusal / drop branch names the REASON, not just the outcome.

The suites are run TOGETHER WITH the committed vector.yaml, so they exercise the
transform the stack actually loads — a fixture that re-declared the VRL would go
green over a broken shipped config, which is the "green test, dead pipeline"
shape this repo keeps removing.

Run:  python3 -m pytest tests/test_pipeline_debug_vrl.py -v
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
AGG_DIR = ROOT / "deployment" / "docker" / "vector"
ROUTER_DIR = ROOT / "deployment" / "docker" / "vector-router"
FIXTURES = AGG_DIR / "tests" / "fixtures"
AGG_SUITE = AGG_DIR / "tests" / "parse-trace.yaml"
ROUTER_SUITE = ROUTER_DIR / "tests" / "parse-trace.yaml"

VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"   # in sync with docker-compose.yml

MARKER_TOKEN = "cx_debug="          # internal/pipedebug MarkerField + "="
TRACE_FIELD = ".cx_parse_trace"

# The stubbed secrets are the same idiom scripts/preflight-configs.sh uses: the
# ingest sources use `${INGEST_TOKEN_*:?}` so Vector REFUSES TO START without
# them. That is correct at runtime; here we are proving the committed config
# COMPILES AND BEHAVES, not that a secret has been provisioned.
ENV_STUBS = [
    "CLICKHOUSE_USER=x", "CLICKHOUSE_PASSWORD=x", "OPENSEARCH_URL=http://x:9200",
    "DB_HOST=x", "DB_USER=x", "DB_PASSWORD=x",
    "INGEST_TOKEN=preflight-stub", "INGEST_TOKEN_TRAPS=preflight-stub",
    "INGEST_TOKEN_PROBES=preflight-stub", "INGEST_TOKEN_METRICS=preflight-stub",
    "INGEST_TOKEN_BUS=preflight-stub",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _cfg(path: Path) -> dict:
    return yaml.safe_load(_read(path))


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=60, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _vector_test(configs: list[str], mounts: list[tuple[Path, str]]) -> subprocess.CompletedProcess:
    cmd = ["docker", "run", "--rm", "--entrypoint", "vector"]
    for kv in ENV_STUBS:
        cmd += ["-e", kv]
    for src, dst in mounts:
        cmd += ["-v", f"{src}:{dst}:ro"]
    cmd += [VECTOR_IMAGE, "test", *configs]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=900, check=False)


def _assert_suite_passed(proc: subprocess.CompletedProcess, expected: int) -> None:
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"vector test failed:\n{out}"
    passed = out.count("... passed")
    assert passed == expected, f"expected {expected} cases to run, saw {passed}:\n{out}"
    assert "failed" not in out.lower(), out


def _case_count(path: Path) -> int:
    return len(yaml.safe_load(_read(path))["tests"])


# ── 1. the hooks exist, in the transforms the debugger actually taps ─────────

@pytest.mark.parametrize("cfg_path,transform", [
    (AGG_DIR / "vector.yaml", "syslog_normalized"),
    (AGG_DIR / "vector.yaml", "snmptrap_normalized"),
    (ROUTER_DIR / "vector.yaml", "applogs_tagged"),      # the shared &log_lane anchor
    (ROUTER_DIR / "vector.yaml", "syslog_tagged"),
    (ROUTER_DIR / "vector.yaml", "snmptrap_tagged"),
    (ROUTER_DIR / "vector.yaml", "flows_decoded"),
])
def test_every_traced_transform_carries_the_decision_hook(cfg_path, transform):
    src = _cfg(cfg_path)["transforms"][transform]["source"]
    assert TRACE_FIELD in src, f"{transform} does not stamp {TRACE_FIELD}"
    assert "log(cx_line" in src, (
        f"{transform} stamps the trace but never logs it — half the requirement "
        "is that the line reaches `docker logs`")


def test_the_pass_through_flow_lane_logs_but_never_stamps():
    """flows_rekey is a declared PASS-THROUGH: the netops.flows payload must
    stay byte-equivalent to goflow2's. Its hook may log the keying decision and
    must NOT add a field — otherwise the hook breaks the contract the lane
    exists to keep."""
    src = _cfg(ROUTER_DIR / "vector.yaml")["transforms"]["flows_rekey"]["source"]
    assert 'log("component=flows_rekey' in src, "flows_rekey has no decision hook"
    # ASSIGNMENTS only. Both the hook's comment and its own log line say, in
    # prose, that nothing is stamped here; a bare substring check would read
    # either of those as the violation it warns against.
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    assert f"{TRACE_FIELD} =" not in code, (
        "flows_rekey must not stamp a field — it is the byte-equivalent "
        "pass-through onto netops.flows")


# ── 2. the guard: one compare, and the RIGHT one ─────────────────────────────

def test_the_guard_is_the_marker_and_nothing_else():
    """The hook must be reachable ONLY through the debugger's marker. A guard on
    anything a producer routinely sets would put the whole block on the hot
    path, which is the one thing this feature may not cost."""
    for cfg_path, transform in (
            (AGG_DIR / "vector.yaml", "syslog_normalized"),
            (AGG_DIR / "vector.yaml", "snmptrap_normalized"),
            (ROUTER_DIR / "vector.yaml", "applogs_tagged")):
        src = _cfg(cfg_path)["transforms"][transform]["source"]
        assert f'contains(cx_msg, "{MARKER_TOKEN}")' in src or \
               f'contains(msg, "{MARKER_TOKEN}")' in src, \
            f"{transform}'s hook is not guarded by the {MARKER_TOKEN} marker"

    # The flow lanes have no free-text field at all (every netops-flows property
    # is an ip/int/keyword) and NetFlow v5 has no vendor-extension space, so the
    # marker rides as a deterministic FLOW TUPLE in RFC 5737 documentation
    # address space (internal/pipedebug/flow.go). The guard is one starts_with()
    # on the source address — a field every flow already has, and a prefix no
    # production traffic uses.
    for transform in ("flows_decoded", "flows_rekey"):
        src = _cfg(ROUTER_DIR / "vector.yaml")["transforms"][transform]["source"]
        assert 'starts_with(cx_src, "192.0.2.")' in src, \
            f"{transform}'s hook is not guarded by the RFC 5737 documentation source prefix"
        assert "exists(.cx_debug)" not in src, \
            (f"{transform} still guards on a .cx_debug field. A NetFlow v5 probe cannot carry "
             "one, so that guard is inert — an inert hook that reads as coverage is the defect "
             "this whole feature exists to remove.")


def test_the_log_level_is_info_and_unthrottled_everywhere():
    """`debug` would NEVER be emitted: Vector reads VECTOR_LOG once at process
    start, has no runtime level switch (pipedebug's VectorLevelReason), and
    docker-compose.yml does not set it — so both tiers run at `info`. And the
    default rate limit would silently de-duplicate a burst of probes, which is
    the exact silence this feature exists to remove."""
    compose = _cfg(ROOT / "deployment" / "docker" / "docker-compose.yml")
    for svc in ("vector-aggregator", "vector-router"):
        env = compose["services"][svc].get("environment") or {}
        keys = env if isinstance(env, dict) else {e.split("=", 1)[0] for e in env}
        assert "VECTOR_LOG" not in keys, (
            f"{svc} now sets VECTOR_LOG — re-derive the level the hooks log at "
            "instead of leaving a comment that has become false")
    for cfg_path in (AGG_DIR / "vector.yaml", ROUTER_DIR / "vector.yaml"):
        raw = _read(cfg_path)
        assert 'level: "debug"' not in raw, (
            "a debug-level log() line is unreachable in this process and would "
            "tell the operator nothing while looking like coverage")
        for hook in raw.split("log(cx_line, ")[1:]:
            head = hook.split(")", 1)[0]
            assert 'level: "info"' in head, head
            assert "rate_limit_secs: 0" in head, head


def test_the_trace_is_one_flat_string_key():
    """The CLAUDE.md dotted-key gotcha: a dynamically mapped field of varying
    shape (Docker's `.label` map, whose com.docker.compose.* keys OpenSearch
    read as object paths) silently dropped EVERY app log once. The debug field
    must be a single flat string under a dot-free key, forever."""
    assert "." not in TRACE_FIELD[1:], TRACE_FIELD
    for cfg_path in (AGG_DIR / "vector.yaml", ROUTER_DIR / "vector.yaml"):
        raw = _read(cfg_path)
        for assignment in ("cx_prev + \" | \" + cx_line", "= cx_line"):
            assert assignment in raw, cfg_path
        assert f"{TRACE_FIELD} = [" not in raw, "the trace must never become an array"
        assert f"{TRACE_FIELD} = {{" not in raw, "the trace must never become an object"


# ── 3. the field cannot break either flow store ──────────────────────────────

def test_a_stray_field_cannot_fail_a_clickhouse_batch():
    """ClickHouse sinks are column-typed and one unknown key can 400 a whole
    insert batch (the `.proto` lesson — netops.flows stayed empty for exactly
    that reason). `skip_unknown_fields` is what makes the stamp safe on the
    flows lane; if it were ever turned off, the field would have to be removed
    before the sink."""
    ch = _cfg(ROUTER_DIR / "vector.yaml")["sinks"]["clickhouse_flows"]
    assert ch["skip_unknown_fields"] is True, (
        "clickhouse_flows no longer skips unknown fields — .cx_parse_trace "
        "would fail the insert batch and must be deleted before this sink")


def test_a_stray_field_cannot_be_rejected_by_opensearch():
    """Every log template is `dynamic: false`, so an undeclared field is kept in
    _source and simply not indexed: no dynamic mapping is created, so there is
    no mapping conflict and no rejected document. That is what makes it safe to
    let a debug string ride to the stores on synthetic records only."""
    import json
    with open(ROOT / "deployment" / "docker" / "opensearch" /
              "index-templates.json", encoding="utf-8") as fh:
        templates = json.load(fh)["templates"]
    for name in ("netops-syslog", "netops-snmptrap", "netops-flows",
                 "netops-applogs", "netops-cloudlogs"):
        mappings = templates[name]["template"]["mappings"]
        assert mappings["dynamic"] is False, (
            f"{name} no longer freezes its field set — an undeclared "
            "cx_parse_trace would then be dynamically mapped")
        assert "cx_parse_trace" not in mappings["properties"], (
            "the trace is deliberately UNDECLARED: it is debug provenance read "
            "from _source, not a searchable field, and declaring it would "
            "advertise a field that is absent on every real document")


# ── 4. the load-bearing part: the real runtime, case by case ─────────────────

_SKIP = ("docker is unavailable — the VRL decision-hook suites DID NOT RUN. "
         "They are the only tests that execute the shipped program; run them "
         "before shipping (the exact docker command is in the header of "
         "deployment/docker/vector/tests/parse-trace.yaml).")


def test_the_aggregator_suite_runs_against_the_shipped_config():
    if not _docker_available():
        pytest.skip(_SKIP)
    proc = _vector_test(
        ["/etc/vector/vector.yaml", "/etc/vector/tests/parse-trace.yaml"],
        [(AGG_DIR / "vector.yaml", "/etc/vector/vector.yaml"),
         (AGG_DIR / "tests", "/etc/vector/tests"),
         (FIXTURES, "/etc/vector/enrichment")])
    _assert_suite_passed(proc, _case_count(AGG_SUITE))


def test_the_router_suite_runs_against_the_shipped_config():
    if not _docker_available():
        pytest.skip(_SKIP)
    proc = _vector_test(
        ["/etc/vector/vector.yaml", "/etc/vector/processors/processors.yaml",
         "/etc/vector/tests/parse-trace.yaml"],
        [(ROUTER_DIR / "vector.yaml", "/etc/vector/vector.yaml"),
         (ROUTER_DIR / "processors-default.yaml", "/etc/vector/processors/processors.yaml"),
         (ROUTER_DIR / "tests", "/etc/vector/tests"),
         (FIXTURES, "/etc/vector/enrichment")])
    _assert_suite_passed(proc, _case_count(ROUTER_SUITE))


def test_both_suites_prove_the_guard_in_BOTH_directions():
    """A suite of only positive cases would pass against a hook that stamped
    unconditionally — which would put the whole block on the hot path and change
    every production document. The negative case is the one that matters."""
    for suite in (AGG_SUITE, ROUTER_SUITE):
        sources = [c["outputs"][0]["conditions"][0]["source"]
                   for c in yaml.safe_load(_read(suite))["tests"]]
        stamped = [s for s in sources if "assert!(exists(.cx_parse_trace)" in s
                   or "string!(.cx_parse_trace)" in s]
        unstamped = [s for s in sources if "assert!(!exists(.cx_parse_trace)" in s]
        assert len(stamped) >= 3, f"{suite.name}: only {len(stamped)} stamped cases"
        assert len(unstamped) >= 1, (
            f"{suite.name}: no case proves an ORDINARY record is left alone")
        reasons = [s for s in sources
                   if "UNATTRIBUTED" in s or "DROPPED" in s or "REFUSED-CLAIM" in s
                   or "NOT-ADMITTED" in s or "no key to look up" in s]
        assert len(reasons) >= 2, (
            f"{suite.name}: the drop/miss branches are not proven to name their "
            "REASON, which is the requirement Wave 2 owes")


def test_the_suites_declare_no_transforms_of_their_own():
    """The suites must exercise the SHIPPED transforms, not a copy: they are run
    alongside the real vector.yaml and carry only `tests:`."""
    for suite in (AGG_SUITE, ROUTER_SUITE):
        loaded = yaml.safe_load(_read(suite))
        assert set(loaded) == {"tests"}, (
            f"{suite.name} declares its own components — a green run would then "
            "say nothing about the config the stack loads")
