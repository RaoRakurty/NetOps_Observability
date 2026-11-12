# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The vendor-pack mechanism (tracker 387, plan §5.1, §6a).

The binding claim: adding a vendor means adding catalogue data, with no new VRL or
Python logic and no vendor name in engine code. The load-bearing test here adds a
synthetic second vendor through a data file alone and runs it through BOTH executors:
the engine's real classifier and the shipped aggregator transform.

The docker legs are the only ones that run the shipped VRL; without docker they skip
loudly, the same as the other Vector suites in this directory.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_harness import Runner, VectorTestRun, run_vector_test

ROOT = Path(__file__).resolve().parent.parent
AGG_DIR = ROOT / "deployment" / "docker" / "vector"
HELM_VECTOR = ROOT / "deployment" / "helm" / "correlix" / "files" / "vector"
FIXTURES = AGG_DIR / "tests" / "fixtures"
CATALOG = ROOT / "telemetry-catalog"
CORRELATION = ROOT / "src" / "correlation"
GEN_PACKS = ROOT / "scripts" / "gen-syslog-packs.py"
VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"
ENV_STUBS = [
    "CLICKHOUSE_USER=x", "CLICKHOUSE_PASSWORD=x", "OPENSEARCH_URL=http://x:9200",
    "DB_HOST=x", "DB_USER=x", "DB_PASSWORD=x",
    "INGEST_TOKEN=preflight-stub", "INGEST_TOKEN_TRAPS=preflight-stub",
    "INGEST_TOKEN_PROBES=preflight-stub", "INGEST_TOKEN_METRICS=preflight-stub",
    "INGEST_TOKEN_BUS=preflight-stub",
]

#: Every vendor the programme names (plan §6a), plus the first pack's own terms.
VENDOR_WORDS = re.compile(
    r"viptela|sdwan|sd-wan|vedge|cedge|vmanage|juniper|junos|nokia|srlinux|aruba|"
    r"arista|sonic|extreme|huawei|mikrotik|ruckus|sophos|ubiquiti|check ?point|acme",
    re.IGNORECASE)

SYNTHETIC_PACK = textwrap.dedent("""\
    pack: acme
    vendor: acme
    severity_words: {FATAL: 1, BAD: 3, MEH: 5}
    grammars:
      - id: body
        parser_id: acme.v1
        literal: 'ACME['
        pattern: 'ACME\\[(?P<sub>\\w+)\\] (?P<level>[A-Z]+) code=(?P<code>\\d+): (?P<text>.*)'
        facility: '{sub}'
        event_type: '{sub}_{code}'
        summary: '{text}'
        severity: {word: level}
        native_text: level
        native_code: code
        alarm_floor: 1
        fidelity: doc_claimed
        source: a synthetic vendor manual
    rules:
      - rule_id: syslog.acme.widget_jam
        lane: syslog
        source: syslog
        kind: device_resource_anomaly
        entity_type: device
        family: null
        vendors: [acme]
        fidelity_status: doc_claimed
        pattern_src: 'ACME\\[\\w+\\] BAD code=77:'
        guard: {re: [msg, 'ACME\\[\\w+\\] BAD code=77:', '']}
        severity: warn
        emit:
          metric: device_alarm
          modality: device_telemetry
          entity: {type: device, id: '{host}'}
          native_id: '{host}|widget_jam|{ts_ms}'
          tokens: [{t: '{host}'}]
          attrs: {}
    fixtures:
      - name: a line the vendor calls bad
        fidelity: doc_claimed
        hostname: spine1
        appname: widgetd
        message: 'ACME[widget] BAD code=77: the widget jammed'
        expect:
          vendor: acme
          vendor_source: format
          parser_id: acme.v1
          parser_status: parsed
          facility: widget
          event_type: widget_77
          summary: the widget jammed
          severity_native_text: BAD
          severity_native_code: '77'
          normalized_severity: error
        signal: {kind: device_resource_anomaly, severity: warn, opens_alone: false}
      - name: a fatal line with no typed row
        fidelity: doc_claimed
        hostname: spine1
        appname: widgetd
        message: 'ACME[widget] FATAL code=1: the widget exploded'
        expect:
          parser_id: acme.v1
          normalized_severity: critical
        signal: {kind: device_alarm, severity: crit, opens_alone: true}
      - name: a bad line with no typed row stays below the floor
        fidelity: doc_claimed
        hostname: spine1
        appname: widgetd
        message: 'ACME[widget] BAD code=2: a lesser problem'
        expect:
          parser_id: acme.v1
          normalized_severity: error
        signal: null
""")


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=20, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


_SKIP = ("docker is unavailable, so the pack suites DID NOT RUN against the shipped "
         "transform. Run them before shipping.")


#: Cases per `vector test` process. Vector 0.40 keeps every case's built topology
#: until the run ends (~110 MB each on this transform, measured 2026-11-10), so one
#: process over the whole pack suite peaked past 10 GB and was OOM-killed on a 15 GB
#: host; it also ran close to the 900 s budget. Chunks bound both.
CASES_PER_RUN = 25

#: Chunks run CONCURRENTLY (CI audit 2026-11-12: the two big suites ran their
#: chunks one after another for 25.9 min of a 35-40 min job). Each process holds
#: ~110 MB per case, so a 25-case chunk is ~2.75 GB: 3 at once is ~8.3 GB on the
#: 16 GB GitHub runner, 4 (the cap) ~11 GB. Override with VECTOR_TEST_WORKERS.
VECTOR_TEST_WORKERS_DEFAULT = 3
VECTOR_TEST_WORKERS_MAX = 4


def vector_test_workers(env: Mapping[str, str] | None = None) -> int:
    """VECTOR_TEST_WORKERS clamped to [1, VECTOR_TEST_WORKERS_MAX]; default 3.

    A value that is not an integer is an error, not a silent default: a typo in
    a CI env must not quietly change the memory profile of the run."""
    env = os.environ if env is None else env
    raw = env.get("VECTOR_TEST_WORKERS", "").strip()
    if not raw:
        return VECTOR_TEST_WORKERS_DEFAULT
    try:
        n = int(raw)
    except ValueError as exc:
        raise ValueError(f"VECTOR_TEST_WORKERS={raw!r} is not an integer") from exc
    return max(1, min(VECTOR_TEST_WORKERS_MAX, n))


def run_vector_chunks(label: str, argvs: Sequence[Sequence[str]], *,
                      workers: int, runner: Runner = subprocess.run,
                      timeout: float = 900) -> int:
    """Run one `vector test` argv per chunk on a bounded thread pool.

    Every chunk runs exactly once (through run_vector_test, so the bounded
    upstream-race retry still applies per chunk). Failures are reported in chunk
    order, each with its own full report, whatever order the threads finished
    in. Returns the number of passed cases summed across chunks; the caller
    compares it with the suite size."""
    def one(n: int) -> VectorTestRun:
        return run_vector_test(argvs[n], label=f"{label} part {n + 1}",
                               timeout=timeout, runner=runner)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {n: pool.submit(one, n) for n in range(len(argvs))}
        runs = {n: f.result() for n, f in futures.items()}
    failures = [f"--- {label} part {n + 1} of {len(argvs)} (exit "
                f"{runs[n].final.returncode}) ---\n{runs[n].report()}"
                for n in sorted(runs) if runs[n].final.returncode != 0]
    assert not failures, ("vector test failed in "
                          f"{len(failures)} of {len(argvs)} chunk(s):\n"
                          + "\n".join(failures))
    return sum(runs[n].output.count("... passed") for n in sorted(runs))


def _vector_test(label: str, config: Path, suite_dir: Path, suite: str,
                 expected: int) -> None:
    cases = yaml.safe_load((suite_dir / suite).read_text(encoding="utf-8"))["tests"]
    assert len(cases) == expected
    with tempfile.TemporaryDirectory(prefix="cx-vector-suite-") as tmp:
        argvs: list[list[str]] = []
        for n, start in enumerate(range(0, len(cases), CASES_PER_RUN)):
            chunk = Path(tmp) / f"{n:02d}-{suite}"
            chunk.write_text(yaml.safe_dump({"tests": cases[start:start + CASES_PER_RUN]},
                                            sort_keys=False), encoding="utf-8")
            chunk.chmod(0o644)
            cmd = ["docker", "run", "--rm", "--entrypoint", "vector"]
            cpus = os.environ.get("VECTOR_TEST_DOCKER_CPUS", "").strip()
            if cpus:  # local runs on a shared host cap each container
                cmd += [f"--cpus={cpus}"]
            for kv in ENV_STUBS:
                cmd += ["-e", kv]
            for src, dst in ((config, "/etc/vector/vector.yaml"),
                             (Path(tmp), "/etc/vector/tests"),
                             (FIXTURES, "/etc/vector/enrichment")):
                cmd += ["-v", f"{src}:{dst}:ro"]
            cmd += [VECTOR_IMAGE, "test", "/etc/vector/vector.yaml",
                    f"/etc/vector/tests/{chunk.name}"]
            argvs.append(cmd)
        passed = run_vector_chunks(label, argvs, workers=vector_test_workers())
    assert passed == expected, f"{passed} of {expected} cases passed"


def _cases(path: Path) -> int:
    return len(yaml.safe_load(path.read_text(encoding="utf-8"))["tests"])


# ── the checked-in artifacts ─────────────────────────────────────────────────

def test_the_generated_artifacts_are_not_stale():
    proc = subprocess.run([sys.executable, str(GEN_PACKS), "--check"],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr


def test_the_helm_copy_is_the_compose_copy():
    assert ((HELM_VECTOR / "vector.yaml").read_bytes()
            == (AGG_DIR / "vector.yaml").read_bytes())
    assert ((HELM_VECTOR / "syslog-admission.vrl").read_bytes()
            == (AGG_DIR / "generated" / "syslog-admission.vrl").read_bytes())


def test_the_new_fields_are_searchable_in_both_templates():
    for path in (ROOT / "deployment/docker/opensearch/index-templates.json",
                 ROOT / "deployment/helm/correlix/files/opensearch/index-templates.json"):
        text = path.read_text(encoding="utf-8")
        for field in ("vendor_source", "severity_native_text", "severity_native_code",
                      "event_category", "dedup_key"):
            assert f'"{field}"' in text, f"{path.name} does not declare {field}"


# ── no vendor in the mechanism ───────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    CORRELATION / "syslog_packs.py",
    ROOT / "scripts" / "syslog_pack_vrl.py",
    GEN_PACKS,
])
def test_the_mechanism_names_no_vendor(path):
    hits = VENDOR_WORDS.findall(path.read_text(encoding="utf-8"))
    assert not hits, f"{path.name} names a vendor: {sorted(set(hits))}"


def test_the_hand_written_stage_b_pack_code_names_no_vendor():
    """Only the seam and the applier are hand-written; both must stay generic."""
    text = (AGG_DIR / "vector.yaml").read_text(encoding="utf-8")
    start = text.index("# Vendor packs (tracker 387")
    end = text.index("# >>> BEGIN GENERATED-SYSLOG-PACKS")
    applier_start = text.index("if cx_pk_parser != \"\" {")
    applier_end = text.index("} else if !cx_parse_fortios {", applier_start)
    seam_start = text.index('if cx_inventory_vendor != "" {')
    seam_end = text.index(".vendor = vendor", seam_start)
    for chunk in (text[start:end], text[applier_start:applier_end], text[seam_start:seam_end]):
        assert not VENDOR_WORDS.findall(chunk), chunk


# ── the shipped transform ────────────────────────────────────────────────────

def test_every_pack_fixture_passes_on_the_shipped_transform():
    if not _docker_available():
        pytest.skip(_SKIP)
    suite = AGG_DIR / "tests" / "syslog-packs.yaml"
    _vector_test("syslog packs", AGG_DIR / "vector.yaml", AGG_DIR / "tests",
                 "syslog-packs.yaml", _cases(suite))


def test_every_older_grammar_is_unmoved_on_the_shipped_transform():
    if not _docker_available():
        pytest.skip(_SKIP)
    suite = AGG_DIR / "tests" / "syslog-legacy-grammars.yaml"
    _vector_test("legacy grammars", AGG_DIR / "vector.yaml", AGG_DIR / "tests",
                 "syslog-legacy-grammars.yaml", _cases(suite))


# ── a synthetic vendor, by data alone ────────────────────────────────────────

@pytest.fixture(scope="module")
def synthetic(tmp_path_factory):
    """A tree where the ONLY difference is one more file in the pack directory."""
    base = tmp_path_factory.mktemp("synthetic")
    packs = base / "packs"
    shutil.copytree(CATALOG / "vendor-packs", packs)
    (packs / "acme.yaml").write_text(SYNTHETIC_PACK, encoding="utf-8")
    module_dir = base / "module"
    module_dir.mkdir()
    subprocess.run(
        [sys.executable, str(CATALOG / "bake_rules.py"), "--packs-dir", str(packs),
         "--out", str(module_dir / "parser_rules.py")],
        check=True, capture_output=True, text=True)
    root = base / "root"
    (root / "deployment/docker/vector/tests").mkdir(parents=True)
    shutil.copy(AGG_DIR / "vector.yaml", root / "deployment/docker/vector/vector.yaml")
    subprocess.run(
        [sys.executable, str(GEN_PACKS), "--packs-dir", str(packs), "--root", str(root)],
        check=True, capture_output=True, text=True)
    return {"packs": packs, "module": module_dir, "root": root}


_ENGINE_PROBE = textwrap.dedent("""\
    import json, sys
    from datetime import datetime, timezone
    import producers as P
    out = []
    for ev in json.load(sys.stdin):
        tag = ev["appname"].upper()
        sig = P.syslog_control_signal(ev, "t1", datetime.now(timezone.utc))
        out.append({
            "num": P.syslog_severity_num(ev, tag),
            "alarm": P.syslog_alarm_num(ev, tag),
            "promotable": P.syslog_promotable(ev),
            "kind": sig.kind if sig else None,
            "severity": sig.severity.value if sig else None,
        })
    json.dump(out, sys.stdout)
""")


def _run_engine(module_dir: Path, events: list[dict]) -> list[dict]:
    """The real classifier, importing the synthetic bake first on the path."""
    proc = subprocess.run(
        [sys.executable, "-c", _ENGINE_PROBE],
        input=json.dumps(events), capture_output=True, text=True, check=False,
        env={"PYTHONPATH": f"{module_dir}:{CORRELATION}", "PATH": "/usr/bin:/bin"},
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _ev(message: str) -> dict:
    return {"hostname": "spine1", "appname": "widgetd", "severity": "notice",
            "message": message, "timestamp": "2026-11-09T10:00:00Z"}


def test_a_synthetic_vendor_reaches_the_engine_through_data_alone(synthetic):
    jam, fatal, lesser, meh = _run_engine(synthetic["module"], [
        _ev("ACME[widget] BAD code=77: the widget jammed"),
        _ev("ACME[widget] FATAL code=1: the widget exploded"),
        _ev("ACME[widget] BAD code=2: a lesser problem"),
        _ev("ACME[widget] MEH code=3: nothing much"),
    ])
    # The pack's own word map drove the severity.
    assert jam["num"] == 3 and fatal["num"] == 1 and meh["num"] == 5
    # Its floor drove the gate: only the fatal line may alarm on severity alone.
    assert jam["alarm"] is None and lesser["alarm"] is None
    assert fatal["alarm"] == 1
    # Its rule row classified, at the row's below-floor severity.
    assert (jam["kind"], jam["severity"]) == ("device_resource_anomaly", "warn")
    # The generic net fired for the critical line and stayed silent for the other.
    assert (fatal["kind"], fatal["severity"]) == ("device_alarm", "crit")
    assert lesser["kind"] is None and not lesser["promotable"]


def test_the_same_vendor_means_nothing_to_the_shipped_tree(synthetic):
    """The control: the identical lines through the real bake have no pack."""
    jam, fatal = _run_engine(CORRELATION, [
        _ev("ACME[widget] BAD code=77: the widget jammed"),
        _ev("ACME[widget] FATAL code=1: the widget exploded"),
    ])
    assert jam["num"] == 5 and fatal["num"] == 5
    assert jam["kind"] is None and fatal["kind"] is None


def test_a_synthetic_vendor_touches_no_logic_file(synthetic):
    """The generator's output differs from the shipped tree in grammar rows only."""
    shipped = (AGG_DIR / "vector.yaml").read_text(encoding="utf-8")
    generated = (synthetic["root"] / "deployment/docker/vector/vector.yaml").read_text(
        encoding="utf-8")
    assert generated != shipped
    b = "# >>> BEGIN GENERATED-SYSLOG-PACKS"
    e = "# <<< END GENERATED-SYSLOG-PACKS"
    assert generated[:generated.index(b)] == shipped[:shipped.index(b)]
    assert generated[generated.index(e):] == shipped[shipped.index(e):]


def test_a_synthetic_vendor_passes_on_the_real_transform(synthetic):
    if not _docker_available():
        pytest.skip(_SKIP)
    tests = synthetic["root"] / "deployment/docker/vector/tests"
    _vector_test("synthetic vendor",
                 synthetic["root"] / "deployment/docker/vector/vector.yaml", tests,
                 "syslog-packs.yaml", _cases(tests / "syslog-packs.yaml"))


def test_the_engine_honours_an_inventory_vendor():
    """The other executor of the same seam. Only an INVENTORY vendor narrows: a
    vendor stamped by format matching is a guess about the device."""
    line = "%Viptela-vEdge-1-SYSMGR-2-CRIT-200069: System cpu usage is above 90%"
    base = {"hostname": "e1", "appname": "SYSMGR", "severity": "notice", "message": line,
            "timestamp": "2026-11-09T10:00:00Z"}
    guessed, listed = _run_engine(CORRELATION, [
        {**base, "vendor": "other", "vendor_source": "format"},
        {**base, "vendor": "other", "vendor_source": "inventory"},
    ])
    assert guessed["num"] == 2
    assert listed["num"] == 5


# ── the parallel chunk runner (CI audit 2026-11-12, C1) ─────────────────────
#
# No docker: a stubbed runner stands in for `docker run … vector test`, so these
# prove the scheduling contract on every host, including the CI job that runs
# the real chunks.

class _StubVector:
    """A thread-safe fake `subprocess.run` keyed by the chunk argv's last word."""

    def __init__(self, passed: dict[str, int], fail: frozenset[str] = frozenset(),
                 delay: float = 0.0):
        self.passed, self.fail, self.delay = passed, fail, delay
        self.calls: list[str] = []
        self.active = self.peak = 0
        self._lock = threading.Lock()

    def __call__(self, argv, **_kw):
        chunk = argv[-1]
        with self._lock:
            self.calls.append(chunk)
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            time.sleep(self.delay)
            out = "".join(f"test {chunk}#{i} ... passed\n"
                          for i in range(self.passed[chunk]))
            if chunk in self.fail:
                out += (f"test {chunk}#bad ... failed\n\nfailures:\n\ntest {chunk}#bad:\n"
                        "  condition failed: .facility == \"x\"\n")
                return subprocess.CompletedProcess(argv, 1, out, "")
            return subprocess.CompletedProcess(argv, 0, out, "")
        finally:
            with self._lock:
                self.active -= 1


def _argvs(n: int) -> list[list[str]]:
    return [["docker", "run", "vector", "test", f"chunk{i:02d}"] for i in range(n)]


@pytest.mark.parametrize("workers", [1, 3, 4])
def test_every_chunk_runs_exactly_once_and_passed_sums(workers):
    stub = _StubVector({f"chunk{i:02d}": 25 - i for i in range(7)}, delay=0.01)
    passed = run_vector_chunks("unit", _argvs(7), workers=workers, runner=stub)
    assert sorted(stub.calls) == [f"chunk{i:02d}" for i in range(7)]
    assert passed == sum(25 - i for i in range(7))
    assert stub.peak <= workers


def test_chunks_really_overlap_when_workers_allow():
    stub = _StubVector({f"chunk{i:02d}": 1 for i in range(6)}, delay=0.2)
    run_vector_chunks("unit", _argvs(6), workers=3, runner=stub)
    assert stub.peak == 3


def test_a_failing_chunk_fails_with_its_report_in_chunk_order():
    stub = _StubVector({f"chunk{i:02d}": 2 for i in range(5)},
                       fail=frozenset({"chunk03", "chunk01"}))
    with pytest.raises(AssertionError) as exc:
        run_vector_chunks("unit", _argvs(5), workers=4, runner=stub)
    msg = str(exc.value)
    assert "2 of 5 chunk(s)" in msg
    # each failure carries ITS chunk's report, in chunk order, whatever order
    # the threads finished in
    assert msg.index("part 2 of 5") < msg.index("chunk01#bad") < msg.index("part 4 of 5")
    assert msg.index("part 4 of 5") < msg.index("chunk03#bad")
    assert "part 1 of 5" not in msg and "part 3 of 5" not in msg
    assert sorted(stub.calls) == [f"chunk{i:02d}" for i in range(5)]  # none abandoned


def test_a_short_chunk_is_left_to_the_total():
    """Every chunk exits 0 but one ran fewer cases: the sum is honest, so the
    caller's `passed == expected` catches it."""
    stub = _StubVector({"chunk00": 25, "chunk01": 24})
    assert run_vector_chunks("unit", _argvs(2), workers=2, runner=stub) == 49


@pytest.mark.parametrize("env, want", [
    ({}, 3),
    ({"VECTOR_TEST_WORKERS": ""}, 3),
    ({"VECTOR_TEST_WORKERS": "1"}, 1),
    ({"VECTOR_TEST_WORKERS": "2"}, 2),
    ({"VECTOR_TEST_WORKERS": " 4 "}, 4),
    ({"VECTOR_TEST_WORKERS": "16"}, 4),
    ({"VECTOR_TEST_WORKERS": "0"}, 1),
    ({"VECTOR_TEST_WORKERS": "-3"}, 1),
])
def test_worker_count_from_env(env, want):
    assert vector_test_workers(env) == want


def test_worker_default_and_cap_are_what_the_memory_budget_says():
    assert VECTOR_TEST_WORKERS_DEFAULT == 3
    assert VECTOR_TEST_WORKERS_MAX == 4


def test_a_garbage_worker_count_is_an_error_not_a_default():
    with pytest.raises(ValueError, match="VECTOR_TEST_WORKERS"):
        vector_test_workers({"VECTOR_TEST_WORKERS": "three"})


def test_the_suite_runner_honours_the_env(monkeypatch):
    """_vector_test reads the worker count from the environment at call time and
    still holds the chunk total to the suite size."""
    seen: dict[str, int] = {}

    def fake(label, argvs, *, workers, **_kw):
        seen["workers"], seen["chunks"] = workers, len(argvs)
        return 0

    monkeypatch.setenv("VECTOR_TEST_WORKERS", "2")
    monkeypatch.setattr(sys.modules[__name__], "run_vector_chunks", fake)
    with pytest.raises(AssertionError, match="0 of 7 cases passed"):
        _vector_test("unit", AGG_DIR / "vector.yaml", AGG_DIR / "tests",
                     "syslog-legacy-grammars.yaml", 7)
    assert seen == {"workers": 2, "chunks": 1}
