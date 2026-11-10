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
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_harness import run_vector_test

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


def _vector_test(label: str, config: Path, suite_dir: Path, suite: str,
                 expected: int) -> None:
    cases = yaml.safe_load((suite_dir / suite).read_text(encoding="utf-8"))["tests"]
    assert len(cases) == expected
    passed = 0
    with tempfile.TemporaryDirectory(prefix="cx-vector-suite-") as tmp:
        for n, start in enumerate(range(0, len(cases), CASES_PER_RUN)):
            chunk = Path(tmp) / f"{n:02d}-{suite}"
            chunk.write_text(yaml.safe_dump({"tests": cases[start:start + CASES_PER_RUN]},
                                            sort_keys=False), encoding="utf-8")
            chunk.chmod(0o644)
            cmd = ["docker", "run", "--rm", "--entrypoint", "vector"]
            for kv in ENV_STUBS:
                cmd += ["-e", kv]
            for src, dst in ((config, "/etc/vector/vector.yaml"),
                             (Path(tmp), "/etc/vector/tests"),
                             (FIXTURES, "/etc/vector/enrichment")):
                cmd += ["-v", f"{src}:{dst}:ro"]
            cmd += [VECTOR_IMAGE, "test", "/etc/vector/vector.yaml",
                    f"/etc/vector/tests/{chunk.name}"]
            run = run_vector_test(cmd, label=f"{label} part {n + 1}", timeout=900)
            assert run.final.returncode == 0, f"vector test failed:\n{run.report()}"
            passed += run.output.count("... passed")
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
