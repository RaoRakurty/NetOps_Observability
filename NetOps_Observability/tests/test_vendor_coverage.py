# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The coverage scorecard, its ratchet and the parse-status metrics (tracker 387 PR 14).

The rule behind all of it: test the value, never the presence. A field present on
100 % of records with the value `unparsed` is the failure this plan exists to fix, so a
fixture counts only if it asserts a real parse, and the alert rules read the value.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_harness import run_vector_test

ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "scripts" / "gen-vendor-coverage.py"
ROUTER_DIR = ROOT / "deployment" / "docker" / "vector-router"
AGG = ROOT / "deployment" / "docker" / "vector" / "vector.yaml"
FIXTURES = ROOT / "deployment" / "docker" / "vector" / "tests" / "fixtures"
PACKS = ROOT / "telemetry-catalog" / "vendor-packs"
COVERAGE = ROOT / "src" / "backend" / "parsercov" / "vendor_coverage.json"
FLOOR = ROOT / "telemetry-catalog" / "vendor_coverage_floor.json"
RULES = ROOT / "src" / "config" / "rules-scale-slo.yaml"
VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"
ENV_STUBS = [
    "CLICKHOUSE_USER=x", "CLICKHOUSE_PASSWORD=x", "OPENSEARCH_URL=http://x:9200",
    "DB_HOST=x", "DB_USER=x", "DB_PASSWORD=x", "CX_MAC_KEY=stub",
    "INGEST_TOKEN=preflight-stub", "INGEST_TOKEN_TRAPS=preflight-stub",
    "INGEST_TOKEN_PROBES=preflight-stub", "INGEST_TOKEN_METRICS=preflight-stub",
    "INGEST_TOKEN_BUS=preflight-stub",
]
VENDOR_WORDS = re.compile(
    r"viptela|sdwan|sd-wan|vedge|cedge|vmanage|cisco|juniper|junos|nokia|srlinux|aruba|"
    r"arista|sonic|extreme|huawei|mikrotik|ruckus|sophos|ubiquiti|check ?point|fortinet|paloalto",
    re.IGNORECASE)


@pytest.fixture(scope="module")
def gen():
    spec = importlib.util.spec_from_file_location("gen_vendor_coverage", GEN)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _rows() -> dict[str, dict]:
    return {r["vendor"]: r for r in json.loads(COVERAGE.read_text(encoding="utf-8"))["vendors"]}


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(GEN), *args], capture_output=True, text=True, check=False)


# ── the checked-in artifacts ─────────────────────────────────────────────────

def test_the_artifacts_are_fresh_and_nothing_is_below_its_floor():
    """This is the CI ratchet: `--check`, in the suite no path filter can skip."""
    proc = _run("--check")
    assert proc.returncode == 0, proc.stderr


def test_the_generator_names_no_vendor():
    hits = VENDOR_WORDS.findall(GEN.read_text(encoding="utf-8"))
    assert not hits, f"the generator names a vendor: {sorted(set(hits))}"


def test_every_vendor_profile_has_a_row_or_is_declared_not_a_vendor(gen):
    rows = _rows()
    for vendor, doc in gen.load_profiles(str(ROOT)).items():
        if doc["detection"].get("agent_identity"):
            assert vendor not in rows, f"{vendor} names an agent, not a vendor"
        else:
            assert vendor in rows, f"{vendor} has no scorecard row"
    assert rows[gen.STANDARD]["standard"] is True


def test_a_vendor_with_nothing_reads_as_nothing():
    """The honest-empty input the page words as `Not covered yet`. If a future change
    gave these a count by accident they would read as coverage nobody earned."""
    rows = _rows()
    for vendor in ("extreme", "dell"):
        for lane, stats in rows[vendor]["lanes"].items():
            assert stats["fixtures"] == 0, f"{vendor}/{lane}"
            assert stats["rules"] == {}, f"{vendor}/{lane}"


def test_the_covered_vendors_read_as_covered():
    rows = _rows()
    cisco = rows["cisco"]["lanes"]
    assert cisco["syslog"]["grammars"] >= 4
    assert cisco["syslog"]["fixtures"] >= 10
    assert cisco["snmptrap"]["mib_nodes"] > 0
    assert rows["nokia"]["lanes"]["snmptrap"]["mib_nodes"] > 0
    assert rows["standard"]["lanes"]["snmptrap"]["mib_nodes"] > 0


def test_every_older_grammar_is_listed_and_every_listed_one_exists(gen):
    """The list the metric's label set and the scorecard read, against the VRL."""
    text = AGG.read_text(encoding="utf-8")
    in_vrl = set(re.findall(r'\.parser_id = "([^"]+)"', text))
    listed = {g["parser_id"] for g in gen._older_grammars(str(ROOT))}
    assert in_vrl == listed, f"VRL {sorted(in_vrl)} != catalogue {sorted(listed)}"


# ── the value rule ───────────────────────────────────────────────────────────

def test_every_grammar_has_a_fixture_asserting_a_real_parse(gen):
    """Plan §6, PR 14: each grammar's fixture asserts parser_status == parsed and a
    specific event_type. Presence would pass on the failure this exists to catch."""
    sys.path.insert(0, str(ROOT / "src" / "correlation"))
    import bake_rules
    from syslog_packs import PackTable
    packs = bake_rules.load_packs(str(PACKS))
    table = PackTable(*bake_rules.pack_tables(packs))
    proved: set[str] = set()
    for pack in packs:
        for fx in pack["fixtures"]:
            if not gen._counts_as_syslog_fixture(fx):
                continue
            # The line the grammars see, after any envelope row has run on it.
            ev = {"hostname": fx.get("hostname", "spine1"), "appname": fx.get("appname", "unknown"),
                  "severity": fx.get("severity", "notice"), "message": fx["message"]}
            if "msgid" in fx:
                ev["msgid"] = fx["msgid"]
            msg = table.parse(ev).get("message", fx["message"])
            app = str(ev["appname"]).lower()
            # The grammar the executor would pick for this line, first match wins.
            for g in table.grammars:
                text = g.haystack(msg, ev)
                if g.applies(text, app, "") and g.regex.search(text):
                    proved.add(g.grammar_id)
                    break
    every = {g.grammar_id for g in table.grammars}
    assert every - proved == set(), f"grammars with no fixture asserting a parse: {sorted(every - proved)}"


def test_a_fixture_that_only_asserts_presence_does_not_count(gen):
    assert gen._counts_as_syslog_fixture({"expect": {"parser_status": "parsed", "event_type": "x"}})
    assert not gen._counts_as_syslog_fixture({"expect": {"parser_status": "unparsed", "event_type": "x"}})
    assert not gen._counts_as_syslog_fixture({"expect": {"parser_status": "parsed"}})
    assert not gen._counts_as_syslog_fixture({"expect": {"event_type": "x"}})
    assert not gen._counts_as_syslog_fixture({"expect": {}})


# ── the ratchet ──────────────────────────────────────────────────────────────

def test_the_floor_blocks_a_drop_and_says_which(gen):
    current = {"a/syslog/grammars": 3, "a/syslog/fixtures": 7}
    assert gen.below_floor(current, {"a/syslog/grammars": 3}) == []
    breaches = gen.below_floor(current, {"a/syslog/grammars": 4, "gone/snmptrap/mibs": 1})
    assert breaches == ["a/syslog/grammars: 3 is below its floor 4",
                        "gone/snmptrap/mibs: 0 is below its floor 1"]


def test_a_fidelity_promotion_does_not_trip_the_ratchet(gen):
    """A rule moved from doc_claimed to lab_validated is progress."""
    def cov(rules):
        return {"vendors": [{"vendor": "a", "lanes": {"syslog": {"rules": rules, "grammars": 1, "fixtures": 1}}}]}
    before = gen.floors_of(cov({"doc_claimed": 2}))
    after = gen.floors_of(cov({"doc_claimed": 1, "lab_validated": 1}))
    assert gen.below_floor(after, before) == []
    assert after["a/syslog/rules_validated"] == 1
    # ...and losing a validated rule, or any rule at all, is not.
    assert gen.below_floor(gen.floors_of(cov({"doc_claimed": 2})), after)
    assert gen.below_floor(gen.floors_of(cov({"doc_claimed": 1})), before)


def test_check_fails_on_a_raised_floor_and_a_plain_run_refuses_to_lower_one(gen, tmp_path):
    """End to end, through the CLI, on a copy of the tree."""
    root = tmp_path / "tree"
    for rel in (gen.PROFILES_DIR, gen.TRAP_PACKS, "telemetry-catalog/vendor-packs"):
        shutil.copytree(ROOT / rel, root / rel)
    for rel in (gen.OID_INDEX, gen.TRAP_FIXTURES, gen.OLDER_GRAMMARS, gen.OLDER_SUITE,
                "telemetry-catalog/events.yaml", gen.COVERAGE_REL, gen.FLOOR_REL, gen.ROUTER_RELS[0]):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, root / rel)
    proc = _run("--check", "--root", str(root))
    assert proc.returncode == 0, proc.stderr

    floor_path = root / gen.FLOOR_REL
    floor = json.loads(floor_path.read_text(encoding="utf-8"))
    key = next(k for k, v in floor.items() if v > 0)
    floor[key] += 1
    floor_path.write_text(json.dumps(floor), encoding="utf-8")
    for args in (("--check",), ()):
        proc = _run(*args, "--root", str(root))
        assert proc.returncode == 1, proc.stdout
        assert key in proc.stderr and "went DOWN" in proc.stderr
    assert json.loads(floor_path.read_text(encoding="utf-8"))[key] == floor[key], "a run lowered a floor"


def test_a_new_pack_raises_coverage_through_data_alone(gen, tmp_path):
    packs = tmp_path / "packs"
    shutil.copytree(PACKS, packs)
    (packs / "newvendor.yaml").write_text(yaml.safe_dump({
        "pack": "newvendor",
        "vendor": "extreme",
        "grammars": [{
            "id": "body", "parser_id": "newvendor.v1", "literal": "NV[",
            "pattern": r"NV\[(?P<code>\d+)\]", "event_type": "nv_{code}", "fidelity": "doc_claimed",
            "source": "a synthetic vendor manual",
        }],
        "fixtures": [{"name": "a line", "fidelity": "doc_claimed", "message": "NV[7] something",
                      "expect": {"parser_id": "newvendor.v1", "parser_status": "parsed", "event_type": "nv_7"},
                      "signal": None}],
    }), encoding="utf-8")
    rows = {r["vendor"]: r for r in gen.compute(str(ROOT), str(packs))["vendors"]}
    assert rows["extreme"]["lanes"]["syslog"]["grammars"] == 1
    assert rows["extreme"]["lanes"]["syslog"]["fixtures"] == 1
    assert "newvendor.v1" in gen.known_parser_ids(str(ROOT), str(packs))


# ── the metric's labels ──────────────────────────────────────────────────────

def test_the_label_sets_are_bounded_and_the_stated_bound_is_true(gen):
    vendors = gen.known_vendors(str(ROOT))
    parsers = gen.known_parser_ids(str(ROOT), str(PACKS))
    text = (ROUTER_DIR / "vector.yaml").read_text(encoding="utf-8")
    # Each list holds what the generator derives, plus the two buckets it writes.
    assert json.dumps(vendors) in text and json.dumps(parsers) in text
    n_vendor, n_parser, n_status = len(vendors) + 1, len(parsers) + 2, len(gen.PARSER_STATUSES) + 1
    assert f"vendor is at most {n_vendor} values" in text, "update the series count in vector.yaml"
    assert f"parser_id {n_parser}" in text, "update the series count in vector.yaml"
    assert f"{n_vendor} x {n_parser} x {n_status} statuses" in text
    assert f"{n_vendor * n_parser * n_status}, and the pipeline" in " ".join(text.replace("#", " ").split())
    assert n_vendor * n_parser * n_status < 5000, "the label product has outgrown the exporter"


def test_no_field_a_record_writes_freely_reaches_a_label():
    """Only the generated copy is a label source; a tag reading a raw field is the bug."""
    doc = yaml.safe_load((ROUTER_DIR / "vector.yaml").read_text(encoding="utf-8"))
    tr = doc["transforms"]
    assert tr["parse_status_metric"]["inputs"] == ["parse_status_labels"]
    assert tr["trap_varbind_metric"]["inputs"] == ["trap_varbind_counts"]
    assert tr["flow_enrichment_metric"]["inputs"] == ["flow_enrichment_labels"]
    for name in ("parse_status_labels", "trap_varbind_counts", "flow_enrichment_labels"):
        assert re.search(r"^\s*\. = \{", tr[name]["source"], re.MULTILINE), f"{name} must replace the record"
    sink = doc["sinks"]["prometheus_internal"]["inputs"]
    for name in ("parse_status_metric", "trap_varbind_metric", "flow_enrichment_metric"):
        assert name in sink, f"{name} is not exported"
    tags = set(tr["parse_status_metric"]["metrics"][0]["tags"])
    assert tags == {"lane", "vendor", "parser_id", "parser_status"}


def test_rules_read_the_metric_the_router_exports():
    text = RULES.read_text(encoding="utf-8")
    for m in ("netops_parse_status_events", "corr_syslog_high_severity_no_signal_total"):
        assert m in text
    assert "netops_parse_status_events_total" not in text, "Vector's exporter appends no _total"


def test_parse_rules_are_warning_tier_and_never_page():
    group = next(g for g in yaml.safe_load(RULES.read_text(encoding="utf-8"))["groups"]
                 if g["name"] == "parse-coverage")
    names = {r["alert"] for r in group["rules"]}
    assert names == {"ParseLaneStuckUnparsed", "ParseUnparsedShareRose", "EngineIgnoredHighSeverityLinesRose"}
    for rule in group["rules"]:
        assert rule["labels"]["tier"] == "warning", rule["alert"]
        assert rule["labels"]["severity"] == "warning", rule["alert"]
        assert (ROOT / rule["annotations"]["runbook"]).exists(), rule["alert"]


def test_the_level_rule_reads_the_value_of_the_status():
    group = next(g for g in yaml.safe_load(RULES.read_text(encoding="utf-8"))["groups"]
                 if g["name"] == "parse-coverage")
    expr = next(r["expr"] for r in group["rules"] if r["alert"] == "ParseLaneStuckUnparsed")
    assert 'parser_status=~"unparsed|raw_only"' in expr
    assert ">= 0.99" in expr


# ── the shipped transforms ───────────────────────────────────────────────────

def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=20, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def test_the_metric_transforms_on_the_shipped_config():
    if not _docker_available():
        pytest.skip("docker is unavailable, so the metric transforms DID NOT RUN on the shipped config")
    suite = ROUTER_DIR / "tests" / "parse-metrics.yaml"
    cases = len(yaml.safe_load(suite.read_text(encoding="utf-8"))["tests"])
    cmd = ["docker", "run", "--rm", "--entrypoint", "vector"]
    for kv in ENV_STUBS:
        cmd += ["-e", kv]
    for src, dst in ((ROUTER_DIR / "vector.yaml", "/etc/vector/vector.yaml"),
                     (ROUTER_DIR / "processors-default.yaml", "/etc/vector/processors/processors.yaml"),
                     (ROUTER_DIR / "tests", "/etc/vector/tests"),
                     (FIXTURES, "/etc/vector/enrichment")):
        cmd += ["-v", f"{src}:{dst}:ro"]
    cmd += [VECTOR_IMAGE, "test", "/etc/vector/vector.yaml", "/etc/vector/processors/processors.yaml",
            "/etc/vector/tests/parse-metrics.yaml"]
    run = run_vector_test(cmd, label="router parse metrics", timeout=900)
    assert run.final.returncode == 0, f"vector test failed:\n{run.report()}"
    assert run.output.count("... passed") == cases, run.output
