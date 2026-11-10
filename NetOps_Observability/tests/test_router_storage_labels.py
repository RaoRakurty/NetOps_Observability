# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""What the router tier stores, and what it calls it (tracker 387).

Config pins run everywhere. The docker-gated tests run the SHIPPED transforms and
sinks: `vector test` for the VRL, and a real Vector process writing to a mock
_bulk endpoint for the part `vector test` cannot reach (a sink's encoder).
"""

from __future__ import annotations

import http.server
import json
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_harness import VectorTestRun, run_vector_test  # tracker 350

ROOT = Path(__file__).resolve().parent.parent
ROUTER_DIR = ROOT / "deployment" / "docker" / "vector-router"
ROUTER = ROUTER_DIR / "vector.yaml"
SUITE = ROUTER_DIR / "tests" / "storage-labels.yaml"
FIXTURES = ROOT / "deployment" / "docker" / "vector" / "tests" / "fixtures"
TEMPLATES = ROOT / "deployment" / "docker" / "opensearch" / "index-templates.json"
TRAP_GO = ROOT / "src" / "backend" / "collectors" / "snmptrap.go"
VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"   # in sync with docker-compose.yml

# What Vector's kafka source stamps on every event, overwriting any payload field
# of the same name. Not one of them is content on any lane.
KAFKA_METADATA = {"topic", "partition", "offset", "headers", "source_type"}


def _router() -> dict:
    return yaml.safe_load(ROUTER.read_text(encoding="utf-8"))


def _templates() -> dict:
    return json.loads(TEMPLATES.read_text(encoding="utf-8"))["templates"]


def _props(name: str) -> dict:
    return _templates()[name]["template"]["mappings"]["properties"]


def _os_sinks(cfg: dict) -> dict:
    return {k: v for k, v in cfg["sinks"].items() if v["type"] == "elasticsearch"}


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=60, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


needs_docker = pytest.mark.skipif(not _docker_available(), reason="docker not available")


# ── PR 3: the record's message_key survives the bus ──────────────────────────

def test_every_kafka_source_leaves_the_payload_message_key_alone():
    """Vector's default `key_field` writes the Kafka record KEY (the tenant, on
    this bus) over the payload's `message_key`. Trap documents read
    `message_key: "global"` and the receiver's dedup identity was lost."""
    sources = {k: v for k, v in _router()["sources"].items() if v["type"] == "kafka"}
    assert len(sources) >= 10, "the kafka sources moved; update this guard"
    wrong = {k: v.get("key_field", "<default: message_key>") for k, v in sources.items()
             if v.get("key_field") != ""}
    assert not wrong, f"kafka sources stamping the record key over the payload: {wrong}"


def test_trap_receiver_still_sets_the_key_this_protects():
    assert 'json:"message_key,omitempty"' in TRAP_GO.read_text(encoding="utf-8")


# ── PR 3: trap fields are searchable, by value ───────────────────────────────

# TrapEvent JSON fields that stay out of the mapping on purpose. Everything else
# the receiver emits must be declared, or `dynamic: false` makes it unsearchable.
TRAP_FIELDS_NOT_DECLARED = {
    "_signal",            # routing scaffold; the aggregator stamps `signal`
    "snmp_community",     # a credential: never searchable (tracker 387 D1)
    "snmp_user",          # v3 security name: identity data, see D7 before widening
    "sys_uptime_human",   # display form of sys_uptime_seconds
    "device_uptime_human",  # display form of device_uptime_s (tracker 387, trap semantics)
    "fields",             # vendor-controlled free-form map, like varbinds
}


def test_trap_envelope_fields_are_declared():
    props = _props("netops-snmptrap")
    expected = {
        "parser_status": "keyword", "enrichment_status": "keyword",
        "event_type": "keyword", "category": "keyword", "family": "keyword",
        "summary": "text", "vendor": "keyword", "message_key": "keyword",
        "authenticated": "boolean", "sys_uptime_seconds": "double",
        "varbinds_dropped": "integer", "truncated": "boolean",
        # Tracker 387 PR 13c': which rung named the device. Filterable, so the
        # Logs page and the runbook can group `attribution_basis:none`.
        "attribution_basis": "keyword",
        # Tracker 387 PR 13c: the affected interface, named through the device's
        # own ifIndex map, and how it was named.
        "interface": "keyword", "ifindex": "keyword", "interface_basis": "keyword",
    }
    wrong = {k: props.get(k, {}).get("type") for k, t in expected.items()
             if props.get(k, {}).get("type") != t}
    assert not wrong, f"netops-snmptrap field types: {wrong}"


# Tracker 387, trap semantics: the operator-facing meaning, filterable by value.
# bgp.peer_address is a keyword ON PURPOSE: an RFC 4001 zoned address
# (2001:db8::1%3) is not an OpenSearch `ip` and would reject the whole document.
def test_trap_semantic_fields_are_declared_with_their_types():
    props = _props("netops-snmptrap")
    flat = {
        "title": "text", "title_basis": "keyword", "device_name": "keyword",
        "native_severity": "keyword", "metrics_invalid": "keyword",
        "threshold_reported_percent": "double", "threshold_basis": "keyword",
        "received_time": "keyword", "observed_delay_s": "double", "delay_basis": "keyword",
        "device_uptime_s": "double", "correlation_key": "keyword", "event_id": "keyword",
        "lifecycle_state": "keyword", "lifecycle_basis": "keyword", "recovery_verified": "boolean",
        "auth_model": "keyword", "event_severity": "keyword", "op_state": "keyword",
        "impact": "keyword", "if_admin_status": "keyword", "if_oper_status": "keyword",
        "transition_id": "keyword", "transition_seq": "integer",
        "transition_representative": "boolean", "occurrence_count": "integer",
        "first_seen": "keyword", "last_seen": "keyword",
        "platform": "keyword", "device_type": "keyword",
    }
    wrong = {k: props.get(k, {}).get("type") for k, t in flat.items() if props.get(k, {}).get("type") != t}
    assert not wrong, f"netops-snmptrap semantic field types: {wrong}"
    bgp = props["bgp"]
    assert bgp.get("dynamic") is False, "bgp must not grow fields from the wire"
    bgp_types = {"peer_address": "keyword", "peer_afi": "keyword", "peer_as": "long",
                 "vrf": "keyword", "prev_state": "keyword", "state": "keyword",
                 "transition_class": "keyword", "peer_basis": "keyword",
                 "last_error_code": "integer"}
    wrong = {k: bgp["properties"].get(k, {}).get("type") for k, t in bgp_types.items()
             if bgp["properties"].get(k, {}).get("type") != t}
    assert not wrong, f"bgp sub-field types: {wrong}"
    m = props["metrics"]
    assert m.get("dynamic") is False
    assert m["properties"]["cpu_total_percent"]["properties"]["value"]["type"] == "double"
    assert m["properties"]["cpu_total_percent"]["properties"]["basis"]["type"] == "keyword"
    # Pack text: kept in the document, never a mapping a pack edit could grow.
    assert props["guidance"] == {"type": "object", "enabled": False}
    assert props["enrichment"]["properties"]["unknown"]["type"] == "keyword"


def test_the_metrics_mapping_covers_every_pack_metric():
    """A pack metric the template does not declare is unsearchable by value."""
    import glob
    import json as _json
    packs = ROOT / "src" / "backend" / "collectors" / "mibs" / "packs"
    names = set()
    for f in glob.glob(str(packs / "*.json")):
        pack = _json.loads(open(f, encoding="utf-8").read())
        names |= {o["field"] for o in pack.get("objects", {}).values()
                  if o.get("type") in ("float", "int")}
        names |= {d["field"] for d in pack.get("derived", [])}
    declared = set(_props("netops-snmptrap")["metrics"]["properties"])
    assert names <= declared, f"pack metrics not declared: {sorted(names - declared)}"


def test_every_trap_event_field_is_declared_or_deliberately_not():
    src = TRAP_GO.read_text(encoding="utf-8")
    body = src[src.index("type TrapEvent struct"):]
    body = body[:body.index("\n}\n")]
    tags = set(re.findall(r'json:"([^",]+)', body))
    assert {"trap_oid", "message_key", "parser_status"} <= tags, "the struct parser broke"
    undeclared = tags - set(_props("netops-snmptrap")) - TRAP_FIELDS_NOT_DECLARED
    assert not undeclared, (
        f"TrapEvent fields neither declared in netops-snmptrap nor listed as "
        f"deliberately undeclared: {sorted(undeclared)}")


@pytest.mark.parametrize("secret", ["snmp_community", "community"])
def test_no_template_makes_a_credential_searchable(secret):
    for name, tpl in _templates().items():
        assert secret not in tpl["template"]["mappings"]["properties"], name


# ── PR 3: pipeline metadata stops at the sink ────────────────────────────────

def test_every_opensearch_sink_strips_the_kafka_metadata():
    sinks = _os_sinks(_router())
    assert len(sinks) == 8, f"new OpenSearch sink? review its metadata: {sorted(sinks)}"
    for name, sink in sinks.items():
        strip = set(sink.get("encoding", {}).get("except_fields", []))
        missing = KAFKA_METADATA - strip
        assert not missing, f"{name} stores pipeline metadata: {sorted(missing)}"
        assert sink["id_key"] not in strip, f"{name} strips its own document id"
        assert "tenant_seg" not in strip and "tenant_id" not in strip, (
            f"{name} must keep the tenant fields: the read path filters on them")


def test_path_is_stripped_only_where_it_is_plumbing():
    """`path` is the aggregator's http_server stamp on the trap lane. On applogs
    and cloud logs it can be the producer's own field, which is evidence."""
    sinks = _os_sinks(_router())
    assert "path" in sinks["opensearch_snmptrap"]["encoding"]["except_fields"]
    for name in ("opensearch_applogs", "opensearch_cloudlogs"):
        assert "path" not in sinks[name]["encoding"]["except_fields"], name


def test_the_counters_that_read_topic_run_before_the_strip():
    """`.topic` labels two counters. They read the *_tagged transforms, never the
    sinks' output, so removing it from the stored document leaves them labelled."""
    t = _router()["transforms"]
    assert t["tenant_attribution_metric"]["metrics"][0]["tags"]["topic"] == "{{ topic }}"
    assert all(i.endswith(("_tagged", "_decoded")) for i in t["tenant_attribution_metric"]["inputs"])
    assert t["source_masked_metric"]["metrics"][0]["tags"]["topic"] == "{{ topic }}"
    assert all(i.endswith(("_tagged", "_decoded")) for i in t["source_masked_events"]["inputs"])


class _MockBulk(http.server.BaseHTTPRequestHandler):
    bodies: list[bytes] = []

    def do_POST(self) -> None:  # noqa: N802 (stdlib name)
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n)
        if self.headers.get("Content-Encoding") == "gzip":
            import gzip
            raw = gzip.decompress(raw)
        type(self).bodies.append(raw)
        out = b'{"took":1,"errors":false,"items":[]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *_args) -> None:  # stdlib signature; keep test output clean
        return


def _bulk_through_shipped_sink(tmp_path: Path, sink: str, transform: str, record: dict) -> tuple[dict, dict]:
    """Run one record through the SHIPPED transform and the SHIPPED sink block,
    with a real Vector and a mock _bulk endpoint. Returns (action, document)."""
    cfg = _router()
    _MockBulk.bodies = []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MockBulk)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        sink_cfg = dict(cfg["sinks"][sink])
        sink_cfg["inputs"] = ["under_test"]
        sink_cfg["endpoints"] = [f"http://127.0.0.1:{srv.server_address[1]}"]
        sink_cfg.pop("auth", None)
        test_cfg = {
            "sources": {"in": {"type": "stdin", "decoding": {"codec": "json"}}},
            "transforms": {"under_test": {**cfg["transforms"][transform], "inputs": ["in"]}},
            "sinks": {"out": sink_cfg},
        }
        path = tmp_path / "router-sink.yaml"
        path.write_text(yaml.safe_dump(test_cfg, sort_keys=False).replace("$", "$$"), encoding="utf-8")
        path.chmod(0o644)
        tmp_path.chmod(0o755)
        proc = subprocess.run(
            ["docker", "run", "--rm", "-i", "--network", "host", "--entrypoint", "vector",
             "-v", f"{path}:/etc/vector/vector.yaml:ro", VECTOR_IMAGE,
             "--config", "/etc/vector/vector.yaml"],
            input=json.dumps(record) + "\n", capture_output=True, text=True,
            timeout=180, check=False)
        assert proc.returncode == 0, proc.stderr[-2000:]
        assert _MockBulk.bodies, f"vector wrote nothing:\n{proc.stderr[-2000:]}"
    finally:
        srv.shutdown()
        srv.server_close()
    lines = _MockBulk.bodies[0].decode("utf-8").strip().splitlines()
    return json.loads(lines[0]), json.loads(lines[1])


@needs_docker
def test_trap_doc_loses_the_metadata_and_keeps_its_id_and_key(tmp_path):
    action, doc = _bulk_through_shipped_sink(tmp_path, "opensearch_snmptrap", "snmptrap_tagged", {
        "message": "linkDown on eth0",
        "device": "spine1",
        "tenant_id": "lab",
        "tenant_registry": "hit",
        "message_key": "snmptrap:arista:spine1:1.3.6.1.6.3.1.1.5.3",
        "topic": "netops.snmptrap", "partition": 2, "offset": 41,
        "headers": {}, "path": "/",
    })
    meta = action["index"]
    # The id was derived from the coordinate BEFORE the encoder removed it.
    assert meta["_id"] == "cxk:netops.snmptrap:2:41", action
    assert meta["_index"].startswith("netops-snmptrap-lab-"), action
    leaked = (KAFKA_METADATA | {"path"}) & set(doc)
    assert not leaked, f"metadata reached storage: {sorted(leaked)}"
    assert doc["message_key"] == "snmptrap:arista:spine1:1.3.6.1.6.3.1.1.5.3"
    assert doc["tenant_id"] == "lab" and doc["tenant_seg"] == "lab"
    assert doc["message"] == "linkDown on eth0"


@needs_docker
def test_an_application_field_named_path_survives_on_applogs(tmp_path):
    _, doc = _bulk_through_shipped_sink(tmp_path, "opensearch_applogs", "applogs_tagged", {
        "message": "GET handled", "path": "/api/v1/devices",
        "topic": "netops.applogs", "partition": 0, "offset": 7,
    })
    assert doc["path"] == "/api/v1/devices"
    assert not KAFKA_METADATA & set(doc), doc


# ── PR 4 (owner D6): `platform_owned` is a label, never access ────────────────

def _lane_source(name: str) -> str:
    return _router()["transforms"][name]["source"]


@pytest.mark.parametrize("lane", ["applogs_tagged", "syslog_tagged", "snmptrap_tagged",
                                  "cloudlogs_tagged", "security_tagged", "flows_decoded"])
def test_every_lane_can_say_platform_owned(lane):
    assert "platform_owned" in _lane_source(lane), lane


@pytest.mark.parametrize("lane", ["syslog_tagged", "flows_decoded"])
def test_the_storage_scope_is_decided_before_the_label(lane):
    """§3a. tenant_seg names the index. It is derived first and the label reads
    it, so no value of the label can move a document into a different scope."""
    src = _lane_source(lane)
    assert src.index(".tenant_seg = seg") < src.index('"platform_owned"')
    between = src[src.index(".tenant_seg = seg"):]
    assert ".tenant_seg =" not in between[len(".tenant_seg = seg"):], "tenant_seg reassigned after the label"
    assert ".tenant_id =" not in between, "tenant_id reassigned after the label"


def test_the_label_is_never_derived_from_an_address():
    """Owner decision 2026-11-01: tenant comes from the channel and the registry
    answer, never from an address match written into this decision."""
    for lane in ("syslog_tagged", "flows_decoded"):
        src = _lane_source(lane)
        i = src.index('"platform_owned"')
        decision = src[max(0, i - 200):i + 60]
        for addr in ("source_ip", "sampler_address", ".host", "src_addr"):
            assert addr not in decision, f"{lane}: label decision reads {addr}"


def test_no_read_path_or_policy_keys_on_the_label():
    """§3a. The API, the ClickHouse policies and the templates' access surfaces
    must not branch on the attribution label. The one allowed Go reference is the
    processors' protected-field list, which forbids rewriting it."""
    allowed = {ROOT / "src/backend/processors/rule.go"}
    hits = []
    for path in (ROOT / "src" / "backend").rglob("*.go"):
        if path.name.endswith("_test.go") or "vendor" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if ("tenant_attribution" in text or "platform_owned" in text) and path not in allowed:
            hits.append(str(path.relative_to(ROOT)))
    assert not hits, f"Go code reads the attribution label: {hits}"
    for sql in (ROOT / "deployment/docker/clickhouse/init.sql",
                ROOT / "src/backend/internal/chschema/policies.go"):
        text = sql.read_text(encoding="utf-8")
        assert "tenant_attribution" not in text and "platform_owned" not in text, sql


def test_miss_rate_alert_counts_only_misses():
    rules = yaml.safe_load((ROOT / "src/config/rules.yaml").read_text(encoding="utf-8"))
    rule = next(r for g in rules["groups"] for r in g["rules"]
                if r.get("alert") == "TenantEnrichmentMissRateJumped")
    assert rule["expr"].count('outcome="unmatched"') == 2, rule["expr"]
    assert "platform_owned" not in rule["expr"], "the numerator must stay misses only"
    assert (ROOT / "src/config/rules-tests/tenant-enrichment.test.yaml").is_file()


# ── PR 5: sampling is labelled, never multiplied ─────────────────────────────

def test_sampling_status_is_declared_in_both_stores():
    assert _props("netops-flows")["sampling_status"]["type"] == "keyword"
    # sample_rate is the router's own 1:50 stamp and must stay beside it.
    assert _props("netops-flows")["sample_rate"]["type"] == "long"
    init = (ROOT / "deployment/docker/clickhouse/init.sql").read_text(encoding="utf-8")
    table = init[init.index("CREATE TABLE IF NOT EXISTS netops.flows"):]
    table = table[:table.index("ENGINE")]
    assert re.search(r"sampling_status\s+LowCardinality\(String\) DEFAULT ''", table), \
        "fresh installs must get the column the boot ALTER gives upgrades"
    go = (ROOT / "src/backend/internal/chschema/policies.go").read_text(encoding="utf-8")
    assert "ADD COLUMN IF NOT EXISTS sampling_status LowCardinality(String) DEFAULT ''" in go


def test_only_the_flow_lane_that_stores_the_row_stamps_it():
    """flows_rekey is a declared pass-through: the engine's copy on netops.flows
    must stay byte-equivalent to goflow2's, so the label goes on after it."""
    t = _router()["transforms"]
    assert "sampling_status" in t["flows_decoded"]["source"]
    assert "sampling_status" not in t["flows_rekey"]["source"]


def test_no_total_reads_the_label_and_the_scaling_rule_is_unchanged():
    """Owner correction 2026-11-09 (plan §4): flows are not understated 50x and
    nothing here may multiply anything. Every query scales by the exporter's own
    rate, exactly as before; only the coverage count reads the new column."""
    for path in (ROOT / "src" / "backend").glob("*.go"):
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "sampling_status" not in text:
            continue
        assert path.name == "flows.go", f"{path.name} reads the sampling label"
        for line in text.splitlines():
            if "sampling_status" in line:
                assert "countIf(" in line and "bytes" not in line and "packets" not in line, line
    flows = (ROOT / "src/backend/flows.go").read_text(encoding="utf-8")
    assert "bytes * if(sampling_rate = 0, 1, sampling_rate)" in flows
    src = _router()["transforms"]["flows_os_stamped"]["source"]
    assert re.search(r"^\s*\.sample_rate = 50$", src, re.M), "the router's sample stamp must not change"
    code = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
    assert ".bytes" not in code and ".packets" not in code, "the sample path must not touch a counter"


# ── `vector test` over the shipped config ────────────────────────────────────

ENV_STUBS = ["CLICKHOUSE_USER=x", "CLICKHOUSE_PASSWORD=x"]


def _run_suite() -> VectorTestRun:
    cmd = ["docker", "run", "--rm", "--entrypoint", "vector"]
    for kv in ENV_STUBS:
        cmd += ["-e", kv]
    for src, dst in [
        (ROUTER, "/etc/vector/vector.yaml"),
        (ROUTER_DIR / "processors-default.yaml", "/etc/vector/processors/processors.yaml"),
        (ROUTER_DIR / "tests", "/etc/vector/tests"),
        (FIXTURES, "/etc/vector/enrichment"),
    ]:
        cmd += ["-v", f"{src}:{dst}:ro"]
    cmd += [VECTOR_IMAGE, "test", "/etc/vector/vector.yaml",
            "/etc/vector/processors/processors.yaml", "/etc/vector/tests/storage-labels.yaml"]
    return run_vector_test(cmd, label="router storage-labels", timeout=900)


@needs_docker
def test_storage_label_suite_passes_on_the_shipped_config():
    run = _run_suite()
    assert run.final.returncode == 0, f"vector test failed:\n{run.report()}"
    expected = len(yaml.safe_load(SUITE.read_text(encoding="utf-8"))["tests"])
    assert run.output.count("... passed") == expected, run.output


def test_the_timeline_keys_are_searchable_on_both_event_lanes():
    """The event panel's Timeline queries records by these keys through the logs
    search: undeclared under `dynamic: false`, they would match nothing."""
    for lane in ("netops-snmptrap", "netops-syslog"):
        props = _props(lane)
        for k in ("correlation_key", "event_id", "transition_id", "platform", "device_type"):
            assert props.get(k, {}).get("type") == "keyword", (lane, k, props.get(k))

# Tracker 387, the syslog event model: the same names and types the trap lane uses, so
# the event panel and the Timeline read one contract on both lanes.
def test_syslog_event_model_fields_are_declared_with_their_types():
    props = _props("netops-syslog")
    flat = {
        "title": "text", "correlation_key": "keyword",
        "audit_user": "keyword", "audit_action": "keyword", "audit_source": "keyword",
        "audit_via": "keyword", "session_id": "keyword", "audit_groups": "keyword",
        "dump_id": "keyword", "event_category": "keyword",
    }
    wrong = {k: props.get(k, {}).get("type") for k, t in flat.items() if props.get(k, {}).get("type") != t}
    assert not wrong, f"netops-syslog event-model field types: {wrong}"
    m = props["metrics"]
    assert m.get("dynamic") is False, "metrics must not grow fields from the wire"
    for name, spec in m["properties"].items():
        assert spec["properties"]["value"]["type"] in ("double", "keyword"), name
        assert spec["properties"]["basis"]["type"] == "keyword", name
    # Pack text: kept in the document, never a mapping a pack edit could grow.
    assert props["guidance"] == {"type": "object", "enabled": False}
    for k in ("fields_observed", "fields_derived", "fields_guidance", "unknown"):
        assert props["enrichment"]["properties"][k]["type"] == "keyword", k


def test_the_syslog_metrics_mapping_covers_every_pack_metric():
    """A pack metric the template does not declare is unsearchable by value."""
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "telemetry-catalog"))
    import bake_rules
    grammars, _ = bake_rules.pack_tables(bake_rules.load_packs())
    names = {m for g in grammars for m in (g.get("metrics") or {})}
    declared = _props("netops-syslog")["metrics"]["properties"]
    assert names and names <= set(declared), f"pack metrics not declared: {sorted(names - set(declared))}"
    # A number is a double, a `{text: group}` metric a keyword: the value's own type.
    for g in grammars:
        for name, spec in (g.get("metrics") or {}).items():
            want = "keyword" if isinstance(spec, dict) else "double"
            got = declared[name]["properties"]["value"]["type"]
            assert got == want, f"metrics.{name}.value is {got}, the pack states a {want}"


def test_every_event_field_a_pack_can_state_is_declared_for_syslog():
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "telemetry-catalog"))
    import bake_rules
    props = _props("netops-syslog")
    missing = [f for f in bake_rules.EVENT_FIELDS if f not in props]
    assert not missing, f"event fields a pack may write but the template drops: {missing}"
