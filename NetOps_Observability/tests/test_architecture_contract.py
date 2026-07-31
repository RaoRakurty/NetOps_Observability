"""Architecture contract tests — fail CI if the finalized wiring is broken.

These are STATIC checks against the real config/source files (no running stack),
so a future edit that re-wires the metric/trap path the wrong way fails the
build. They encode the finalized NetOps_Observability architecture:

  * SNMP metrics are owned by the Go collector — NOT Telegraf (critical test #2)
  * Go collector → Vector :8690 → netops.metrics is the live metric path (#1)
  * correlation consumes the 5 bus topics; the live RCA path does not query VM
  * traps reach correlation only via the normalized classifier (#4 plumbing)

Run:  python3 -m pytest tests/test_architecture_contract.py -v
"""
import os
import re

import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts)) as fh:
        return fh.read()


# ── critical #2: Telegraf is NOT the canonical SNMP metric bus producer ───────

def test_telegraf_is_not_a_bus_producer():
    """Telegraf must not publish to Kafka/Redpanda or to netops.metrics. The Go
    collector is the sole SNMP metric producer; a second producer would create
    duplicate canonical series (ownership violation)."""
    cfg = read("deployment", "docker", "telegraf", "telegraf.conf")
    assert "[[outputs.kafka]]" not in cfg, "Telegraf must not have a Kafka output"
    assert "netops.metrics" not in cfg, "Telegraf must not target netops.metrics"


def test_telegraf_is_gated_off_by_default():
    """Telegraf must be a non-default (legacy-profile) service so it can never
    silently run as a second SNMP path. The Go collector owns SNMP metrics."""
    compose = yaml.safe_load(read("deployment", "docker", "docker-compose.yml"))
    tg = compose["services"].get("telegraf")
    if tg is not None:  # allowed to be removed entirely; if present it must be gated
        assert "legacy" in (tg.get("profiles") or []), \
            "Telegraf must be gated behind the 'legacy' compose profile (not default)"


def test_telegraf_keeps_only_its_vm_output():
    """Telegraf may still write to VictoriaMetrics (its only legitimate output);
    it must not gain a bus output. Exactly one outputs block, and it's http/VM."""
    cfg = read("deployment", "docker", "telegraf", "telegraf.conf")
    outputs = re.findall(r"\[\[outputs\.(\w+)\]\]", cfg)
    assert outputs == ["http"], f"Telegraf outputs must be [http] only, got {outputs}"


# ── critical #1: Go collector → Vector :8690 → netops.metrics ─────────────────

def test_go_collector_is_the_metric_bus_producer():
    """The Go collector owns the canonical MetricEvent → bus path, default sink
    is the Vector metrics source on :8690."""
    src = read("src", "backend", "collectors", "metric_events.go")
    assert "func forwardMetricEvents" in src
    assert "func buildMetricEvent" in src
    assert ":8690" in src, "default METRIC_EVENT_SINK_URL must point at Vector :8690"
    # provenance stamp is part of the single canonical contract
    for field in ('observer_type', 'modality_class', 'collection_path',
                  'signal_family', 'snmp_poll', 'device_telemetry'):
        assert field in src, f"MetricEvent missing canonical field/value: {field}"


def test_metric_filter_is_an_explicit_allowlist():
    """Only RCA families reach the bus — no raw firehose. The allowlist must
    include the key families and must NOT include noisy packet counters."""
    src = read("src", "backend", "collectors", "metric_events.go")
    for keep in ("device_if_in_errors", "device_if_out_discards", "device_if_oper_status",
                 "device_bgp_peer_state", "device_cpu_percent"):
        assert keep in src, f"RCA family missing from allowlist: {keep}"
    for drop in ("device_if_in_ucast_pkts", "device_if_out_mcast_pkts",
                 "device_if_in_bcast_pkts"):
        assert drop not in src, f"noisy counter must NOT be on the bus: {drop}"


# ── Layer 2B: Vector route contract ───────────────────────────────────────────

def _vector_cfg():
    return yaml.safe_load(read("deployment", "docker", "vector", "vector.yaml"))


def test_vector_has_metrics_source_on_8690():
    cfg = _vector_cfg()
    src = cfg["sources"].get("metrics_in")
    assert src is not None, "vector metrics_in source missing"
    assert src["address"].endswith(":8690"), f"metrics_in must bind :8690, got {src['address']}"
    # NDJSON: one event per line, not a single array event
    assert src["decoding"]["codec"] == "json"
    assert src["framing"]["method"] == "newline_delimited"


def test_vector_routes_metrics_to_correct_topic():
    cfg = _vector_cfg()
    sink = cfg["sinks"].get("kafka_metrics")
    assert sink is not None, "kafka_metrics sink missing"
    assert sink["topic"] == "netops.metrics", f"wrong topic: {sink['topic']}"
    assert sink["inputs"] == ["metrics_normalized"], "sink must read the normalized metric stream"
    # the normalized transform must feed from the :8690 source (no cross-wiring)
    assert cfg["transforms"]["metrics_normalized"]["inputs"] == ["metrics_in"]


def test_vector_does_not_misroute_metrics_to_other_topics():
    cfg = _vector_cfg()
    for name, sink in cfg["sinks"].items():
        if sink.get("inputs") == ["metrics_normalized"]:
            assert sink["topic"] == "netops.metrics", f"{name} misroutes metrics → {sink['topic']}"


# ── Layer 2C: correlation topic contract ──────────────────────────────────────

def _correlation_topics():
    src = read("src", "correlation", "main.py")
    m = re.search(r"TOPICS\s*=\s*\[([^\]]*)\]", src)
    assert m, "TOPICS list not found in correlation main.py"
    return set(re.findall(r"netops\.\w+", m.group(1)))


def test_correlation_consumes_all_bus_planes():
    topics = _correlation_topics()
    for required in ("netops.metrics", "netops.syslog", "netops.flows",
                     "netops.probes", "netops.snmptrap"):
        assert required in topics, f"correlation must consume {required}; has {topics}"


# ── Layer 2D: VictoriaMetrics is not the LIVE correlation path ────────────────

def test_correlation_live_path_does_not_query_victoriametrics():
    """Live RCA must consume the bus, not poll VM. A VM-query bridge may exist for
    replay/backfill later, but not in the live consume/handle path today.

    2026-07-22: this used to assert `"victoria" not in main.py.lower()`, which
    had rotted into a false failure — the word now appears in a service-name
    LIST (a health-probe default) and in a comment saying VM SCRAPES this
    service's /metrics. Neither is a query. Nothing caught the rot because this
    file was in no CI workflow; it is now (ingest-contract-ci.yml), so the
    assertion has to mean what it says: no VM QUERY api, no VM endpoint."""
    src = read("src", "correlation", "main.py")
    for probe in ("/api/v1/query", "/api/v1/query_range", ":8428", "VICTORIA_URL", "VM_URL"):
        assert probe not in src, \
            f"correlation must not query VictoriaMetrics on the live path (found {probe!r})"


# ── critical #4 plumbing: traps reach correlation only via the classifier ─────

def test_trap_classifier_is_an_allowlist_not_a_firehose():
    """trap_control_signal classifies high-value families and returns None for
    everything else (unknown traps stay searchable, never an RCA signal)."""
    src = read("src", "correlation", "producers.py")
    assert "def trap_control_signal" in src
    assert "return None" in src.split("def trap_control_signal", 1)[1], \
        "unclassified traps must return None (no signal)"
    # the standard high-value notification OIDs must be recognized
    for oid in ("1.3.6.1.6.3.1.1.5.3",   # linkDown
                "1.3.6.1.6.3.1.1.5.1",   # coldStart
                "1.3.6.1.2.1.15.7.2"):   # bgpBackwardTransition
        assert oid in src, f"trap classifier missing standard OID {oid}"


def test_source_enum_includes_trap_everywhere():
    """The corr_signals.source enum must list 'trap' in BOTH the Go DDL and the
    SQL init, or normalized trap signals fail to insert (the bug this guards)."""
    assert "'trap'=8" in read("src", "backend", "internal", "chschema", "corr_schema.go")
    assert read("deployment", "docker", "clickhouse", "init.sql").count("'trap'=8") >= 2


def test_source_enum_includes_audit_everywhere():
    """Item 121: 'audit'=13 must exist in the Go DDL, the SQL init AND the
    Python Signal model, or the audit→feed bridge inserts fail (Go) / read-back
    raises (Python)."""
    assert "'audit'=13" in read("src", "backend", "internal", "chschema", "corr_schema.go")
    assert read("deployment", "docker", "clickhouse", "init.sql").count("'audit'=13") >= 2
    assert 'AUDIT = "audit"' in read("src", "correlation", "signals.py")
