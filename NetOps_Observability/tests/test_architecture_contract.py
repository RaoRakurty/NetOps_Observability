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


# ---------------------------------------------------------------------------
# SEC-001.1 — the as-built transport inventory stays truthful and complete.
# docs/security/transport-inventory.yaml is JSON-formatted (valid YAML) so the
# stdlib-only preflight gate can parse it; here we get yaml for free.
# ---------------------------------------------------------------------------

def _load_inventory():
    import json
    with open(os.path.join(ROOT, "docs", "security", "transport-inventory.yaml")) as fh:
        return json.load(fh)


def test_transport_inventory_covers_every_published_service():
    """A compose service that publishes a port with no inventory edge is an
    untracked attack surface — the exact drift SEC-001.1 exists to catch."""
    inv = _load_inventory()
    with open(os.path.join(ROOT, "deployment", "docker", "docker-compose.yml")) as fh:
        compose = yaml.safe_load(fh)
    published = {name for name, svc in compose.get("services", {}).items()
                 if isinstance(svc, dict) and svc.get("ports")}
    named = set()
    for e in inv["edges"]:
        named.add(e["source"]); named.add(e["destination"])
    missing = sorted(published - named)
    assert not missing, (
        f"compose services publish ports but have no transport-inventory edge: {missing} "
        "— add an edge to docs/security/transport-inventory.yaml (SEC-001.1)")


def test_transport_inventory_names_resolve_to_compose_services():
    inv = _load_inventory()
    with open(os.path.join(ROOT, "deployment", "docker", "docker-compose.yml")) as fh:
        compose = yaml.safe_load(fh)
    services = set(compose.get("services", {}))
    externals = set(inv.get("external_peers", []))
    ghosts = sorted({n for e in inv["edges"] for n in (e["source"], e["destination"])}
                    - externals - services)
    assert not ghosts, f"inventory names non-existent compose services: {ghosts}"


def test_transport_inventory_baseline_is_honest():
    """Acceptance criterion (c) of SEC-001.1: until a SEC epic deliberately
    changes a hop, these rows must match the verified compose facts.
    When an epic lands, it updates the inventory row AND this pin together.

    Enforce wave 2026-08-09 (SEC-006.3/007.2/009/012.2 listener removals):
    the kafka and valkey plaintext listeners no longer exist, so their edges'
    `current` moved to the achieved state per the tls-enforce-wave runbook.
    OpenSearch/Victoria/Postgres keep plaintext `current` (their base-compose
    default listener still exists; the lab conversion lives in
    security_profile)."""
    inv = _load_inventory()
    by_id = {e["id"]: e for e in inv["edges"]}
    for edge_id in ("api-opensearch", "api-victoria", "api-postgres"):
        cur = by_id[edge_id]["current"]
        assert cur["transport"] == "plaintext", (
            f"{edge_id}: inventory says current transport {cur['transport']!r}; "
            "if this hop was really secured, update this pin with the epic that did it")
    assert by_id["api-opensearch"]["current"]["authn"] == "none"
    # Enforce-wave pins: a regression back to plaintext must fail this test.
    assert by_id["vector-kafka"]["current"]["transport"] == "mtls"
    assert by_id["vector-kafka"]["current"]["authz"] == "topic-acls"
    assert by_id["api-valkey"]["current"]["transport"] == "tls"
    assert by_id["api-valkey"]["current"]["authn"] == "password"


def test_transport_inventory_rows_reflect_shipped_epics():
    """F-2 (assurance run 2026-08-09): three rows lagged the epics that
    changed their hops, so the inventory under-reported achieved security and
    the coverage rule (security_profile → mtls-edges row) never saw them.
    Pin the refreshed truth; a regression back to the stale shape must fail.

    `current` records BASE-COMPOSE facts (api-opensearch precedent): the lane
    and sealing hops stay plaintext-by-default there, so what this pins for
    them is the authn narrowing (a base fact — vector.yaml lane tokens are
    fail-closed `${VAR:?}` with no shared fallback) and the security_profile
    that records the TLS-deployment shape."""
    inv = {e["id"]: e for e in _load_inventory()["edges"]}

    lanes = inv["collectors-vector-lanes"]
    assert lanes["current"]["authn"] == "basic-per-lane", (
        "SEC-013.2 + wave narrowing: each lane verifies its OWN token and the "
        "shared INGEST_TOKEN opens no lane — 'basic-shared' is the pre-epic shape")
    assert "tls" in (lanes.get("security_profile", {}).get("transport") or "").lower(), (
        "SEC-013.1 shipped four-lane mTLS 2026-08-06; the row must carry a "
        "security_profile (F-2)")

    sealing = inv["vector-router-api-sealing-keys"]
    assert "tls" in (sealing.get("security_profile", {}).get("transport") or "").lower(), (
        "SEC-018.1 shipped router-SVID-only key fetch over TLS 2026-08-06; "
        "'worst hop in the inventory' is no longer the truth (F-2)")

    valkey = inv["api-valkey"]
    assert valkey["security_profile"]["transport"] == "tls", (
        "SEC-012.2 + enforce wave: TLS 6380 is the ONLY listener; a "
        "'plaintext-authenticated' profile misstates the store (F-2)")


def test_transport_inventory_targets_record_owner_accepted_shapes():
    """F-3 (assurance run 2026-08-09): three targets still said `mtls`/`svid`
    from before the owner accepted different shapes. A target nobody intends
    to build reads as an open gap forever; restate it as the accepted shape
    WITH the decision recorded in notes, so posture reads 'achieved', not
    'permanently behind target'."""
    inv = {e["id"]: e for e in _load_inventory()["edges"]}

    for edge_id in ("api-opensearch", "vector-router-opensearch"):
        tgt = inv[edge_id]["target"]
        assert tgt["transport"] == "tls" and tgt["authn"] == "basic-per-identity", (
            f"{edge_id}: owner steer §0a (smallest sufficient mechanism) accepted "
            "HTTPS + least-privilege basic identities; the mTLS-to-OS-role HLD "
            "ideal is not being built (F-3)")
        assert "0a" in (tgt.get("notes") or ""), (
            f"{edge_id}: the target restatement must cite the owner steer that "
            "authorized it")

    goflow = inv["goflow2-kafka"]["target"]
    assert goflow["transport"] == "tls" and goflow["authn"] == "none", (
        "goflow2-kafka: owner option-1 (2026-08-05, U3 resolved) IS the target — "
        "TLS-anon on FLOWS:9095, ACL-bounded (F-3)")
    assert "option-1" in (goflow.get("notes") or ""), (
        "goflow2-kafka: the target must record the option-1 decision, with its "
        "reopen condition")


def test_transport_inventory_evidence_paths_exist():
    inv = _load_inventory()
    dead = []
    for e in inv["edges"]:
        for ev in e.get("evidence", []):
            p = ev.split(":")[0]
            if not os.path.exists(os.path.join(ROOT, p)):
                dead.append(f"{e['id']}: {p}")
    assert not dead, f"inventory evidence paths missing: {dead}"


def test_legacy_profiled_services_not_presented_as_active():
    """SEC-001.2: a compose service under profiles:[legacy] does not run; any
    ARCHITECTURE.md line naming it must say so (legacy / does not run), or an
    incident responder gets sent to a component that isn't there."""
    with open(os.path.join(ROOT, "deployment", "docker", "docker-compose.yml")) as fh:
        compose = yaml.safe_load(fh)
    legacy = {name for name, svc in compose.get("services", {}).items()
              if isinstance(svc, dict) and "legacy" in (svc.get("profiles") or [])}
    assert legacy, "expected at least one legacy-profiled service (telegraf); if the class is gone, delete this guard"
    with open(os.path.join(ROOT, "docs", "ARCHITECTURE.md")) as fh:
        lines = fh.readlines()
    offenders = []
    for name in legacy:
        for i, line in enumerate(lines, 1):
            if re.search(rf"\b{re.escape(name)}\b", line, re.IGNORECASE):
                if not re.search(r"legacy|does not run|not running|archaeology", line, re.IGNORECASE):
                    offenders.append(f"{name} at ARCHITECTURE.md:{i}: {line.strip()[:80]}")
    assert not offenders, (
        "legacy-profiled services presented as active in ARCHITECTURE.md: "
        + "; ".join(offenders))
