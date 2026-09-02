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
import sys

import pytest
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

def _correlation_main():
    """The engine module itself, imported (its siblings import flat, so the
    package dir goes on sys.path). RESOLVED values, not a source regex: TOPICS
    is now computed (LANE_TOPICS + the env-grounded evidence topics), and a
    regex over the assignment would silently read only the first literal list
    it found — under-reporting the very topics an ACL has to cover."""
    corr = os.path.join(ROOT, "src", "correlation")
    if corr not in sys.path:
        sys.path.insert(0, corr)
    try:
        # Imported here, not at module scope: sys.path has to carry
        # src/correlation before the import can resolve.
        import main
    except Exception as exc:  # noqa: BLE001 — reported, never hidden
        pytest.skip(f"correlation main.py is not importable here ({exc}) — the "
                    "topic/ACL contract DID NOT RUN")
    return main


def _correlation_topics():
    return set(_correlation_main().TOPICS)


def test_correlation_consumes_all_bus_planes():
    topics = _correlation_topics()
    for required in ("netops.metrics", "netops.syslog", "netops.flows",
                     "netops.probes", "netops.snmptrap"):
        assert required in topics, f"correlation must consume {required}; has {topics}"


# ── Layer 2C.1: the A4 pre-screened syslog lane (topic pin) ───────────────────

SYSLOG_CONTROL_TOPIC = "netops.syslog.control"


def _kafka_init_topics(compose_text: str) -> set[str]:
    """The netops.* topic set the kafka-init loop pre-creates, from the raw
    compose TEXT (both files write it as a folded shell one-liner)."""
    m = re.search(r"for t in (.*?)\s*;\s*do", compose_text, re.DOTALL)
    assert m, "kafka-init lost its topic for-loop"
    return {t for t in m.group(1).split() if t.startswith("netops.")}


def test_syslog_control_topic_is_pre_created_in_both_compose_files():
    """A4 Phase 1. The aggregator produces the pre-screened syslog subset onto
    netops.syslog.control, so the topic must EXIST with the same partition
    count as every other netops.* topic — co-partitioning is what lets a
    consumer move between netops.syslog and netops.syslog.control without
    resharding a tenant. Auto-creation would give it the broker default and
    race the first producer (the reason kafka-init exists at all)."""
    for rel in (("deployment", "docker", "docker-compose.yml"),
                ("deployment", "docker", "compose.tls.yml")):
        topics = _kafka_init_topics(read(*rel))
        assert SYSLOG_CONTROL_TOPIC in topics, (
            f"{rel[-1]} kafka-init must pre-create {SYSLOG_CONTROL_TOPIC}")
        assert "netops.syslog" in topics, (
            f"{rel[-1]} must still pre-create the FULL syslog lane — the "
            "control topic is an addition, never a replacement")


def test_syslog_control_topic_is_produced_by_the_aggregator_only():
    """The split is a SUPERSET/subset pair, not a re-route: kafka_syslog still
    carries the whole lane, kafka_syslog_control carries the admitted subset,
    and both are keyed identically so the two topics co-partition."""
    sinks = _vector_cfg()["sinks"]
    full, ctrl = sinks["kafka_syslog"], sinks["kafka_syslog_control"]
    assert full["topic"] == "netops.syslog"
    assert ctrl["topic"] == SYSLOG_CONTROL_TOPIC
    for field in ("key_field", "librdkafka_options", "compression"):
        assert ctrl[field] == full[field], (
            f"kafka_syslog_control.{field} must match kafka_syslog — a "
            "different key or partitioner breaks co-partitioning")
    assert ctrl["encoding"] == full["encoding"]
    assert ctrl["tls"] == full["tls"], "the control sink must ride the same mTLS"
    assert ctrl["inputs"] == ["syslog_admission.control"], (
        "the control sink must be fed by the admission ROUTE, never by the "
        "unfiltered lane")


def test_router_does_not_consume_the_syslog_control_topic():
    """OpenSearch indexes the FULL lane from netops.syslog. A router
    subscription to the pre-screened copy would duplicate every admitted
    document — and it is the ACL, not just the config, that has to say so."""
    router = yaml.safe_load(
        read("deployment", "docker", "vector-router", "vector.yaml"))
    for name, src in router.get("sources", {}).items():
        assert SYSLOG_CONTROL_TOPIC not in (src.get("topics") or []), (
            f"vector-router source {name!r} must not consume "
            f"{SYSLOG_CONTROL_TOPIC}")
    acls = read("deployment", "docker", "kafka", "apply-acls.sh")
    grants = {}   # principal variable -> the topic set its Read loop covers
    for topics, body in re.findall(r"for t in (.*?);\s*do(.*?)done", acls,
                                   re.DOTALL):
        for principal in re.findall(r'"\$(\w+)"', body):
            grants.setdefault(principal, set()).update(
                t for t in topics.replace("\\", " ").split()
                if t.startswith("netops."))
    assert "ROUTER" in grants and "CORR" in grants, (
        f"apply-acls.sh no longer has per-principal topic loops: {sorted(grants)}")
    assert SYSLOG_CONTROL_TOPIC not in grants["ROUTER"], (
        "the router principal must NOT be granted the control topic — it "
        "indexes the full lane and would duplicate every admitted document")
    assert SYSLOG_CONTROL_TOPIC in grants["CORR"], (
        "correlation must be granted Read on the control topic, so switching "
        "the engine over is one env var and not an ACL change in the window")
    assert "netops.syslog" in grants["CORR"], (
        "correlation keeps Read on the full lane — the control topic is opt-in")
    # T2b BLOCKER (2026-09-02): netops.security was granted to the ROUTER only,
    # while the engine grounds the same findings lane itself. A kafka-python
    # consumer that subscribes to a topic it may not Describe fails the WHOLE
    # subscription, so the missing grant would have taken every lane down under
    # enforced ACLs — not just security — with all healthchecks still green.
    # Every topic the engine actually subscribes to must therefore be granted:
    # this asserts the SET, so a lane added to main.py without an ACL is red.
    for topic in _correlation_topics():
        assert topic in grants["CORR"], (
            f"correlation subscribes to {topic} but has no Read/Describe ACL — "
            "one ungranted topic fails the entire subscription")


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

    Truthfulness review 2026-08-14: the schema note DEFINES `current` as what
    the BASE compose ships on a fresh install, and the mtls-edges.yaml schema
    note defines the inventory `port` as the base-compose port (the TLS-time
    endpoint lives in the mtls-edges contract row). The 2026-08-09 enforce
    wave removed the plaintext listeners on the LAB / TLS variant only
    (compose.tls.yml); the base docker-compose.yml still ships kafka
    PLAINTEXT:9092 as the only client listener, valkey plaintext 6379, and
    clickhouse http 8123 (install.py defaults --tls off on non-TTY). So every
    one of these edges keeps plaintext `current` + the base port; the
    achieved TLS shape lives in security_profile and a regression THERE fails
    this test instead."""
    inv = _load_inventory()
    by_id = {e["id"]: e for e in inv["edges"]}
    for edge_id in ("api-opensearch", "api-victoria", "api-postgres",
                    # base compose: ${BROKER_URLS:-kafka:9092} on the single
                    # PLAINTEXT listener (docker-compose.yml KAFKA_LISTENERS)
                    "vector-kafka", "vector-router-kafka", "api-kafka",
                    "goflow2-kafka",
                    # base compose: REDIS_PORT 6379, CLICKHOUSE_URL/-ENDPOINT
                    # default http://clickhouse:8123
                    "api-valkey", "api-clickhouse", "vector-router-clickhouse"):
        cur = by_id[edge_id]["current"]
        assert cur["transport"] == "plaintext", (
            f"{edge_id}: inventory says current transport {cur['transport']!r} "
            "but `current` is DEFINED as the base-compose (plaintext-default) "
            "state; the TLS-variant state belongs in security_profile. If the "
            "BASE compose really secured this hop, update this pin with the "
            "epic that did it")
    assert by_id["api-opensearch"]["current"]["authn"] == "none"
    # Base-compose authn facts (verified against docker-compose.yml env).
    assert by_id["api-valkey"]["current"]["authn"] == "password"      # requirepass
    assert by_id["api-clickhouse"]["current"]["authn"] == "basic"     # CLICKHOUSE_USER/PASSWORD
    assert by_id["vector-router-clickhouse"]["current"]["authn"] == "basic"
    for edge_id in ("vector-kafka", "vector-router-kafka", "goflow2-kafka",
                    "api-kafka"):
        assert by_id[edge_id]["current"]["authn"] == "none", (
            f"{edge_id}: base kafka listener has no SASL/mTLS authn")
    # `port` records the BASE-compose port (mtls-edges.yaml carries the
    # TLS-time endpoint); a TLS-only listener port here misleads reviewers.
    for edge_id in ("vector-kafka", "vector-router-kafka", "api-kafka",
                    "goflow2-kafka", "kafka-init-kafka",
                    "kafka-exporter-kafka", "cloud-ingest-kafka"):
        assert by_id[edge_id]["port"] == 9092, (
            f"{edge_id}: base compose dials kafka:9092; 9094/9095 exist only "
            "under compose.tls.yml")
    assert by_id["api-valkey"]["port"] == 6379
    assert by_id["api-clickhouse"]["port"] == 8123
    assert by_id["vector-router-clickhouse"]["port"] == 8123
    # Enforce-wave achievements stay pinned where they live: the profile.
    # A regression of the TLS-variant shape must still fail loudly.
    assert by_id["vector-kafka"]["security_profile"]["transport"] == "mtls"
    assert by_id["vector-router-kafka"]["security_profile"]["transport"] == "mtls"
    assert by_id["api-valkey"]["security_profile"]["transport"] == "tls"
    assert by_id["api-clickhouse"]["security_profile"]["transport"] == "tls"


def test_every_compose_service_appears_in_the_transport_inventory():
    """F-5 (assurance run 2026-08-09): the aux-tier intra-stack edges
    (api→gotenberg tenant PDFs, api→keycloak, api→netbox, the nginx→UI
    upstreams …) had NO inventory row, so the 'every edge declared' promise
    (SEC-001) silently excluded them — the same class as the
    aggregator→opensearch edge missed before F-17, and the coverage rule can
    only validate edges that exist.

    Mechanical ratchet, the workloadid two-table idiom: every compose service
    appears in at least one edge (source or destination) OR carries an
    explicit exemption with the reason on record. Adding a service forces an
    explicit transport decision."""
    EXEMPT = {
        # legacy profile — does not run (see
        # test_legacy_profiled_services_not_presented_as_active).
        "telegraf": "legacy profile, not running",
        # The seal provider is reached over a UNIX socket bind-mount
        # (SEAL_SOCKET=/run/secrets-seal/seal.sock) — there is no network
        # transport on this hop to declare.
        "secrets-seal": "unix-socket seam, no network hop",
    }
    inv = _load_inventory()
    with open(os.path.join(ROOT, "deployment", "docker", "docker-compose.yml")) as fh:
        compose = yaml.safe_load(fh)
    services = set(compose.get("services", {}))
    named = {n for e in inv["edges"] for n in (e["source"], e["destination"])}

    missing = sorted(services - named - set(EXEMPT))
    assert not missing, (
        f"compose services with NO transport-inventory edge and no exemption: {missing} "
        "— add an edge (docs/security/transport-inventory.yaml) or an exemption "
        "with the reason on record (F-5)")

    stale = sorted(set(EXEMPT) - services)
    assert not stale, f"exemptions for services that no longer exist: {stale}"

    double = sorted(set(EXEMPT) & named)
    assert not double, (
        f"services BOTH exempted and declared: {double} — a service is in exactly "
        "one table (the workloadid ratchet rule)")


def test_transport_is_deny_by_default():
    """Owner decision 2026-08-12 (O10): the inventory is DENY-BY-DEFAULT —
    every edge must be encrypted, OR carry an explicit declared exception,
    OR appear in the grandfathered open-conversion list below (each entry =
    a KNOWN open target, visible here instead of tribal knowledge). A new
    plaintext transport that is none of those fails this test: introducing
    one now requires either encrypting it, declaring the exception, or an
    explicit, reviewable edit to this list."""
    KNOWN_OPEN = {
        # Device-side protocols — the transport-encryption device programme
        # (P0–P4), phase 2+: cannot be closed intra-stack.
        "device-syslog-ng", "device-snmp-poll", "device-snmp-trap",
        # gnmic dials devices with skip-verify:true — tls-UNVERIFIED, i.e.
        # plaintext-equivalent against an active MITM, so it registers here
        # like plaintext until SEC-016 (phase 2+) makes prod refuse insecure.
        "gnmic-device",
        # Post-v1 scoped rows (remote vantage; operator consoles behind the
        # authenticated ingress).
        "remote-vantage-api", "operator-grafana-osd",
        # The F-5 aux tail — open conversion targets, dormant or
        # ingress-terminated; each row carries its own honest notes.
        "api-keycloak", "api-netbox", "netbox-netbox-postgres",
        "netbox-valkey", "nginx-frontend", "nginx-grafana", "nginx-osd",
        "nginx-netbox", "nginx-keycloak",
        # pgjdbc negotiates TLS since F-4 hostssl but does NO CA/hostname
        # verification (tls-unverified) — open until SEC-011 verify-full.
        "keycloak-postgres",
        # No kafka client exists on this edge — BROKER_URLS feeds only the
        # stack-health TCP liveness probe (firstBrokerAddr); the base listener
        # is plaintext and there is no api-side TLS profile to declare.
        "api-kafka",
    }

    def _counts_encrypted(transport: str) -> bool:
        # "tls-unverified" (e.g. skip-verify / no CA check) does NOT count:
        # without server verification the hop is plaintext-equivalent against
        # an active MITM, so it needs a declared exception or a KNOWN_OPEN
        # entry exactly like plaintext (review finding 2026-08-14).
        return "tls" in transport and "unverified" not in transport

    inv = _load_inventory()
    offenders, stale = [], []
    seen = set()
    for e in inv["edges"]:
        seen.add(e["id"])
        prof = (e.get("security_profile", {}).get("transport") or "").lower()
        cur = (e.get("current", {}).get("transport") or "").lower()
        encrypted = _counts_encrypted(prof) or _counts_encrypted(cur)
        if encrypted or e.get("exception"):
            continue
        if e["id"] not in KNOWN_OPEN:
            offenders.append(e["id"])
    stale = sorted(k for k in KNOWN_OPEN if k not in seen)
    assert not offenders, (
        f"UNREGISTERED plaintext transport(s): {offenders} — encrypt the hop, "
        "declare an exception{owner,accepted,reason}, or (only with review) "
        "add it to KNOWN_OPEN with the reason it stays open (O10 deny-by-default)")
    assert not stale, f"KNOWN_OPEN entries no longer in the inventory: {stale}"


def test_transport_inventory_edges_are_unique_per_pair_and_port():
    """Review finding 2026-08-14 (ratchet granularity): KNOWN_OPEN and the
    deny-by-default gate key on edge ids, so an id must denote exactly ONE
    (source, destination, port) hop — two rows sharing a hop (or one id
    reused) would let a grandfather entry silently cover a second, different
    transport."""
    inv = _load_inventory()
    ids, keys = {}, {}
    for e in inv["edges"]:
        assert e["id"] not in ids, f"duplicate edge id {e['id']!r}"
        ids[e["id"]] = True
        key = (e["source"], e["destination"], e.get("port"))
        assert key not in keys, (
            f"edges {keys[key]!r} and {e['id']!r} both declare hop {key} — "
            "one hop, one row (edge-granular ratchet)")
        keys[key] = e["id"]


def test_compose_connection_facts_resolve_to_inventory_edges():
    """Review finding 2026-08-14: the deny-by-default gate iterates only
    DECLARED edges and the coverage tests check service NAMES, so a NEW
    plaintext hop between two already-inventoried services (the class that
    shipped undeclared twice: aggregator→opensearch pre-F-17, prober→victoria
    2026-08-07) triggered nothing.

    Edge-granular ratchet: derive (client, server, port) connection facts
    from the base compose itself — every env value / command argument that
    names another compose service with a port is a hop somebody wired — and
    require each fact to resolve to an inventory edge for that service pair
    (matching the declared base-compose port, or a pair edge declaring no
    single port). New wiring between inventoried services now forces a new
    inventory row, which the deny-by-default gate then adjudicates."""
    # Edge-keyed grandfather list: facts the scanner sees today that predate
    # this ratchet and have no inventory row of their own yet. Each entry is
    # (client, server, port) with the reason it is tolerated — removing the
    # wiring OR adding the row removes the entry.
    KNOWN_UNDECLARED = {
        ("correlation", "opensearch", 9200):
            "rides the combined correlation-kafka-ch-pg row's notes today; "
            "needs its own edge row (same class as pre-F-17 aggregator hop)",
        ("correlation", "clickhouse", 8123):
            "rides the combined correlation-kafka-ch-pg row (CH hop named in "
            "its notes); needs its own edge row",
        ("prober", "vector-aggregator", 8689):
            "probe-lane client beside the api on collectors-vector-lanes "
            "(PROBE_EVENT_SINK_URL); needs its own edge row",
    }
    inv = _load_inventory()
    pair_ports = {}
    for e in inv["edges"]:
        pair_ports.setdefault((e["source"], e["destination"]), set()).add(e.get("port"))
    with open(os.path.join(ROOT, "deployment", "docker", "docker-compose.yml")) as fh:
        compose = yaml.safe_load(fh)
    services = set(compose.get("services", {}))

    facts = set()
    for name, svc in compose["services"].items():
        if not isinstance(svc, dict):
            continue
        blobs = []
        env = svc.get("environment") or {}
        if isinstance(env, dict):
            blobs += [f"{k}={v}" for k, v in env.items()]
        else:
            blobs += [str(v) for v in env]
        cmd = svc.get("command")
        if isinstance(cmd, list):
            blobs += [str(x) for x in cmd]
        elif cmd:
            blobs.append(str(cmd))
        for m in re.finditer(r"\b([a-z][a-z0-9-]*):(\d{2,5})\b", "\n".join(blobs)):
            dest, port = m.group(1), int(m.group(2))
            if dest != name and dest in services:
                facts.add((name, dest, port))
    # Scanner self-check: if compose parsing or the pattern rots, this test
    # must fail loudly instead of silently asserting over nothing.
    assert len(facts) >= 15, (
        f"compose connection-fact scanner found only {len(facts)} facts — "
        "the extraction rotted; fix the scanner, do not delete the ratchet")

    offenders = []
    for src, dst, port in sorted(facts):
        ports = pair_ports.get((src, dst))
        covered = ports is not None and (port in ports or None in ports)
        if not covered and (src, dst, port) not in KNOWN_UNDECLARED:
            offenders.append(f"{src} -> {dst}:{port}")
    assert not offenders, (
        f"compose wires hops with NO matching transport-inventory edge: {offenders} "
        "— add an edge row (docs/security/transport-inventory.yaml) so the "
        "deny-by-default gate can adjudicate it (edge-granular ratchet)")

    stale_grandfather = [k for k in KNOWN_UNDECLARED if k not in facts]
    assert not stale_grandfather, (
        f"KNOWN_UNDECLARED entries no longer wired in compose: {stale_grandfather} "
        "— delete them (a grandfather entry may only cover live wiring)")


def test_transport_exceptions_carry_future_review_by():
    """Review finding 2026-08-14: exception rows carried only
    owner/accepted/reason, so an accepted exception whose environment drifts
    in ways the mechanical checks cannot see stayed accepted forever. Every
    exception must now carry a review_by date in the future; when it comes
    due, CI fails until an owner re-reviews and re-dates (or removes) it."""
    import datetime
    bad = []
    for e in _load_inventory()["edges"]:
        exc = e.get("exception")
        if not exc:
            continue
        rb = exc.get("review_by")
        if not rb:
            bad.append(f"{e['id']}: exception has no review_by date")
            continue
        try:
            due = datetime.date.fromisoformat(rb)
        except ValueError:
            bad.append(f"{e['id']}: review_by {rb!r} is not YYYY-MM-DD")
            continue
        if due <= datetime.date.today():
            bad.append(
                f"{e['id']}: review_by {rb} is due — re-review the exception "
                "with its owner and re-date it (or encrypt/remove the hop)")
    assert not bad, "transport exception review_by violations: " + "; ".join(bad)


def test_metrics_scrape_exceptions_hold_their_boundary():
    """O10 decision 2: the two metrics-only scrape hops stay plaintext as
    DECLARED exceptions. The exception is valid only while (a) it is on
    record with owner+date+the payload/boundary policy in its reason, and
    (b) the endpoints stay unpublished to the host — mechanical checks for
    the two invalidation conditions this test can see. (Payload class is
    re-verified live in the acceptance evidence; a scrape endpoint growing
    non-metrics content is a code change that must revisit the rows.)"""
    inv = {e["id"]: e for e in _load_inventory()["edges"]}
    for edge_id in ("victoria-cadvisor", "victoria-node-exporter"):
        e = inv[edge_id]
        exc = e.get("exception")
        assert exc, f"{edge_id}: the metrics-only exception is no longer declared (O10)"
        assert e.get("target", {}).get("transport") == "plaintext-DECLARED", (
            f"{edge_id}: exception rows carry target plaintext-DECLARED "
            "(the preflight validates their exception object)")
        for field in ("owner", "accepted", "reason"):
            assert exc.get(field), f"{edge_id}: exception missing {field}"
        for needle in ("metrics", "no credentials", "invalidates"):
            assert needle in exc["reason"], (
                f"{edge_id}: exception reason must state the payload boundary "
                f"and its invalidation condition (missing {needle!r})")
    with open(os.path.join(ROOT, "deployment", "docker", "docker-compose.yml")) as fh:
        compose = yaml.safe_load(fh)
    for svc in ("cadvisor", "node-exporter"):
        assert not compose["services"][svc].get("ports"), (
            f"{svc}: host-published — the internal-boundary condition of the "
            "metrics-only exception is violated; TLS/mTLS review required (O10)")


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

    goten = inv["api-gotenberg"]["target"]
    goten_notes = goten.get("notes") or ""
    assert "O10" in goten_notes and "pending" not in goten_notes.lower(), (
        "api-gotenberg: the owner decided (O10 decision 1, 2026-08-12, LIVE "
        "same day) — native gotenberg TLS, server-verified against the mesh "
        "CA; a target.notes still saying the decision is pending re-opens a "
        "decided item (the F-2/F-3 stale-row class)")
    assert "server-verified" in goten_notes.lower(), (
        "api-gotenberg: target.notes must record the accepted shape — "
        "server-verified TLS (gotenberg does not verify client certs, so not "
        "mTLS), mirroring the goflow2-kafka option-1 restatement pattern")

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
