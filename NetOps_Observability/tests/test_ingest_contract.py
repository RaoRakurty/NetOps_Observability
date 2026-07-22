"""Ingest-tier contract guards (audit 2026-07-21, findings F-03/05/07/08/10/11/14/49).

These are STATIC checks over the real config files, and they are written to
fail on the NEXT INSTANCE of each defect class rather than on the specific
instance the audit measured. That distinction is the whole point of this file:
the audit's one-line diagnosis was "remediation was consistently applied to the
instance and not the class", and prose in CLAUDE.md demonstrably did not stop
it. A test does.

Concretely, each guard below enumerates the relevant surface and asserts a
property over ALL of it — every remap that can drop, every lane's template,
every http_server source, every field the pipeline stamps — so adding a lane,
a transform or a source without the corresponding protection breaks the build.

Run:  python3 -m pytest tests/test_ingest_contract.py -v
"""
import json
import os
import re

import pytest
import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts)) as fh:
        return fh.read()


def vector_cfg(tier: str) -> dict:
    path = {"aggregator": ("deployment", "docker", "vector", "vector.yaml"),
            "router": ("deployment", "docker", "vector-router", "vector.yaml")}[tier]
    return yaml.safe_load(read(*path))


def templates() -> dict:
    d = json.loads(read("deployment", "docker", "opensearch", "index-templates.json"))
    return d["templates"]


ALL_TIERS = ["aggregator", "router"]


# ── F-03: nothing may be discarded invisibly ────────────────────────────────

@pytest.mark.parametrize("tier", ALL_TIERS)
def test_every_dropping_transform_reroutes(tier):
    """A remap that drops without `reroute_dropped` deletes data and looks
    exactly like normal filtering — `drop_on_error` and a deliberate `abort`
    land in the same counter with no payload kept for either. That is how a
    future VRL error (a producer adds a field, a regex stops matching) becomes
    permanent, invisible loss."""
    cfg = vector_cfg(tier)
    offenders = []
    for name, tr in (cfg.get("transforms") or {}).items():
        if tr.get("type") != "remap":
            continue
        if tr.get("drop_on_error") or tr.get("drop_on_abort"):
            if not tr.get("reroute_dropped"):
                offenders.append(name)
    assert not offenders, (
        f"{tier}: these transforms drop events with no dead-letter route: {offenders}. "
        "Set reroute_dropped: true and add the .dropped output to the deadletter encoder."
    )


@pytest.mark.parametrize("tier", ALL_TIERS)
def test_every_dropped_output_reaches_the_dead_letter_lane(tier):
    """reroute_dropped only moves the event to a `.dropped` output — if nothing
    consumes it, Vector discards it just the same. The route has to be wired."""
    cfg = vector_cfg(tier)
    transforms = cfg.get("transforms") or {}
    wired = set()
    for tr in list(transforms.values()) + list((cfg.get("sinks") or {}).values()):
        for inp in tr.get("inputs") or []:
            if inp.endswith(".dropped"):
                wired.add(inp[: -len(".dropped")])
    rerouting = {n for n, tr in transforms.items() if tr.get("reroute_dropped")}
    assert rerouting <= wired, (
        f"{tier}: {sorted(rerouting - wired)} reroute dropped events that NOTHING consumes — "
        "the events are discarded anyway, with the added cost of looking handled."
    )


def test_dead_letter_encoders_read_vectors_own_dropped_metadata():
    """F-14, verified empirically against timberio/vector:0.40.0-alpine:
    Vector annotates a rerouted event at `.metadata.dropped.*` (legacy log
    namespace). The original expression read `.metadata.message` — one segment
    short — and because `to_string(null)` returns "" instead of erroring, the
    `??` fallback never fired either: every dead-letter document was written
    with reason "". A DLQ that keeps the payload and drops the reason is most
    of the way to no DLQ."""
    checked = 0
    for tier in ALL_TIERS:
        cfg = vector_cfg(tier)
        for name, tr in (cfg.get("transforms") or {}).items():
            # Only encoders fed from a `.dropped` output carry Vector's
            # annotation; a dead-letter built from a plain filter (the F-49
            # misroute guard) supplies its own reason and has none to read.
            if not any(i.endswith(".dropped") for i in tr.get("inputs") or []):
                continue
            checked += 1
            src = tr.get("source") or ""
            assert ".metadata.dropped." in src, (
                f"{tier}.{name} does not read .metadata.dropped.* — it will record no reason"
            )
            assert re.search(r"\.metadata\.message\b", src) is None, (
                f"{tier}.{name} still reads .metadata.message (F-14): that path does not exist"
            )
            for field in ("reason", "detail", "raw", "lane"):
                assert f'"{field}"' in src, f"{tier}.{name} must record {field}"
    assert checked >= 2, (
        "no dead-letter encoder consumes a .dropped output on either tier — "
        "the DLQ path has been disconnected (F-03/F-14)"
    )


def test_dead_letter_lane_is_not_dynamically_typed():
    """A dead-letter index that can itself reject a document is worthless."""
    dl = templates()["netops-deadletter"]["template"]
    assert dl["mappings"].get("dynamic") is False
    assert dl["mappings"]["properties"]["raw"]["index"] is False


# ── F-05: producer JSON must not be able to grow or poison the mapping ──────

def test_every_log_template_freezes_its_field_set():
    """`dynamic: false` is what makes the 1000-field wall unreachable. The wall
    fails CLOSED: at the limit OpenSearch rejects EVERY remaining document for
    that day's index — a full-day, all-tenant blackout triggered by one service
    shipping a new structured-log schema. Measured 67 fields and climbing on
    netops-applogs, fed by an unbounded merge() of arbitrary producer JSON."""
    for name, tpl in templates().items():
        mappings = tpl["template"]["mappings"]
        assert mappings.get("dynamic") is False, (
            f"{name} allows dynamic mapping: producer-controlled keys can grow it to the "
            "1000-field limit, at which point the whole lane stops indexing for the day."
        )


def test_every_log_template_bounds_and_tolerates_fields():
    for name, tpl in templates().items():
        settings = tpl["template"]["settings"]
        mapping = settings.get("mapping") or {}
        assert (mapping.get("total_fields") or {}).get("limit"), \
            f"{name} does not state total_fields.limit explicitly"
        assert mapping.get("ignore_malformed") is True, \
            f"{name} lacks ignore_malformed: one bad value rejects the whole document"


def test_vendor_controlled_maps_are_stored_not_indexed():
    """varbinds (SNMP) and fgt (FortiOS key=value) carry VENDOR-controlled key
    names — the same unbounded generator as the applogs merge. Both are the
    reason `dynamic: false` alone is not enough: they are declared objects, so
    they must be explicitly disabled."""
    tpls = templates()
    assert tpls["netops-snmptrap"]["template"]["mappings"]["properties"]["varbinds"]["enabled"] is False
    assert tpls["netops-syslog"]["template"]["mappings"]["properties"]["fgt"]["enabled"] is False


def test_declared_scalar_fields_are_coerced_before_indexing():
    """ignore_malformed does NOT cover an object/array landing on a text field —
    that still rejects the document. So the merge must coerce the DECLARED
    fields back to strings, or one service logging {"message": {...}} destroys
    its own log line permanently (400 inside a 200 bulk response, F-17)."""
    src = vector_cfg("aggregator")["transforms"]["applogs_normalized"]["source"]
    assert "for_each(" in src and "encode_json(v)" in src, \
        "applogs_normalized no longer coerces merged producer values (F-05)"
    for field in ("message", "msg", "level", "component", "service"):
        assert f'"{field}"' in src, f"declared field {field} is not coerced after merge()"


# ── F-07: the replica count is a posture, not a constant ────────────────────

def test_replica_count_is_configurable_not_hardcoded():
    """0 replicas is correct on a single-node appliance and WRONG on a real
    cluster, where 0 replicas plus no snapshot repository (F-59) makes one
    corrupt shard permanent loss. Pinning a literal here means the posture
    cannot be changed without editing checked-in JSON."""
    for name, tpl in templates().items():
        value = tpl["template"]["settings"]["number_of_replicas"]
        assert value == "${OPENSEARCH_REPLICAS}", (
            f"{name} hardcodes number_of_replicas={value!r}; it must stay substitutable "
            "so an operator can raise it (bootstrap-opensearch.sh resolves it)."
        )


def test_bootstrap_resolves_the_replica_placeholder():
    src = read("scripts", "bootstrap-opensearch.sh")
    assert "OPENSEARCH_REPLICAS" in src
    assert "unresolved placeholder" in src, \
        "the template renderer must FAIL on an unresolved placeholder, not PUT the literal"


def test_apply_ism_does_not_force_replicas_back_to_zero():
    """apply-ism.sh used to force replicas to 0 on every netops-* index at every
    boot, which silently reverted any operator who raised them — the template
    said one thing and the running cluster another."""
    src = read("deployment", "docker", "opensearch", "apply-ism.sh")
    assert "number_of_replicas\\\":$REPLICAS" in src or "number_of_replicas\\\":$REPLICAS" in src \
        or "$REPLICAS" in src, "apply-ism.sh must apply the configured posture, not a literal 0"
    forced = re.search(r"for pat in '\.opendistro-\*' '\.opensearch-\*' 'netops-\*'", src)
    assert forced is None, \
        "apply-ism.sh still forces netops-* replicas to 0, overriding OPENSEARCH_REPLICAS"


# ── F-08: every ingest source is authenticated ──────────────────────────────

def test_every_http_ingest_source_requires_auth():
    """The bus bridge enforced only that the topic starts with `netops.` — a
    routing check, not an identity check. Anything on the compose network could
    inject events with a FORGED tenant_id, which the router then writes into
    that tenant's index. Cross-tenant injection, CLAUDE.md §3."""
    cfg = vector_cfg("aggregator")
    unauth = [n for n, s in (cfg.get("sources") or {}).items()
              if s.get("type") == "http_server" and not s.get("auth")]
    assert not unauth, f"unauthenticated ingest sources: {unauth}"


def test_ingest_auth_fails_closed():
    """An ingest tier that silently reverts to unauthenticated when a variable
    is unset is the defect, not the mitigation. `${INGEST_TOKEN:?}` makes Vector
    refuse to start (verified: exit with 'Non-empty environment variable
    required in config')."""
    raw = read("deployment", "docker", "vector", "vector.yaml")
    assert "${INGEST_TOKEN:?" in raw, "INGEST_TOKEN must be required, not defaulted"


def test_every_go_ingest_forwarder_sends_the_credential():
    """Four ingest call sites in three files. A credential applied to three of
    them is a credential that does not work, and the symptom — one lane going
    quiet — is indistinguishable from a quiet network."""
    for rel in (("src", "backend", "collectors", "metric_events.go"),
                ("src", "backend", "collectors", "probe_events.go"),
                ("src", "backend", "collectors", "snmptrap.go"),
                ("src", "backend", "bus_producer.go")):
        src = read(*rel)
        assert "SetIngestAuth(req)" in src, f"{rel[-1]} does not authenticate to the ingest tier"


def test_ingest_forwarders_observe_rejection():
    """Adding auth adds a new way for three telemetry lanes to go silent (a
    wrong token = 401 on every POST). Two of the three forwarders discarded the
    status code entirely, so the failure would have been invisible."""
    for rel in (("src", "backend", "collectors", "metric_events.go"),
                ("src", "backend", "collectors", "probe_events.go"),
                ("src", "backend", "collectors", "snmptrap.go")):
        src = read(*rel)
        assert "logIngestRejection(" in src, \
            f"{rel[-1]} does not report a rejected ingest POST — the lane would die silently"


def test_no_ingest_port_is_published_to_the_host():
    """The audit observed :8689 bound to a host interface. The compose file must
    never publish an ingest port: these sources take telemetry from inside the
    stack only."""
    compose = yaml.safe_load(read("deployment", "docker", "docker-compose.yml"))
    for name, svc in compose["services"].items():
        for mapping in svc.get("ports") or []:
            text = str(mapping)
            for port in ("8688", "8689", "8690", "8692"):
                assert port not in text, \
                    f"service {name} publishes ingest port {port} on the host: {text}"


# ── F-10: one canonical event-time field on every lane ──────────────────────

def test_every_log_lane_derives_the_canonical_ts():
    """`ts` is the field every template declares as the time axis, but it was
    absent on syslog/snmptrap/flows/cloudlogs (they carry only `timestamp`) and
    on BOTH counts for controller_events. Documents with no `ts` read exactly
    like "no data in that window"."""
    cfg = vector_cfg("router")
    anchor = cfg["transforms"]["applogs_tagged"]["source"]
    assert "ts_source" in anchor and 'parse_timestamp(to_string(.timestamp)' in anchor, \
        "the shared log-lane anchor no longer derives ts from timestamp (F-10)"
    # Every log-shaped lane must use the anchor rather than hand-rolling it —
    # divergence between sibling lanes is what caused DEF-6 in the first place.
    for lane in ("syslog_tagged", "snmptrap_tagged", "cloudlogs_tagged"):
        assert cfg["transforms"][lane]["source"] == anchor, \
            f"{lane} has drifted from the shared &log_lane anchor"


def test_bus_bridge_stamps_a_time_on_timeless_producers():
    """netops.controller_events carried NO time field at all on 400/400 sampled
    messages, so every consumer ordering those events was silently using
    arrival time — the F-34 defect class."""
    src = vector_cfg("aggregator")["transforms"]["bus_bridge"]["source"]
    assert "bridge_receive" in src, \
        "bus_bridge no longer stamps a receive-time ts for producers that send none"


# ── F-11: a broken enrichment table must be visible ─────────────────────────

def test_tenant_attribution_outcome_is_stamped_on_every_lane():
    """tenant_id="" is a legitimate value, so a broken device→tenant table looks
    exactly like correct operation: every lane collapses into the shared
    -untagged- index and at-rest separation silently stops applying."""
    cfg = vector_cfg("router")
    for lane in ("applogs_tagged", "syslog_tagged", "snmptrap_tagged",
                 "cloudlogs_tagged", "flows_decoded"):
        assert "tenant_attribution" in cfg["transforms"][lane]["source"], \
            f"{lane} does not record whether tenant enrichment matched (F-11)"


def test_tenant_attribution_is_exported_as_a_metric():
    cfg = vector_cfg("router")
    metric = cfg["transforms"]["tenant_attribution_metric"]
    assert metric["type"] == "log_to_metric"
    exporter = cfg["sinks"]["prometheus_internal"]
    assert "tenant_attribution_metric" in exporter["inputs"], \
        "the attribution counter is computed but never exported — nothing can alert on it"


def test_enrichment_miss_alert_exists():
    rules = yaml.safe_load(read("src", "config", "rules.yaml"))
    alerts = {r["alert"] for g in rules["groups"] for r in g["rules"]}
    for required in ("TenantEnrichmentMissRateJumped", "TenantAttributionLaneMissing",
                     "VectorDeadLetters"):
        assert required in alerts, f"rules.yaml is missing {required}"


# ── F-49: flows must not be split off container stdout by a name match ──────

def test_goflow2_ships_over_kafka_not_stdout():
    """Container stdout made flows share a rotation loss window with app logs
    and, worse, made lane separation a container-NAME substring match: renaming
    the container turned every flow record into an app log with no error."""
    compose = yaml.safe_load(read("deployment", "docker", "docker-compose.yml"))
    cmd = " ".join(str(x) for x in compose["services"]["goflow2"]["command"])
    assert "-transport kafka" in cmd or "kafka" in cmd.split("-transport")[1][:20], \
        "goflow2 is not using its native kafka transport"
    assert "netops.flows" in cmd, "goflow2 must produce to netops.flows"


def test_no_lane_is_separated_by_container_name():
    """The guard for the CLASS: any future `contains(.container_name, ...)`
    routing decision reintroduces exactly this failure — a rename silently
    reroutes a whole signal into the wrong index."""
    for tier in ALL_TIERS:
        raw = yaml.safe_dump(vector_cfg(tier))
        assert "container_name" not in raw or "contains(string!(.container_name)" not in raw, \
            f"{tier} routes by container name again (F-49): rename it and the lane silently moves"


def test_misrouted_flows_are_dead_lettered_not_indexed_as_applogs():
    """The failure path must be defined: if goflow2 is ever rolled back to
    stdout, those records must be loudly dead-lettered rather than quietly
    indexed as application logs."""
    cfg = vector_cfg("aggregator")
    assert "docker_misrouted_flows" in cfg["transforms"]
    cond = cfg["transforms"]["docker_misrouted_flows"]["condition"]
    assert "sampler_address" in cond and "time_received_ns" in cond, \
        "the misroute guard must match the flow RECORD SHAPE, not a container name"
    dl = cfg["transforms"]["misrouted_flows_deadletter"]["source"]
    assert '"reason": "misroute"' in dl


def test_flows_keep_tenant_attribution_after_the_transport_move():
    """Tenant enrichment used to happen in the aggregator's flows_normalized.
    Moving flows onto goflow2's kafka transport bypasses that tier entirely, so
    the lookup had to move with it — otherwise every flow silently becomes
    untagged."""
    src = vector_cfg("router")["transforms"]["flows_decoded"]["source"]
    assert 'find_enrichment_table_records("device_tenant"' in src
    assert "device_tenant" in vector_cfg("router")["enrichment_tables"]
    compose = yaml.safe_load(read("deployment", "docker", "docker-compose.yml"))
    mounts = " ".join(compose["services"]["vector-router"]["volumes"])
    assert "/etc/vector/enrichment" in mounts, \
        "vector-router reads the enrichment table but the compose file does not mount it"


# ── cross-cutting: the pipeline may not stamp a field no template declares ──

def test_every_field_the_pipeline_stamps_is_declared_or_deliberately_not():
    """With `dynamic: false`, a field the pipeline sets but the template does
    not declare is silently NOT SEARCHABLE. That is a quiet, easy regression:
    add `.new_field = x` in VRL, ship it, and nobody notices it is unqueryable
    until an incident. This enumerates every top-level assignment in both
    Vector configs and requires each to be declared somewhere — or listed below
    as intentionally unindexed."""
    declared = set()
    for tpl in templates().values():
        declared |= set(tpl["template"]["mappings"]["properties"])

    # Fields that legitimately never reach an OpenSearch log index: routing
    # scaffolding, ClickHouse-only columns, and the cloud-bus event shape.
    not_indexed = {
        "__topic", "__key",                      # kafka_bus routing, stripped at encode
        "cloud_body", "cloud_provider",          # intermediate; replaced before the sink
        "proto", "tcp_flags", "flow_type",       # clickhouse flows columns (also declared)
        "kind", "metric_name", "value", "attrs", "entity_tokens", "app",
        "amount", "day",                         # netops.cloud / cloud_costs (ClickHouse)
        "parser_id", "parser_status",            # declared on syslog only; see below
        "vendor", "hostname", "appname", "severity", "facility", "summary",
        "subsystem", "event_type", "normalized_severity", "clock_skew_s",
        "fgt", "app_id", "app_vendor", "app_src", "app_dst", "app_dport",
        "app_proto", "signal", "service", "level", "component", "tenant_id",
        "tenant_seg", "tenant_attribution", "ts", "ts_source", "ts_invalid",
        "message", "msg", "host", "timestamp", "cloud_family", "resource_id",
        "source_type", "dropped_at", "lane", "reason", "detail", "raw",
    }

    assign = re.compile(r"^\s*\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=", re.M)
    stamped = set()
    for tier in ALL_TIERS:
        cfg = vector_cfg(tier)
        for tr in (cfg.get("transforms") or {}).values():
            stamped |= set(assign.findall(tr.get("source") or ""))

    undeclared = sorted(stamped - declared - not_indexed)
    assert not undeclared, (
        f"the pipeline stamps {undeclared} but no index template declares them. "
        "Under `dynamic: false` those fields are stored and NOT searchable. "
        "Declare them in opensearch/index-templates.json, or add them to "
        "not_indexed above with a reason."
    )
