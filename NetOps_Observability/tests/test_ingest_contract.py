# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

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
import sys

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
    its own log line permanently (400 inside a 200 bulk response, F-17).

    The coercion list must cover EVERY string-typed field the applogs template
    declares (finder 2026-08-14: the first fix coerced 12 fields but the
    template also declares container_id / image / source_type — a producer
    logging {"image": {...}} still destroyed its own line). Enumerated from the
    template rather than hand-listed so a newly declared scalar cannot ship
    uncoerced."""
    src = vector_cfg("aggregator")["transforms"]["applogs_normalized"]["source"]
    assert "for_each(" in src and "encode_json(v)" in src, \
        "applogs_normalized no longer coerces merged producer values (F-05)"
    m = re.search(r"for_each\(\[(.*?)\]\)", src, re.S)
    assert m, "applogs_normalized lost the for_each coercion loop (F-05)"
    coerced = set(re.findall(r'"([a-z_]+)"', m.group(1)))
    props = templates()["netops-applogs"]["template"]["mappings"]["properties"]
    declared_strings = {name for name, spec in props.items()
                        if spec.get("type") in ("keyword", "text")}
    # `ts`/`ts_source`/`ts_invalid`/tenant fields/topic are overwritten AFTER
    # the merge from code — the aggregator resets .tenant_id unconditionally
    # and the router derives/stamps the rest — so producer JSON cannot reach
    # the sink through them. Everything else the merge can reach must be in
    # the loop (timestamp_raw included: it is a declared keyword a producer
    # could clobber with an object just like any other).
    router_stamped = {"ts_source", "ts_invalid", "tenant_id", "tenant_seg",
                      "tenant_attribution", "topic"}
    missing = sorted(declared_strings - coerced - router_stamped)
    assert not missing, (
        f"declared string fields not coerced after merge(): {missing} — a producer "
        "logging an object under any of these keys rejects its own document (F-05)"
    )


def test_applog_timestamp_is_guarded_not_string_coerced():
    """`timestamp` is DECLARED `date`. Producer JSON with {"timestamp": {...}}
    puts an object on a date field — ignore_malformed does NOT cover objects/
    arrays, so the whole document is rejected (400 inside a 200 bulk response)
    and the log line silently lost. The fix must NOT be the string-coercion
    loop (encode_json would corrupt the NATIVE timestamp docker_logs stamps on
    every normal doc); it needs its own guard: keep native/string timestamps,
    re-parse what still renders as a timestamp, and move anything else aside to
    `timestamp_raw` so the offending producer stays greppable instead of
    invisible (finder 2026-08-14)."""
    src = vector_cfg("aggregator")["transforms"]["applogs_normalized"]["source"]
    m = re.search(r"for_each\(\[(.*?)\]\)", src, re.S)
    assert m and '"timestamp"' not in m.group(1), \
        "timestamp must NOT ride the string-coercion loop — encode_json(v) would " \
        "JSON-quote every native timestamp"
    assert "is_timestamp(" in src and "timestamp_raw" in src and "del(.timestamp)" in src, \
        "applogs_normalized does not guard a non-string producer .timestamp (F-05)"
    # The move-aside field must be searchable: declared on both applog templates.
    for tpl in ("netops-applogs", "netops-platformlogs"):
        assert "timestamp_raw" in templates()[tpl]["template"]["mappings"]["properties"], \
            f"{tpl} does not declare timestamp_raw — the moved-aside producer " \
            "timestamp would be stored but unsearchable"


def test_syslog_severity_reconcile_covers_short_keywords():
    """Vector 0.40's syslog source emits SHORT severity keywords — a PRI-0
    frame arrives as severity="emerg" (proven empirically against
    timberio/vector:0.40.0-alpine, RFC5424 and RFC3164 both; finder
    2026-08-14). The reconcile matched only the long forms, so the single most
    severe syslog class fell through to else=info: every filter/sort on
    normalized_severity ranked a system-unusable message below a warning."""
    src = vector_cfg("aggregator")["transforms"]["syslog_normalized"]["source"]
    m = re.search(r"sysint = if (.*?)\{ 2 \}", src)
    assert m, "syslog_normalized lost the sysint severity reconcile expression"
    crit_branch = m.group(1)
    for kw in ("emergency", "alert", "critical", "crit", "emerg", "panic"):
        assert f'"{kw}"' in crit_branch, (
            f"severity keyword {kw!r} missing from the ==2/critical branch — a "
            "PRI-0 frame would store normalized_severity=info"
        )
    # Fixture: walk the map exactly as VRL evaluates it (first match wins) and
    # assert the PRI-0 keyword lands on critical, not the else=info arm.
    branches = re.findall(r"if ([^{}]+)\{ (\d) \}", src.split("sysint = ", 1)[1].split("\n", 1)[0])
    assert branches, "cannot parse the sysint branch map; update this fixture with it"

    def lookup(word: str) -> int:
        for cond, value in branches:
            if f'"{word}"' in cond:
                return int(value)
        return 6  # the else arm

    assert lookup("emerg") == 2, "PRI-0 'emerg' must map to critical (2)"
    assert lookup("panic") == 2, "legacy 'panic' must map to critical (2)"
    assert lookup("warning") == 4 and lookup("debug") == 7, "fixture drifted from the map"


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
    is unset is the defect, not the mitigation. SEC-013.1 scoped the credential
    per lane: EVERY lane must carry its own `${INGEST_TOKEN_<LANE>:?}` guard so
    Vector refuses to start without it, and the pre-SEC-013 shared anchor must
    not quietly return."""
    raw = read("deployment", "docker", "vector", "vector.yaml")
    for lane in ("TRAPS", "PROBES", "METRICS", "BUS"):
        assert f"${{INGEST_TOKEN_{lane}:?" in raw, \
            f"lane token INGEST_TOKEN_{lane} must be required, not defaulted"
    assert "auth: &ingest_auth" not in raw and "auth: *ingest_auth" not in raw, (
        "the shared ingest_auth anchor is back — one credential opening all "
        "four lanes (the bus bridge included) is SEC-013.1's named defect")


def test_no_lane_credential_falls_back_to_the_shared_token():
    """SEC-013 NARROWING (enforce wave step 4), guarded as a CLASS: the shared
    INGEST_TOKEN must not reappear as a fallback for ANY lane credential, in
    any config surface that carries one. Before the narrowing, compose
    defaulted every absent per-lane var to the shared token
    (`${INGEST_TOKEN_X:-${INGEST_TOKEN}}`), which made one secret a skeleton
    key for whichever lanes lacked their own — the epic's named defect wearing
    a different file. The client halves (ingest_auth.go / ingest_auth.py) are
    guarded here too: a fallback reintroduced on either side re-arms the
    skeleton key without touching compose."""
    lanes = ("TRAPS", "PROBES", "METRICS", "BUS")
    # Compose: no nested-interpolation fallback from a lane var to the shared.
    compose = read("deployment", "docker", "docker-compose.yml")
    for lane in lanes:
        assert f"${{INGEST_TOKEN_{lane}:-${{INGEST_TOKEN" not in compose, (
            f"INGEST_TOKEN_{lane} defaults to the shared INGEST_TOKEN in "
            "docker-compose.yml — the narrowing removed that fallback")
    # Go client: the per-lane read must not fall back to the shared token.
    go_src = read("src", "backend", "collectors", "ingest_auth.go")
    assert 'os.Getenv("INGEST_TOKEN")' not in go_src, (
        "collectors/ingest_auth.go reads the shared INGEST_TOKEN — lane "
        "credentials are per-lane ONLY after the narrowing")
    # Python mirror: same property (parity with the Go side is a documented
    # invariant of the file).
    py_src = read("deployment", "docker", "cloud-ingest", "ingest_auth.py")
    assert '"INGEST_TOKEN"' not in py_src and "'INGEST_TOKEN'" not in py_src, (
        "cloud-ingest/ingest_auth.py reads the shared INGEST_TOKEN — lane "
        "credentials are per-lane ONLY after the narrowing")


def test_every_go_ingest_forwarder_sends_the_credential():
    """Four ingest call sites in three files. A credential applied to three of
    them is a credential that does not work, and the symptom — one lane going
    quiet — is indistinguishable from a quiet network. SEC-013.1: each site
    stamps its OWN lane's credential."""
    for rel, lane in ((("src", "backend", "collectors", "metric_events.go"), "LaneMetrics"),
                      (("src", "backend", "collectors", "probe_events.go"), "LaneProbes"),
                      (("src", "backend", "collectors", "snmptrap.go"), "LaneTraps"),
                      (("src", "backend", "bus_producer.go"), "LaneBus")):
        src = read(*rel)
        assert f"SetIngestAuth(req, {lane.replace('Lane', 'collectors.Lane') if 'bus_producer' in rel[-1] else lane})" in src \
            or f"SetIngestAuth(req, {lane})" in src, \
            f"{rel[-1]} does not authenticate with its lane credential ({lane})"


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

def processors_default() -> dict:
    return yaml.safe_load(read("deployment", "docker", "vector-router", "processors-default.yaml"))


# ── item 121: per-tenant processor hooks ─────────────────────────────────────

def test_every_storage_sink_routes_through_its_processor_hook():
    """The router's storage sinks must read the generated *_rules hooks, not
    the *_tagged transforms directly — otherwise a tenant's redaction rules
    exist in the API but never touch what is actually stored."""
    cfg = vector_cfg("router")
    # F-11: the device-attribution lanes interpose a store ROUTE between the
    # hook and the sink (quarantine envelopes peel off to the dedicated
    # index). The hook is still mandatory — the route itself must read it, so
    # the chain is <lane>_rules → <lane>_store_route → sink.
    expect = {
        "opensearch_applogs": ("applogs_rules", None),
        "opensearch_syslog": ("syslog_rules", "syslog_store_route"),
        "opensearch_snmptrap": ("snmptrap_rules", "snmptrap_store_route"),
        "opensearch_cloudlogs": ("cloudlogs_rules", None),
        "clickhouse_flows": ("flows_rules", "flows_store_route"),
        # P3-L1 security findings lane. Its store route peels off findings whose
        # (native_id, scan_id) identity is incomplete — see tests/test_security_lane.py.
        "opensearch_secfindings": ("security_rules", "security_store_route"),
    }
    # Every hook — the security lane's included — comes from the GENERATED file;
    # a static duplicate in vector.yaml would be a duplicate component id across
    # the router's two --config files (pinned in tests/test_security_lane.py).
    hooks = processors_default()["transforms"]
    for sink, (hook, route) in expect.items():
        got = cfg["sinks"][sink]["inputs"]
        if route is None:
            assert got == [hook], \
                f"{sink} bypasses the processor hook (reads {got})"
        else:
            assert got == [route + "._unmatched"], \
                f"{sink} must read {route}._unmatched (quarantine peel-off, F-11); reads {got}"
            assert cfg["transforms"][route]["inputs"] == [hook], \
                f"{route} bypasses the processor hook (reads {cfg['transforms'][route]['inputs']})"
            assert "quarantine" in cfg["transforms"][route].get("route", {}), \
                f"{route} lost its quarantine route condition"
        assert hook in hooks, f"default processors file no longer defines {hook} — a cold start cannot boot"
    assert cfg["transforms"]["flows_os_sample"]["inputs"] == ["flows_store_route._unmatched"], \
        "the OS flow sample must see the SAME shaped (and quarantine-filtered) records as ClickHouse"
    # The quarantine sink consumes exactly the four routes' quarantine outputs
    # (P3-L1 added security: a finding with no deterministic doc identity).
    assert sorted(cfg["sinks"]["opensearch_quarantine"]["inputs"]) == [
        "flows_store_route.quarantine",
        "security_store_route.quarantine",
        "snmptrap_store_route.quarantine",
        "syslog_store_route.quarantine",
    ], "opensearch_quarantine must consume exactly the four lanes' quarantine routes"


def test_processor_hooks_shape_after_attribution_not_before():
    """Each lane is a PAIR: <lane>_rules_apply runs the ordered processor chain
    (a remap), <lane>_rules filters events a drop_event processor marked (a
    filter). The apply stage consumes the *_tagged / flows_decoded transforms so
    tenant attribution (and its metric) is measured BEFORE any tenant rule runs,
    and the tenant guard inside the generated VRL has a tenant_id to read."""
    hooks = processors_default()["transforms"]
    expected_inputs = {
        "applogs": "applogs_tagged", "syslog": "syslog_tagged",
        "snmptrap": "snmptrap_tagged", "cloudlogs": "cloudlogs_tagged",
        # P3-L1: the findings lane hangs off security_identity, so the
        # deterministic doc id and the quarantine mark are computed before any
        # tenant rule runs — the same ordering rule as tenant attribution.
        "security": "security_identity",
        "flows": "flows_decoded",
    }
    for lane, inp in expected_inputs.items():
        apply_name, hook_name = f"{lane}_rules_apply", f"{lane}_rules"
        assert hooks[apply_name]["type"] == "remap"
        assert hooks[apply_name]["inputs"] == [inp], f"{apply_name} must consume {inp}"
        # The sink-facing hook is the drop FILTER over the apply stage. A filter
        # (not `abort`) keeps deliberate drops out of the dead-letter lane, which
        # is reserved for malformed records — an operator's drop is not a failure.
        assert hooks[hook_name]["type"] == "filter"
        assert hooks[hook_name]["inputs"] == [apply_name]


def test_processor_metrics_are_exported():
    """Per-processor match counters must reach the exporter — a metric that is
    computed and never exported cannot be alerted on (the F-11 lesson)."""
    gen = processors_default()["transforms"]
    assert gen["cx_processor_metrics"]["type"] == "log_to_metric"
    exporter = vector_cfg("router")["sinks"]["prometheus_internal"]
    assert "cx_processor_metrics" in exporter["inputs"], \
        "the per-processor counter is computed but never exported"
    # The attribution metric stays on the PRE-hook transforms.
    metric = vector_cfg("router")["transforms"]["tenant_attribution_metric"]
    assert set(metric["inputs"]) == {"applogs_tagged", "syslog_tagged", "snmptrap_tagged",
                                     "cloudlogs_tagged", "security_tagged", "flows_decoded"}


def test_router_loads_and_watches_the_generated_processors_config():
    compose = yaml.safe_load(read("deployment", "docker", "docker-compose.yml"))
    router = compose["services"]["vector-router"]
    assert "--watch-config" in router["command"], \
        "without --watch-config a rule change needs a container restart to apply"
    assert "/etc/vector/processors/processors.yaml" in router["command"]
    assert any("/etc/vector/processors" in v for v in router["volumes"]), \
        "the generated-config mount is missing"


def test_installer_seeds_the_processors_config():
    """The router loads the generated file at boot; a cold start before the api
    has ever written it must find the checked-in no-op default."""
    src = read("scripts", "install.py")
    assert "processors-default.yaml" in src, "install.py no longer seeds the processors config"


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


def test_ingest_alerts_reference_metrics_the_pipeline_actually_emits():
    """An alert whose selector matches ZERO series reads as coverage — the F-35
    defect, found five times in this audit (all five container OOM/restart rules
    matched nothing because cAdvisor emits no `name` label).

    This bit during THIS fix: the first draft of TenantEnrichmentMissRateJumped
    said `netops_tenant_attribution_events_total`, on the reasonable assumption
    that the exporter appends `_total` to counters like most Prometheus client
    libraries. Verified against timberio/vector:0.40.0-alpine: it does NOT. The
    rule would have been permanently silent.

    So: every `netops_*` metric an ingest rule names must be produced by a
    log_to_metric transform in one of the Vector configs — or be a
    StatusEmitted family of the api's security-metric vocabulary
    (internal/secobs/vocab.go), whose emission is itself contract-guarded by
    scripts/audit_metric_contract.py (F-11 added api-sourced quarantine gauges
    to this group), spelled identically either way.
    """
    produced = set()
    for tier in ALL_TIERS:
        for tr in (vector_cfg(tier).get("transforms") or {}).values():
            if tr.get("type") != "log_to_metric":
                continue
            for m in tr.get("metrics") or []:
                # Vector's prometheus_exporter emits the configured name
                # VERBATIM — no _total suffix, no namespace prefix.
                produced.add(m["name"])
    # The api's /metrics surface: StatusEmitted rows of the secobs vocabulary
    # (same line-oriented parse as scripts/audit_metric_contract.py, which is
    # what keeps "StatusEmitted" and "actually emitted" from drifting apart).
    vocab = read("src", "backend", "internal", "secobs", "vocab.go")
    produced |= {name for name, status in
                 re.findall(r'\{Name:\s*"([a-z0-9_]+)",.*?Status:\s*Status(Emitted|Reserved)\}', vocab)
                 if status == "Emitted"}

    rules = yaml.safe_load(read("src", "config", "rules.yaml"))
    group = next(g for g in rules["groups"] if g["name"] == "ingest-integrity")
    referenced = set()
    for rule in group["rules"]:
        referenced |= set(re.findall(r"\bnetops_[a-z0-9_]+", str(rule.get("expr", ""))))

    missing = sorted(referenced - produced)
    assert not missing, (
        f"ingest-integrity alerts reference {missing}, which no log_to_metric transform "
        f"produces (produced: {sorted(produced)}). A selector that matches nothing is "
        "worse than no rule — it reads as coverage."
    )


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


# ── syslog-ng edge capacity: burst absorption + fleet-scale TCP ─────────────

def test_syslog_edge_absorbs_bursts_and_fleet_scale():
    """(finder 2026-08-14) udp() with no so-rcvbuf() left the ~208 KiB kernel
    default: a device storm (link-flap fan-out, reboot bursts — when logs
    matter most) overflows the socket and the KERNEL drops datagrams before
    syslog-ng ever reads them, invisible to the F-48 dropped/queued stats.
    tcp max-connections(64) accept()ed-then-closed the 65th device connection
    with only a stderr line — its syslog silently never arrived."""
    src = read("deployment", "docker", "syslog-ng", "core.conf")
    m = re.search(r"udp\([^;]*so-rcvbuf\((\d+)\)", src)
    assert m, "core.conf udp() sets no so-rcvbuf — kernel-default ~208 KiB, " \
              "burst drops happen in the kernel where no counter sees them"
    rcvbuf = int(m.group(1))
    assert rcvbuf >= 8388608, f"so-rcvbuf({rcvbuf}) is below the 8 MiB burst budget"
    m = re.search(r"tcp\([^;]*max-connections\((\d+)\)", src)
    assert m, "core.conf tcp() lost its max-connections bound"
    assert int(m.group(1)) >= 1024, (
        f"tcp max-connections({m.group(1)}) refuses device N+1 silently — "
        "size it above the TCP-logging fleet"
    )
    # The rcvbuf request is clamped at net.core.rmem_max (host-global sysctl;
    # syslog-ng 4.7 has no SO_RCVBUFFORCE — verified against the pinned image).
    # The config must SAY so, or the setting reads as delivered when it is
    # silently capped to the kernel default.
    assert "rmem_max" in src, \
        "core.conf must document the net.core.rmem_max host prerequisite for so-rcvbuf"

    # And the SHIPPED host preparation must DELIVER that prerequisite, not
    # just document it: prepare-host.sh's sysctl set raises net.core.rmem_max
    # (and rmem_default, which the same block manages) to at least the
    # so-rcvbuf request — and ties the value to the clamp in a comment, so a
    # future edit can't lower it without tripping the WHY. Two files, one
    # budget: this cross-pin is what keeps them from drifting apart silently.
    prep = read("scripts", "prepare-host.sh")
    pm = re.search(r"\[net\.core\.rmem_max\]=(\d+)", prep)
    assert pm, ("prepare-host.sh no longer manages net.core.rmem_max — on a "
                "default kernel (212992) the so-rcvbuf request is silently "
                "clamped back to ~208 KiB and burst drops return")
    assert int(pm.group(1)) >= rcvbuf, (
        f"prepare-host.sh rmem_max ({pm.group(1)}) is below the syslog-ng "
        f"so-rcvbuf request ({rcvbuf}) — the clamp wins and the buffer is "
        f"silently smaller than configured")
    pd = re.search(r"\[net\.core\.rmem_default\]=(\d+)", prep)
    assert pd and int(pd.group(1)) >= rcvbuf, (
        "prepare-host.sh must keep net.core.rmem_default >= the so-rcvbuf "
        "request alongside rmem_max (the block manages both)")
    assert "so-rcvbuf" in prep, (
        "prepare-host.sh must tie the rmem sysctls to the syslog-ng "
        "so-rcvbuf clamp — without the WHY, the next tidy-up lowers them")


# ── app-log lane: rotation-race disk buffer on the kafka sink ───────────────

def test_applogs_kafka_sink_buffers_to_disk():
    """(finder 2026-08-14) kafka_applogs rode Vector's 500-event memory
    default: a Kafka stall stops docker_logs reading while containers keep
    writing json-file logs capped at 3x50 MB — a chatty service under incident
    load rotates unread lines away, uncounted and unrecoverable. This is the
    same rotation-loss mechanism F-49 removed for flows; a bounded disk buffer
    decouples the tail from the broker so the spool absorbs the outage and
    replays on recovery."""
    sink = vector_cfg("aggregator")["sinks"]["kafka_applogs"]
    buf = sink.get("buffer") or {}
    assert buf.get("type") == "disk", \
        "kafka_applogs has no disk buffer — a Kafka stall loses rotated json-file logs"
    assert int(buf.get("max_size") or 0) >= 268435488, (
        "disk buffer below Vector's 268435488-byte floor is rejected at BOOT "
        "(not by `vector validate`) — see the F-04 sink comments"
    )
    assert buf.get("when_full") == "block", \
        "when_full must block (backpressure), never drop newest silently"


# ── flows sample honesty: the 1:N OS sample must SAY it is a sample ─────────

def test_flows_os_sample_is_stamped_and_disclosed():
    """(finder 2026-08-14) netops-flows-* holds a 1-in-50 SAMPLE (ClickHouse is
    the canonical flow store), but the Logs surface served it as exact —
    "showing X of Y matched", retention totals, "Export all" — so an operator
    concluded ~50x too little traffic existed, from a view labeled exact.
    Every surface that serves the sample must carry the rate: the stored doc
    (sample_rate stamp), the search/retention response (logs.go), the UI
    (Logs.tsx) and the export path (logs_export.go) — all pinned to the SAME
    rate so the disclosure cannot drift from the sampler."""
    cfg = vector_cfg("router")
    rate = int(cfg["transforms"]["flows_os_sample"]["rate"])
    stamp = cfg["transforms"].get("flows_os_stamped")
    assert stamp, "router has no flows_os_stamped transform — sampled docs carry no rate"
    assert stamp["inputs"] == ["flows_os_sample"], \
        "the stamp must ride AFTER the sampler (only sampled docs carry it)"
    assert f".sample_rate = {rate}" in stamp["source"], \
        f"flows_os_stamped must stamp .sample_rate = {rate} (the sampler's rate)"
    assert cfg["sinks"]["opensearch_flows"]["inputs"] == ["flows_os_stamped"], \
        "opensearch_flows must write the STAMPED sample"
    # The canonical ClickHouse store stays unsampled and unstamped.
    assert cfg["sinks"]["clickhouse_flows"]["inputs"] == ["flows_store_route._unmatched"], \
        "clickhouse_flows must keep reading the full (quarantine-filtered) stream"
    assert "sample_rate" in templates()["netops-flows"]["template"]["mappings"]["properties"], \
        "netops-flows must declare sample_rate or the stamp is unsearchable (dynamic: false)"
    # Cross-language parity: backend and UI disclose the SAME rate.
    go = read("src", "backend", "logs.go")
    assert f"flowsOSSampleRate = {rate}" in go, \
        "logs.go flowsOSSampleRate has drifted from the router's sample rate"
    assert "sampling" in read("src", "backend", "logs_export.go"), \
        "logs_export.go no longer discloses sampling on flow exports"
    tsx = read("src", "frontend", "src", "tabs", "Logs.tsx")
    assert f"FLOWS_OS_SAMPLE_RATE = {rate}" in tsx, \
        "Logs.tsx FLOWS_OS_SAMPLE_RATE has drifted from the router's sample rate"
    assert "totals are estimates" in tsx, \
        "Logs.tsx lost the flows sampling disclosure"


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
        "tenant_registry",                       # F-11 hit/miss discriminator — routing scaffolding, never a search field
        "cx_quarantine", "cx_event_id",          # F-11 envelope fields — declared in the netops-quarantine template, not the lane templates
        "cloud_body", "cloud_provider",          # intermediate; replaced before the sink
        "proto", "tcp_flags", "flow_type",       # clickhouse flows columns (also declared)
        "kind", "metric_name", "value", "attrs", "entity_tokens", "app",
        "amount", "day",                         # netops.cloud / cloud_costs (ClickHouse)
        # ── DEM experience lane (tracker 254) ──────────────────────────────
        # ClickHouse-only, by design AND by wiring: `netops.experience` is read
        # by the `experience_*` transforms and written ONLY to
        # clickhouse_experience_events / clickhouse_business_events. No
        # OpenSearch sink reads this lane, so there is no `dynamic: false`
        # template for these fields to be missing from — and every one of them
        # IS declared, as a column of netops.experience_events (30 d) or
        # netops.business_events (400 d), in BOTH
        # deployment/docker/clickhouse/init.sql and
        # src/backend/internal/chschema/experience_schema.go.
        # `test_experience_lane_fields_are_declared_clickhouse_columns` below
        # pins that claim MECHANICALLY, so this entry is not prose standing in
        # for a guard: stamping `.new_col` in an experience transform without
        # the matching column fails there rather than being swallowed by the
        # sinks' `skip_unknown_fields`.
        #
        # PII review (DEM_2026-09-05.md §M.8, dem-privacy.md §3, dem-api.md):
        # none of these fields is a direct identifier. `cohort_*` are
        # POPULATION dimensions (site · isp · region · device_type · browser ·
        # app_version · network_type) — a per-user value there would destroy
        # the cohort comparison they exist for — and correlix-rum.js derives
        # them from a closed vocabulary (browser FAMILY, never the full
        # user-agent; connection type), never from user data. The lane's two
        # identifier-shaped fields, `user_ref` and `session_id`, are NOT in
        # this list because the router never stamps them: they ride through
        # untouched, and `user_ref`'s direct-identifier refusal lives at the
        # api boundary (ExperienceEvent.Validate → requirePseudonymous, which
        # REFUSES rather than silently hashing). `event_id` is a producer id
        # for a record, not for a person. Both tables carry the STRICT tenant
        # row policy, so an untagged row is platform-only, never universal.
        "event_id", "producer", "observation", "data_class", "schema_name",
        "event_at", "observed_at",               # provenance.* -> columns (ms epoch)
        "cohort_site", "cohort_isp", "cohort_region", "cohort_device",
        "cohort_browser", "cohort_version", "cohort_network",
        "duration_ms", "status_code", "success",
        "lcp_ms", "inp_ms", "cls", "ttfb_ms", "fcp_ms",   # web vitals (ms; cls unitless)
        "quantity",                              # business_events only
        "parser_id", "parser_status",            # declared on syslog only; see below
        # W2 pipeline-debugger decision trace. DELIBERATELY UNDECLARED: it is
        # stamped ONLY on a record carrying the debugger's `cx_debug=<ulid>`
        # marker (pipedebug.MarkerTag), so it is absent from every production
        # document, and it is read out of _source by `correlix-debug` /
        # `docker logs`, never queried. Declaring it would advertise a
        # searchable field that no real document has. Under `dynamic: false` an
        # undeclared field is stored and not indexed — no mapping conflict, no
        # rejected doc; tests/test_pipeline_debug_vrl.py pins both halves.
        "cx_parse_trace",
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


# ── the DEM experience lane's fields are declared in ClickHouse ─────────────

EXPERIENCE_TABLES = ("experience_events", "business_events")


def _ch_columns(sql: str, table: str) -> set:
    """Column names of the `CREATE TABLE ... netops.<table> ( ... )` block."""
    m = re.search(
        r"CREATE TABLE IF NOT EXISTS netops\." + re.escape(table) + r"\s*\(\n(.*?)\n\)",
        sql, re.S)
    assert m, (
        f"netops.{table} is no longer created by a `CREATE TABLE IF NOT EXISTS` "
        "block this parser can read — update _ch_columns() together with the DDL"
    )
    cols = set()
    for line in m.group(1).splitlines():
        c = re.match(r"\s+([a-z_][a-z0-9_]*)\s+[A-Za-z]", line)
        if c:
            cols.add(c.group(1))
    assert cols, f"parsed no columns out of netops.{table}"
    return cols


def _experience_transforms() -> dict:
    cfg = vector_cfg("router")
    lane = {n: t for n, t in (cfg.get("transforms") or {}).items()
            if n.startswith("experience_")}
    assert lane, (
        "vector-router has no `experience_*` transform: the DEM experience lane "
        "(tracker 254) was removed or renamed. If it was renamed, rename its "
        "entries in `not_indexed` with it — they are excused from the OpenSearch "
        "templates ONLY because this lane is ClickHouse-only."
    )
    return lane


def test_experience_lane_fields_are_declared_clickhouse_columns():
    """The experience lane is the one lane excused from the index templates
    (it never reaches OpenSearch), so `not_indexed` carries 23 of its fields.
    That excuse is only honest while the fields really ARE declared somewhere,
    and here that somewhere is ClickHouse — where an undeclared field is not
    merely unsearchable but silently DISCARDED, because both sinks run with
    `skip_unknown_fields: true`. Same defect class as F-05, different store: add
    `.new_col = x` to an experience transform, ship it, and the value is dropped
    at the sink with no error anywhere. This asserts the property over the whole
    lane rather than over the fields that exist today."""
    stamped = set()
    for tr in _experience_transforms().values():
        stamped |= set(re.findall(r"^\s*\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=",
                                  tr.get("source") or "", re.M))
    assert stamped, "the experience transforms stamp nothing — the lane is inert"

    init_sql = read("deployment", "docker", "clickhouse", "init.sql")
    go_ddl = read("src", "backend", "internal", "chschema", "experience_schema.go")

    for where, sql in (("clickhouse/init.sql", init_sql),
                       ("chschema/experience_schema.go", go_ddl)):
        cols = set()
        for table in EXPERIENCE_TABLES:
            cols |= _ch_columns(sql, table)
        missing = sorted(stamped - cols)
        assert not missing, (
            f"the experience lane stamps {missing} but {where} declares no such "
            f"column on netops.{' / netops.'.join(EXPERIENCE_TABLES)}. Both sinks set "
            "`skip_unknown_fields: true`, so those values are DISCARDED on write. "
            "Add the column (to BOTH DDLs), or stop stamping the field."
        )

    # A fresh install reads init.sql; an existing install converges on the Go
    # DDL at api boot. If the two drift, which one you get depends on when you
    # installed — the worst kind of storage bug to debug.
    for table in EXPERIENCE_TABLES:
        assert _ch_columns(init_sql, table) == _ch_columns(go_ddl, table), (
            f"netops.{table} differs between clickhouse/init.sql and "
            "chschema/experience_schema.go: "
            f"{sorted(_ch_columns(init_sql, table) ^ _ch_columns(go_ddl, table))}. "
            "The two are required to be identical (init.sql says so in a comment); "
            "a fresh install and an upgraded one would otherwise get different tables."
        )

    # STRICT row policy on both tables: this lane carries per-tenant
    # user-behaviour data, much of it classified `pseudonymous_user`, so an
    # untagged row must be invisible rather than visible to every tenant.
    for table in EXPERIENCE_TABLES:
        assert re.search(r"CREATE ROW POLICY[^;]*ON netops\." + table, init_sql), (
            f"netops.{table} has no row policy in init.sql — an untagged "
            "experience row would be readable by every tenant"
        )


def test_the_experience_lane_never_reaches_an_opensearch_index():
    """`not_indexed` excuses the experience fields on the grounds that nothing
    indexes them. Wire an OpenSearch sink to this lane and that stops being
    true instantly and silently: `dynamic: false` would store all 23 fields
    unsearchable. The dead-letter path is deliberately exempt — it consumes the
    `.dropped` outputs and replaces the event with its own flat shape."""
    cfg = vector_cfg("router")
    lane = set(_experience_transforms())
    offenders = []
    for name, sink in (cfg.get("sinks") or {}).items():
        if sink.get("type") != "elasticsearch":
            continue
        if lane & set(sink.get("inputs") or []):
            offenders.append(name)
    assert not offenders, (
        f"{offenders} index the DEM experience lane. Its fields are listed in "
        "`not_indexed` precisely because no OpenSearch template declares them — "
        "declare them in opensearch/index-templates.json first, or drop the sink."
    )


# ── SEC-006.1: no topic may exist only by auto-creation ─────────────────────

def _compose() -> dict:
    return yaml.safe_load(read("deployment", "docker", "docker-compose.yml"))


def _kafka_init_topics() -> set:
    """The topics kafka-init explicitly creates (parsed from its for-loop)."""
    entry = _compose()["services"]["kafka-init"]["entrypoint"]
    script = " ".join(entry) if isinstance(entry, list) else entry
    m = re.search(r"for t in (.*?)\s*;\s*do", script, re.S)
    assert m, ("kafka-init no longer enumerates topics in a `for t in ...; do` "
               "loop — update _kafka_init_topics() together with it")
    return {t for t in m.group(1).split() if t.startswith("netops.")}


def _correlation_main():
    """The engine module, imported for its RESOLVED subscription set.

    `TOPICS` is no longer a literal list — it is composed (LANE_TOPICS + the
    env-grounded CORR_EVIDENCE_TOPICS, then the A4 syslog-topic substitution).
    A regex over the source reads whichever literal list appears first and
    reports something that is NOT the subscription set: it silently dropped
    netops.security (and would drop netops.syslog.control the moment the engine
    is switched onto it), i.e. exactly the topics whose absence from kafka-init
    this test exists to catch. Ask the module what it computed instead."""
    corr = os.path.join(ROOT, "src", "correlation")
    if corr not in sys.path:
        sys.path.insert(0, corr)
    try:
        # Imported here, not at module scope: sys.path has to carry
        # src/correlation before the import can resolve.
        import main
    except Exception as exc:  # noqa: BLE001 — reported, never hidden
        pytest.skip(f"correlation main.py is not importable here ({exc}) — the "
                    "topic-creation contract DID NOT RUN")
    return main


def _pipeline_topics() -> set:
    """Every topic any live producer or consumer names: Vector kafka
    components (sink `topic:` + source `topics:`), the correlation consumer's
    TOPICS list (which also covers the Go bus-bridge producers — everything
    they publish, correlation consumes), and goflow2's compose command."""
    used = set()
    for tier in ALL_TIERS:
        cfg = vector_cfg(tier)
        for section in ("sinks", "sources"):
            for comp in (cfg.get(section) or {}).values():
                if comp.get("type") != "kafka":
                    continue
                topic = comp.get("topic")
                if isinstance(topic, str) and topic.startswith("netops."):
                    used.add(topic)
                for t in comp.get("topics") or []:
                    if isinstance(t, str) and t.startswith("netops."):
                        used.add(t)
    used |= set(_correlation_main().TOPICS)
    goflow2 = _compose()["services"]["goflow2"]["command"]
    if "-transport.kafka.topic" in goflow2:
        used.add(goflow2[goflow2.index("-transport.kafka.topic") + 1])
    return used


def test_every_pipeline_topic_is_created_explicitly():
    """SEC-006.1 turned KAFKA_AUTO_CREATE_TOPICS_ENABLE off (an authenticated
    bus with auto-create is still an injection surface), which converts a
    topic missing from kafka-init into a lane that silently never exists on a
    fresh install — the single most likely data-loss vector of the epic (the
    wireless topics were ALREADY relying on auto-creation when this test was
    written). Every referenced topic must be pre-created."""
    missing = sorted(_pipeline_topics() - _kafka_init_topics())
    assert not missing, (
        f"topics used by the pipeline but not created by kafka-init: {missing} "
        "— with auto-creation off these lanes never exist on a fresh install; "
        "add them to the kafka-init for-loop in docker-compose.yml"
    )


def test_broker_autocreate_stays_off():
    env = _compose()["services"]["kafka"]["environment"]
    assert env.get("KAFKA_AUTO_CREATE_TOPICS_ENABLE") == "false", (
        "KAFKA_AUTO_CREATE_TOPICS_ENABLE must stay false (SEC-006.1): "
        "auto-create lets anything that reaches the broker mint topics, and "
        "it hides missing kafka-init entries until a fresh install loses data"
    )


# ── #209: an OpenSearch storage block must DELAY evidence, never destroy it ──
#
# storm-s10 (run 09012025x578, 2026-09-01): the host root-fs crossed
# OpenSearch's flood-stage watermark, every index went read-only-allow-delete
# for 11 minutes, and the router's opensearch_syslog sink DISCARDED 291,296
# events (900,001 injected -> 610,001 OS docs). Measured against
# netops-vector-router:0.40.0-curl on 2026-09-02: a blocked cluster answers
# _bulk with HTTP 200 and a per-ITEM 429 cluster_block_exception, and Vector
# 0.40 treats a 200-with-"errors":true body as NON-retriable unless
# `request_retry_partial` is set -- the option defaults to FALSE. With it
# false the discard counter reached 500 in 30s and nothing was logged; with it
# true the counter never appeared. These guards pin the class, not the one
# sink: any elasticsearch sink added later inherits them.

def _es_sinks(tier: str) -> dict:
    return {name: sink for name, sink in (vector_cfg(tier).get("sinks") or {}).items()
            if sink.get("type") == "elasticsearch"}


# The retry envelope the config comment advertises. Vector 0.40 backs off
# 1,2,4,8,16 then holds flat at retry_max_duration_secs (verified: that field
# caps the DELAY BETWEEN retries, it is NOT a total deadline), so
#   envelope ~= sum(1,2,4,8,16) + max_backoff * (attempts - 5).
_S10_BLOCK_SECONDS = 11 * 60          # the measured read-only-allow-delete window
_MIN_ENVELOPE_SECONDS = 30 * 60       # cover a 30-minute block at the V1 rate
_MAX_ENVELOPE_SECONDS = 2 * 3600      # bounded: request_retry_partial retries the WHOLE
                                      # batch, so a permanently-rejected doc stalls its lane for
                                      # the whole envelope — too long is "stall-prone", the
                                      # opposite failure for an evidence lane


def _retry_envelope_seconds(request: dict) -> float:
    attempts = int(request["retry_attempts"])
    initial = float(request["retry_initial_backoff_secs"])
    cap = float(request["retry_max_duration_secs"])
    total, delay = 0.0, initial
    for _ in range(attempts):
        total += min(delay, cap)
        delay *= 2
    return total


@pytest.mark.parametrize("tier", ALL_TIERS)
def test_opensearch_sinks_retry_partial_bulk_failures(tier):
    """Vector 0.40's `request_retry_partial` defaults to FALSE, which makes a
    200-with-per-item-429 bulk response a silent, terminal discard. That single
    default is the whole s10 loss mechanism."""
    for name, sink in _es_sinks(tier).items():
        assert sink.get("request_retry_partial") is True, (
            f"{tier}/{name} does not set request_retry_partial: true — a "
            "flood-stage cluster_block_exception arrives as a per-ITEM 429 "
            "inside an HTTP 200 bulk response and is discarded on the first "
            "attempt (storm-s10 lost 291,296 events exactly this way)"
        )
        assert sink.get("id_key"), (
            f"{tier}/{name} retries partial bulk failures with no id_key — the "
            "replayed batch would DUPLICATE instead of upserting (F-18)"
        )


@pytest.mark.parametrize("tier", ALL_TIERS)
def test_opensearch_sink_retry_envelope_outlives_a_storage_block(tier):
    """Bounded, but long. Unbounded retry would let one permanently-rejected
    batch (a per-item 400 mapping rejection — this stack has measured 1,127 of
    those) wedge the lane forever; too short a bound is the s10 loss again."""
    for name, sink in _es_sinks(tier).items():
        req = sink.get("request") or {}
        for field in ("retry_attempts", "retry_initial_backoff_secs", "retry_max_duration_secs"):
            assert field in req, (
                f"{tier}/{name} leaves {field} implicit — the retry envelope "
                "documented on the sink is only true if its inputs are pinned"
            )
        envelope = _retry_envelope_seconds(req)
        assert envelope >= _MIN_ENVELOPE_SECONDS, (
            f"{tier}/{name} retries for only {envelope:.0f}s — shorter than the "
            f"{_MIN_ENVELOPE_SECONDS}s a 30-minute flood-stage block needs "
            f"(s10's block alone ran {_S10_BLOCK_SECONDS}s)"
        )
        assert envelope <= _MAX_ENVELOPE_SECONDS, (
            f"{tier}/{name} retries for {envelope:.0f}s — a permanently rejected "
            "batch would hold the lane (and its Kafka offsets) that long"
        )


@pytest.mark.parametrize("tier", ALL_TIERS)
def test_opensearch_sinks_backpressure_instead_of_dropping(tier):
    """`when_full: block` is what turns a full buffer into Kafka consumer lag
    instead of a silent drop; `acknowledgements` (F-04) is what makes the
    retained topic the real buffer. A disk buffer is deliberately NOT used on
    the router: its only writable host path is the same filesystem whose
    exhaustion triggers the block, so spooling there deepens the outage. If one
    is ever added it must be sized above Vector's boot-time floor AND the tier
    must actually mount a data volume for it."""
    cfg = vector_cfg(tier)
    assert (cfg.get("acknowledgements") or {}).get("enabled") is True, (
        f"{tier} lost end-to-end acknowledgements — without them a blocking "
        "sink no longer holds the Kafka offset and back-pressure loses data"
    )
    compose = yaml.safe_load(read("deployment", "docker", "docker-compose.yml"))
    service = {"aggregator": "vector-aggregator", "router": "vector-router"}[tier]
    volumes = " ".join(compose["services"][service].get("volumes") or [])
    for name, sink in _es_sinks(tier).items():
        buf = sink.get("buffer") or {}
        assert buf.get("when_full") == "block", (
            f"{tier}/{name} must set when_full: block — drop_newest (or the "
            "unpinned default drifting) discards under pressure, which is the "
            "s10 failure with extra steps"
        )
        assert buf.get("type") in ("memory", "disk"), \
            f"{tier}/{name} has no explicit buffer type"
        if buf.get("type") == "disk":
            assert int(buf.get("max_size") or 0) >= 268435488, (
                f"{tier}/{name}: a disk buffer below Vector's 268435488-byte "
                "floor is rejected at BOOT, not by `vector validate`"
            )
            assert "/var/lib/vector" in volumes, (
                f"{tier}/{name} declares a disk buffer but {service} mounts no "
                "data volume — the spool would land on the container layer, on "
                "the same root filesystem whose exhaustion causes the block"
            )


def test_flood_stage_block_is_alerted_and_pinned_to_the_sink_buffer():
    """s10 had NO alarm on the block itself: DiskFloodStageImminent says 'this
    is coming', and OpenSearchDocumentsRejected requires a simultaneous Vector
    discard — which the fix above removes. The buffer alert's threshold is
    80% of the sink's pinned max_events; if either side moves alone the alert
    silently stops meaning what its comment says."""
    rules = yaml.safe_load(read("src", "config", "rules.yaml"))
    by_name = {r["alert"]: r for g in rules["groups"] for r in g["rules"]}
    for required in ("OpenSearchFloodStageBlock", "VectorSinkBufferFilling",
                     "VectorOpenSearchRetryStorm"):
        assert required in by_name, f"rules.yaml is missing {required} (#209)"
        assert by_name[required]["labels"]["severity"] == "critical", \
            f"{required} must be critical — it is active evidence delay"

    sinks = _es_sinks("router")
    caps = {int((s.get("buffer") or {})["max_events"]) for s in sinks.values()}
    assert len(caps) == 1, \
        f"router OpenSearch sinks disagree on max_events ({sorted(caps)}) — the alert can only pin one"
    threshold = int(re.search(r">\s*(\d+)\s*$", by_name["VectorSinkBufferFilling"]["expr"].strip()).group(1))
    assert threshold == int(0.8 * caps.pop()), (
        "VectorSinkBufferFilling's threshold has drifted from 80% of the sinks' "
        "pinned buffer max_events — it no longer means '80% full'"
    )
    assert 'component_id=~"opensearch_.*"' in by_name["VectorSinkBufferFilling"]["expr"], \
        "VectorSinkBufferFilling must select the OpenSearch sinks by pattern, not one instance"

    # The retry-storm rule is the ONLY thing that sees a poison-batch stall:
    # measured, a full retry storm leaves the buffer at 137/500 (27%), well
    # under VectorSinkBufferFilling's 80% floor, and drops the sink's
    # vector_component_sent_events_total series entirely. `unless` is therefore
    # load-bearing — an `== 0` comparison against an ABSENT series matches
    # nothing and reads as coverage (F-35).
    storm = by_name["VectorOpenSearchRetryStorm"]["expr"]
    assert "unless" in storm, (
        "VectorOpenSearchRetryStorm must use `unless` — during a full stall the "
        "sink's vector_component_sent_events_total series is ABSENT, not zero, "
        "so an `== 0` form can never fire"
    )
    assert "vector_http_client_requests_sent_total" in storm and \
           "vector_component_sent_events_total" in storm, \
        "VectorOpenSearchRetryStorm must compare requests ISSUED against events DELIVERED"
