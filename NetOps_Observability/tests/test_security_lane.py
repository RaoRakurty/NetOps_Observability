"""P3-L1 — the security FINDINGS lane (netops.security → netops-secfindings-*).

The durable findings store decided in
docs/design/SECURITY_FINDINGS_STORE_DECISION_2026-08-28.md: a per-tenant
OpenSearch index written by vector-router from the `netops.security` Kafka
topic, exactly as syslog/flows/cloudlogs are written. These are STATIC contract
guards over the real config files, in the same spirit as
tests/test_ingest_contract.py — they fail on the next instance of the defect
CLASS, not on one instance of it:

  * the lane is wired end to end (source → shared &log_lane anchor → identity →
    processor hook → store route → sink), so it cannot half-exist;
  * the document identity is DETERMINISTIC — sha2(native_id | scan_id) — and a
    finding that cannot produce one is QUARANTINED, never written under an
    invented/auto id (which would re-insert the same verdict on every replay
    and inflate every CTEM facet count). The VRL is not merely grepped: it is
    EXECUTED in the pinned Vector 0.40.0 image against three fixtures;
  * the index template maps every facet field as `keyword` and every narrative
    field as `text`, with the F-05 field wall (`dynamic: false`) closed, so a
    dotted producer key (the CLAUDE.md `del(.label)` gotcha) can never blow the
    mapping and silently drop the whole lane;
  * the router principal actually holds READ on netops.security — a lane whose
    ACL is missing is auth-dead while every healthcheck stays green
    (the 2026-08-16 incident).

The VRL-execution test needs docker + the pinned image; it SKIPS (never
silently passes) when either is unavailable.

Run:  python3 -m pytest tests/test_security_lane.py -v
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile

import pytest
import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"  # pinned: docker-compose.yml + preflight-configs.sh

TOPIC = "netops.security"
INDEX_PATTERN = "netops-secfindings-{{ tenant_seg }}-%Y.%m.%d"
TEMPLATE = "netops-secfindings"


def read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts)) as fh:
        return fh.read()


def router() -> dict:
    return yaml.safe_load(read("deployment", "docker", "vector-router", "vector.yaml"))


def processors_default() -> dict:
    return yaml.safe_load(read("deployment", "docker", "vector-router", "processors-default.yaml"))


def templates() -> dict:
    return json.loads(read("deployment", "docker", "opensearch", "index-templates.json"))["templates"]


def secfindings_props() -> dict:
    return templates()[TEMPLATE]["template"]["mappings"]["properties"]


# ── wiring: source → anchor → identity → hook → route → sink ────────────────


def test_security_source_consumes_the_topic_like_every_other_lane():
    src = router()["sources"]["kafka_security"]
    assert src["type"] == "kafka"
    assert src["topics"] == [TOPIC]
    assert src["group_id"] == "netops-router-security", \
        "the consumer group must sit under the netops-router- prefix the ACL grants"
    assert src["decoding"] == {"codec": "json"}
    # SEC-006.2: the same opt-in mTLS shape as every other kafka source — a lane
    # that hardcodes plaintext cannot join a TLS deployment.
    tls = src["tls"]
    assert tls["enabled"] == "${KAFKA_TLS_ENABLED:-false}", \
        "kafka_security does not honour KAFKA_TLS_ENABLED (SEC-006.2)"
    for key in ("ca_file", "crt_file", "key_file"):
        assert "KAFKA_TLS" in tls[key], f"kafka_security {key} is not env-driven"
    assert src["bootstrap_servers"] == "${BROKER_URLS:-kafka:9092}"


def test_security_lane_uses_the_shared_log_lane_anchor():
    """DEF-6: sibling lanes that hand-roll the head drift apart. security_tagged
    must BE the anchor (same YAML anchor as applogs/syslog/snmptrap/cloudlogs),
    which is what strips the producer-forgeable control marks, derives the
    tenant segment and normalises `ts`."""
    cfg = router()
    anchor = cfg["transforms"]["applogs_tagged"]["source"]
    lane = cfg["transforms"]["security_tagged"]
    assert lane["inputs"] == ["kafka_security"]
    assert lane["source"] == anchor, \
        "security_tagged has drifted from the shared &log_lane anchor"
    # The anchor is what makes the three guarantees below true for this lane.
    assert "del(.cx_quarantine)" in anchor and "del(.cx_drop)" in anchor
    assert ".tenant_seg = seg" in anchor
    assert "ts_source" in anchor


def test_security_lane_is_counted_by_the_tenant_attribution_metric():
    """F-11: a lane missing from the attribution counter is a lane whose broken
    tenant stamping is invisible."""
    inputs = router()["transforms"]["tenant_attribution_metric"]["inputs"]
    assert "security_tagged" in inputs, \
        "the security lane does not feed the tenant-attribution counter (F-11)"


def test_identity_stage_guards_the_dotted_key_gotcha():
    """CLAUDE.md: a `.label` map (com.docker.compose.*) is read by OpenSearch as
    an object PATH; the resulting mapping conflict silently dropped ALL app logs
    once already. Hostile/dotted fields die at the head of the lane."""
    src = router()["transforms"]["security_identity"]["source"]
    assert "del(.label)" in src


def test_sink_routes_through_the_hook_and_the_store_route():
    """Same chain shape as the F-11 lanes: <lane>_rules → <lane>_store_route →
    sink, so a tenant's processors touch what is actually stored and an
    unidentifiable finding peels off before the tenant index."""
    cfg = router()
    assert cfg["sinks"]["opensearch_secfindings"]["inputs"] == ["security_store_route._unmatched"]
    route = cfg["transforms"]["security_store_route"]
    assert route["type"] == "route"
    assert route["inputs"] == ["security_rules"]
    assert route["route"]["quarantine"] == "to_bool(.cx_quarantine) ?? false"
    assert cfg["transforms"]["security_rules"]["inputs"] == ["security_rules_apply"]
    assert cfg["transforms"]["security_rules_apply"]["inputs"] == ["security_identity"]
    assert cfg["transforms"]["security_identity"]["inputs"] == ["security_tagged"]


def test_unidentifiable_findings_reach_the_quarantine_sink():
    """The quarantine peel-off must actually be consumed. A route output nothing
    reads is a silent drop — the exact failure this lane refuses to have."""
    inputs = router()["sinks"]["opensearch_quarantine"]["inputs"]
    assert "security_store_route.quarantine" in inputs


def test_the_static_hook_and_the_generated_one_are_mutually_exclusive():
    """src/backend/processors/generate.go does not enumerate `security`, so the
    hook pair is declared STATICALLY in vector.yaml. Vector refuses to start on
    a duplicate component id across its two --config files, so the day the
    generator gains the lane the static pair MUST be deleted in the same
    change — otherwise the whole router fails to boot."""
    generated = processors_default()["transforms"]
    static = router()["transforms"]
    for name in ("security_rules", "security_rules_apply"):
        assert name in static, f"{name} is not declared statically in the router config"
        assert name not in generated, (
            f"{name} is now emitted by the processor generator AND declared statically "
            "in vector.yaml — duplicate component ids; delete the static pair"
        )
    # generate.go must still not know the lane; if it learns it, this test is
    # the reminder that the static pair above has to go.
    assert '"security"' not in read("src", "backend", "processors", "generate.go"), \
        "generate.go now enumerates a security lane — remove the static hook pair from vector.yaml"


def test_sink_writes_the_per_tenant_index_with_the_deterministic_id():
    sink = router()["sinks"]["opensearch_secfindings"]
    assert sink["type"] == "elasticsearch"
    assert sink["mode"] == "bulk"
    assert sink["bulk"]["index"] == INDEX_PATTERN, \
        "the findings index must carry the tenant segment (§3a at-rest separation)"
    assert sink["bulk"]["action"] == "index"
    assert sink["id_key"] == "cx_finding_id", (
        "the findings doc id must be the deterministic verdict identity, not the "
        "Kafka coordinate and never an auto id"
    )
    assert sink["healthcheck"] is False, "SEC-008: the write-only identity cannot pass a READ healthcheck"


def test_sink_carries_the_209_retry_and_backpressure_settings():
    """storm-s10: a blocked OpenSearch answers _bulk with HTTP 200 carrying
    per-item 429s; without request_retry_partial Vector treats that as
    non-retriable and DISCARDS the batch (291,296 syslog events, measured).
    An evidence lane degrades to DELAYED, never to LOST."""
    sink = router()["sinks"]["opensearch_secfindings"]
    assert sink["request_retry_partial"] is True
    req = sink["request"]
    assert req["retry_attempts"] == 90
    assert req["retry_initial_backoff_secs"] == 1
    assert req["retry_max_duration_secs"] == 30
    buf = sink["buffer"]
    assert buf["type"] == "memory", "no disk buffer: the router's only writable path is the full root fs"
    assert buf["max_events"] == 500
    assert buf["when_full"] == "block", \
        "drop_newest would silently discard evidence during a storage block (s10)"


# ── doc identity: EXECUTED, not grepped ────────────────────────────────────

NATIVE = "security|security_posture|posture|CIS-1.1.1|dev-1|scan-A|f1"

FIXTURES = [
    # 1. a complete finding, with a dotted `.label` map attached
    {"native_id": NATIVE, "attrs": {"scan_id": "scan-A"},
     "label": {"com.docker.compose.project": "netops"}},
    # 2. the SAME verdict redelivered (no label) → must collapse onto the same _id
    {"native_id": NATIVE, "attrs": {"scan_id": "scan-A"}},
    # 3. the same rule+device in a LATER scan → a NEW document (trend/drift)
    {"native_id": NATIVE.replace("scan-A", "scan-B"), "attrs": {"scan_id": "scan-B"}},
    # 4. no native_id → unidentifiable → quarantine, never a random id
    {"attrs": {"scan_id": "scan-A"}},
    # 5. no scan_id → unidentifiable → quarantine
    {"native_id": NATIVE, "attrs": {}},
]


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", VECTOR_IMAGE],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def _run_identity_vrl() -> list:
    """Execute the COMMITTED security_identity VRL in the pinned Vector image."""
    program = router()["transforms"]["security_identity"]["source"]
    # `vector vrl` prints the program's RESULT; end with `.` so we get the whole
    # event back and can assert on the quarantine mark as well as the id.
    program = program.rstrip() + "\n.\n"
    work = tempfile.mkdtemp(prefix="secfindings-vrl-")
    try:
        with open(os.path.join(work, "program.vrl"), "w") as fh:
            fh.write(program)
        with open(os.path.join(work, "input.json"), "w") as fh:
            for ev in FIXTURES:
                fh.write(json.dumps(ev) + "\n")
        proc = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{work}:/w:ro", "--entrypoint", "vector",
             VECTOR_IMAGE, "vrl", "--input", "/w/input.json", "--program", "/w/program.vrl"],
            capture_output=True, text=True, timeout=180)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    assert proc.returncode == 0, f"vector vrl failed: {proc.stderr[-2000:]}"
    out = [ln for ln in proc.stdout.splitlines() if ln.startswith("{")]
    assert len(out) == len(FIXTURES), \
        f"expected {len(FIXTURES)} evaluated events, got {len(out)}: {proc.stdout[-2000:]}"
    return [json.loads(ln) for ln in out]


@pytest.mark.skipif(not _docker_available(),
                    reason=f"docker + {VECTOR_IMAGE} required to execute the VRL")
def test_doc_identity_is_deterministic_and_fails_closed():
    """_id = sha2(native_id | scan_id) — the decision's "Doc identity" section.

    Retaining every scan's verdict gives trend/drift; a deterministic id makes a
    redelivery or a #209 bulk retry an UPSERT instead of a duplicated verdict
    (which would inflate every facet count the CTEM funnel is built on). A
    finding that cannot produce one is QUARANTINED — an auto id would silently
    re-insert it on every replay."""
    ev = _run_identity_vrl()

    same_a, same_b, other_scan, no_native, no_scan = ev

    assert same_a["cx_finding_id"] == same_b["cx_finding_id"], \
        "the same (native_id, scan_id) produced two different _ids — replays would duplicate"
    assert re.fullmatch(r"[0-9a-f]{64}", same_a["cx_finding_id"]), \
        "the doc id is not a sha2-256 hex digest"
    assert other_scan["cx_finding_id"] != same_a["cx_finding_id"], \
        "a later scan collapsed onto the earlier verdict's _id — trend/drift would be destroyed"

    # the dotted-key map never survives into the document
    assert "label" not in same_a, "del(.label) did not strip the dotted producer map"

    for name, doc in (("no native_id", no_native), ("no scan_id", no_scan)):
        assert "cx_finding_id" not in doc, \
            f"{name}: an unidentifiable finding was given an id anyway"
        assert doc.get("cx_quarantine") is True, \
            f"{name}: an unidentifiable finding was not quarantined"
        assert doc.get("lane") == "security"
        assert doc.get("reason"), f"{name}: quarantined with no reason recorded (§10)"


def test_identity_requires_both_halves_and_never_invents_one():
    """Static companion to the executed test above, so the property is still
    pinned in an environment with no docker."""
    src = router()["transforms"]["security_identity"]["source"]
    assert "sha2(" in src and 'variant: "SHA-256"' in src
    assert ".native_id" in src and ".attrs.scan_id" in src, \
        "the id must be built from native_id and the scan id the bus envelope carries"
    assert ".cx_quarantine = true" in src, "a finding with no identity must be quarantined"
    assert "uuid_v4" not in src and "random" not in src, \
        "the findings doc id must never be random — a replay would duplicate the verdict"


# ── index template: facets are keyword, narrative is text ──────────────────

FACET_FIELDS = [
    "tenant_seg",       # the §3a per-tenant routing segment the index name carries
    "tenant_id",
    "severity",
    "status",
    "status_id",
    "standards",
    "control_id",
    "evidence_class",
    "source",
    "scan_id",
    "native_id",
    "seam_id",
    "seam_type",
    "kind",
    "entity_id",
    "cx_finding_id",
]

NARRATIVE_FIELDS = ["title", "observed", "intended", "detail", "remediation"]

RESOURCE_FACETS = ["device", "host", "kind", "platform"]


def test_template_exists_and_matches_the_lane_index_pattern():
    tpl = templates()[TEMPLATE]
    assert tpl["index_patterns"] == ["netops-secfindings-*"]
    # the sink's index name must be matched by the template's pattern
    assert INDEX_PATTERN.startswith("netops-secfindings-")


def test_every_facet_field_is_a_keyword():
    """The T8 access patterns are terms aggregations (CTEM funnel, compliance-%
    by framework, severity breakdown). A facet field that lands as `text` is
    analysed and cannot be aggregated on."""
    props = secfindings_props()
    for field in FACET_FIELDS:
        assert field in props, f"the findings template does not declare the facet field {field}"
        assert props[field]["type"] == "keyword", \
            f"{field} is {props[field]['type']}, not keyword — it cannot be faceted"
    resource = props["resource"]["properties"]
    for field in RESOURCE_FACETS:
        assert resource.get(field, {}).get("type") == "keyword", \
            f"resource.{field} is not a keyword facet"


def test_narrative_fields_are_full_text():
    """Full-text narrative search is one of the two reasons OpenSearch won this
    store over ClickHouse — a keyword mapping would make it exact-match only."""
    props = secfindings_props()
    for field in NARRATIVE_FIELDS:
        assert field in props, f"the findings template does not declare the narrative field {field}"
        assert props[field]["type"] == "text", \
            f"{field} is {props[field]['type']}, not text — narrative search would be exact-match only"


def test_time_axis_is_a_date():
    props = secfindings_props()
    for field in ("ts", "time"):
        assert props[field]["type"] == "date", f"{field} must be a date for trend/range queries"
    assert "epoch_millis" in props["ts"]["format"], \
        "the router normalises ts to epoch-millis (DEF-6); the mapping must accept it"


def test_template_closes_the_field_wall_against_dotted_keys():
    """F-05 + the CLAUDE.md dotted-key gotcha: `attrs` and `evidence_refs` are
    producer-shaped objects. With dynamic mapping on, one dotted or novel key
    grows the mapping toward the 1000-field limit — which fails CLOSED, i.e. a
    whole-day blackout for the lane — or conflicts outright and drops docs."""
    mappings = templates()[TEMPLATE]["template"]["mappings"]
    assert mappings["dynamic"] is False
    settings = templates()[TEMPLATE]["template"]["settings"]
    assert settings["mapping"]["total_fields"]["limit"]
    assert settings["mapping"]["ignore_malformed"] is True
    assert settings["number_of_replicas"] == "${OPENSEARCH_REPLICAS}", \
        "F-07: the replica count is a per-install posture, never a hardcoded literal"


def test_template_declares_the_bus_envelope_fields_the_producer_emits():
    """The producer is secbus.FromFinding: the classification rides in `attrs`
    and the pointers in `evidence_refs`. Undeclared, they are stored but not
    searchable — the quiet regression `dynamic: false` trades for safety."""
    props = secfindings_props()
    attrs = props["attrs"]["properties"]
    for field in ("evidence_class", "provider_source", "control_id", "scan_id",
                  "status", "status_id", "standards"):
        assert attrs.get(field, {}).get("type") == "keyword", \
            f"attrs.{field} is not declared as a keyword facet"
    refs = props["evidence_refs"]["properties"]
    for field in ("locator", "kind", "ruleset_version", "digest"):
        assert refs.get(field, {}).get("type") == "keyword", \
            f"evidence_refs.{field} is not declared (§5c by-reference evidence)"


def test_bootstrap_registers_the_template_from_the_json():
    """F-06/F-15/F-53: the applier enumerates index-templates.json rather than
    carrying a hardcoded list — which is how two lanes once stayed 100%
    dynamically mapped while a template sat in the repo looking authoritative.
    Assert the enumeration still holds AND that it reaches this template."""
    script = read("scripts", "bootstrap-opensearch.sh")
    assert "json.load(open('$TEMPLATES'))['templates']" in script, \
        "bootstrap-opensearch.sh no longer enumerates the templates file — a new lane would be skipped"
    assert TEMPLATE in templates(), "the findings template is not in index-templates.json"


def test_findings_retention_is_bounded_by_an_ism_policy():
    """F-53: a lane matching NO ism_template is never deleted — unbounded growth
    on the filesystem whose exhaustion caused the s10 evidence loss."""
    ism = read("deployment", "docker", "opensearch", "apply-ism.sh")
    assert '"netops-secfindings-*"' in ism, \
        "netops-secfindings-* is not covered by the retention policy patterns"
    assert "netops-secfindings-*," in ism or ",netops-secfindings-*" in ism, \
        "netops-secfindings-* is not in the ISM add-patterns list"
    assert "OPENSEARCH_LOG_RETENTION_DAYS" in ism, \
        "the findings lane must ride the same retention env-var family as the other lanes"


# ── authorization: the lane must not be auth-dead ──────────────────────────


def test_router_principal_holds_read_on_the_security_topic():
    """SEC-007: with allow.everyone.if.no.acl.found=false, a topic missing from
    the matrix is a lane that is authorization-dead while every container stays
    "healthy" (the 2026-08-16 incident, 80 minutes)."""
    acls = read("deployment", "docker", "kafka", "apply-acls.sh")
    m = re.search(r'echo "acls: router.*?\ndone', acls, re.S)
    assert m, "apply-acls.sh no longer applies the router's topic loop in one block"
    block = m.group(0)
    assert TOPIC in block, f"the router principal has no READ grant on {TOPIC}"
    assert "--operation Read" in block


def test_router_is_not_granted_write_on_the_security_topic():
    """Least privilege: the router CONSUMES findings. Only the backend's secbus
    producer writes them (through the aggregator's prefixed netops. grant)."""
    acls = read("deployment", "docker", "kafka", "apply-acls.sh")
    assert not re.search(r'--producer\s*\\?\s*\n?\s*--topic %s\b' % re.escape(TOPIC), acls), \
        "the router must not hold a producer grant on the findings topic"


def test_the_topic_is_created_explicitly_on_both_compose_variants():
    """SEC-006.1: auto-create is off, so a topic missing from kafka-init is a
    lane that silently never exists on a fresh install."""
    for compose in ("docker-compose.yml", "compose.tls.yml"):
        text = read("deployment", "docker", compose)
        m = re.search(r"for t in (netops\..*?)\s*;\s*do", text, re.S)
        assert m, f"{compose} no longer enumerates topics in a `for t in ...; do` loop"
        assert TOPIC in m.group(1).split(), \
            f"{compose} kafka-init does not create {TOPIC}"


def test_correlation_topic_set_is_unchanged():
    """The findings lane is a STORAGE consumer. The Python engine grounds the
    same topic independently (T2b, not yet built), so correlation's TOPICS list
    must not have been quietly widened by this change."""
    src = read("src", "correlation", "main.py")
    m = re.search(r"^TOPICS\s*=\s*\[(.*?)\]", src, re.S | re.M)
    assert m, "correlation main.py no longer declares a TOPICS list"
    assert TOPIC not in m.group(1), (
        "netops.security appeared in correlation's TOPICS — the P3-L1 findings lane "
        "is a vector-router → OpenSearch path; the engine's consumer is T2b and lands "
        "with its own ACL grant and its own tests"
    )
