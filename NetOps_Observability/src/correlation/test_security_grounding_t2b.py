# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""T2b — the correlation engine grounds security evidence with ZERO
security-specific code.

The contract under test (SECURITY_OBSERVABILITY_HLD_2026-08-25 "security is a
REMOVABLE module" + SECURITY_BUILD_PLAN T2/T2b): a security lane PUBLISHES a
generic evidence object (entity + seam + timestamp + evidence refs) onto
`netops.security`, and the engine grounds it through a generic intake that
neither imports nor branches on anything security-specific. Everything the
engine knows about the class is one row of DATA in `signals.EVIDENCE_CLASSES`
plus three catalog templates.

What is asserted here, in the order the evidence flows:

  1. envelope -> Signal, field by field, against the EXACT wire shape
     `src/backend/internal/secbus/event.go` emits — and an idempotent
     `signal_id` on redelivery.
  2. registration: kinds, modality, causal layer, coverage classification.
  3. malformed input dead-letters + is counted, exactly like every other lane.
  4. grounding: a verdict co-locates with independently-measured network
     evidence on ONE object; a verdict ALONE never reaches confirmed.
  5. the removable-module proof — no security import anywhere in the engine,
     and dropping the topic makes the whole registration inert.
  6. tenant isolation (§3a): a verdict about tenant A's device can never be
     filed under tenant B.
  7. the V1 byte-identity proof: a security-free stream produces byte-identical
     objects with and without the new templates.
  8. metrics + /healthz exposure.
"""
from __future__ import annotations

import ast
import asyncio
import pathlib
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest

import layers
import main
import signals
from catalog import BUILTIN_TEMPLATES, EXPOSURE_STORY_TEMPLATES, load_catalog
from confirmability import KIND_MODALITY
from coverage import EMITTED_KINDS, classify_kind
from engine import EngineConfig, run_window
from signals import (
    DeadLetter,
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
    evidence_classes_of,
    evidence_signal_from_event,
)
from verdicts import VerdictTier

T0 = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)
NEW_TEMPLATE_IDS = {t["id"] for t in EXPOSURE_STORY_TEMPLATES}
# This suite is about the SECURITY class specifically. Read from the
# registry row so it can never drift from what the engine registered.
SECURITY_KINDS = set(signals.EVIDENCE_CLASSES["security"].kinds)


# ── the exact wire shape secbus.EvidenceEvent marshals ───────────────────────
def envelope(**over) -> dict:
    ev = {
        "schema_version": "1",
        "tenant_id": "acme",
        "ts": "2026-09-02T12:00:00.123456789Z",
        "kind": "security_exposure",
        "entity_id": "edge-r1",
        "entity_type": "device",
        "entity_tokens": ["edge-r1", "device:edge-r1", "host:edge-r1.acme", "seam:seam-7"],
        "severity": "critical",
        "native_id": "security|security_exposure|exposure|CVE-2026-1234|edge-r1|scan-99|f-1",
        "seam_id": "seam-7",
        "seam_type": "DIA",
        "internet_facing": True,
        "evidence_refs": [{"locator": "os://netops-secfindings/f-1", "kind": "advisory",
                           "ruleset_version": "feed-2026-09-01", "digest": "ab12"}],
        "attrs": {
            "evidence_class": "exposure",
            "provider_source": "vuln",
            "control_id": "CVE-2026-1234",
            "raw_rule_id": "vuln.version-match",
            "scan_id": "scan-99",
            "status": "Fail",
            "standards": ["CIS", "STIG"],
            "fidelity": "lab_validated",
        },
    }
    ev.update(over)
    return ev


class FakeCH:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def insert(self, table: str, rows, dedup_token="") -> None:
        for r in rows:
            self.rows.append({"_table": table, **r})


@pytest.fixture
def rig(monkeypatch):
    """A hermetic engine: fake ClickHouse, empty window, a device registry that
    owns `edge-r1` for tenant `acme` and nothing else."""
    ch = FakeCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    monkeypatch.setattr(main, "_tenant_registry", lambda: {"edge-r1": "acme"})
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    return ch


def evidence_rows(ch: FakeCH) -> list[dict]:
    return [r for r in ch.rows
            if r["_table"] == "netops.corr_signals" and r.get("source") == "security"]


def drive(ev: dict) -> None:
    asyncio.run(main.handle_evidence_event(ev))
    asyncio.run(main.SIGNAL_BATCH.flush())


# ══ 1. envelope -> Signal ════════════════════════════════════════════════════
def test_envelope_maps_onto_every_signal_field():
    sig = evidence_signal_from_event(envelope(), "acme")
    assert sig.tenant_id == "acme"
    # RFC3339Nano: the fraction is TRUNCATED to microseconds, never rounded.
    assert sig.ts == datetime(2026, 9, 2, 12, 0, 0, 123456, tzinfo=timezone.utc)
    assert sig.source is Source.SECURITY
    assert sig.kind == "security_exposure"
    assert sig.modality_class is ModalityClass.SECURITY
    assert sig.entity_type is EntityType.DEVICE
    assert sig.entity_id == "edge-r1"
    assert sig.severity is Severity.CRIT              # "critical" alias
    assert sig.native_id.endswith("|f-1")
    assert sig.entity_tokens == ("edge-r1", "device:edge-r1", "host:edge-r1.acme",
                                 "seam:seam-7")
    # the witness is the platform lane, NEVER the device under evaluation —
    # a verdict can therefore never corroborate the device's own telemetry.
    assert sig.observer.observer_id == "security:vuln"
    assert sig.observer.observer_type is ObserverType.PLATFORM
    assert sig.observer.observer_id != sig.entity_id


def test_attrs_carry_class_seam_refs_and_provenance():
    attrs = evidence_signal_from_event(envelope(), "acme").attrs
    assert attrs["evidence_class"] == "security"        # the ENGINE's fourth class
    assert attrs["evidence_subclass"] == "exposure"     # the lane's own, kept not dropped
    assert attrs["seam_id"] == "seam-7" and attrs["seam_type"] == "DIA"
    assert attrs["internet_facing"] is True
    assert attrs["evidence_refs"][0]["locator"] == "os://netops-secfindings/f-1"
    # W1b provenance: the rule that produced the verdict, and an HONEST
    # parser_rev — no parser ran, the record arrived canonical.
    assert attrs["rule_id"] == "vuln.version-match"
    assert attrs["parser_rev"] == "bus"
    assert attrs["fidelity"] == "lab_validated"
    # by-reference only: no raw config/payload is inlined onto the spine.
    assert "detail" not in attrs and "observed" not in attrs


def test_severity_and_entity_type_defaults_are_honest():
    assert evidence_signal_from_event(
        envelope(severity="totally-unknown"), "acme").severity is Severity.WARN
    ev = envelope()
    ev.pop("entity_type")
    assert evidence_signal_from_event(ev, "acme").entity_type is EntityType.DEVICE


def test_signal_id_is_idempotent_on_redelivery():
    a = evidence_signal_from_event(envelope(), "acme")
    b = evidence_signal_from_event(envelope(), "acme")
    assert a.signal_id == b.signal_id
    ts_ms = int(a.ts.timestamp() * 1000)
    assert a.signal_id == uuid.uuid5(
        signals.SIGNAL_NS, f"security|{a.native_id}|{ts_ms}")
    # A NEW scan of the same finding is a NEW signal, not a dedup'd redelivery.
    # Since 2026-09-03 (L-01) the native_id is STABLE per (tenant, device, rule)
    # — the scan id was removed from it so the findings list's native_id
    # collapse can actually supersede — so the discriminator here is the
    # TIMESTAMP, which uuid5 already folds in above. Both halves are asserted:
    # a different native_id is a different signal, AND the same native_id
    # observed at a different instant is a different signal.
    other = envelope()
    other["native_id"] = other["native_id"].replace("|f-1", "|f-2")
    assert evidence_signal_from_event(other, "acme").signal_id != a.signal_id
    later = envelope(ts="2026-09-02T12:05:00.123456789Z")
    assert evidence_signal_from_event(later, "acme").signal_id != a.signal_id


def test_evidence_refs_are_bounded():
    ev = envelope(evidence_refs=[{"locator": f"os://x/{i}"} for i in range(50)])
    refs = evidence_signal_from_event(ev, "acme").attrs["evidence_refs"]
    assert len(refs) == signals.EVIDENCE_REFS_MAX


# ══ 2. registration ═════════════════════════════════════════════════════════
def test_kinds_modality_and_layer_are_registered():
    # The SECURITY class's own vocabulary. Scoped to the class deliberately:
    # the bus registry is shared, and a second class registering its kinds must
    # not make this suite red (it must not make it PASS vacuously either, which
    # is why the row is read from the registry rather than restated).
    assert SECURITY_KINDS == {
        "security_posture", "security_exposure", "security_signal"}
    assert SECURITY_KINDS <= signals.EVIDENCE_BUS_KINDS
    for kind in SECURITY_KINDS:
        assert kind in EMITTED_KINDS
        assert KIND_MODALITY[kind] is ModalityClass.SECURITY
        # consumed by the Exposure Story family -> never a dead template/orphan
        assert classify_kind(kind, load_catalog(BUILTIN_TEMPLATES)) == "fully_connected"
    # a standing property of the device orders ROOT-WARD of the symptoms it
    # could explain; a detection has no fixed layer, so the prior abstains.
    assert layers.layer_of("security_exposure") is layers.CausalLayer.DEVICE
    assert layers.layer_of("security_posture") is layers.CausalLayer.DEVICE
    assert layers.layer_of("security_signal") is None


def test_the_security_modality_is_its_own_plane():
    # It must not collapse into an existing plane, or a verdict would count as
    # corroboration for the lane it collapsed into.
    assert ModalityClass.SECURITY.value == "security"
    assert ModalityClass.SECURITY not in (
        ModalityClass.CONTROL_PLANE, ModalityClass.MANAGEMENT_PLANE,
        ModalityClass.DEVICE_TELEMETRY, ModalityClass.PASSIVE_FLOW,
        ModalityClass.ACTIVE_PROBE, ModalityClass.ACTIVE_VERIFICATION)


# ══ 3. malformed input ══════════════════════════════════════════════════════
@pytest.mark.parametrize("over,why", [
    ({"kind": "definitely_not_a_kind"}, "unknown kind"),
    ({"entity_id": ""}, "no entity"),
    ({"native_id": ""}, "no identity"),
    ({"ts": "not-a-time"}, "unparseable ts"),
    ({"schema_version": "99"}, "unsupported schema"),
    ({"entity_type": "banana"}, "unknown entity type"),
])
def test_malformed_envelope_dead_letters(over, why):
    with pytest.raises(DeadLetter):
        evidence_signal_from_event(envelope(**over), "acme")


def test_handler_counts_and_quarantines_malformed_input(rig):
    dl, dropped = main.DEADLETTER_COUNT, main.EVIDENCE_EVENTS_DROPPED
    invalid = main.EVIDENCE_EVENTS_TOTAL["security|invalid"]
    main.QUARANTINE.clear()
    drive(envelope(entity_id=""))
    assert evidence_rows(rig) == []
    assert not main.WINDOW_BUFFER
    assert main.DEADLETTER_COUNT == dl + 1
    assert main.EVIDENCE_EVENTS_DROPPED == dropped + 1
    assert main.EVIDENCE_EVENTS_TOTAL["security|invalid"] == invalid + 1
    # the payload is KEPT (the same path every other lane's malformed input takes)
    assert any(q.get("topic") == "deadletter:evidence" for q in main.QUARANTINE)


def test_an_unregistered_kind_cannot_widen_the_metric_label_set(rig):
    keys = set(main.EVIDENCE_EVENTS_TOTAL)
    before = main.EVIDENCE_EVENTS_TOTAL["unknown|invalid"]
    drive(envelope(kind="cosmic_ray_detected"))
    assert set(main.EVIDENCE_EVENTS_TOTAL) == keys          # bounded (§9)
    assert main.EVIDENCE_EVENTS_TOTAL["unknown|invalid"] == before + 1


# ══ 4. grounding ════════════════════════════════════════════════════════════
def netsig(kind: str, modality: ModalityClass, entity: str, observer: str,
           *, secs: int = 0, etype: EntityType = EntityType.DEVICE,
           tenant: str = "acme") -> Signal:
    return Signal(
        tenant_id=tenant, ts=T0 + timedelta(seconds=secs), source=Source.SYSLOG,
        kind=kind, observer=Observer(observer_id=observer,
                                     observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=etype, entity_id=entity,
        severity=Severity.HIGH, native_id=f"{observer}|{kind}|{entity}|{secs}",
        entity_tokens=(entity,))


def security_signal(*, entity: str = "edge-r1", tenant: str = "acme",
                    kind: str = "security_exposure", secs: int = 0) -> Signal:
    ev = envelope(kind=kind, entity_id=entity,
                  entity_tokens=[entity, f"device:{entity}"],
                  ts=(T0 + timedelta(seconds=secs)).isoformat())
    return evidence_signal_from_event(ev, tenant)


CAT = load_catalog(BUILTIN_TEMPLATES)


def test_verdict_grounds_with_network_evidence_on_the_same_device():
    window = [security_signal(secs=0),
              netsig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE,
                     "edge-r1", "syslog-edge-r1", secs=30)]
    snaps = run_window(window, CAT, (), EngineConfig())
    assert len(snaps) == 1, "the verdict and the fault must land on ONE object"
    snap = snaps[0]
    kinds = {s.kind for n in snap.nodes for s in n.signals}
    assert {"security_exposure", "bgp_adjacency_change"} <= kinds
    # the projection the backend filters Exposure Stories with
    assert evidence_classes_of(kinds) == ("security",)
    assert "sig.ent.security.exposure-story" in {
        h.template_id for h in snap.ranking.hypotheses}


def test_a_verdict_alone_is_never_confirmed():
    """One plane, one witness — the honest cap. INVARIANTS §10a: prefer still
    analyzing over an unsupported cause."""
    for kind in sorted(SECURITY_KINDS):
        snaps = run_window([security_signal(kind=kind)], CAT, (), EngineConfig())
        for snap in snaps:
            assert snap.ranking.verdict_tier is not VerdictTier.CONFIRMED, kind


def test_two_verdicts_from_the_same_lane_still_cannot_confirm():
    """Independence is about PLANES, not counts: a second verdict on the same
    device is the same modality and the same witness."""
    window = [security_signal(kind="security_exposure", secs=0),
              security_signal(kind="security_posture", secs=10)]
    for snap in run_window(window, CAT, (), EngineConfig()):
        assert snap.ranking.verdict_tier is not VerdictTier.CONFIRMED


NIL_UUID = str(uuid.UUID(int=0))


def test_edge_evidence_joins_back_to_the_security_signals():
    """QA D-01: the Exposure Story LIST joins corr_evidence.signal_id ->
    corr_signals.signal_id and keeps objects whose attached signal kind is in
    the security vocabulary. `_edge_evidence_row` used to hardcode the nil UUID,
    so that join returned nothing and the list could NEVER return a row while
    the detail route (which does not use the predicate) worked.

    This pins the engine half: an all-security object's edge evidence carries a
    real signal id that belongs to one of the edge's endpoint nodes AND resolves
    to a signal of a security kind — i.e. the backend predicate is productive."""
    window = [security_signal(kind="security_exposure", secs=0),
              security_signal(kind="security_posture", secs=10)]
    snaps = run_window(window, CAT, (), EngineConfig())
    assert len(snaps) == 1
    snap = snaps[0]
    assert snap.edges, "the two verdicts must be joined by an edge to have a row"
    # corr_signals, as the engine would have written it: id -> kind
    kind_of = {str(s.signal_id): s.kind for n in snap.nodes for s in n.signals}
    assert set(kind_of.values()) <= SECURITY_KINDS
    rows = [r for r in snap.to_evidence_rows(1) if r["subject_kind"] == "edge"]
    assert len(rows) == len(snap.edges)
    for r in rows:
        assert r["signal_id"] != NIL_UUID, "the D-01 nil UUID is back"
        # the backend predicate, evaluated in Python
        assert kind_of.get(r["signal_id"]) in SECURITY_KINDS
    # ...and the subject_id the backend's SECOND branch reads is still the
    # literal "<from_node>-><to_node>", with node keys ending in ":<kind>".
    for e, r in zip(snap.edges, rows):
        assert r["subject_id"] == f"{e.from_node}->{e.to_node}"
        halves = r["subject_id"].split("->")
        assert any(h.endswith(f":{k}") for h in halves for k in SECURITY_KINDS)


# ══ 5. the removable-module proof ═══════════════════════════════════════════
FORBIDDEN_IMPORT_TOKENS = ("security", "secbus", "secfindings", "vuln",
                           "compliance", "threat", "hardening", "advisory")


def test_the_engine_imports_nothing_named_security():
    """The constraint, mechanically: no engine module may import a module whose
    name names the security domain. Registration is DATA; if it were code, this
    is where the dependency would show up."""
    here = pathlib.Path(__file__).parent
    offenders: list[str] = []
    for path in sorted(here.glob("*.py")):
        if path.name.startswith("test_") or path.name.startswith("bench_"):
            continue
        tree = ast.parse(path.read_text(), str(path))
        names: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.append(node.module)
        for name in names:
            head = name.split(".")[0].lower()
            if any(tok in head for tok in FORBIDDEN_IMPORT_TOKENS):
                offenders.append(f"{path.name}: import {name}")
    assert not offenders, (
        "the correlation engine must not depend on a security module — "
        f"security is a PRODUCER onto the bus, not an import: {offenders}")


def test_dropping_the_topic_makes_the_registration_inert(monkeypatch, rig):
    """The run-time half: `CORR_EVIDENCE_TOPICS=""` unsubscribes the class and
    the engine consumes exactly the lanes it consumed before it existed."""
    assert main.evidence_topics_from_env("") == ()
    # unset = EVERY registered class's topic (today: bgp + security, sorted)
    assert main.evidence_topics_from_env(None) == signals.EVIDENCE_TOPICS
    assert "netops.security" in main.evidence_topics_from_env(None)
    assert main.evidence_topics_from_env("netops.other") == ("netops.other",)
    # with nothing subscribed, the lane dispatch does not reach the handler …
    monkeypatch.setattr(main, "EVIDENCE_TOPIC_SET", frozenset())
    received = main.EVIDENCE_EVENTS_RECEIVED
    asyncio.run(main._handle_lane("netops.security", envelope()))
    assert main.EVIDENCE_EVENTS_RECEIVED == received
    assert evidence_rows(rig) == [] and not main.WINDOW_BUFFER
    # … and the 12 network lanes are exactly the topic list they always were.
    assert len(main.LANE_TOPICS) == 12
    assert all(t in main.TOPICS for t in main.LANE_TOPICS)


def test_the_class_is_one_row_of_data():
    """Adding/removing an evidence class is a registry edit — the handler and
    the adapter name no class at all."""
    spec = signals.EVIDENCE_CLASSES["security"]
    assert spec.topic == "netops.security"
    assert spec.source is Source.SECURITY and spec.modality is ModalityClass.SECURITY
    assert "netops.security" in signals.EVIDENCE_TOPICS
    src = pathlib.Path(main.__file__).read_text()
    body = src.split("async def handle_evidence_event", 1)[1].split(
        "\nasync def ", 1)[0]
    for token in ("security_exposure", "security_posture", "security_signal"):
        assert token not in body, (
            f"handle_evidence_event names {token!r} — the class must be selected "
            f"by registry lookup, never by a branch")


# ══ 6. tenant isolation (§3a) ═══════════════════════════════════════════════
def test_a_contradicted_tenant_claim_is_refused(rig):
    """`edge-r1` belongs to acme. A verdict claiming it for `evil` is refused
    BEFORE anything is persisted — it can never attach to either tenant."""
    dl = main.DEADLETTER_COUNT
    invalid = main.EVIDENCE_EVENTS_TOTAL["security|invalid"]
    drive(envelope(tenant_id="evil"))
    assert evidence_rows(rig) == []
    assert not main.WINDOW_BUFFER
    assert main.DEADLETTER_COUNT == dl + 1
    assert main.EVIDENCE_EVENTS_TOTAL["security|invalid"] == invalid + 1


def test_the_registry_tenant_wins_over_the_claim(rig):
    drive(envelope(tenant_id="acme"))
    rows = evidence_rows(rig)
    assert len(rows) == 1 and rows[0]["tenant_id"] == "acme"
    assert main.EVIDENCE_EVENTS_TOTAL["security|grounded"] >= 1


def test_an_unregistered_subject_is_counted_orphan_not_misattributed(rig):
    """A host/container the device registry has never heard of still grounds
    under its OWN claimed tenant — never another one — and is counted so the
    coverage gap is visible rather than silent."""
    orphans = main.EVIDENCE_EVENTS_TOTAL["security|orphan"]
    drive(envelope(entity_id="app-host-7", tenant_id="other",
                   entity_tokens=["app-host-7"]))
    rows = evidence_rows(rig)
    assert len(rows) == 1 and rows[0]["tenant_id"] == "other"
    assert main.EVIDENCE_EVENTS_TOTAL["security|orphan"] == orphans + 1


def test_a_verdict_never_joins_another_tenants_object():
    """Cross-tenant co-location is impossible even when the entity id matches:
    the window is single-tenant by construction and the engine refuses a mixed
    one, so tenant B's verdict cannot reach tenant A's object."""
    a = netsig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE,
               "edge-r1", "syslog-edge-r1", tenant="acme")
    b = security_signal(entity="edge-r1", tenant="other")
    for snap in run_window([a], CAT, (), EngineConfig()):
        assert snap.tenant_id == "acme"
        assert all(s.tenant_id == "acme" for n in snap.nodes for s in n.signals)
    with pytest.raises(ValueError, match="tenant"):
        run_window([a, b], CAT, (), EngineConfig())


# ══ 7. V1 byte-identity ═════════════════════════════════════════════════════
BASE_CAT = load_catalog([t for t in BUILTIN_TEMPLATES
                         if t["id"] not in NEW_TEMPLATE_IDS])


def v1_shaped_window() -> list[Signal]:
    """A security-FREE stream in the shape the V1 storm workload produces:
    control-plane transitions plus device telemetry across several devices."""
    out: list[Signal] = []
    for i in range(4):
        dev = f"leaf{i}"
        out.append(netsig("link_state_change", ModalityClass.CONTROL_PLANE,
                          f"{dev}:Gi0/1", f"syslog-{dev}", secs=i,
                          etype=EntityType.INTERFACE))
        out.append(netsig("if_metric_anomaly", ModalityClass.DEVICE_TELEMETRY,
                          f"{dev}:Gi0/1", f"snmp-{dev}", secs=i + 5,
                          etype=EntityType.INTERFACE))
        out.append(netsig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE,
                          dev, f"syslog-{dev}", secs=i + 10))
    return out


CATALOG_VERSION_RE = re.compile(r'"catalog_version": ?"cat-[0-9a-f]+"')


def _blind_catalog_version(text: str) -> str:
    """Erase the rule-base revision stamp so the DECISION content can be
    compared byte-for-byte. It is the one value that MUST move when the catalog
    changes — it is the replay pin's record of WHICH rule base scored the
    object — and it is a stamp, not an input: it cannot alter a verdict, a
    hypothesis, an edge or an object's identity."""
    return CATALOG_VERSION_RE.sub('"catalog_version": "<pinned>"', text)


def test_v1_stream_is_byte_identical_with_and_without_the_templates():
    """The accuracy guard. The security kind is the REQUIRED clause of every new
    template, so a stream carrying none can never match one — and the object's
    whole decision content (nodes, signals, edges, every hypothesis, the verdict,
    affected, layer coverage) is byte-for-byte what it was.

    Asserted as a set difference, not a spot check: the ONLY field allowed to
    differ anywhere in the object row is `catalog_version`."""
    window = v1_shaped_window()
    with_new = run_window(window, CAT, (), EngineConfig())
    without = run_window(window, BASE_CAT, (), EngineConfig())
    assert with_new and len(with_new) == len(without)
    for new, old in zip(with_new, without):
        a, b = new.to_object_row(version=1), old.to_object_row(version=1)
        assert set(a) == set(b)
        differing = {k for k in a if a[k] != b[k]}
        assert differing == {"hypotheses", "catalog_version"}, differing
        assert a["catalog_version"] != b["catalog_version"]
        # …and inside the hypotheses blob the difference is that same stamp.
        assert _blind_catalog_version(a["hypotheses"]) == _blind_catalog_version(
            b["hypotheses"])
        assert new.to_edge_rows(version=1) == old.to_edge_rows(version=1)
        assert new.to_evidence_rows(version=1) == old.to_evidence_rows(version=1)
        assert new.correlation_id == old.correlation_id
        assert new.ranking.verdict_tier is old.ranking.verdict_tier
        assert new.ranking.top_hypothesis == old.ranking.top_hypothesis


def test_no_new_template_can_match_without_an_evidence_class_signal():
    """Stated directly rather than only observed: every Exposure Story template
    REQUIRES an evidence-class kind, so it is inapplicable to a stream without
    one. The inverse shape would have made them fire on every V1 object."""
    for template in EXPOSURE_STORY_TEMPLATES:
        required = [c for c in template["requires"] if not c.get("optional")]
        assert len(required) == 1
        assert required[0]["kind"] in signals.EVIDENCE_BUS_KINDS


# ══ 8. observability ════════════════════════════════════════════════════════
def test_counters_reach_healthz_and_metrics(rig):
    drive(envelope())
    health = main._health_payload()
    ingest = health["ingest"]
    assert "netops.security" in ingest["evidence_topics"]
    assert ingest["evidence_topics"] == list(main.CORR_EVIDENCE_TOPICS)
    assert ingest["evidence_received"] >= 1 and ingest["evidence_signals"] >= 1
    # One pre-seeded key per REGISTERED class x outcome, plus the fixed
    # "unknown" bucket — bounded by the registry, never by traffic (§9).
    assert set(ingest["evidence_by_class"]) == {
        f"{cls}|{outcome}"
        for cls in list(signals.EVIDENCE_CLASSES) + ["unknown"]
        for outcome in main.EVIDENCE_EVENT_OUTCOMES}
    text = main._metrics_text(health)
    for outcome in main.EVIDENCE_EVENT_OUTCOMES:
        assert (f'corr_evidence_events_total{{class="security",'
                f'outcome="{outcome}"}}') in text
    # distinct from the Evidence PLANE's queue metric of a similar name
    assert "corr_evidence_queue_depth" in text
