"""A9b — `device_config_change`: the symptom the trap audit found INVISIBLE.

A9 closed with a recorded finding: config-change notifications hint `notice` in
the MIB index, which is BELOW `producers.ALARM_SEVERITY_FLOOR`, so a device
being reconfigured never reached the engine — not as a typed symptom, not even
as the generic `device_alarm` safety net. The syslog side was invisible for the
mirror-image reason: `%SYS-5-CONFIG_I` is severity notice, so it fell through
every typed rule and then below the same floor.

That mattered because "what changed?" is the first question of every real RCA
and the only evidence that can DATE a hardening drift (a failed posture control
is a standing property with no onset).

WHAT THIS FILE PINS, in the order the change had to happen:

  1. THE ADMISSION GATE — the vendored MIB index seeds the config-change AND the
     hardware/environment notifications at `warning`, so they clear the alarm
     floor. Pinned against the checked-in index AND end-to-end through the trap
     producer, because an index value nothing reads is not a fix.
  2. THE SYMPTOM — per-vendor syslog and trap fixtures classify to
     `device_config_change` with the same entity, state and grounding tokens;
     the near misses (a config ERROR, a reload request, a login) do not.
  3. IDENTITY — content-bearing and idempotent under redelivery (tracker 198),
     and the grounding token set is the DEVICE only: `user` must never be a
     global token or every box `admin` ever touched welds into one object.
  4. THE KIND IS NOT INERT — it is registered (EMITTED_KINDS, KIND_MODALITY, the
     causal layer) and CONSUMED, as an OPTIONAL clause, by five templates.
  5. IT CHANGES NOTHING ELSE — a V1 stream that carries no config change scores
     byte-identically with and without the new clauses, `catalog_version` apart,
     and the tracker-157 structural gate is untouched.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
from datetime import datetime, timedelta, timezone

import pytest

import producers as P
from catalog import BUILTIN_TEMPLATES, builtin_catalog, load_catalog
from confirmability import KIND_MODALITY
from coverage import EMITTED_KINDS, INTENTIONAL_BLIND, consumed_kinds
from engine import EngineConfig, run_window
from layers import CausalLayer, layer_of
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG_DIR = os.path.abspath(os.path.join(HERE, "..", "..", "telemetry-catalog"))
FIXTURES = os.path.join(CATALOG_DIR, "fixtures", "config_change_events.jsonl")
MIB_INDEX = os.path.abspath(os.path.join(
    HERE, "..", "backend", "collectors", "mibs", "index", "oididx.json"))

T0 = datetime(2026, 9, 2, 10, 0, 0, tzinfo=timezone.utc)
KIND = "device_config_change"

#: The templates that gained the optional clause. A kind no template names is
#: inert evidence — that is the reason A9 did not promote this symptom, so the
#: list is stated here and asserted, not left to be observed.
CONSUMING_TEMPLATES = frozenset({
    "sig.ent.wan-edge.bgp-peer-flap",
    "sig.ent.access.ospf-adjacency-flap",
    "sig.ent.fabric.isis-adjacency-flap",
    "sig.ent.wan-edge.controller-change-induced",
    "sig.ent.security.hardening-drift-story",
})


def _fixtures() -> list[dict]:
    with open(FIXTURES, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


ROWS = _fixtures()
POSITIVE = [r for r in ROWS if "NEAR-MISS" not in r["_case"]]
NEAR_MISS = [r for r in ROWS if "NEAR-MISS" in r["_case"]]


@contextlib.contextmanager
def promoted():
    """Run the SHADOW syslog row as if `shadow: false`.

    `syslog.config.change` ships shadow — evaluated, COUNTED, emits nothing —
    for a WORKLOAD reason, not a parser one: `%SYS-5-CONFIG_I` is 35 of the 100
    noise slots of the ratified V1 profile (`scripts/scale-miniladder.py
    EVENT_MIX_NOISE`), declared there as a line that never classifies, so
    emitting would re-classify a third of the V1 background and silently
    re-baseline every CORRELIX_REFERENCE_CAPACITY_V1 number. Promotion is the
    one-line `shadow: false` once that profile is versioned — and this context
    manager is how the grammar is PROVEN before that day rather than after it.
    """
    from dataclasses import replace
    rules = tuple(replace(r, shadow=False) if r.shadow else r
                  for r in P._SYSLOG_RULES)
    before = P._SYSLOG_PLAN
    P._SYSLOG_PLAN = P._plan(rules)
    try:
        yield
    finally:
        P._SYSLOG_PLAN = before


def classify(fx: dict):
    if fx["_lane"] == "trap":
        return P.trap_control_signal(dict(fx["trap"]), "t1", T0)
    if fx.get("_shadow"):
        with promoted():
            return P.syslog_control_signal(dict(fx["syslog"]), "t1", T0)
    return P.syslog_control_signal(dict(fx["syslog"]), "t1", T0)


# ══ 1. the admission gate: the severity seed ═════════════════════════════════

#: (notification, the hint it MUST now carry, why). Every one of these was
#: `notice` or unhinted before A9b, i.e. below `ALARM_SEVERITY_FLOOR`.
SEEDED: tuple[tuple[str, str, str], ...] = (
    ("ciscoConfigManEvent", "warning", "config change (was notice)"),
    ("entConfigChange", "warning", "config change (was notice)"),
    ("ccmCLIRunningConfigChanged", "warning", "config change (was unhinted)"),
    ("jnxCmCfgChange", "warning", "config change (was unhinted)"),
    ("ciscoEnvMonFanNotification", "warning", "environment: fan"),
    ("ciscoEnvMonTemperatureNotification", "warning", "environment: temperature"),
    ("cefcPowerStatusChange", "warning", "hardware: PSU"),
    ("cefcFanTrayStatusChange", "warning", "hardware: fan tray"),
    ("entStateOperDisabled", "warning", "hardware: entity out of service"),
    ("aristaEntSensorAlarm", "warning", "environment: sensor threshold"),
    ("jnxFanFailure", "warning", "hardware: fan"),
    ("jnxPowerSupplyFailure", "warning", "hardware: PSU"),
    ("tmnxEqFanFailure", "warning", "hardware: fan"),
    # …and the recovery twins stay BELOW the floor, exactly like linkUp: a
    # clear is not a fault and must never open an RCA object.
    ("cefcFRUInserted", "info", "hardware recovery/inventory"),
    ("jnxFanOK", "info", "hardware recovery"),
    ("entStateOperEnabled", "info", "hardware recovery"),
)


@pytest.fixture(scope="module")
def mib_nodes() -> dict:
    with open(MIB_INDEX, encoding="utf-8") as fh:
        return json.load(fh)["nodes"]


@pytest.mark.parametrize("name,hint,why", SEEDED, ids=[s[0] for s in SEEDED])
def test_the_vendored_index_seeds_the_notification_at_the_hint_it_needs(
        name, hint, why, mib_nodes):
    """THE FIX ITSELF, pinned on the checked-in artifact the Go receiver embeds.
    `trapMeta` (collectors/snmptrap.go) defaults an unhinted notification to
    `notice`, and notice (5) > ALARM_SEVERITY_FLOOR (4), so a missing hint is
    silent invisibility rather than a visible error."""
    hits = [n for n in mib_nodes.values()
            if n.get("name") == name and n.get("kind") == "notification"]
    assert hits, f"{name} ({why}) is not a notification in the vendored index"
    for node in hits:
        assert node.get("severity_hint") == hint, (
            f"{name} ({why}) hints {node.get('severity_hint')!r}, want {hint!r} — "
            "regenerate with `make mib-index` after editing gen_index.py "
            "SEVERITY_HINT")


@pytest.mark.parametrize("name,hint,_why", [s for s in SEEDED if s[1] == "warning"],
                         ids=[s[0] for s in SEEDED if s[1] == "warning"])
def test_a_seeded_notification_clears_the_alarm_floor(name, hint, _why):
    """The hint is only worth what the ENGINE does with it: `warning` (4) must
    be `<= ALARM_SEVERITY_FLOOR`, which is what the generic net's gate tests."""
    assert P._SEVERITY_NUM[hint] <= P.ALARM_SEVERITY_FLOOR
    assert P._SEVERITY_NUM["notice"] > P.ALARM_SEVERITY_FLOOR, (
        "the floor moved — this whole finding was about notice being below it")


def test_a_hardware_trap_now_reaches_the_engine_as_a_generic_alarm():
    """END TO END on the trap path, for a family with NO typed kind to be
    promoted to. At `notice` this produced no signal at all; at the seeded
    `warning` it becomes the generic `device_alarm` — searchable, groundable and
    able to corroborate, which is the entire point of the seed."""
    ev = {"_signal": "snmptrap", "timestamp": "2026-09-02T10:00:00.000Z",
          "device": "leaf1", "authenticated": False, "varbinds": [],
          "trap_oid": "1.3.6.1.4.1.9.9.13.3.0.4",
          "trap_name": "ciscoEnvMonFanNotification",
          "event_type": "cisco_env_mon_fan_notification", "severity": "warning"}
    sig = P.trap_control_signal(dict(ev), "t1", T0)
    assert sig is not None and sig.kind == "device_alarm"
    assert sig.attrs["rule_id"] == "trap.generic.device_alarm"
    # …and the SAME trap at the old `notice` hint is still nothing, which is the
    # before-picture this test exists to contrast with.
    assert P.trap_control_signal({**ev, "severity": "notice"}, "t1", T0) is None


def test_the_shadow_row_widens_neither_screen():
    """THE INGEST-SCREEN CONTRACT for a shadow row (A9b).

    `syslog_promotable` is a NECESSARY condition for promotion and its generated
    VRL twin runs in the AGGREGATOR, so every literal in it admits more raw
    syslog into both producers across the whole estate. A row that emits nothing
    must not buy that: it is observed only on lines the screen already admits
    for some other rule, and measuring the shapes the screen REJECTS is the
    parser-coverage mining path (`parsercov`), off the bus, off the hot path.

    Stated in the rejecting direction, and against the DERIVED marker set, so
    the exclusion is a contract rather than an accident of ordering."""
    rule = P.RULES_BY_ID["syslog.config.change"]
    assert rule.shadow and rule.markers
    assert not set(rule.markers) & set(P._CP_GUARD_MARKERS)
    assert not {m.lower() for m in rule.markers} & set(P._SYSLOG_SCREEN_LITERALS or ())
    for fx in POSITIVE:
        if fx["_lane"] == "syslog":
            assert not P.syslog_promotable(dict(fx["syslog"])), fx["_case"]


def test_the_shadow_row_is_counted_and_emits_nothing():
    """A8, on the first row to use it. The hit is what makes the shadow useful:
    it is exported as `corr_parser_shadow_hits_total{rule_id}`, so the grammar's
    real-traffic rate is measured before it is allowed to produce evidence."""
    for fx in POSITIVE:
        if fx["_lane"] != "syslog":
            continue
        before = P.SHADOW_HITS["syslog.config.change"]
        assert P.syslog_control_signal(dict(fx["syslog"]), "t1", T0) is None, fx["_case"]
        assert P.SHADOW_HITS["syslog.config.change"] == before + 1, fx["_case"]


# ══ 2. the symptom, per vendor ═══════════════════════════════════════════════


@pytest.mark.parametrize("fx", ROWS, ids=lambda f: f["_case"])
def test_the_fixture_classifies_exactly_as_declared(fx):
    sig = classify(fx)
    want = fx["_expect"]
    if want.get("kind") is None:
        assert sig is None, f"{fx['_case']}: expected NO signal, got {sig}"
        return
    assert sig is not None, f"{fx['_case']}: produced no signal at all"
    assert sig.attrs["rule_id"] == want["rule_id"]
    assert sig.kind == want["kind"]
    assert sig.entity_type.value == want["entity_type"]
    assert sig.entity_id == want["entity_id"]
    assert sig.severity.value == want["severity"]
    for key in ("state", "user", "source", "line", "method", "destination"):
        if key in want:
            assert sig.attrs.get(key) == want[key], key
    if "native_id" in want:
        ts_ms = str(int(T0.timestamp() * 1000))
        assert sig.native_id == want["native_id"].replace("{ts_ms}", ts_ms)
    if "tokens" in want:
        assert list(sig.entity_tokens) == want["tokens"]


def test_every_declared_vendor_has_a_fixture_that_reaches_the_rule():
    """`vendors` is an audit claim on the coverage matrix; a vendor with no
    fixture is a claim nothing checks."""
    seen: dict[str, set[str]] = {}
    for fx in POSITIVE:
        sig = classify(fx)
        seen.setdefault(sig.attrs["rule_id"], set()).add(fx["_vendor"])
    assert set(seen) == {"syslog.config.change", "trap.config.change"}
    for rid, vendors in seen.items():
        declared = set(P.RULES_BY_ID[rid].vendors)
        assert vendors <= declared, f"{rid}: fixtures exercise undeclared {vendors - declared}"
        assert vendors, rid
    assert {"cisco", "arista", "juniper"} <= seen["syslog.config.change"]
    assert {"cisco", "juniper", "standard", "nokia"} <= seen["trap.config.change"]


def test_the_near_misses_are_not_claimed_as_config_changes():
    """A guard is worth only what it REFUSES. A config ERROR trap, a reload
    request and a login all carry config/user/source words and must not be filed
    as somebody editing the box."""
    assert len(NEAR_MISS) >= 4
    for fx in NEAR_MISS:
        sig = classify(fx)
        assert sig is None or sig.kind != KIND, fx["_case"]


# ══ 3. identity (tracker 198) and grounding (tracker 168) ════════════════════


@pytest.mark.parametrize("fx", ROWS, ids=lambda f: f["_case"])
def test_redelivery_is_idempotent(fx):
    a, b = classify(fx), classify(fx)
    if a is None:
        assert b is None
        return
    assert a.signal_id == b.signal_id and a.native_id == b.native_id


def test_the_identity_is_content_bearing():
    """A TYPED rule must not lean on the generic content hash: its extracted
    fields ARE the content, so the id has to MOVE when the content moves."""
    def sig(message):
        with promoted():      # the syslog half is shadow today; see `promoted`
            return P.syslog_control_signal(
                {"hostname": "leaf1", "appname": "%SYS-5-CONFIG_I",
                 "severity": "notice", "timestamp": "2026-09-02T10:00:00.000Z",
                 "message": message}, "t1", T0)

    base = sig("Configured from console by admin on vty0")
    assert base.attrs.get("content_tag") is None
    for msg in ("Configured from console by intruder on vty0",   # who
                "Configured from vty1 by admin on vty0",         # where from
                "Configured from console by admin on vty9"):     # which session
        other = sig(msg)
        assert other.native_id != base.native_id, msg
        assert other.signal_id != base.signal_id, msg


def test_the_user_is_an_attribute_and_never_a_grounding_token():
    """THE TOKEN RULE. A grounding token is an INFRASTRUCTURE identity — a
    device, an interface, an address. A username is not: `admin` touches every
    box in the estate, so tokening it would weld the whole fleet into one
    correlation object (tracker 168's failure mode, at estate scale)."""
    for fx in POSITIVE:
        sig = classify(fx)
        assert list(sig.entity_tokens) == [sig.entity_id]
        user = sig.attrs.get("user")
        if user:
            assert user not in sig.entity_tokens
            assert all(user not in t for t in sig.entity_tokens)


# ══ 4. one symptom, two observers ════════════════════════════════════════════


@pytest.mark.parametrize(
    "fx", [r for r in ROWS if r.get("_syslog_counterpart")],
    ids=lambda f: f["_case"])
def test_the_trap_and_the_syslog_line_are_one_symptom(fx):
    """The A9 contract, applied to the new pair: same kind, same entity shape,
    same state vocabulary, same modality. ONLY the observer differs — and a trap
    is still the device talking about itself, so it corroborates and can never
    be the independent second plane."""
    t = P.trap_control_signal(dict(fx["trap"]), "t1", T0)
    with promoted():          # the syslog half is shadow today; see `promoted`
        s = P.syslog_control_signal(dict(fx["_syslog_counterpart"]), "t1", T0)
    assert t is not None and s is not None
    assert t.kind == s.kind == KIND
    assert t.entity_type is s.entity_type is EntityType.DEVICE
    assert t.entity_id == s.entity_id
    assert t.attrs["state"] == s.attrs["state"] == "changed"
    assert t.modality_class is s.modality_class is ModalityClass.CONTROL_PLANE
    assert t.source is Source.TRAP and s.source is Source.SYSLOG
    assert t.native_id != s.native_id, (
        "two observers of one change are two observations — they must not "
        "collapse onto one identity")


# ══ 5. the kind is registered and CONSUMED ═══════════════════════════════════


def test_only_the_trap_observer_emits_the_kind_today():
    """The A9b shipping decision, stated once: the kind is real and consumed,
    and exactly one of its two observers is allowed to speak until the V1
    workload profile is versioned."""
    emitting = sorted(r.rule_id for r in P.RULES if r.kind == KIND and not r.shadow)
    shadowed = sorted(r.rule_id for r in P.RULES if r.kind == KIND and r.shadow)
    assert emitting == ["trap.config.change"]
    assert shadowed == ["syslog.config.change"]


def test_the_kind_is_registered_everywhere_a_kind_must_be():
    assert KIND in EMITTED_KINDS
    assert KIND in {r.kind for r in P.RULES}
    assert KIND_MODALITY[KIND] is ModalityClass.CONTROL_PLANE
    assert layer_of(KIND) is CausalLayer.DEVICE
    assert KIND not in INTENTIONAL_BLIND, (
        "a config change is consumed by real templates — it is not a declared "
        "blind spot")


def test_the_kind_is_not_inert():
    """A9's stated reason for NOT promoting this symptom: a kind no signature
    names is evidence that grounds, stores and confirms nothing. This is the
    test that closes it."""
    cat = builtin_catalog()
    assert KIND in consumed_kinds(cat)
    naming = {t.id for t in cat.enabled_templates()
              if any(KIND in c.kinds() for c in t.requires)}
    assert naming == CONSUMING_TEMPLATES, naming ^ CONSUMING_TEMPLATES


def test_every_consuming_clause_is_optional():
    """It must never be REQUIRED. A config change is context, not a fault: made
    required it would suppress every one of these families on the (overwhelming)
    majority of objects where nobody touched the box."""
    for t in builtin_catalog().enabled_templates():
        for clause in t.requires:
            if KIND in clause.kinds():
                assert clause.optional, f"{t.id}: {KIND} must be optional"


def test_the_config_change_clause_never_supplies_a_second_modality():
    """The honest reading of "the config changed and then it broke". The clause
    is CONTROL_PLANE — the same plane as the transition it corroborates — so it
    can raise coverage and can never promote a verdict to confirmed on its own.
    """
    for tid in CONSUMING_TEMPLATES:
        t = builtin_catalog().get(tid)
        others = {k for c in t.requires for k in c.kinds() if k != KIND}
        planes = {KIND_MODALITY[k] for k in others if k in KIND_MODALITY}
        assert KIND_MODALITY[KIND] in planes or not planes, (
            f"{tid}: the config-change clause introduces a plane no other "
            "clause has — check that is intended")


def test_the_tracker_157_structural_gate_is_untouched():
    """The optional clause names no topology ROLE, so `requires_structure` stays
    empty on every template it was added to and the structural gate remains a
    dict lookup that cannot fire."""
    for tid in CONSUMING_TEMPLATES:
        assert not builtin_catalog().get(tid).requires_structure


# ══ 6. it changes nothing else ═══════════════════════════════════════════════


def _without_the_clause() -> list[dict]:
    """The BUILTIN template list with the new optional clause removed — the
    pre-A9b catalog, rebuilt rather than remembered."""
    out = []
    for raw in BUILTIN_TEMPLATES:
        t = dict(raw)
        if t["id"] in CONSUMING_TEMPLATES:
            t["requires"] = [c for c in t["requires"] if c.get("kind") != KIND]
        out.append(t)
    return out


CAT = builtin_catalog()
BASE_CAT = load_catalog(_without_the_clause())
CATALOG_VERSION_RE = re.compile(r'"catalog_version": ?"cat-[0-9a-f]+"')


def _netsig(kind, modality, entity_id, observer_id, *, secs=0,
            etype=EntityType.DEVICE, sev=Severity.HIGH):
    return Signal(
        tenant_id="acme", ts=T0 + timedelta(seconds=secs), source=Source.SYSLOG,
        kind=kind, observer=Observer(observer_id=observer_id,
                                     observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=etype, entity_id=entity_id,
        severity=sev, native_id=f"fx|{kind}|{entity_id}|{secs}",
        entity_tokens=(entity_id.split(":")[0],), attrs={})


def _v1_window() -> list[Signal]:
    """A config-change-FREE stream in the shape the V1 storm workload produces."""
    out: list[Signal] = []
    for i in range(4):
        dev = f"leaf{i}"
        out.append(_netsig("link_state_change", ModalityClass.CONTROL_PLANE,
                           f"{dev}:Gi0/1", f"syslog-{dev}", secs=i,
                           etype=EntityType.INTERFACE))
        out.append(_netsig("if_metric_anomaly", ModalityClass.DEVICE_TELEMETRY,
                           f"{dev}:Gi0/1", f"snmp-{dev}", secs=i + 5,
                           etype=EntityType.INTERFACE))
        out.append(_netsig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE,
                           dev, f"syslog-{dev}", secs=i + 10))
    return out


def test_v1_stream_is_byte_identical_with_and_without_the_optional_clause():
    """THE ACCURACY GUARD, and the justification for re-freezing FIXTURE_GOLDEN.

    An optional clause that matches nothing contributes no coverage and no bonus
    (`scoring.score_template` divides by the REQUIRED clauses only), so a stream
    with no config change must decide EXACTLY as before. Asserted as a set
    difference, not a spot check: the only field allowed to differ anywhere in
    the object row is `catalog_version`, which is the rule-base revision stamp
    and MUST move when the rule base does."""
    window = _v1_window()
    new = run_window(window, CAT, (), EngineConfig())
    old = run_window(window, BASE_CAT, (), EngineConfig())
    assert new and len(new) == len(old)
    for a_snap, b_snap in zip(new, old):
        a, b = a_snap.to_object_row(version=1), b_snap.to_object_row(version=1)
        assert set(a) == set(b)
        differing = {k for k in a if a[k] != b[k]}
        assert differing <= {"hypotheses", "catalog_version"}, differing
        assert CATALOG_VERSION_RE.sub('"catalog_version": "<pinned>"', a["hypotheses"]) \
            == CATALOG_VERSION_RE.sub('"catalog_version": "<pinned>"', b["hypotheses"])
        assert a_snap.to_edge_rows(version=1) == b_snap.to_edge_rows(version=1)
        assert a_snap.correlation_id == b_snap.correlation_id
        assert a_snap.ranking.verdict_tier is b_snap.ranking.verdict_tier
        assert a_snap.ranking.top_hypothesis == b_snap.ranking.top_hypothesis


def test_a_lone_config_change_opens_no_rca_object():
    """VOLUME SAFETY, stated as behaviour. A config change is emitted at `info`,
    below `EngineConfig.severity_open_floor` (`high`), so a fleet-wide
    reconfiguration cannot manufacture RCA objects — it can only join an object
    a real fault already opened. This is what makes a high-rate symptom safe to
    admit."""
    with promoted():          # the syslog half is shadow today; see `promoted`
        sig = P.syslog_control_signal(
            {"hostname": "leaf1", "appname": "%SYS-5-CONFIG_I",
             "severity": "notice", "timestamp": "2026-09-02T10:00:00.000Z",
             "message": "Configured from console by admin on vty0"}, "t1", T0)
    assert sig.severity is Severity.INFO
    assert EngineConfig().severity_open_floor == "high"
    lone = _netsig(KIND, ModalityClass.CONTROL_PLANE, "leaf1", "syslog-leaf1",
                   sev=Severity.INFO)
    assert run_window([lone], CAT, (), EngineConfig()) == []


def test_a_config_change_joins_an_object_a_real_fault_opened():
    """…and the other half: on a device that IS failing, the change lands on the
    same object and raises the family's coverage. That is the whole product
    claim — "possibly because of the change 90 seconds earlier"."""
    window = [
        _netsig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE,
                "leaf1", "syslog-leaf1", secs=90),
        _netsig("if_metric_anomaly", ModalityClass.DEVICE_TELEMETRY,
                "leaf1:Gi0/1", "snmp-leaf1", secs=95, etype=EntityType.INTERFACE),
        _netsig(KIND, ModalityClass.CONTROL_PLANE, "leaf1", "syslog-leaf1",
                secs=0, sev=Severity.INFO),
    ]
    snaps = run_window(window, CAT, (), EngineConfig())
    assert snaps, "the fault should still open an object"
    kinds = {s.kind for snap in snaps for n in snap.nodes for s in n.signals}
    assert KIND in kinds, "the config change did not reach the object at all"
    hyps = [h for snap in snaps for h in snap.ranking.hypotheses
            if h.template_id == "sig.ent.wan-edge.bgp-peer-flap"]
    assert hyps and KIND in set(hyps[0].satisfied), (
        "the optional clause matched no signal on an object that carries one")
