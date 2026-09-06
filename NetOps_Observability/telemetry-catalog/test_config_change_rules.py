# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Pytest: the A9b config-change rows, replayed through the REAL producers.

A9 audited the trap lane and recorded one finding it deliberately did NOT act
on: a config change is invisible, not merely untyped. `ciscoConfigManEvent` and
`entConfigChange` were seeded `notice` in `gen_index.py SEVERITY_HINT` — below
`producers.ALARM_SEVERITY_FLOOR` — so they were not even generic `device_alarm`s,
and the syslog half (`%SYS-5-CONFIG_I`, severity notice) fell the same way. A9
would not open the gap because typing it needs a KIND, and a kind no signature
template names is inert evidence.

A9b closes it on both counts, and this file is the catalog's half of the proof
(so a catalog edit is red HERE before it is red in the engine's suite):

  1. every fixture — per vendor, both observers — classifies to the rule, kind,
     entity, state, severity, native_id and tokens its `_expect` declares;
  2. the NEAR MISSES do not: a config ERROR trap, a reload request and a login
     all carry config/user/source words and must stay unclaimed;
  3. identity is CONTENT-BEARING and idempotent under redelivery (tracker 198);
  4. the rows' catalog claims are honest — `fidelity_status` is on the ladder,
     every declared vendor has a fixture, and every OID a guard or an extraction
     names RESOLVES in the vendored MIB index (the A9 anti-fabrication rule);
  5. the kind is NOT inert: it is in `producers.EMITTED_KINDS` and it is named
     by real signature templates.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import sys
from datetime import datetime, timezone

import pytest

import bake_rules as B

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.abspath(os.path.join(HERE, "..", "src", "correlation"))
MIB_INDEX = os.path.abspath(os.path.join(
    HERE, "..", "src", "backend", "collectors", "mibs", "index", "oididx.json"))
sys.path.insert(0, ENGINE)

P = pytest.importorskip("producers")

T0 = datetime(2026, 9, 2, 10, 0, 0, tzinfo=timezone.utc)
TS_MS = int(T0.timestamp() * 1000)

KIND = "device_config_change"
#: One symptom, two observers — the A9 contract, applied to the new pair.
A9B_RULE_IDS = ("syslog.config.change", "trap.config.change")


def _fixtures() -> list[dict]:
    path = os.path.join(HERE, "fixtures", "config_change_events.jsonl")
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


FIXTURES = _fixtures()
POSITIVE = [f for f in FIXTURES if "NEAR-MISS" not in f["_case"]]


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    return B.load()[1]


@pytest.fixture(scope="module")
def a9b_rows(rows) -> dict[str, dict]:
    return {r["rule_id"]: r for r in rows if r["rule_id"] in A9B_RULE_IDS}


#: Asks the ENGINE, in its own interpreter, which templates name a kind.
#:
#: NOT an import: `telemetry-catalog/` has a `catalog.py` of its own (the metric
#: catalog) and pytest puts the rootdir first on `sys.path`, so a plain
#: `import catalog` here resolves to the wrong module — and a wrong module that
#: happens to import is how a test goes quietly vacuous. Loading the engine's by
#: path is no better (its pydantic models resolve forward refs through the
#: module name). A subprocess rooted in the engine directory asks the real
#: question with no ambiguity and no cross-test contamination.
_CONSUMERS_PROBE = f"""
import json
from catalog import builtin_catalog
print(json.dumps(sorted(
    (t.id, all(c.optional for c in t.requires if {KIND!r} in c.kinds()))
    for t in builtin_catalog().enabled_templates()
    if any({KIND!r} in c.kinds() for c in t.requires))))
"""


def _templates_naming_the_kind() -> list[tuple[str, bool]]:
    import subprocess
    out = subprocess.run([sys.executable, "-c", _CONSUMERS_PROBE], cwd=ENGINE,
                         capture_output=True, text=True, timeout=120, check=False)
    assert out.returncode == 0, f"engine catalog probe failed: {out.stderr[-2000:]}"
    return [tuple(row) for row in json.loads(out.stdout)]


@contextlib.contextmanager
def promoted():
    """Run the SHADOW row as if `shadow: false` — the one-line flip it is
    waiting on — so its GRAMMAR is proven NOW and not on the day the V1
    workload profile is versioned. An unproven grammar sitting in shadow is how
    a promotion becomes a leap of faith.

    The shipped behaviour (emits nothing, counts a hit) is asserted separately,
    against the unmodified plan."""
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
    """The fixture through its real producer. A shadow fixture is classified
    under `promoted()`, because as shipped it produces nothing to compare."""
    if fx["_lane"] == "trap":
        return P.trap_control_signal(dict(fx["trap"]), "t1", T0)
    if fx.get("_shadow"):
        with promoted():
            return P.syslog_control_signal(dict(fx["syslog"]), "t1", T0)
    return P.syslog_control_signal(dict(fx["syslog"]), "t1", T0)


def test_the_syslog_row_ships_as_shadow_and_emits_nothing():
    """THE SHIPPED BEHAVIOUR, stated before any grammar assertion below relies
    on `promoted()`. The row matches (the hit is counted and exported as
    `corr_parser_shadow_hits_total{rule_id}`) and the parser emits exactly what
    it would with the row absent: nothing, because a config-change line is
    below the alarm floor.

    WHY: `%SYS-5-CONFIG_I` is 35 of the 100 noise slots of the ratified V1
    workload profile (`scripts/scale-miniladder.py EVENT_MIX_NOISE`), declared
    there as a line that NEVER classifies. Emitting would re-classify a third of
    the V1 background — a semantic change to the profile every
    CORRELIX_REFERENCE_CAPACITY_V1 number was measured on, which is the owner's
    call to version, not the parser's to make."""
    assert P.RULES_BY_ID["syslog.config.change"].shadow
    shadow_fx = [f for f in POSITIVE if f.get("_shadow")]
    assert shadow_fx, "no shadow fixture — this contract would be untested"
    for fx in shadow_fx:
        before = P.SHADOW_HITS["syslog.config.change"]
        assert P.syslog_control_signal(dict(fx["syslog"]), "t1", T0) is None, fx["_case"]
        assert P.SHADOW_HITS["syslog.config.change"] == before + 1, fx["_case"]


def test_the_trap_twin_is_not_shadowed():
    """The other half of the decision: V1 injects SYSLOG only, so the trap rule
    re-classifies nothing in the ratified profile and ships emitting. One
    symptom, two observers — for now only one of them speaks."""
    assert not P.RULES_BY_ID["trap.config.change"].shadow


# ══ 1 + 2. every fixture lands where the catalog says it lands ═══════════════


@pytest.mark.parametrize("fx", FIXTURES, ids=lambda f: f["_case"])
def test_the_fixture_classifies_exactly_as_declared(fx):
    sig = classify(fx)
    want = fx["_expect"]
    if want.get("kind") is None:
        assert sig is None, f"{fx['_case']}: expected NO signal, got {sig.kind}"
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
        assert sig.native_id == want["native_id"].replace("{ts_ms}", str(TS_MS))
    if "tokens" in want:
        assert list(sig.entity_tokens) == want["tokens"]


def test_every_near_miss_is_refused():
    """The trap near misses fall to the unchanged severity-floor net; the syslog
    ones stay below that floor and classify as nothing at all. Either way, the
    one thing they must never be is a config change."""
    misses = [f for f in FIXTURES if "NEAR-MISS" in f["_case"]]
    assert len(misses) >= 4, "each observer needs its own near miss, at least"
    for fx in misses:
        sig = classify(fx)
        assert sig is None or sig.kind != KIND, fx["_case"]
        assert sig is None or sig.attrs["rule_id"] not in A9B_RULE_IDS, fx["_case"]


def test_both_rules_have_a_positive_fixture():
    fired = {classify(f).attrs["rule_id"] for f in POSITIVE}
    assert set(A9B_RULE_IDS) - fired == set(), f"unreached: {set(A9B_RULE_IDS) - fired}"


def test_every_declared_vendor_is_exercised_by_a_fixture(a9b_rows):
    """`vendors` is an audit claim that reaches the coverage matrix. A vendor
    listed on a row with no fixture is a claim nothing checks."""
    seen: dict[str, set[str]] = {rid: set() for rid in A9B_RULE_IDS}
    for fx in POSITIVE:
        rid = classify(fx).attrs["rule_id"]
        if rid in seen:
            seen[rid].add(fx["_vendor"])
    for rid, row in a9b_rows.items():
        assert seen[rid], f"{rid}: no fixture at all"
        assert seen[rid] <= set(row["vendors"]), (
            f"{rid}: fixtures exercise vendors "
            f"{sorted(seen[rid] - set(row['vendors']))} the row does not declare")


# ══ 3. identity: content-bearing and idempotent ══════════════════════════════


def test_a_typed_rule_does_not_lean_on_the_generic_content_tag():
    for fx in POSITIVE:
        assert classify(fx).attrs.get("content_tag") is None, fx["_case"]


@pytest.mark.parametrize("fx", FIXTURES, ids=lambda f: f["_case"])
def test_redelivery_is_idempotent(fx):
    """A Kafka redelivery is byte-identical, so it must re-derive the SAME
    signal_id and dedup."""
    a, b = classify(fx), classify(fx)
    if a is None:
        assert b is None
        return
    assert a.signal_id == b.signal_id and a.native_id == b.native_id


def test_the_identity_moves_when_the_content_moves():
    """tracker 198. The extracted fields ARE the content of a typed rule, so a
    different operator, session or source is a different event — the ONE
    exception is a notification the MIB defines as carrying no content at all,
    where two in a millisecond really are one edit reported twice."""
    free = [f for f in POSITIVE if f.get("_content_free")]
    assert free, "the content-free cases are declared IN the fixtures, with a reason"
    for fx in POSITIVE:
        base = classify(fx)
        moved = json.loads(json.dumps(fx))
        if fx.get("_content_free"):
            # Declared content-free IN THE FIXTURE, with the MIB/vendor reason.
            # Verify the claim rather than trusting it: there is nothing in the
            # observation to mutate.
            if fx["_lane"] == "trap":
                assert not moved["trap"]["varbinds"], (
                    f"{fx['_case']}: declared content-free but carries varbinds")
            assert base.native_id.count("?") >= 2, (
                f"{fx['_case']}: declared content-free but its id carries fields")
            continue
        if fx["_lane"] == "trap":
            moved["trap"]["varbinds"][-1]["value"] = "someone-else"
        else:
            moved["syslog"]["message"] = (
                moved["syslog"]["message"].replace("admin", "intruder"))
        other = classify(moved)
        assert other is not None and other.native_id != base.native_id, fx["_case"]


# ══ 4. the catalog's claims about itself ═════════════════════════════════════


def test_both_rows_state_a_rung_on_the_ladder(a9b_rows):
    assert len(a9b_rows) == len(A9B_RULE_IDS), "a rule vanished from the catalog"
    for rid, row in a9b_rows.items():
        assert row.get("fidelity_status") in B.FIDELITY_STATUSES, rid
        assert row["fidelity_status"] == "doc_claimed", (
            f"{rid}: the fixtures are built from vendor documentation and MIB "
            "definitions, not captured off a device — promote the rung only "
            "with a real capture (README fidelity ladder)")


_OID_RE = re.compile(r"^\d+(?:\.\d+)+$")


def _oids_in(node) -> set[str]:
    out: set[str] = set()
    if isinstance(node, dict):
        for v in node.values():
            out |= _oids_in(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            out |= _oids_in(v)
    elif isinstance(node, str) and _OID_RE.match(node):
        out.add(node)
    return out


def _guard_names(node, out: set[str]) -> set[str]:
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("equals_any", "eq") and isinstance(v, (list, tuple)) \
                    and len(v) == 2 and v[0] == "name":
                vals = v[1] if isinstance(v[1], (list, tuple)) else [v[1]]
                out |= {str(x) for x in vals}
                continue
            _guard_names(v, out)
    elif isinstance(node, (list, tuple)):
        for v in node:
            _guard_names(v, out)
    return out


@pytest.fixture(scope="module")
def mib_nodes() -> dict:
    with open(MIB_INDEX, encoding="utf-8") as fh:
        return json.load(fh)["nodes"]


def test_every_oid_the_trap_guard_tests_resolves_in_the_vendored_mib_index(
        a9b_rows, mib_nodes):
    """THE A9 ANTI-FABRICATION GATE, inherited. An OID written from memory is an
    invented wire contract that fails silently on real hardware. The Nokia arm
    of this rule names NO OID for exactly that reason — TIMETRA-SYSTEM-MIB
    compiles no notification into the index, so it is matched on the MIB-decoded
    event_type instead."""
    row = a9b_rows["trap.config.change"]
    names = _guard_names(row["guard"], set())
    oids = sorted(_oids_in(row["guard"]))
    assert oids, "the guard asserts no OID at all — did the rule lose its anchor?"
    for oid in oids:
        assert oid in mib_nodes, (
            f"guard OID {oid} is not in the vendored MIB index — vendor the MIB "
            "and run `make mib-index`, or key off the MIB-decoded event_type")
        assert mib_nodes[oid]["kind"] == "notification", (
            f"guard OID {oid} is a {mib_nodes[oid]['kind']}, which is a varbind "
            "object and never a trap identity")
        assert mib_nodes[oid]["name"] in names, (
            f"guard OID {oid} resolves to {mib_nodes[oid]['name']!r}, which the "
            f"rule's name arm {sorted(names)} does not list — the two arms would "
            "classify different notifications as one symptom")


def test_every_varbind_oid_the_trap_rule_extracts_resolves_too(a9b_rows, mib_nodes):
    """Same gate on the EXTRACTION side: a column OID that does not exist yields
    '' forever, which reads as "the device did not send it"."""
    row = a9b_rows["trap.config.change"]
    for oid in sorted(_oids_in(row.get("extract") or {})):
        assert oid in mib_nodes, f"varbind OID {oid} is not in the MIB index"
        assert mib_nodes[oid]["kind"] in ("column", "scalar"), (
            f"{oid} is a {mib_nodes[oid]['kind']}, not a varbind object")


def test_every_config_change_notification_it_names_is_seeded_above_the_floor(
        a9b_rows, mib_nodes):
    """The finding this change exists to close, asserted where the rule states
    it: a notification the rule claims to type must actually REACH the platform
    at or above the alarm floor, or the row is a promise the pipeline breaks."""
    row = a9b_rows["trap.config.change"]
    for oid in sorted(_oids_in(row["guard"])):
        hint = mib_nodes[oid].get("severity_hint")
        assert hint is not None, (
            f"{mib_nodes[oid]['name']} carries no severity hint — `trapMeta` "
            "defaults it to `notice`, which is BELOW ALARM_SEVERITY_FLOOR")
        assert P._SEVERITY_NUM[hint] <= P.ALARM_SEVERITY_FLOOR, (
            f"{mib_nodes[oid]['name']} hints {hint!r}, below the alarm floor")


# ══ 5. the kind is registered, and it is NOT inert ═══════════════════════════


def test_the_kind_is_emitted_and_named_by_real_templates():
    """A9's stated reason for leaving this symptom alone was that a kind no
    signature names is inert evidence. This is the assertion that makes the new
    kind legitimate rather than a repeat of that mistake."""
    assert KIND in P.EMITTED_KINDS
    emitting = [r.rule_id for r in P.RULES if r.kind == KIND and not r.shadow]
    assert emitting == ["trap.config.change"], (
        f"{KIND} reaches production through {emitting} — if the syslog row was "
        "promoted, the V1 workload profile must have been versioned with it")
    naming = _templates_naming_the_kind()
    assert len(naming) >= 4, f"only {sorted(t for t, _ in naming)} consume {KIND}"
    for template_id, every_clause_optional in naming:
        assert every_clause_optional, (
            f"{template_id}: a config change is CONTEXT — made required it would "
            "suppress this family on every object where nobody touched the box")


def test_both_observers_emit_the_same_kind_entity_and_state(a9b_rows):
    """One symptom, two observers — the row-level statement of the A9 contract
    (the engine-side proof is test_config_change_symptom.py)."""
    kinds = {row["kind"] for row in a9b_rows.values()}
    entities = {row["entity_type"] for row in a9b_rows.values()}
    assert kinds == {KIND} and entities == {"device"}
    for row in a9b_rows.values():
        assert row["extract"]["state"] == {"const": "changed"}
        assert row["emit"]["modality"] == "control_plane"
        # Declared ONCE, at row level, like every other fixed-severity rule in
        # the table (an `emit.severity` would silently win over it).
        assert row["severity"] == "info" and row["emit"].get("severity") is None, (
            "a change is not a fault: `info` keeps it below "
            "`severity_open_floor`, so it cannot open an RCA object alone")
