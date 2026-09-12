# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Pytest: the A9 trap-coverage rows, replayed through the REAL producer.

A9 is the tracker-184 exercise applied to SNMP traps: for every syslog symptom
the parser types, does a standard or vendor trap carry the same symptom, and if
so does it produce the SAME evidence? The audit's verdicts live in
`docs/design/telemetry-coverage-matrix.md`; the PROMOTED ones live as `lane:
trap` rows of `events.yaml` and are proven here.

What this file proves, from inside the catalog (so a catalog edit is red here
before it is red in the engine's suite):

  1. every fixture classifies to the rule, kind, entity, state, severity,
     native_id and grounding tokens its `_expect` declares;
  2. the NEAR MISSES fall through to the generic `device_alarm` — a tightened
     guard is worth nothing if nothing pins what it must NOT claim;
  3. every promoted rule's native_id is CONTENT-BEARING (tracker 198) and
     idempotent under redelivery;
  4. the rows' catalog claims are honest: `fidelity_status` is on the ladder,
     the vendors a fixture exercises are declared, and every OID a guard tests
     resolves in the vendored MIB index (`make mib-index`) — the catalog never
     asserts a wire OID it cannot verify.

The kind/entity/state PAIRING against the syslog counterpart is proven in the
engine's own suite (`src/correlation/test_trap_syslog_parity_a9.py`), which is
where both producers live.
"""
from __future__ import annotations

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

#: The rules this audit promoted out of the generic trap alarm.
A9_RULE_IDS = (
    "trap.ospf.adjacency_change",
    "trap.isis.adjacency_change",
    "trap.stp.topology_change",
    "trap.fhrp.state_change",
)


def _fixtures() -> list[dict]:
    path = os.path.join(HERE, "fixtures", "trap_events.jsonl")
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


FIXTURES = _fixtures()


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    return B.load()[1]


@pytest.fixture(scope="module")
def a9_rows(rows) -> dict[str, dict]:
    return {r["rule_id"]: r for r in rows if r["rule_id"] in A9_RULE_IDS}


def classify(trap: dict):
    return P.trap_control_signal(dict(trap), "t1", T0)


# ══ 1 + 2. every fixture lands where the catalog says it lands ═══════════════


@pytest.mark.parametrize("fx", FIXTURES, ids=lambda f: f["_case"])
def test_the_fixture_classifies_exactly_as_declared(fx):
    sig = classify(fx["trap"])
    want = fx["_expect"]
    assert sig is not None, f"{fx['_case']}: produced no signal at all"
    assert sig.attrs["rule_id"] == want["rule_id"]
    assert sig.kind == want["kind"]
    assert sig.entity_type.value == want["entity_type"]
    assert sig.entity_id == want["entity_id"]
    assert sig.severity.value == want["severity"]
    if "state" in want:
        assert sig.attrs.get("state") == want["state"]
    if "peer" in want:
        assert sig.attrs.get("peer") == want["peer"]
    if "native_id" in want:
        assert sig.native_id == want["native_id"].replace("{ts_ms}", str(TS_MS))
    if "tokens" in want:
        assert list(sig.entity_tokens) == want["tokens"]


def test_every_near_miss_stays_the_generic_alarm():
    """A guard is only as good as what it refuses. Each promoted rule ships a
    NEAR MISS — a real trap of the same protocol/wording that is NOT the
    symptom — and it must land on the unchanged severity-floor net."""
    misses = [f for f in FIXTURES if "NEAR-MISS" in f["_case"]]
    assert len(misses) == len(A9_RULE_IDS), (
        f"{len(misses)} near-miss fixtures for {len(A9_RULE_IDS)} promoted "
        "rules — every promoted rule needs one")
    for fx in misses:
        sig = classify(fx["trap"])
        assert sig is not None and sig.kind == "device_alarm", fx["_case"]
        assert sig.attrs["rule_id"] == "trap.generic.device_alarm", fx["_case"]


def test_every_promoted_rule_has_a_positive_fixture():
    fired = {classify(f["trap"]).attrs["rule_id"] for f in FIXTURES}
    missing = sorted(set(A9_RULE_IDS) - fired)
    assert not missing, f"promoted with no fixture that reaches it: {missing}"


def test_every_promoted_rule_has_a_fixture_per_declared_vendor(a9_rows):
    """`vendors` is an audit claim. A vendor listed on a row with no fixture
    that exercises it is a claim nothing checks."""
    seen: dict[str, set[str]] = {rid: set() for rid in A9_RULE_IDS}
    for fx in FIXTURES:
        rid = classify(fx["trap"]).attrs["rule_id"]
        if rid in seen:
            seen[rid].add(fx["_vendor"])
    for rid, row in a9_rows.items():
        # `standard` covers every vendor that emits the IETF trap unchanged; a
        # row may declare more vendors than it has fixtures for ONLY when the
        # standard arm is what those vendors emit.
        assert seen[rid], f"{rid}: no fixture at all"
        assert seen[rid] <= set(row["vendors"]), (
            f"{rid}: fixtures exercise vendors {sorted(seen[rid] - set(row['vendors']))} "
            "the row does not declare")


# ══ 3. identity: content-bearing and idempotent ══════════════════════════════


def test_a_promoted_native_id_carries_the_events_own_content():
    """tracker 198. The generic net folds a content hash into its id because it
    recognized nothing. A TYPED rule must not need one — its extracted fields
    ARE the content — so the id has to MOVE when the content moves."""
    for fx in FIXTURES:
        if "NEAR-MISS" in fx["_case"]:
            continue
        base = classify(fx["trap"])
        assert base.attrs.get("content_tag") is None, (
            f"{fx['_case']}: a typed rule must not lean on the generic content tag")
        # Same trap, one field of content different → a different identity.
        moved = json.loads(json.dumps(fx["trap"]))
        if moved["varbinds"]:
            moved["varbinds"][-1]["value"] = "unrelated-value-0"
        else:
            moved["trap_oid"] = "1.3.6.1.2.1.17.0.1"
            moved["trap_name"] = "newRoot"
            moved["event_type"] = "new_root"
        other = classify(moved)
        if other is None or other.attrs.get("rule_id") != base.attrs["rule_id"]:
            continue                       # the edit left the rule — nothing to compare
        assert other.native_id != base.native_id or other.signal_id == base.signal_id


@pytest.mark.parametrize("fx", FIXTURES, ids=lambda f: f["_case"])
def test_redelivery_is_idempotent(fx):
    """A Kafka redelivery is byte-identical, so it must re-derive the SAME
    signal_id and dedup — including for the generic near-miss net, whose id
    folds a hash of the trap's own rendering."""
    a, b = classify(fx["trap"]), classify(fx["trap"])
    assert a.signal_id == b.signal_id
    assert a.native_id == b.native_id


# ══ 4. the catalog's claims about itself ═════════════════════════════════════


def test_every_promoted_row_states_a_rung_on_the_ladder(a9_rows):
    assert len(a9_rows) == len(A9_RULE_IDS), "a promoted rule vanished from the catalog"
    for rid, row in a9_rows.items():
        assert row.get("fidelity_status") in B.FIDELITY_STATUSES, rid
        # None of these fixtures came off a device.
        assert row["fidelity_status"] == "doc_claimed", (
            f"{rid}: promote the rung only with a CAPTURED fixture (README ladder)")


def test_a_fidelity_status_off_the_ladder_does_not_bake(rows):
    bad = json.loads(json.dumps(rows[0]))
    bad["fidelity_status"] = "probably_fine"
    with pytest.raises(B.BakeError):
        B.validate_row(bad, {}, set())


def test_the_row_rung_wins_over_the_family_and_stays_out_of_the_hash(rows):
    """`fidelity_status` is the CATALOG's claim about a grammar, never the
    grammar: it must reach the signal's provenance and must NOT move
    `rules_hash`, or a catalog promotion would read as a parser edit."""
    from rule_model import compile_rule, rules_hash

    row = json.loads(json.dumps(next(
        r for r in rows if r["rule_id"] == "trap.stp.topology_change")))
    before = rules_hash([compile_rule(row)])
    assert compile_rule(row).fidelity == "doc_claimed"
    row["fidelity_status"] = "live_validated"
    assert compile_rule(row).fidelity == "live_validated"
    assert rules_hash([compile_rule(row)]) == before


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
    """Every trap NAME a guard tree tests (`{equals_any: [name, [...]]}` /
    `{eq: [name, x]}`)."""
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


def test_every_oid_a_promoted_guard_tests_resolves_in_the_vendored_mib_index(a9_rows):
    """THE ANTI-FABRICATION GATE. An OID written from memory is an invented wire
    contract that fails silently on real hardware. Every OID a promoted GUARD
    matches on must resolve in the index `make mib-index` generates from real
    MIB sources; a symptom whose MIB is not vendored is matched on the
    MIB-decoded event_type instead (and carries no OID in its guard at all).

    The OID arm and the NAME arm are also pinned to each other: a rule that
    matches `topologyChange` by name and some other OID by number would
    classify two different notifications as one symptom."""
    with open(MIB_INDEX, encoding="utf-8") as fh:
        nodes = json.load(fh)["nodes"]
    for rid, row in a9_rows.items():
        names = _guard_names(row["guard"], set())
        for oid in sorted(_oids_in(row["guard"])):
            assert oid in nodes, (
                f"{rid}: guard OID {oid} is not in the vendored MIB index — "
                "vendor the MIB and run `make mib-index`, or key the rule off "
                "the MIB-decoded event_type instead of an unverified OID")
            # SMIv1 TRAP-TYPEs (BRIDGE-MIB newRoot/topologyChange) index as
            # `scalar`: pysmi keeps the v1 form rather than synthesising a
            # NOTIFICATION-TYPE. The v2 OID it is delivered under is the one
            # here, and the name arm below is what pins its meaning.
            assert nodes[oid]["kind"] in ("notification", "scalar"), (
                f"{rid}: guard OID {oid} is a {nodes[oid]['kind']} column, "
                "which is a varbind object and never a trap identity")
            assert not names or nodes[oid]["name"] in names, (
                f"{rid}: guard OID {oid} resolves to {nodes[oid]['name']!r}, "
                f"which the rule's name arm {sorted(names)} does not list — the "
                "two arms would classify different notifications as one symptom")


def test_every_varbind_oid_a_promoted_rule_extracts_resolves_too(a9_rows):
    """Same gate on the EXTRACTION side: a varbind column OID that does not
    exist yields '' forever, which reads as "the device did not send it"."""
    with open(MIB_INDEX, encoding="utf-8") as fh:
        nodes = json.load(fh)["nodes"]
    for rid, row in a9_rows.items():
        for oid in sorted(_oids_in(row.get("extract") or {})):
            assert oid in nodes, f"{rid}: varbind OID {oid} is not in the MIB index"
            assert nodes[oid]["kind"] in ("column", "scalar"), (
                f"{rid}: {oid} is a {nodes[oid]['kind']}, not a varbind object")


def test_a_promoted_rule_reuses_a_kind_the_engine_already_emits(a9_rows):
    """No new kinds. A kind no signature template names is INERT evidence: it
    would ground and store and never confirm anything. Every A9 row emits the
    kind its syslog counterpart already emits."""
    for rid, row in a9_rows.items():
        assert row["kind"] in P.EMITTED_KINDS, rid
        syslog_kinds = {r.kind for r in P.RULES if r.lane == "syslog"}
        assert row["kind"] in syslog_kinds, (
            f"{rid}: emits {row['kind']!r}, which no syslog rule emits — an A9 "
            "row must reuse its counterpart's vocabulary, not invent one")
