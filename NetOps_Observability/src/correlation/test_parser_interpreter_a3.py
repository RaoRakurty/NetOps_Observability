"""A3 — the catalog becomes the executor.

W1b made every fact ABOUT a parser branch a row of a table while the branch
bodies stayed hand-written Python. A3 moved the GRAMMAR into those rows, put
them in `telemetry-catalog/events.yaml` (the same file the catalog's own
conformance reader uses), baked them into a checked-in generated module because
the image does not ship the catalog, and replaced the branches with a generic
interpreter.

What this file proves, in the order the change has to be trusted:

  1. THE BAKE       the checked-in module IS the catalog (drift guard), the bake
                    is deterministic, and a hand-edit of the generated file is
                    caught by the hash it carries.
  2. THE SCHEMA     a row that is incomplete, misspelt, or lying about its screen
                    coverage does not bake at all.
  3. PARITY         the interpreter and the FROZEN pre-A3 branch code agree on
                    every one of the 1,115 golden-corpus entries — kind, entity,
                    state, tokens, native_id, signal_id, severity, attrs.
  4. ORDER          order is behaviour: swap two rules and a near-miss line
                    classifies differently, and the hash moves.
  5. SHADOW (A8)    a `shadow: true` row is evaluated and COUNTED and emits
                    nothing, changing no output.
  6. COST           the interpreter is within 1.5x of the branch code on the
                    corpus — parsing is on the ingest hot path.
  7. ONE COPY       events.yaml carries the grammar exactly once, and the
                    catalog's conformance reader executes the same rows.
"""
from __future__ import annotations

import copy
import json
import os
import sys
import time
from datetime import datetime, timezone

import pytest

import parser_rules
import producers as P
from rule_model import Ctx, RuleError, compile_guard, compile_rule, rules_hash
from signals import DeadLetter

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG_DIR = os.path.abspath(os.path.join(HERE, "..", "..", "telemetry-catalog"))
GOLDEN = os.path.join(HERE, "fixtures", "parser_golden_corpus.jsonl")

sys.path.insert(0, os.path.join(HERE, "fixtures"))
sys.path.insert(0, CATALOG_DIR)

bake = pytest.importorskip("bake_rules")
baseline = pytest.importorskip("parser_branch_baseline")

T0 = datetime(2026, 9, 2, 10, 0, 0, tzinfo=timezone.utc)
TS = "2026-09-02T10:00:00.000Z"


@pytest.fixture(autouse=True)
def _clean_counters():
    P.reset_parser_counters()
    yield
    P.reset_parser_counters()


@pytest.fixture(scope="module")
def catalog():
    return bake.load()


@pytest.fixture(scope="module")
def golden() -> list[dict]:
    with open(GOLDEN, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def syslog_ev(tag: str, msg: str, severity: str = "notice", host: str = "leaf1") -> dict:
    return {"hostname": host, "appname": tag, "message": msg,
            "severity": severity, "timestamp": TS}


# ══ 1. the bake ══════════════════════════════════════════════════════════════

def test_the_checked_in_module_is_a_fresh_bake(catalog):
    """THE DRIFT GUARD. `parser_rules.py` is generated; if events.yaml moved and
    nobody re-baked, the runtime is parsing with rules that are not the spec.
    Same shape as the docs-corpus drift test: regenerate, compare, fail loud."""
    data, rows = catalog
    fresh = bake.render(data, rows)
    with open(os.path.join(HERE, "parser_rules.py"), encoding="utf-8") as fh:
        current = fh.read()
    assert current == fresh, (
        "src/correlation/parser_rules.py is STALE vs telemetry-catalog/"
        "events.yaml — run `python3 telemetry-catalog/bake_rules.py`")


def test_the_bake_is_deterministic(catalog):
    """Two bakes of one catalog must be byte-equal, or `--check` is a coin toss
    and the drift guard means nothing."""
    data, rows = catalog
    assert bake.render(data, rows) == bake.render(*bake.load())


def test_a_hand_edit_of_the_generated_module_cannot_hide(catalog):
    """The generated file carries the hash the BAKE computed; the module
    recomputes it at import and `producers` refuses to load on a mismatch. So
    editing a rule in the generated file (instead of the catalog) is fatal, not
    silent."""
    assert parser_rules.BAKED_RULES_HASH == parser_rules.RULES_HASH
    assert P.RULES_HASH == parser_rules.BAKED_RULES_HASH
    _data, rows = catalog
    runtime = [r for r in rows if r["lane"] in bake.RUNTIME_LANES]
    assert rules_hash(compile_rule(r) for r in runtime) == P.RULES_HASH


def test_the_catalog_only_rows_never_reach_the_runtime(catalog):
    """`lane: catalog` is how a family the canonical-event schema covers, and no
    correlation lane consumes, stays OUT of the image: zero hot-path cost, one
    grammar. Promoting one is an explicit `lane:` change, never an accident."""
    _data, rows = catalog
    catalog_only = {r["rule_id"] for r in rows if r["lane"] == "catalog"}
    assert catalog_only, "the fixture for this test disappeared"
    assert catalog_only.isdisjoint({r.rule_id for r in P.RULES})


def test_the_rule_count_is_what_the_lanes_add_up_to():
    assert len(P.RULES) == len(P._SYSLOG_RULES) + len(P._PORT_RULES) + len(P._TRAP_RULES)
    assert len(P.RULES) == 38


# ══ 2. the schema ════════════════════════════════════════════════════════════


def _row(catalog, rule_id: str) -> dict:
    _data, rows = catalog
    return copy.deepcopy(next(r for r in rows if r["rule_id"] == rule_id))


def _families(catalog) -> dict:
    return (catalog[0].get("families") or {})


def _expect_rejected(catalog, row: dict, needle: str) -> None:
    with pytest.raises(bake.BakeError) as exc:
        bake.validate_row(row, _families(catalog), set())
    assert needle in str(exc.value)


def test_the_real_catalog_validates(catalog):
    """The canary: every other rejection test below is meaningless if the real
    rows do not pass the same validator."""
    data, rows = catalog
    seen: set[str] = set()
    for row in rows:
        bake.validate_row(row, data["families"], seen)
    assert len(seen) == len(rows)


def test_an_unknown_row_key_is_rejected(catalog):
    row = _row(catalog, "syslog.link.state_change")
    row["entitiy_type"] = "device"        # a typo must not be silently ignored
    _expect_rejected(catalog, row, "unknown key")


def test_a_missing_required_key_is_rejected(catalog):
    row = _row(catalog, "syslog.link.state_change")
    del row["guard"]
    _expect_rejected(catalog, row, "missing required key")


def test_a_row_must_declare_its_family_even_when_it_has_none(catalog):
    row = _row(catalog, "syslog.link.state_change")
    del row["family"]
    _expect_rejected(catalog, row, "must declare `family`")


def test_a_family_that_does_not_exist_is_rejected(catalog):
    row = _row(catalog, "syslog.link.state_change")
    row["family"] = "no_such_family"
    _expect_rejected(catalog, row, "not defined in `families:`")


def test_a_pattern_src_that_is_not_in_its_own_guard_is_rejected(catalog):
    """The screen contract. `pattern_src` is what the ingest pre-filter screens
    this rule by; if it is not actually a gate of the rule, the screen advertises
    coverage for something that is gone."""
    row = _row(catalog, "syslog.mac.flap")
    row["pattern_src"] = r"\bnot-in-the-guard\b"
    _expect_rejected(catalog, row, "pattern_src is not a `re` node")


def test_a_lower_case_marker_is_rejected(catalog):
    """The screen matches an UPPER-CASED classification token, so a lower-case
    marker would silently never screen anything in."""
    row = _row(catalog, "syslog.link.state_change")
    row["markers"] = ["updown"]
    _expect_rejected(catalog, row, "UPPER-CASE")


def test_a_duplicate_rule_id_is_rejected(catalog):
    row = _row(catalog, "syslog.link.state_change")
    with pytest.raises(bake.BakeError) as exc:
        bake.validate_row(row, _families(catalog), {row["rule_id"]})
    assert "duplicate rule_id" in str(exc.value)


def test_an_unknown_lane_is_rejected(catalog):
    row = _row(catalog, "syslog.link.state_change")
    row["lane"] = "somewhere_else"
    _expect_rejected(catalog, row, "lane")


def test_a_runtime_rule_without_a_native_id_is_rejected(catalog):
    """Identity is not optional: a runtime rule with no native_id would emit
    signals that cannot be de-duplicated."""
    row = _row(catalog, "syslog.link.state_change")
    del row["emit"]["native_id"]
    _expect_rejected(catalog, row, "emit.native_id")


def test_an_unknown_emit_key_is_rejected(catalog):
    row = _row(catalog, "syslog.link.state_change")
    row["emit"]["severty"] = "high"
    _expect_rejected(catalog, row, "unknown emit key")


def test_a_conditional_entity_needs_its_else_branch(catalog):
    row = _row(catalog, "syslog.link.state_change")
    row["emit"]["entity"]["when"] = {"truthy": "$ifname"}
    _expect_rejected(catalog, row, "no `else`")


@pytest.mark.parametrize("bad_guard", [
    {"nosuchop": ["msg", "x"]},
    {"contains": ["msg", "x"], "any": []},       # two keys = ambiguous
    "not-a-mapping",
])
def test_an_unrecognized_guard_node_is_rejected(catalog, bad_guard):
    """An unknown node must RAISE, never evaluate to False: a guard that
    silently never fires is a branch nobody noticed was deleted."""
    row = _row(catalog, "syslog.link.state_change")
    row["guard"] = bad_guard
    row.pop("pattern_src", None)
    with pytest.raises(bake.BakeError):
        bake.validate_row(row, _families(catalog), set())


def test_an_unknown_regex_flag_is_rejected():
    with pytest.raises(RuleError):
        compile_guard({"re": ["msg", "x", "mux"]})


def test_a_family_without_labels_or_join_on_is_rejected():
    with pytest.raises(bake.BakeError):
        bake.validate_family("f", {"join_on": ["device"]})
    with pytest.raises(bake.BakeError):
        bake.validate_family("f", {"labels": {"device": "hostname"}})


# ══ 3. PARITY — the interpreter vs the frozen branch code ════════════════════


def _shot(sig) -> dict | None:
    if sig is None:
        return None
    attrs = sig.attrs if isinstance(sig.attrs, dict) else {}
    return {
        "kind": sig.kind,
        "entity_type": sig.entity_type.value,
        "entity_id": sig.entity_id,
        "tokens": list(sig.entity_tokens),
        "native_id": sig.native_id,
        "signal_id": str(sig.signal_id),
        "severity": sig.severity.value,
        "metric_name": sig.metric_name,
        "modality_class": sig.modality_class.value,
        "attrs": dict(sorted(attrs.items())),
    }


def _call(fn, ev):
    try:
        return _shot(fn(dict(ev), "t1", T0))
    except DeadLetter as exc:
        return {"error": type(exc).__name__}


LANE_FNS = {
    "syslog": (("syslog_control_signal", P.syslog_control_signal,
                baseline.syslog_control_signal),
               ("port_event_signal", P.port_event_signal,
                baseline.port_event_signal)),
    "trap": (("trap_control_signal", P.trap_control_signal,
              baseline.trap_control_signal),),
}


#: A9 — the ONLY way an entry may sit out the parity run. The frozen branch code
#: in `fixtures/parser_branch_baseline.py` is the pre-A3 parser: a symptom
#: PROMOTED after it was frozen has no branch there to be compared against, and
#: the promotion IS the behaviour change. Such an entry must say so IN THE FILE
#: (`"baseline": "absent"` + a `baseline_reason`), never fail silently and never
#: be dropped from the corpus — it is still replayed byte-identically against
#: its recorded output by `test_parser_provenance_w1b`, and its kind/entity/
#: state are pinned against the syslog counterpart by
#: `test_trap_syslog_parity_a9`.
BASELINE_ABSENT = "absent"


def _skips_baseline(entry: dict) -> bool:
    return entry.get("baseline") == BASELINE_ABSENT


def test_the_interpreter_and_the_branch_code_agree_on_the_whole_corpus(golden):
    """THE PROOF. Not "the interpreter matches a recorded snapshot" — both sides
    are RUN, on the same events, and every emitted field is compared, provenance
    INCLUDED (the rule that fires must be the same rule)."""
    assert len(golden) >= 1000, f"corpus shrank to {len(golden)} entries"
    mismatches, skipped = [], 0
    for entry in golden:
        if _skips_baseline(entry):
            skipped += 1
            continue
        ev = entry["ev"]
        for name, new_fn, old_fn in LANE_FNS[entry["lane"]]:
            got, want = _call(new_fn, ev), _call(old_fn, ev)
            if got != want:
                mismatches.append((name, ev.get("message") or ev.get("trap_oid"),
                                   want, got))
    assert not mismatches, (
        f"{len(mismatches)} of {len(golden)} corpus events classify differently "
        f"under the interpreter. First: {mismatches[0]}")
    # The skip must never be able to hollow the proof out.
    assert len(golden) - skipped >= 1000, (
        f"{skipped} of {len(golden)} entries opted out of the parity run — the "
        "baseline comparison is no longer proving anything")


def test_every_baseline_skip_is_declared_and_justified(golden):
    """A silent skip is how a parity proof rots. An entry may leave the run ONLY
    by declaring it in the corpus with a reason, and only because the FROZEN
    branch code genuinely has no branch for it — which this test checks by
    running the baseline and asserting it really does classify differently."""
    skipped = [e for e in golden if _skips_baseline(e)]
    assert skipped, ("no entry skips the baseline — if the last post-freeze "
                     "promotion was reverted, delete this test with it")
    for entry in skipped:
        reason = str(entry.get("baseline_reason") or "")
        assert len(reason) > 40, (
            f"a baseline skip needs a REASON, not a flag: {entry['ev']}")
        ev = entry["ev"]
        for name, new_fn, old_fn in LANE_FNS[entry["lane"]]:
            got, want = _call(new_fn, ev), _call(old_fn, ev)
            assert got != want, (
                f"{name}: this entry claims the frozen branch code cannot "
                f"classify it, but the two agree — remove the skip. {ev}")


def test_the_baseline_skips_are_exactly_the_post_freeze_promotions(golden):
    """Pins WHICH rules are allowed to sit out, so a future promotion cannot
    quietly join the list: the set is stated here and in the corpus, and the two
    must agree."""
    allowed = {
        "trap.ospf.adjacency_change", "trap.isis.adjacency_change",
        "trap.stp.topology_change", "trap.fhrp.state_change",
    }
    fired = set()
    for entry in golden:
        if not _skips_baseline(entry):
            continue
        for _name, new_fn, _old in LANE_FNS[entry["lane"]]:
            sig = _call(new_fn, entry["ev"])
            if sig is not None and "error" not in sig:
                fired.add(P.trap_control_signal(
                    dict(entry["ev"]), "t1", T0).attrs["rule_id"])
    assert fired == allowed, f"unexpected baseline-skipping rules: {fired ^ allowed}"


def test_the_corpus_exercises_every_rule(golden):
    """A parity run that never reaches a rule proves nothing about it."""
    fired: set[str] = set()
    for entry in golden:
        for _name, fn, _old in LANE_FNS[entry["lane"]]:
            try:
                sig = fn(dict(entry["ev"]), "t1", T0)
            except DeadLetter:
                continue
            if sig is not None:
                fired.add(sig.attrs["rule_id"])
    missing = sorted({r.rule_id for r in P.RULES} - fired)
    assert not missing, f"the corpus never fires: {missing}"


# ══ 4. ORDER IS BEHAVIOUR ════════════════════════════════════════════════════

# A NEAR MISS: %CLNS-5-ADJCHANGE satisfies BOTH the IS-IS guard (CLNS ∧ ADJ) and
# the catch-all routing guard (ADJCHANGE). Only the ORDER of the two rows decides
# which one claims it — which is exactly why `rules_hash` covers the order.
NEAR_MISS = syslog_ev("%CLNS-5-ADJCHANGE", "IS-IS adjacency 1921.6800.1001 to state Down")


def test_the_near_miss_classifies_by_order(monkeypatch):
    before = P.syslog_control_signal(dict(NEAR_MISS), "t1", T0)
    assert before is not None and before.kind == "isis_adjacency_change"

    ids = [r.rule_id for r in P._SYSLOG_RULES]
    i = ids.index("syslog.isis.adjacency_change")
    j = ids.index("syslog.routing.adjacency_change")
    swapped = list(P._SYSLOG_RULES)
    swapped[i], swapped[j] = swapped[j], swapped[i]
    monkeypatch.setattr(P, "_SYSLOG_PLAN", P._plan(tuple(swapped)))

    after = P.syslog_control_signal(dict(NEAR_MISS), "t1", T0)
    assert after is not None
    assert after.kind == "routing_adjacency_change", (
        "moving the catch-all adjacency rule ahead of IS-IS did NOT change the "
        "classification — the interpreter is not honouring table order")
    assert after.attrs["rule_id"] == "syslog.routing.adjacency_change"


def test_swapping_two_rules_moves_the_hash():
    swapped = (P.RULES[1], P.RULES[0]) + P.RULES[2:]
    assert rules_hash(swapped) != P.RULES_HASH


def test_the_grammar_is_part_of_the_digest(catalog):
    """A3 widened `digest_fields` to the guard/extract/emit trees. Editing a
    regex inside a rule must move the hash even though every W1b-era field is
    untouched — that is the whole point of moving the grammar into the row."""
    row = _row(catalog, "syslog.link.state_change")
    row["guard"]["all"][1]["contains"][1] = "UPDOWNX"
    mutant = tuple(compile_rule(row) if r.rule_id == row["rule_id"] else r
                   for r in P.RULES)
    assert rules_hash(mutant) != P.RULES_HASH


# ══ 5. SHADOW ROWS (A8) ══════════════════════════════════════════════════════

SHADOW_ROW = {
    "rule_id": "syslog.test.shadow_candidate",
    "lane": "syslog", "source": "syslog", "kind": "device_alarm",
    "entity_type": "device", "family": None, "vendors": ["generic"],
    "markers": ["UPDOWN"], "generic": False, "shadow": True,
    "guard": {"contains": ["ctoken", "UPDOWN"]},
    "extract": {"state": {"const": "down"}},
    "emit": {"kind": "device_alarm", "metric": "device_alarm",
             "modality": "control_plane", "severity": "high",
             "entity": {"type": "device", "id": "{host}"},
             "native_id": "{host}|shadow|{ts_ms}",
             "tokens": [{"t": "{host}"}], "attrs": {"state": {"var": "state"}}},
}
LINK_EV = syslog_ev("%LINK-3-UPDOWN", "Interface GigabitEthernet0/1, changed state to down")


@pytest.fixture
def shadowed(monkeypatch):
    """The shadow row placed AHEAD of the rule that really owns this line, so a
    shadow that emitted would be impossible to miss."""
    rule = compile_rule(SHADOW_ROW)
    assert rule.shadow
    rules = list(P._SYSLOG_RULES)
    rules.insert(0, rule)
    monkeypatch.setattr(P, "_SYSLOG_PLAN", P._plan(tuple(rules)))
    monkeypatch.setitem(P.SHADOW_HITS, rule.rule_id, 0)
    monkeypatch.setitem(P.RULE_HITS, rule.rule_id, 0)
    return rule


def test_a_shadow_rule_emits_nothing_and_falls_through(shadowed):
    sig = P.syslog_control_signal(dict(LINK_EV), "t1", T0)
    assert sig is not None
    assert sig.kind == "link_state_change", (
        "the shadow row claimed the line — a shadow must never emit")
    assert sig.attrs["rule_id"] == "syslog.link.state_change"


def test_a_shadow_rule_counts_its_hits(shadowed):
    for _ in range(3):
        P.syslog_control_signal(dict(LINK_EV), "t1", T0)
    assert P.SHADOW_HITS[shadowed.rule_id] == 3, (
        "a shadow row that is not counted measures nothing, which is its only job")
    assert P.RULE_HITS[shadowed.rule_id] == 0, (
        "a shadow row must not appear in the emitted-rule hit counter")


def test_a_shadow_miss_is_not_counted(shadowed):
    P.syslog_control_signal(
        dict(syslog_ev("%BGP-5-ADJCHANGE", "neighbor 10.0.0.1 Down")), "t1", T0)
    assert P.SHADOW_HITS[shadowed.rule_id] == 0


def test_shadow_hits_are_exported_and_resettable(shadowed):
    P.syslog_control_signal(dict(LINK_EV), "t1", T0)
    assert P.parser_stats()["shadow_hits"][shadowed.rule_id] == 1
    P.reset_parser_counters()
    assert P.parser_stats()["shadow_hits"][shadowed.rule_id] == 0


def test_a_shadow_rule_does_not_move_the_promotion_rate(shadowed):
    """The promotion rate is typed-over-admitted. A shadow row admits nothing,
    so it must not enter either side of that fraction."""
    P.syslog_control_signal(dict(LINK_EV), "t1", T0)
    assert P.semantic_promotion_rate() == 1.0
    assert P.parser_stats()["promotion_window_used"] == 1


def test_shadow_is_a_first_class_catalog_field(catalog):
    """It survives the round trip: a row can declare it, the bake keeps it, and
    the digest covers it (so turning shadow off is a rule change)."""
    row = _row(catalog, "syslog.link.state_change")
    row["shadow"] = True
    assert compile_rule(row).shadow
    assert compile_rule(row).digest_fields() != P.RULES_BY_ID[row["rule_id"]].digest_fields()
    bad = _row(catalog, "syslog.link.state_change")
    bad["shadow"] = "yes"
    _expect_rejected(catalog, bad, "must be a boolean")


def test_no_shadow_rule_ships_today():
    """Pinned so a shadow row cannot be left switched on by accident: shipping
    one is a deliberate act, and this line is where you record it."""
    assert [r.rule_id for r in P.RULES if r.shadow] == []


# ══ 6. COST ══════════════════════════════════════════════════════════════════

#: The gate. Parsing is on the ingest hot path — 900k raw lines produce 44k
#: signals on the ratified 2.5k workload, and `handle.syslog` was measured at
#: 789 s of engine time. A tidier parser that costs 3x is not an improvement.
BENCH_RATIO = 1.5

#: The trap lane gets a looser budget, deliberately and with the reason stated.
#: It is EMISSION-dominated — every corpus trap classifies, so ~35 interpreter
#: dispatches per event land on top of a 36-46 us branch path that had them all
#: inline — and it carries orders of magnitude less volume than syslog: traps
#: arrive in the tens per second where syslog arrives in the tens of thousands.
#: MEASURED 1.40x on an idle box and up to 1.65x on a contended one; the budget
#: is set above that spread so this gate reports a real regression rather than
#: the neighbours on the CI runner. The gates that matter (the corpus as a whole
#: and the syslog lane) stay at 1.5x.
#:
#: A9 RE-MEASURED, budget UNCHANGED. The four promoted trap rows add four guards
#: that an unclassified trap now walks before reaching the generic net. Measured
#: on the pre-A9 trap corpus with the four rows plan-patched in and out:
#: 56.13 -> 56.54 us/event, ratio 1.57 -> 1.58 — **0.41 us/event, 0.7 %**. The
#: guards are OID/name equality and short substring tests; the lane's cost is
#: dominated by EMISSION (the generic alarm's content rendering + sha256), which
#: A9 did not touch. So the budget stays where it is: widening it would have
#: hidden the next real regression behind a change that did not cause one.
TRAP_BENCH_RATIO = 2.0


def _bench(fns, events, repeats: int = 5) -> float:
    """CPU time (`process_time`), best of N.

    Wall clock on a shared CI box measures the neighbours, not the parser: the
    same pair of runs swung between 1.3x and 2.2x on wall clock while CPU time
    held steady within a few percent. Best-of-N because a min is the run least
    disturbed by everything else on the machine.
    """
    best = float("inf")
    for _ in range(repeats):
        t0 = time.process_time()
        for ev in events:
            for fn in fns:
                try:
                    fn(ev, "t1", T0)
                except DeadLetter:
                    pass
        best = min(best, time.process_time() - t0)
    return best


def _ab(golden, lane) -> tuple[float, float, int]:
    events = [e["ev"] for e in golden if e["lane"] == lane]
    new = [f for _n, f, _o in LANE_FNS[lane]]
    old = [f for _n, _f, f in LANE_FNS[lane]]
    # Warm every cache (interned observers, compiled patterns) on both sides.
    _bench(new, events, repeats=1)
    _bench(old, events, repeats=1)
    return _bench(new, events), _bench(old, events), len(events)


def test_the_interpreter_is_within_1_5x_of_the_branch_code(golden):
    """THE COST GATE, over the whole corpus — both lanes, every event.

    The frozen pre-A3 branch code is the denominator (see
    fixtures/parser_branch_baseline.py), so this is the real question: does
    running the catalog cost materially more than running the hand-written
    chain it replaced?
    """
    t_new = t_old = 0.0
    per_lane = {}
    for lane in ("syslog", "trap"):
        n, o, count = _ab(golden, lane)
        t_new += n
        t_old += o
        per_lane[lane] = f"{n / o:.2f}x over {count}"
    ratio = t_new / t_old
    assert ratio <= BENCH_RATIO, (
        f"the interpreter costs {ratio:.2f}x the branch code over the corpus "
        f"(per lane: {per_lane})")


def test_the_hot_syslog_lane_is_within_1_5x(golden):
    """The lane that actually matters: 95 % of ingest volume is syslog, and the
    control-plane classifier is where the P3 measurement put 789 s of engine
    time. Gated on its own so a regression here cannot hide behind the trap
    lane's small event count."""
    t_new, t_old, count = _ab(golden, "syslog")
    ratio = t_new / t_old
    assert ratio <= BENCH_RATIO, (
        f"syslog lane: the interpreter costs {ratio:.2f}x the branch code "
        f"({t_new * 1e6 / count:.1f} us/event vs {t_old * 1e6 / count:.1f} "
        f"us/event over {count} events)")


def test_the_trap_lane_stays_inside_its_stated_budget(golden):
    """See TRAP_BENCH_RATIO for why this budget is looser than the syslog one.
    It is still a gate: a change that made trap classification 3x would be red
    here, and the number is written down rather than assumed."""
    t_new, t_old, count = _ab(golden, "trap")
    ratio = t_new / t_old
    assert ratio <= TRAP_BENCH_RATIO, (
        f"trap lane: the interpreter costs {ratio:.2f}x the branch code "
        f"({t_new * 1e6 / count:.1f} us/event vs {t_old * 1e6 / count:.1f} "
        f"us/event over {count} events)")


def test_the_expensive_derivations_stay_lazy():
    """`msg.upper()` on a 2 KB device string, and the trap content rendering, are
    built only if a rule actually asks. A line that classifies as nothing must
    not pay for either."""
    ev = syslog_ev("%SYS-6-CONFIG", "nothing interesting here", severity="info")
    ctx = Ctx({"ev": ev, "msg": ev["message"], "tag": "%SYS-6-CONFIG",
               "ctoken": "%SYS-6-CONFIG"}, {"host": "h", "ts_ms": 0}, lambda: None)
    assert "msg_u" not in ctx.base
    assert ctx.field("msg_u") == "NOTHING INTERESTING HERE"
    assert "msg_u" in ctx.base          # memoized, derived once


def test_an_extraction_only_the_catalog_reads_is_never_run_by_the_producer():
    """`isis_adjacency_change` carries an `ifname` grammar for the catalog's
    canonical `ifName` label; the Signal does not use it, so ingest must not pay
    for that regex."""
    sig = P.syslog_control_signal(dict(syslog_ev(
        "-", "isis|8808|EV|isisAdjacencyChange|W: the adjacency with system "
             "0100.0000.0011, using interface ethernet-1/1.0, moved to state DOWN.")),
        "t1", T0)
    assert sig is not None and sig.kind == "isis_adjacency_change"
    assert "ifname" not in sig.attrs
    rule = P.RULES_BY_ID["syslog.isis.adjacency_change"]
    assert "ifname" in rule.extract, "the catalog label grammar went missing"


# ══ 7. ONE COPY OF THE GRAMMAR ═══════════════════════════════════════════════

GRAMMAR_KEYS = ("match_tag", "grammars", "state", "target_state_re", "severity")


def test_no_family_row_carries_a_second_copy_of_the_grammar(catalog):
    """The regression this whole change exists to prevent. Before A3 the family
    rows held `match_tag` / `grammars` / `state` AND producers.py held the same
    regexes; the two drifted. A family row now carries the CORRELATION contract
    only."""
    for name, fam in _families(catalog).items():
        offending = sorted(set(fam) & set(GRAMMAR_KEYS))
        assert not offending, (
            f"family {name!r} re-declares grammar key(s) {offending} — the "
            "grammar belongs to its `rules:` row, once")


def test_the_conformance_reader_runs_the_same_rows():
    """`parse_events.py` is the catalog's own interpreter. It must be reading the
    rule table, not a private copy: the rule that classifies a line there is the
    rule that stamps provenance here."""
    parse_events = pytest.importorskip("parse_events")
    cat = parse_events.EventCatalog.load()
    assert {r.rule_id for r in cat.rules} <= {r["rule_id"] for r in bake.load()[1]}
    ev = {"hostname": "edge1", "appname": "%BGP-5-NBR_RESET",
          "message": "Neighbor 10.0.0.200 reset (BGP Notification received)"}
    event = parse_events.parse_event(dict(ev), cat)
    sig = P.syslog_control_signal(dict(ev, severity="warning", timestamp=TS), "t1", T0)
    assert event is not None and sig is not None
    assert event["rule_id"] == sig.attrs["rule_id"] == "syslog.bgp.route_churn"
    assert event["state"] == sig.attrs["state"] == "churn"
    assert event["labels"]["peer"] == sig.attrs["peer"] == "10.0.0.200"


def test_the_one_known_divergence_is_declared_and_bounded(catalog):
    """`bgp_adjacency_change` reads its transition target in the CONFORMANCE
    reader and not in the executable rule — an old defect that predates A3 and
    that closing would re-classify stored signals. It is recorded IN the row
    (`target_scope: catalog`) instead of hidden in a second grammar, and this
    test is the ceiling on how many such divergences may exist."""
    _data, rows = catalog

    def scopes(node, out):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "scan" and v.get("target_scope") == "catalog":
                    out.append(v)
                else:
                    scopes(v, out)
        elif isinstance(node, list):
            for v in node:
                scopes(v, out)
        return out

    diverging = sorted(r["rule_id"] for r in rows if scopes(r.get("extract"), []))
    assert diverging == ["syslog.bgp.adjacency_change"], (
        "a NEW spec/implementation divergence appeared. Either fix the rule "
        "(and re-bake the golden corpus) or record it here deliberately.")

    parse_events = pytest.importorskip("parse_events")
    flap_up = {"hostname": "leaf2", "appname": "%BGP-5-ADJCHANGE",
               "message": "peer 10.0.0.2 old state Idle new state Established"}
    assert parse_events.parse_event(dict(flap_up))["state"] == "up"
    sig = P.syslog_control_signal(dict(flap_up, severity="notice", timestamp=TS),
                                  "t1", T0)
    assert sig is not None and sig.attrs["state"] == "down"


# ══ 8. the lane entry point ══════════════════════════════════════════════════

def test_classify_routes_each_lane():
    assert P.classify(dict(LINK_EV), "syslog", "t1", T0).kind == "link_state_change"
    assert P.classify(
        dict(syslog_ev("%OPTICS-3-LOS", "no light detected on Ethernet4")),
        "port", "t1", T0).kind == "link_down_no_light"
    assert P.classify(
        {"device": "leaf9", "trap_oid": "1.3.6.1.6.3.1.1.5.1",
         "trap_name": "coldStart", "timestamp": TS}, "trap", "t1", T0
    ).kind == "device_restart"


def test_an_unknown_lane_raises_rather_than_classifying_nothing():
    """A typo must not read as "this event matched no rule" — that is a silent
    evidence hole, which §10 forbids."""
    with pytest.raises(ValueError, match="unknown parser lane"):
        P.classify(dict(LINK_EV), "sylsog", "t1", T0)
    with pytest.raises(ValueError, match="unknown parser lane"):
        P.classify(dict(LINK_EV), "catalog", "t1", T0)


# ══ 9. the DSL itself ════════════════════════════════════════════════════════

def _ctx(**base) -> Ctx:
    base.setdefault("ev", {})
    return Ctx(base, {"host": "sw1", "ts_ms": 7}, lambda: None)


def test_a_token_whose_vars_are_empty_is_dropped_not_stubbed():
    """`vlan{vlan}` with no VLAN must vanish, not become the token `vlan` — a
    stub like that welded every switch in the estate together (tracker 168)."""
    rule = P.RULES_BY_ID["syslog.evpn.mac_move"]
    sig = P.syslog_control_signal(dict(syslog_ev(
        "%EVPN-3-BLACKLISTED_DUPLICATE_MAC", "duplicate host detected")), "t1", T0)
    assert sig is not None and sig.attrs["rule_id"] == rule.rule_id
    assert sig.entity_tokens == ("leaf1",)
    assert not any(t.startswith("vlan") for t in sig.entity_tokens)


def test_a_device_local_token_is_qualified_with_its_device():
    sig = P.syslog_control_signal(dict(syslog_ev(
        "%HSRP-5-STATECHANGE", "Vlan10 Grp 1 state Standby -> Active")), "t1", T0)
    assert sig is not None
    assert sig.entity_tokens == ("leaf1", "leaf1:Vlan10", "leaf1:grp1")


def test_an_unknown_local_name_is_not_a_token():
    """`_device_local` dropped "unknown"; the declarative form must too, or every
    FHRP event with an unparsed interface grows a fake `<host>:unknown` node."""
    sig = P.syslog_control_signal(dict(syslog_ev(
        "%VRRP-6-STATECHANGE", "state Backup -> Master")), "t1", T0)
    assert sig is not None
    assert sig.attrs["interface"] == "unknown"
    assert "leaf1:unknown" not in sig.entity_tokens


def test_a_template_default_fills_only_an_empty_var():
    sig = P.syslog_control_signal(dict(syslog_ev(
        "%BGP-5-ADJCHANGE", "session went Down, no peer named")), "t1", T0)
    assert sig is not None
    assert sig.native_id == "leaf1|bgp_adj|?|down|1788343200000"


def test_the_reason_picker_skips_vendor_bookkeeping():
    """Cisco trails "(afi 0)" and Junos "(External AS 65001)" alongside the real
    reason, so the LAST non-bookkeeping parenthesis wins."""
    sig = P.syslog_control_signal(dict(syslog_ev(
        "%BGP-3-NOTIFICATION",
        "received from neighbor 10.0.0.200 (External AS 65001) 6/4 "
        "(Administrative Reset) 0 bytes")), "t1", T0)
    assert sig is not None
    assert sig.attrs["reason"] == "Administrative Reset"
    assert sig.attrs["code"] == "6/4"


def test_a_guard_reading_an_undeclared_var_fails_loudly():
    g = compile_guard({"truthy": "$nope"})
    with pytest.raises(RuleError, match="undeclared var"):
        g(_ctx(msg="x"))


def test_a_rule_reading_a_field_its_lane_does_not_build_is_rejected(catalog):
    """A field access is INLINED by the compiler (`c.base[field]`), so a typo
    would surface as a KeyError on a production line. The bake refuses it
    instead: each lane declares its haystacks and a row may only read those."""
    row = _row(catalog, "syslog.link.state_change")
    row["guard"] = {"contains": ["oid", "X"]}       # a trap field, on the syslog lane
    row.pop("pattern_src", None)
    _expect_rejected(catalog, row, "does not build")


def test_a_lazy_field_is_still_reachable_by_name():
    """`msg_u` / `ctoken_msg_u` are derived, not built by the lane, and must
    still resolve — they are how the SR-Linux nil-appname rules classify."""
    g = compile_guard({"contains": ["msg_u", "REMOTEPEER"]})
    assert g(_ctx(msg="lldp remotePeerRemoved on interface ethernet-1/1"))
    assert not g(_ctx(msg="nothing here"))
