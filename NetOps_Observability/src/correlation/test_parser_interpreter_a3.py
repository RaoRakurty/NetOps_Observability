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
import re
import sys
import time
from datetime import datetime, timezone

import pytest

import parser_rules
import producers as P
import rule_model
from rule_model import (
    Ctx,
    RuleError,
    compile_guard,
    compile_rule,
    compile_template,
    rules_hash,
)
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
    # 38 through A9 · 40 since A9b (`trap.config.change` emits;
    # `syslog.config.change` ships SHADOW — see events.yaml for why).
    assert len(P.RULES) == 40


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
        # A9b. Only the TRAP half: `syslog.config.change` is a shadow row, so it
        # emits nothing and the frozen code agrees with it line for line — its
        # corpus entries stay IN the parity run, which is what proves a shadow
        # row cannot change what the parser emits.
        "trap.config.change",
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
    """A parity run that never reaches a rule proves nothing about it.

    A SHADOW row is "reached" when its guard matches, not when it emits — it
    never emits by construction — so it is counted through `SHADOW_HITS`, which
    is the same signal `corr_parser_shadow_hits_total` exports. Reading emission
    alone would leave a shadow row permanently uncovered and the gap invisible.
    """
    before = dict(P.SHADOW_HITS)
    fired: set[str] = set()
    for entry in golden:
        for _name, fn, _old in LANE_FNS[entry["lane"]]:
            try:
                sig = fn(dict(entry["ev"]), "t1", T0)
            except DeadLetter:
                continue
            if sig is not None:
                fired.add(sig.attrs["rule_id"])
    fired |= {rid for rid, n in P.SHADOW_HITS.items() if n > before.get(rid, 0)}
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


def test_the_shipped_shadow_rows_are_exactly_the_declared_ones():
    """Pinned so a shadow row cannot be left switched on by accident: shipping
    one is a deliberate act, and this line is where you record it.

    `syslog.config.change` (A9b) is the first. Its grammar is finished and its
    trap twin emits; it is shadow for a WORKLOAD reason, not a parser one —
    `%SYS-5-CONFIG_I` is 35 of the 100 noise slots of the ratified V1 profile
    (`scripts/scale-miniladder.py EVENT_MIX_NOISE`), declared there as a line
    that never classifies, so emitting would re-classify a third of the V1
    background and silently re-baseline every capacity number measured on it.
    Promotion is `shadow: false` once that profile is versioned."""
    assert [r.rule_id for r in P.RULES if r.shadow] == ["syslog.config.change"]


def test_a_shadow_row_emits_nothing_and_still_counts_itself():
    """The A8 contract, on the first row to use it: the guard matches (the hit
    is counted, and `corr_parser_shadow_hits_total` exports it), evaluation
    continues, and the parser emits exactly what it would with the row absent —
    here nothing, because a config-change line is below the alarm floor."""
    ev = syslog_ev("%SYS-5-CONFIG_I", "Configured from console by admin on vty0")
    before = P.SHADOW_HITS["syslog.config.change"]
    assert P.syslog_control_signal(dict(ev), "t1", T0) is None
    assert P.SHADOW_HITS["syslog.config.change"] == before + 1


def test_a_shadow_row_contributes_nothing_to_the_ingest_screen():
    """A9b. The screen is what keeps the classifiers off the ~95 % of syslog
    that can never promote, so every literal in it admits more raw lines into
    both producers. A row that EMITS NOTHING must not buy that: re-derive the
    screen with the shadow rows included and assert the literal set is the one
    the runtime actually uses, i.e. that the shadow row added none of its own.

    This is also what keeps promotion a single act — flipping `shadow: false`
    re-derives the screen, the generated admission VRL and `rules_hash`
    together, instead of letting the admission change leak in ahead of the
    emission change."""
    assert [r.rule_id for r in P.RULES if r.shadow] == ["syslog.config.change"]
    shadow_markers = {m for r in P.RULES if r.shadow for m in r.markers}
    assert shadow_markers, "the row under test declares no markers to leak"
    assert not shadow_markers & set(P._CP_GUARD_MARKERS)
    assert P._SYSLOG_SCREEN_LITERALS is not None
    assert not {m.lower() for m in shadow_markers} & set(P._SYSLOG_SCREEN_LITERALS)
    # …and the whole screen equals the screen built from the NON-shadow rows,
    # which is the property stated directly rather than inferred from markers.
    non_shadow = {m.lower() for r in P.RULES
                  if r.lane == "syslog" and not r.shadow for m in r.markers}
    assert non_shadow <= set(P._SYSLOG_SCREEN_LITERALS)
    assert not P.syslog_promotable(dict(
        syslog_ev("%SYS-5-CONFIG_I", "Configured from console by admin on vty0")))


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


def _report(label: str, ratio: float, budget: float, detail: str) -> None:
    """Print the measured ratio on a PASS too.

    A gate that only speaks when it fails leaves its own margin invisible:
    tracker 234 was opened because nobody could see how far this number had
    drifted toward the budget until it started tripping. `pytest -s` now shows
    it on every run.
    """
    print(f"[cost] {label}: {ratio:.3f}x of the branch code "
          f"(budget {budget:.2f}x) — {detail}")


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
    _report("corpus", ratio, BENCH_RATIO, str(per_lane))
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
    _report("syslog", ratio, BENCH_RATIO,
            f"{t_new * 1e6 / count:.1f} vs {t_old * 1e6 / count:.1f} us/event")
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
    _report("trap", ratio, TRAP_BENCH_RATIO,
            f"{t_new * 1e6 / count:.1f} vs {t_old * 1e6 / count:.1f} us/event")
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


# ══ 6a. GUARD FUSION (tracker 234) ═══════════════════════════════════════════

# The cost gate above is met by COMPILING a guard subtree into one closure with
# an inline loop, instead of a Python call per node and per leaf. Two things
# have to hold for every fused shape, and both are pinned here:
#
#   * the shape must actually FUSE — a silent fall-back to the general tree is a
#     lost optimisation that no other test would notice; and
#   * the fused closure must answer exactly what the TREE answers, for every
#     combination of operand values.
#
# The second is checked against a reference evaluator rather than against
# hand-written expectations, so what is proved is "same as the tree", not "same
# as what the author believed the tree did".


def _c(field: str, lit: str) -> dict:
    return {"contains": [field, lit]}


def _ref_guard(node: dict, c: Ctx) -> bool:
    """The meaning the fused closures must keep: a plain recursive walk."""
    op, arg = next(iter(node.items()))
    if op == "all":
        return all(_ref_guard(n, c) for n in arg)
    if op == "any":
        return any(_ref_guard(n, c) for n in arg)
    if op == "not":
        return not _ref_guard(arg, c)
    if op == "contains":
        return str(arg[1]) in c.text(str(arg[0]))
    if op == "eq":
        return c.text(str(arg[0])) == str(arg[1])
    if op == "equals_any":
        return c.text(str(arg[0])) in {str(v) for v in arg[1]}
    if op == "re":
        return re.search(str(arg[1]), c.text(str(arg[0]))) is not None
    raise AssertionError(f"reference evaluator has no {op!r}")   # pragma: no cover


#: (closure name, guard node). The name is the CONTRACT: it says which of the
#: compiler's paths the shape earns.
FUSED_SHAPES = [
    # a flat list of eager leaves → one loop over a (kind, field, value) table
    ("_all_contains", {"all": [_c("ctoken", "A"), _c("ctoken", "B")]}),
    ("_all_contains", {"all": [_c("ctoken", "A"), {"eq": ["tag", "T"]}]}),
    ("_any_contains", {"any": [_c("ctoken", "A"), _c("msg", "B")]}),
    ("_any_contains", {"any": [{"equals_any": ["tag", ["T", "U"]]},
                               {"equals_any": ["ctoken", ["A", "AB"]]}]}),
    # one level of nesting → a table of GROUPS, bare leaves as one-element ones
    ("_all_of_any", {"all": [{"any": [_c("ctoken", "A"), _c("msg", "B")]},
                             _c("ctoken", "C")]}),
    ("_all_of_any", {"all": [{"any": [_c("ctoken", "A"), {"eq": ["tag", "T"]}]},
                             {"equals_any": ["tag", ["T", "U"]]}]}),
    ("_any_of_all", {"any": [{"all": [_c("ctoken", "A"), _c("msg", "B")]},
                             _c("ctoken", "C")]}),
    ("_any_of_all", {"any": [{"equals_any": ["tag", ["T"]]},
                             {"all": [_c("ctoken", "A"), _c("ctoken", "B")]}]}),
]

#: The shapes that must NOT fuse. Each names the property that stops it — a
#: fusion that swallowed one of these would be reading a haystack that is not
#: there, or evaluating an operand the tree would have skipped.
UNFUSED_SHAPES = [
    # a `re` leaf is not a table entry
    ("_all", {"all": [_c("ctoken", "A"), {"re": ["msg", "b."]}]}),
    # `not` is a NODE, not a leaf
    ("_all", {"all": [_c("ctoken", "A"), {"not": _c("ctoken", "B")}]}),
    ("_any", {"any": [_c("ctoken", "A"), {"not": _c("msg", "B")}]}),
    # a LAZY field is derived on first use, not a plain `base` index
    ("_any", {"any": [_c("msg_u", "A"), _c("ctoken", "B")]}),
    # three levels: exactly one level of nesting is fused
    ("_any", {"any": [{"all": [{"any": [_c("ctoken", "A")]}, _c("msg", "B")]},
                      _c("ctoken", "C")]}),
]

ALL_SHAPES = FUSED_SHAPES + UNFUSED_SHAPES
_SHAPE_IDS = [f"{i}-{name}" for i, (name, _n) in enumerate(ALL_SHAPES)]

#: Operand values chosen so every leaf of every shape above is decided both
#: ways, including the empty string (a haystack the lane built but left empty).
_OPERANDS = [
    {"ctoken": ct, "msg": m, "tag": tg}
    for ct in ("", "A", "B", "AB", "C", "ABC")
    for m in ("", "B", "xBy")
    for tg in ("", "T", "U")
]


@pytest.mark.parametrize("name,node", ALL_SHAPES, ids=_SHAPE_IDS)
def test_a_guard_compiles_to_the_closure_its_shape_earns(name, node):
    assert compile_guard(node).__name__ == name


@pytest.mark.parametrize("_name,node", ALL_SHAPES, ids=_SHAPE_IDS)
def test_a_compiled_guard_answers_exactly_what_the_tree_answers(_name, node):
    """THE FUSION PROOF. Every shape, fused or not, against every combination of
    its operands, compared with the recursive evaluator."""
    guard = compile_guard(node)
    for base in _OPERANDS:
        got = guard(_ctx(**base))
        want = _ref_guard(node, _ctx(**base))
        assert got == want, f"{node} on {base}: fused={got} tree={want}"


def test_the_group_table_is_the_declared_order():
    """`all` stops at the first failing GROUP and `any` at the first satisfied
    one, so the table has to be the tree's operand list in the tree's order.
    The equivalence test above cannot see a reordering — these leaves are pure —
    so the ORDER is pinned directly, on the table itself."""
    node = [{"any": [_c("ctoken", "A"), _c("ctoken", "B")]},
            _c("ctoken", "C"), {"any": [_c("msg", "D")]}]
    k = rule_model._CONTAINS
    assert rule_model._fused_groups(node, "any") == (
        ((k, "ctoken", "A"), (k, "ctoken", "B")),
        ((k, "ctoken", "C"),),
        ((k, "msg", "D"),),
    )


def test_a_flat_shape_does_not_become_a_group_table():
    """Nothing nested = the flat fusion already covers it with ONE loop instead
    of two, so the group form must decline and let it."""
    flat = [_c("ctoken", "A"), _c("ctoken", "B")]
    assert rule_model._fused_groups(flat, "any") is None
    assert compile_guard({"all": flat}).__name__ == "_all_contains"


@pytest.mark.parametrize("leaf", [
    {"contains": ["msg_u", "A"]},       # derived on first use
    {"contains": ["$peer", "A"]},       # an extraction, resolved through the memo
])
def test_a_lazy_field_or_a_var_never_reaches_a_fused_table(leaf):
    """Both forms are compiled to a plain `c.base[field]` index once fused —
    which is exactly what neither of these can be read with."""
    assert rule_model._fused_contains([leaf, _c("ctoken", "B")]) is None
    assert rule_model._fused_groups([{"any": [leaf]}, _c("ctoken", "B")],
                                    "any") is None


def test_a_lazy_field_leaf_reads_through_the_derivation_not_the_base_index():
    """A `contains` on an EAGER field compiles to `c.base[field]`; a lazy one
    must go through `Ctx.field`, which derives and memoizes it. A base index
    would KeyError on the first line that touched it."""
    g = compile_guard({"contains": ["msg_u", "ADJ"]})
    c = _ctx(msg="bgp adj down")
    assert "msg_u" not in c.base
    assert g(c)
    assert c.base["msg_u"] == "BGP ADJ DOWN"        # derived once, memoized


@pytest.mark.parametrize("node,want", [
    ({"re": ["msg", "ad[jk]"]}, True),
    ({"re": ["msg", "^nope"]}, False),
    ({"eq": ["tag", "%BGP-5-ADJCHANGE"]}, True),
    ({"ne": ["tag", "%BGP-5-ADJCHANGE"]}, False),
    ({"equals_any": ["tag", ["x", "%BGP-5-ADJCHANGE"]]}, True),
    ({"not_in": ["tag", ["%BGP-5-ADJCHANGE"]]}, False),
    ({"truthy": "msg"}, True),
    ({"truthy": "ctoken"}, False),
])
def test_an_eager_operand_leaf_reads_the_same_value_as_the_general_reader(node, want):
    """These leaves index `c.base` directly instead of calling the reader. The
    value they see must be the reader's."""
    c = _ctx(msg="bgp adj down", tag="%BGP-5-ADJCHANGE", ctoken="")
    assert compile_guard(node)(c) is want


class _Tagged(str):
    """A str SUBCLASS — what `v.__class__ is str` deliberately does not match."""


def _var_ctx(**lane_vars) -> Ctx:
    return Ctx({"ev": {}, "msg": "x", "ctoken": "", "tag": ""},
               dict(lane_vars), lambda: None)


def test_a_var_operand_goes_through_the_memo_not_the_base_index():
    c = _var_ctx(host="sw1", peer="10.0.0.9")
    assert compile_guard({"contains": ["$peer", "0.0.0"]})(c)
    assert not compile_guard({"eq": ["$peer", "10.0.0.1"]})(c)


def test_a_str_subclass_var_takes_the_general_coercion():
    """The reader short-circuits on `v.__class__ is str` because that is what
    every extraction returns today. A subclass MISSES that check by design and
    must fall through to the coercion below it — same answer, one branch later."""
    c = _var_ctx(host="sw1", peer=_Tagged("10.0.0.9"))
    assert compile_guard({"contains": ["$peer", "0.0.0"]})(c)
    assert compile_guard({"eq": ["$peer", "10.0.0.9"]})(c)


@pytest.mark.parametrize("value,want", [
    ("peer1", "peer1"),
    (_Tagged("peer1"), "peer1"),        # str subclass: coerced, not dropped
    (_Tagged(""), "-"),                 # ...and an EMPTY one still takes the default
    ("", "-"),
    (None, "-"),
    (0, "0"),
    (7, "7"),
    (True, "True"),
])
def test_a_template_var_renders_the_same_whatever_its_type(value, want):
    """Both template shapes carry the same `v.__class__ is str` short-circuit,
    so both are checked against the spellings the DSL allows."""
    one, _names = compile_template("{a|-}")
    many, _more = compile_template("[{a|-}]")
    assert one(_var_ctx(a=value)) == want
    assert many(_var_ctx(a=value)) == f"[{want}]"


# ══ 6b. THE `re` GUARD'S LITERAL SCREEN (tracker 234) ════════════════════════

# A `re` guard whose pattern is an alternation with bounded gaps
# (`A|B[^\n]{0,80}C`) is the one shape CPython's `re` cannot answer with its
# literal prescan — it walks the subject once per alternative. The twelve port
# rules are all that shape and measured 53 of `port_event_signal`'s 67 us/event,
# so those guards first test a set of literals a match MUST contain, derived by
# `regex_screen.pattern_screen` (the same derivation the ingest prefilter is
# built from).
#
# The screen is a NECESSARY condition, never a sufficient one, so the ONE thing
# that can go wrong is it rejecting a line the regex would have matched — a
# silently dropped signal. That is what this section proves, on the corpus and
# against the unscreened closure.

#: A pattern from the shipped port table: an alternation of long literals.
_SCREENED_PAT = ("unsupported\\s+transceiver|unqualified\\s+(sfp|transceiver|optic)"
                 "|not\\s+qualified|UNSUPPORTED_TRANSCEIVER")


def _re_guards_of_the_shipped_table() -> list[str]:
    pats: list[str] = []

    def walk(node):
        if not isinstance(node, dict) or len(node) != 1:
            return
        op, arg = next(iter(node.items()))
        if op in ("all", "any"):
            for child in arg:
                walk(child)
        elif op == "not":
            walk(arg)
        elif op == "re":
            pats.append(str(arg[1]))

    for rule in P.RULES:
        if rule.guard_src:
            walk(rule.guard_src)
    return pats


def test_the_screen_never_rejects_a_line_the_regex_matches(golden):
    """SOUNDNESS, over every shipped `re` guard and every corpus line: the
    screen is a necessary condition, so `regex matches => screen passes`. The
    other direction is allowed to be loose — a screen that passes a line the
    regex then rejects costs microseconds; one that rejects a line the regex
    would have matched drops a signal in silence."""
    pats = _re_guards_of_the_shipped_table()
    assert pats, "no `re` guard in the shipped table — nothing to prove here"
    texts: list[str] = []
    for entry in golden:
        ev = entry["ev"]
        texts.append(str(ev.get("message") or ""))
        texts.append(str(ev.get("appname") or ""))
        texts.append(f"{ev.get('message') or ''} {ev.get('facility') or ''} "
                     f"{ev.get('event_type') or ''} {ev.get('appname') or ''}")
    screened = 0
    for pat in pats:
        lits = rule_model._screen_of(pat)
        if lits is None:                    # fails OPEN, nothing to check
            continue
        screened += 1
        rx = re.compile(pat)
        for text in texts:
            if rx.search(text) is None:
                continue
            low = text.lower()
            assert any(lit in low for lit in lits), (
                f"UNSOUND screen: {pat!r} matched {text!r} but its literals "
                f"{sorted(lits)} rejected it")
    assert screened >= 5, (
        f"only {screened} of {len(pats)} shipped patterns are screened — if the "
        "table changed shape, re-measure before trusting the cost gate")


def test_a_screened_guard_answers_what_the_unscreened_one_does():
    guard = compile_guard({"re": ["pctoken", _SCREENED_PAT]})
    assert guard.__name__ == "_re_screened"
    rx = re.compile(_SCREENED_PAT)
    for text in ("unsupported transceiver in Et1/1", "UNSUPPORTED_TRANSCEIVER",
                 "unqualified sfp", "unqualified optic seen", "not  qualified",
                 "not qualified", "transceiver ok", "qualified", "", "all good"):
        assert guard(_ctx(pctoken=text)) is (rx.search(text) is not None), text


def test_a_pattern_whose_screen_would_not_pay_keeps_the_plain_regex():
    """The screen costs a fold and a literal scan, so it is taken ONLY when the
    literals are selective. `(Gi|Te|Fa|Po)` screens to two-character literals
    that pass nearly every line — pure added work — and a pattern with no
    mandatory literal at all is unscreenable and must fail OPEN."""
    for pat in (r"\b((?:Gi|Te|Fa|Po)[\d][\w/.\-]*)\b", r"[A-Z]+[0-9]*"):
        assert rule_model._screen_of(pat) is None
        assert compile_guard({"re": ["msg", pat]}).__name__ == "<lambda>"


def test_a_lazy_field_or_var_operand_is_never_screened():
    """The screen caches the folded haystack under `base`; an operand that is
    not a plain base index does not have one."""
    for ref in ("msg_u", "$peer"):
        assert compile_guard({"re": [ref, _SCREENED_PAT]}).__name__ == "<lambda>"


def test_the_folded_haystack_is_derived_once_for_the_whole_lane():
    """Twelve port rules read the same `pctoken`. The fold has to happen once
    per EVENT, not once per rule, or the screen costs more than it saves."""
    g1 = compile_guard({"re": ["pctoken", r"local\s+fault|LOCAL_FAULT"]})
    g2 = compile_guard({"re": ["pctoken", r"remote\s+fault|REMOTE_FAULT"]})
    ctx = _ctx(pctoken="Xcvr REMOTE_FAULT raised")
    key = rule_model._LOW + "pctoken"
    assert key not in ctx.base
    assert not g1(ctx)
    assert ctx.base[key] == "xcvr remote_fault raised"      # folded, memoized
    assert g2(ctx)


def test_the_screen_cache_key_cannot_collide_with_a_lane_field():
    """It is stored in `base` beside the lane's own haystacks, so it must be a
    name no catalog row can ever declare."""
    assert rule_model._LOW.startswith("\x00")
    for lane_fields in rule_model.LANE_FIELDS.values():
        assert not any(f.startswith("\x00") for f in lane_fields)
