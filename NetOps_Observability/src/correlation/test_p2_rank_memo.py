"""P2 delivery step 2 — the LEVEL-1 cross-epoch rank memo.

Spec: `docs/design/DECISION_EVIDENCE_SPLIT_P2_2026-08-28.md` §3 / §9 item 2;
level-2 companion `docs/design/COHORT_TOUCH_GATE_P1_2026-08-28.md` §1-§2;
measured brief `docs/scale/P2_COHORT_PROFILE_2026-08-28.md`.

THE CLAIM UNDER TEST, in one sentence: `rank(catalog, evidence)` reads a small,
enumerable projection of each Signal (`rank_memo.py`'s docstring lists it with
file:line refs), so two components whose projections agree get the SAME
`RankingResult` — and reusing it must not move one byte of anything persisted.

Every test below is one of four mutant checks:

  * **soundness** (T1, T2, T10) — perturb every NON-key field and `rank` must
    not move; perturb ANY key field and the key must. Drop a field from the key
    and T2 goes red; add a non-input to the key and T1's key assertion goes red.
  * **byte identity** (T4, T5) — the objects, digests, blobs and rows a memo-on
    run produces are IDENTICAL to a memo-off run's. T5 poisons the memo to prove
    T4 is not vacuous: serve a stale result and the byte test goes red.
  * **bounds and RSS** (T6, T7) — the LRU really evicts, and the value graph
    holds no Signal / Node / ObjectSnapshot (tracker 156). Make it unbounded and
    T6 goes red.
  * **determinism** (T3, T9) — the key is content-derived: shuffling the
    evidence, rebuilding it from `dataclasses.replace` copies, or computing it in
    a second process under a different PYTHONHASHSEED all give the same hex.
    Put a wall clock, an `id()` or a `hash()` in the key and T3 goes red.
"""
from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from dataclasses import fields as dc_fields
from dataclasses import replace as dc_replace
from datetime import datetime, timedelta, timezone

import pytest

import main
import rank_memo as RM
import signals as S
from catalog import builtin_catalog
from engine import EngineConfig, Node, ObjectSnapshot, run_window
from rank_memo import RankMemo, rank_key, signal_projection
from scoring import (
    VERIFICATION_HEALTHY_KIND,
    VERIFICATION_RESULT_KIND,
    HypothesisScore,
    RankingResult,
    rank,
)

CAT = builtin_catalog()
CFG = EngineConfig()
CATV = CAT.version_hash()
TENANT = "t1"
T0 = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

TEMPLATES = CAT.enabled_templates()
KIND_POOL = sorted({k for t in TEMPLATES for c in t.requires for k in c.kinds()})
MODALITIES = [S.ModalityClass.DEVICE_TELEMETRY, S.ModalityClass.CONTROL_PLANE,
              S.ModalityClass.PASSIVE_FLOW, S.ModalityClass.ACTIVE_PROBE]


# ── fixtures ─────────────────────────────────────────────────────────────────

def sig(kind: str, entity_id: str, *, offset_s: float = 0.0,
        modality: S.ModalityClass = S.ModalityClass.DEVICE_TELEMETRY,
        entity_type: S.EntityType = S.EntityType.INTERFACE,
        observer_id: str = "obs1", collection_path: str = "direct",
        tokens: tuple[str, ...] = (), tenant: str = TENANT,
        severity: S.Severity = S.Severity.HIGH, deviation: float = 9.0,
        attrs: dict | None = None, native: str = "") -> S.Signal:
    """The shared P1/P2 fixture shape (see test_p2_step01.sig), widened to reach
    every field the rank key claims to read."""
    return S.Signal(
        tenant_id=tenant, ts=T0 + timedelta(seconds=offset_s), source=S.Source.METRIC,
        kind=kind,
        observer=S.Observer(observer_id=observer_id,
                            observer_type=S.ObserverType.DEVICE,
                            collection_path=collection_path),
        modality_class=modality, entity_type=entity_type,
        entity_id=entity_id, severity=severity, deviation=deviation,
        native_id=native or f"p2rm|{tenant}|{kind}|{entity_id}|{offset_s}",
        entity_tokens=tokens,
        attrs=dict(attrs) if attrs else {"onset_uncertainty_s": 5.0})


def component(i: int, *, tenant: str = TENANT) -> list[S.Signal]:
    """One two-node identity-grounded component (the P1 fixture shape)."""
    return [
        sig("if_util_high", f"dev{i}:Gi0/1", offset_s=i * 0.1, tenant=tenant,
            tokens=(f"dev{i}", "Gi0/1")),
        sig("if_errors_high", f"dev{i}:Gi0/1", offset_s=i * 0.1 + 5,
            modality=S.ModalityClass.CONTROL_PLANE, tenant=tenant,
            observer_id="obs2", tokens=(f"dev{i}", "Gi0/1"),
            severity=S.Severity.WARN),
    ]


def mixed_window(n: int = 6, *, tenant: str = TENANT) -> list[S.Signal]:
    return [s for i in range(n) for s in component(i, tenant=tenant)]


def random_evidence(rng: random.Random) -> tuple[S.Signal, ...]:
    """A random evidence tuple built from a REAL template's clause vocabulary, so
    the property test exercises satisfied clauses, discriminators, the
    verification lanes and the verdict gate — not an empty scorer."""
    t = rng.choice(TEMPLATES)
    kinds = [min(c.kinds()) for c in t.requires] or [rng.choice(KIND_POOL)]
    out: list[S.Signal] = []
    for i, clause in enumerate(t.requires or ()):
        et = clause.entity_type or rng.choice(
            [S.EntityType.INTERFACE, S.EntityType.DEVICE, S.EntityType.SEGMENT])
        dev = f"dev{rng.randrange(3)}"
        mod = rng.choice(MODALITIES)
        attrs: dict = {"onset_uncertainty_s": 5.0}
        if mod is S.ModalityClass.ACTIVE_PROBE:
            attrs["probe_authority"] = rng.choice(["high", "medium", "low"])
            attrs["probe_scope"] = rng.choice(["customer_path", "internal_self_probe"])
            attrs["agent_host"] = f"agent{rng.randrange(2)}"
        out.append(sig(min(clause.kinds()), f"{dev}:if{i}", offset_s=i,
                       modality=mod, entity_type=et,
                       observer_id=f"obs{rng.randrange(3)}",
                       collection_path=rng.choice(
                           ["direct", "via_aggregator", "via_controller:vm1"]),
                       tokens=(dev,), deviation=rng.choice([0.0, 4.0, 41.5])))
    if rng.random() < 0.6:
        out.append(sig(VERIFICATION_RESULT_KIND, "dev0:if0", offset_s=20,
                       modality=S.ModalityClass.ACTIVE_VERIFICATION,
                       entity_type=((t.requires[0].entity_type if t.requires
                                     else None) or S.EntityType.INTERFACE),
                       observer_id="dev0", tokens=("dev0",),
                       attrs={"corroborates_kinds": [rng.choice(kinds)],
                              "verify_method": rng.choice(["ssh", "snmp", "tcp"])}))
    for j in range(rng.randrange(3)):
        out.append(sig(VERIFICATION_HEALTHY_KIND, "dev0:if0", offset_s=30 + j,
                       modality=S.ModalityClass.ACTIVE_VERIFICATION,
                       observer_id="dev0", tokens=("dev0",),
                       native=f"healthy|{j}|{rng.randrange(10**6)}",
                       attrs={"refutes_kinds": [rng.choice(kinds)],
                              "verify_method": rng.choice(["ssh", "snmp", "tcp"])}))
    rng.shuffle(out)
    return tuple(out)


# ── the NON-key fields: every Signal / Observer field rank provably cannot see ─

def perturb_non_key(rng: random.Random, s: S.Signal) -> S.Signal:
    """Move every field the key omits. If ANY of these turns out to influence
    `rank`, T1 goes red and the field JOINS the key — the memo never widens
    equality beyond the function's true inputs."""
    obs = dc_replace(
        s.observer,
        observer_type=rng.choice(list(S.ObserverType)),
        location=f"rack{rng.randrange(50)}",
        trust_domain=rng.choice(["enterprise", "cloud_tenant", "platform"]),
        clock_quality=rng.choice(["ntp", "ptp", "free_running", "unknown"]),
    )
    attrs = dict(s.attrs)
    attrs.update({
        "message": f"raw text {rng.randrange(10**9)}",
        "reason": f"reason-{rng.randrange(10**6)}",
        "environment": rng.choice(["prod", "lab"]),
        "scenario_id": f"sc{rng.randrange(999)}",
        "run_id": f"run{rng.randrange(999)}",
        "onset_uncertainty_s": float(rng.randrange(30)),
    })
    return dc_replace(
        s,
        ts=s.ts + timedelta(seconds=rng.randrange(-600, 600)),
        source=rng.choice(list(S.Source)),
        severity=rng.choice(list(S.Severity)),
        native_id=f"perturbed|{rng.randrange(10**12)}",   # ⇒ a NEW signal_id
        site=f"site{rng.randrange(20)}",
        path_id=f"p{rng.randrange(20)}",
        service_id=f"svc{rng.randrange(20)}",
        metric_name=f"m{rng.randrange(20)}",
        value=rng.random() * 1000,
        baseline=rng.random() * 1000,
        deviation=-s.deviation,                          # SIGN only: |d| is the input
        observer=obs,
        attrs=attrs,
    )


# ── a snapshot skeleton, so a RankingResult can be compared as BLOB BYTES ─────

def _base_snapshot() -> ObjectSnapshot:
    win = component(0)
    snaps = run_window(win, CAT, (), CFG)
    assert snaps, "fixture must materialize one object"
    return snaps[0]


BASE_SNAP = _base_snapshot()


def blob_of(ranking: RankingResult) -> str:
    """The hypotheses_blob BYTES this ranking produces, holding every other
    snapshot input fixed — the persisted artefact, not just the dataclass."""
    return dc_replace(BASE_SNAP, ranking=ranking).hypotheses_blob()


def stable_key() -> str:
    """A fixed evidence tuple's key. Imported and re-computed by a SECOND
    PROCESS in T3c, so it must depend on nothing but the content."""
    ev = tuple(component(7)) + (
        sig(VERIFICATION_HEALTHY_KIND, "dev7:Gi0/1", offset_s=9,
            modality=S.ModalityClass.ACTIVE_VERIFICATION, observer_id="dev7",
            native="healthy|stable|1",
            attrs={"refutes_kinds": ["if_util_high"], "verify_method": "ssh"}),
        sig(VERIFICATION_HEALTHY_KIND, "dev7:Gi0/1", offset_s=11,
            modality=S.ModalityClass.ACTIVE_VERIFICATION, observer_id="dev7",
            native="healthy|stable|2",
            attrs={"verify_method": "snmp"}),   # refutes nothing: still keyable
    )
    key = rank_key(TENANT, CATV, ev)
    assert key is not None
    return key


# ═══ T0 — the property test must not be vacuous ══════════════════════════════

def test_T0_the_random_fixture_really_exercises_the_scorer():
    """PREMISE for T1. A generator that only ever produced `undetermined` with
    no matched clause would make the perturbation test prove nothing."""
    named, contradicted, healthy, verified, satisfied, keyable = 0, 0, 0, 0, 0, 0
    for seed in range(60):
        ev = random_evidence(random.Random(seed))
        r = rank(CAT, ev)
        named += r.top_hypothesis != "undetermined"
        contradicted += any(h.contradicted for h in r.hypotheses)
        satisfied += any(h.satisfied for h in r.hypotheses)
        healthy += any(s.kind == VERIFICATION_HEALTHY_KIND for s in ev)
        verified += any(s.kind == VERIFICATION_RESULT_KIND for s in ev)
        keyable += rank_key(TENANT, CATV, ev) is not None
    assert named > 5, "no template ever wins — the fixture never reaches rank's hot path"
    assert satisfied > 20, "no clause ever matches"
    assert contradicted > 0, "the discriminator / refutation path is never reached"
    assert healthy > 10 and verified > 10, "the verification lanes are never reached"
    # T1's key assertion (`key(ev) == key(perturbed)`) would pass vacuously if
    # the derivation refused everything. It does not: the fail-closed cases are
    # the narrow ones.
    assert keyable > 35, f"only {keyable}/60 random evidence sets are keyable"


# ═══ T1 — SOUNDNESS: no non-key field can move rank ══════════════════════════

@pytest.mark.parametrize("seed", range(60))
def test_T1_perturbing_every_non_key_field_leaves_rank_identical(seed):
    """THE soundness proof. ts, signal_id, source, severity, site, path/service
    ids, metric name, value, baseline, the SIGN of deviation, observer_type /
    location / trust_domain / clock_quality and every unrelated attrs key are
    moved at once — and `rank` must return the same value AND serialize to the
    same blob bytes. The key must be unchanged too: a key that moved here would
    be reading something rank cannot see (a needless miss); a rank that moved
    here would mean the perturbed field belongs IN the key."""
    rng = random.Random(seed)
    ev = random_evidence(rng)
    perturbed = tuple(perturb_non_key(rng, s) for s in ev)

    a, b = rank(CAT, ev), rank(CAT, perturbed)
    assert a == b, "a non-key field moved the ranking"
    assert blob_of(a) == blob_of(b), "a non-key field moved the persisted blob bytes"
    assert json.dumps(a.to_dict(), sort_keys=True) == \
           json.dumps(b.to_dict(), sort_keys=True)
    assert rank_key(TENANT, CATV, ev) == rank_key(TENANT, CATV, perturbed), \
        "the key reads a field rank does not"


@pytest.mark.parametrize("seed", range(25))
def test_T1b_a_repeated_instance_of_evidence_already_held_keeps_the_key(seed):
    """The sustained-incident case (#100 damping): a component gains a NEW
    INSTANCE of evidence it already had. The DecisionKey (signal ids) moves; the
    RankKey must not — that is the entire cross-epoch value of level 1."""
    rng = random.Random(1000 + seed)
    ev = random_evidence(rng)
    dup = dc_replace(ev[0], ts=ev[0].ts + timedelta(seconds=7),
                     native_id=f"another-instance|{seed}")
    assert str(dup.signal_id) != str(ev[0].signal_id)
    assert rank(CAT, ev + (dup,)) == rank(CAT, ev)
    assert rank_key(TENANT, CATV, ev + (dup,)) == rank_key(TENANT, CATV, ev)


@pytest.mark.parametrize("seed", range(40))
def test_T1c_duplicating_k_signals_under_fresh_ids_changes_nothing(seed):
    """MULTIPLICITY-BLINDNESS — the assumption behind reducing the evidence to a
    SET of projections rather than a multiset.

    `rank` never reads how MANY signals carry a projection, only which
    projections are present. The audit (§11.6 of the spec) with file:line:

      * `_satisfying`'s tuple is used as a truthiness (scoring.py:196, 208, 244,
        258, 260), a `.extend` into matched_signals (197, 210), a
        `{s.kind for s in hits}` set (259) and an `any(...)` (244) — its LENGTH
        is never read;
      * `coverage` counts CLAUSES, not signals (scoring.py:214), and the
        optional bonus is per clause (212);
      * the rank sort's `-len(s.satisfied)` (506) counts clause kinds;
      * the healthy-verification tags are de-duplicated (247-248);
      * `verdicts.coverage` collapses signals to `set(seen.values())`
        (verdicts.py:243-246) — a set of frozen `Witness` VALUES, i.e. exactly
        the projection — and every threshold downstream
        (`modality_count`/`observer_count` vs MIN_MODALITIES/MIN_OBSERVERS at
        verdicts.py:210-215, 371-376) counts members of a frozenset.

    So k extra copies with fresh ids must move nothing. If this ever goes red,
    the key becomes a MULTISET (sorted list with counts)."""
    rng = random.Random(7000 + seed)
    ev = random_evidence(rng)
    dupes = []
    for j in range(rng.randrange(1, 4)):
        src = rng.choice(ev)
        dupes.append(dc_replace(
            src, ts=src.ts + timedelta(seconds=rng.randrange(1, 300)),
            native_id=f"dup|{seed}|{j}|{rng.randrange(10**9)}"))
    ids = {str(s.signal_id) for s in ev}
    assert all(str(d.signal_id) not in ids for d in dupes), "dupes must be new ids"
    fat = tuple(list(ev) + dupes)

    a, b = rank(CAT, ev), rank(CAT, fat)
    assert a == b, "signal multiplicity moved the ranking — the key must be a multiset"
    assert blob_of(a) == blob_of(b), "signal multiplicity moved the blob bytes"
    assert rank_key(TENANT, CATV, ev) == rank_key(TENANT, CATV, fat)


def test_T1d_the_witness_projection_is_exactly_Witness_equality():
    """The crux of T1c, isolated: `verdicts.coverage` de-duplicates by frozen
    `Witness` VALUE (verdicts.py:243), so the set key is sound only if equal
    projections imply equal Witnesses. Every Witness field (and every ProbeFate
    field it nests) must therefore be in the projection — this pins it against
    the dataclasses themselves, so a NEW field on either goes red here."""
    from signals import ProbeFate
    from verdicts import Witness, witness_of
    covered = {"observer_id", "modality", "authority", "probe_authority",
               "probe_scope", "support_only", "fate"}
    assert {f.name for f in dc_fields(Witness)} == covered, \
        "Witness gained a field — extend _witness_projection"
    assert {f.name for f in dc_fields(ProbeFate)} == {
        "agent_host", "source_egress", "seam_id", "target", "schedule_id"}, \
        "ProbeFate gained a field — extend _witness_projection"
    # ...and the implication itself, over the random corpus.
    seen: dict[tuple, Witness] = {}
    for s in range(200):
        for x in random_evidence(random.Random(9000 + s)):
            proj = signal_projection(x)[-1]
            w = witness_of(x)
            if proj in seen:
                assert seen[proj] == w, "equal projections, different Witnesses"
            seen[proj] = w
    assert len(seen) > 20, "the corpus never varied the witness"


# ═══ T2 — SOUNDNESS: every key field must move the key ═══════════════════════

def _probe(**kw) -> S.Signal:
    base = {"modality": S.ModalityClass.ACTIVE_PROBE, "entity_id": "dev1->dev2",
            "attrs": {"probe_authority": "high", "probe_scope": "customer_path",
                      "agent_host": "agentA", "source_egress": "203.0.113.7",
                      "seam_id": "seam-1", "schedule_id": "sch-1",
                      "target": "dev2"}}
    base.update(kw)
    eid = base.pop("entity_id")
    return sig("probe_loss", eid, **base)


KEY_CASES: dict[str, tuple] = {
    # (mutation of the FIRST signal of a two-signal fixture)
    "kind": (lambda s: dc_replace(s, kind="bgp_peer_flap"), None),
    "entity_type": (lambda s: dc_replace(s, entity_type=S.EntityType.DEVICE), None),
    "deviation_magnitude": (lambda s: dc_replace(s, deviation=abs(s.deviation) + 17.5), None),
    "entity_id": (lambda s: dc_replace(s, entity_id="devX:Gi9/9"), None),
    "entity_tokens": (lambda s: dc_replace(s, entity_tokens=("other-token",)), None),
    "modality_class": (lambda s: dc_replace(s, modality_class=S.ModalityClass.PASSIVE_FLOW), None),
    "observer_id": (lambda s: dc_replace(s, observer=dc_replace(
        s.observer, observer_id="somebody-else")), None),
    "collection_path": (lambda s: dc_replace(s, observer=dc_replace(
        s.observer, collection_path="via_controller:vmanage-9")), None),
}

PROBE_ATTR_CASES = ["probe_authority", "probe_scope", "agent_host",
                    "source_egress", "seam_id", "schedule_id", "target"]


@pytest.mark.parametrize("case", sorted(KEY_CASES))
def test_T2_every_key_field_changes_the_key(case):
    """Drop any one of these from `signal_projection` and this goes red."""
    mutate, _ = KEY_CASES[case]
    ev = tuple(component(1))
    other = (mutate(ev[0]),) + ev[1:]
    assert rank_key(TENANT, CATV, ev) != rank_key(TENANT, CATV, other), \
        f"{case} is a rank input but does not reach the key"


@pytest.mark.parametrize("attr", PROBE_ATTR_CASES)
def test_T2b_every_fate_or_authority_attr_changes_the_key(attr):
    """`witness_of` / `_fate_of` read these out of `attrs`; the projection calls
    those same functions, so a new attr they start reading is picked up for
    free — but the ones they read TODAY are pinned here."""
    a = _probe()
    battrs = dict(a.attrs)
    battrs[attr] = battrs[attr] + "-moved"
    b = _probe(attrs=battrs)
    assert rank_key(TENANT, CATV, (a,)) != rank_key(TENANT, CATV, (b,)), \
        f"attrs[{attr}] is a witness input but does not reach the key"


def test_T2c_verification_kind_lists_change_the_key():
    """corroborates_kinds / refutes_kinds are read on the verification lanes
    only — and they decide whether a clause is satisfied or refuted."""
    def result(kinds):
        return sig(VERIFICATION_RESULT_KIND, "dev1:Gi0/1",
                   modality=S.ModalityClass.ACTIVE_VERIFICATION,
                   attrs={"corroborates_kinds": kinds, "verify_method": "ssh"})

    def healthy(kinds):
        return sig(VERIFICATION_HEALTHY_KIND, "dev1:Gi0/1",
                   modality=S.ModalityClass.ACTIVE_VERIFICATION,
                   attrs={"refutes_kinds": kinds, "verify_method": "ssh"})

    base = tuple(component(1))
    assert rank_key(TENANT, CATV, base + (result(["if_util_high"]),)) != \
           rank_key(TENANT, CATV, base + (result(["bgp_peer_flap"]),))
    assert rank_key(TENANT, CATV, base + (healthy(["if_util_high"]),)) != \
           rank_key(TENANT, CATV, base + (healthy(["bgp_peer_flap"]),))
    # verify_method decides support_only, i.e. whether the witness may confirm.
    m1 = sig(VERIFICATION_HEALTHY_KIND, "dev1:Gi0/1",
             modality=S.ModalityClass.ACTIVE_VERIFICATION,
             attrs={"refutes_kinds": ["if_util_high"], "verify_method": "ssh"})
    m2 = dc_replace(m1, attrs={"refutes_kinds": ["if_util_high"],
                               "verify_method": "tcp"})
    assert rank_key(TENANT, CATV, (m1,)) != rank_key(TENANT, CATV, (m2,))


def test_T2d_two_distinct_refuting_witnesses_are_unkeyable():
    """`scoring.py:232` iterates the healthy-verification signals in
    `str(signal_id)` order and appends to an ORDER-SENSITIVE `contradictions`
    tuple. Signal ids are deliberately NOT in the key (a key that carried them
    hits 0 % across epochs — the measured finding this step routes around), so
    the derivation FAILS CLOSED exactly when that order becomes observable:
    two or more DISTINCT refuting healthy witnesses.

    The narrowness is the point — one refuting witness, several identical ones,
    or witnesses that refute nothing all stay keyable."""
    def healthy(kinds, native, *, method="ssh"):
        return sig(VERIFICATION_HEALTHY_KIND, "dev1:Gi0/1",
                   modality=S.ModalityClass.ACTIVE_VERIFICATION, native=native,
                   attrs=({"refutes_kinds": kinds, "verify_method": method}
                          if kinds else {"verify_method": method}))

    base = tuple(component(1))
    one = healthy(["if_util_high"], "h|a")
    same = healthy(["if_util_high"], "h|b")
    other = healthy(["if_errors_high"], "h|c")
    none_ = healthy([], "h|d")
    assert rank_key(TENANT, CATV, base + (one,)) is not None
    assert rank_key(TENANT, CATV, base + (one, same)) is not None, \
        "identical refuting witnesses impose no order"
    assert rank_key(TENANT, CATV, base + (one, none_)) is not None, \
        "a witness that refutes nothing imposes no order"
    assert rank_key(TENANT, CATV, base + (one, other)) is None, \
        "two distinct refuting witnesses must fail closed"
    # ...and the engine counts it rather than minting an id-dependent key.
    win = list(base) + [one, other]
    rm = RankMemo()
    run_window(win, CAT, (), CFG, cohort_keys=keys_of(win), rank_memo=rm)
    assert rm.unkeyable >= 1


def test_T2e_catalog_version_and_tenant_change_the_key():
    ev = tuple(component(1))
    k = rank_key(TENANT, CATV, ev)
    assert k != rank_key(TENANT, CATV + "x", ev), "a catalog reload must miss"
    assert k != rank_key("t2", CATV, ev), \
        "§3a: a key must be unable to cross a tenant boundary"


# ═══ T3 — DETERMINISM: content only, stable across processes ═════════════════

@pytest.mark.parametrize("seed", range(20))
def test_T3_shuffling_the_evidence_does_not_move_the_key(seed):
    rng = random.Random(2000 + seed)
    ev = list(random_evidence(rng))
    k = rank_key(TENANT, CATV, tuple(ev))
    for _ in range(4):
        rng.shuffle(ev)
        assert rank_key(TENANT, CATV, tuple(ev)) == k, \
            "arrival order reached the key"


@pytest.mark.parametrize("seed", range(20))
def test_T3b_replace_copies_key_identically(seed):
    """`dataclasses.replace` copies are different OBJECTS with the same content
    (and no `_signal_id_c` cache). An `id()`-derived key would go red here."""
    ev = random_evidence(random.Random(3000 + seed))
    copies = tuple(dc_replace(s) for s in ev)
    assert all(a is not b for a, b in zip(ev, copies))
    assert rank_key(TENANT, CATV, copies) == rank_key(TENANT, CATV, ev)


def test_T3c_the_key_is_identical_in_another_process():
    """Cross-process stability under a DIFFERENT PYTHONHASHSEED: a key that
    leaked `hash()`, `id()` or a wall clock cannot survive this."""
    mine = stable_key()
    for seed in ("0", "1", "12345"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        out = subprocess.run(
            [sys.executable, "-c",
             "import test_p2_rank_memo as T; print(T.stable_key())"],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env=env, capture_output=True, text=True, timeout=300, check=False)
        assert out.returncode == 0, out.stderr[-2000:]
        assert out.stdout.strip() == mine, \
            f"key is not stable across processes (PYTHONHASHSEED={seed})"


def test_T3d_the_key_is_a_sha256_hex_digest():
    k = stable_key()
    assert len(k) == 64 and all(c in "0123456789abcdef" for c in k)


# ═══ T4 — BYTE IDENTITY: memo on == memo off ════════════════════════════════

def drain(window, cohorts, *, rank_memo, **kw):
    """K cohorts over ONE frozen window, exactly as an epoch does. The level-2
    memo is deliberately OFF (memo=None) so every component reaches `rank` on
    every cohort — which is precisely the population level 1 serves."""
    out, carried = [], {}
    for cohort in cohorts:
        snaps = run_window(window, CAT, (), CFG, cohort_keys=cohort,
                           carried_edges=tuple(carried.values()),
                           memo=None, rank_memo=rank_memo, **kw)
        for s in snaps:
            for e in s.edges:
                carried[(e.from_node, e.to_node)] = e
        out.append(snaps)
    return out


def keys_of(sigs) -> frozenset[str]:
    from engine import build_nodes
    return frozenset(n.key for n in build_nodes(tuple(sigs)))


def fingerprint(snaps) -> list[tuple]:
    """Everything persistence and replay depend on, as bytes."""
    return [(s.correlation_id, s.content_hash(), s.material_hash(),
             s.hypotheses_blob(),
             json.dumps(s.to_object_row(1), sort_keys=True, default=str),
             json.dumps(s.ranking.to_dict(), sort_keys=True))
            for s in snaps]


@pytest.mark.parametrize("k", [2, 3, 5])
def test_T4_memo_on_is_byte_identical_to_memo_off(k):
    win = mixed_window(6)
    cohorts = [keys_of(win)] * k
    rm = RankMemo()
    off = drain(win, cohorts, rank_memo=None)
    on = drain(win, cohorts, rank_memo=rm)
    assert rm.hits > 0, "the memo never hit — this byte test would prove nothing"
    for a, b in zip(off, on):
        assert [s.correlation_id for s in a] == [s.correlation_id for s in b], \
            "emission ORDER moved"
        assert a == b, "a memo hit produced a different object"
        assert fingerprint(a) == fingerprint(b)


def test_T4b_a_storm_aggregate_is_byte_identical():
    """The storm-aggregate branch builds its RankingResult directly, without
    `rank` — it must be untouched, and the objects around it must still match."""
    win = mixed_window(4) + [
        sig("if_util_high", f"noise{i}:Gi0/9", offset_s=i, severity=S.Severity.WARN)
        for i in range(12)]
    cohorts = [keys_of(win)] * 3
    rm = RankMemo()
    off = drain(win, cohorts, rank_memo=None, storm_mode=True)
    on = drain(win, cohorts, rank_memo=rm, storm_mode=True)
    assert any(s.storm_aggregate for s in off[0]), "fixture must build an aggregate"
    assert rm.hits > 0
    for a, b in zip(off, on):
        assert a == b and fingerprint(a) == fingerprint(b)


def test_T4c_a_directed_component_is_byte_identical():
    """A directed object's blob embeds the orientations that make its edges
    replay deterministically (P1 §1.2). A reused ranking must not disturb them."""
    from directed_topology import DirectedTopology
    from engine import TopologyAdjacency
    from flow_direction import netflow_direction_source

    def rsig(dev, off):
        return sig("bgp_adjacency_change", dev, offset_s=off,
                   modality=S.ModalityClass.CONTROL_PLANE,
                   entity_type=S.EntityType.DEVICE, observer_id=dev,
                   tokens=(dev,))

    win = [rsig("leaf1", 0), rsig("spine1", 20)]
    adj = TopologyAdjacency.from_links([{"a": "leaf1", "b": "spine1"}])
    directed = DirectedTopology(sources=(("netflow", netflow_direction_source(
        {("leaf1", "spine1"): 1000.0, ("spine1", "leaf1"): 50.0})),))
    cohorts = [keys_of(win)] * 3
    rm = RankMemo()
    off = drain(win, cohorts, rank_memo=None, adjacency=adj, directed=directed)
    on = drain(win, cohorts, rank_memo=rm, adjacency=adj, directed=directed)
    assert off[0][0].orientations, "fixture must be a directed object"
    assert rm.hits > 0
    for a, b in zip(off, on):
        assert a == b and fingerprint(a) == fingerprint(b)
        assert a[0].orientations == b[0].orientations


# ═══ T5 — the byte test has teeth ═══════════════════════════════════════════

def test_T5_a_stale_memo_entry_is_caught_by_the_byte_test():
    """MUTANT CHECK. Poison the memo with a ranking from OTHER evidence; T4's
    byte comparison must go red. If this passes silently, T4 proves nothing."""
    win = mixed_window(3)
    cohorts = [keys_of(win)] * 2
    honest = drain(win, cohorts, rank_memo=RankMemo())

    poisoned = RankMemo()
    drain(win, [cohorts[0]], rank_memo=poisoned)   # populate honestly
    stale = rank(CAT, tuple(component(99)) + (
        sig("bgp_peer_flap", "dev99", entity_type=S.EntityType.DEVICE,
            modality=S.ModalityClass.CONTROL_PLANE),))
    for key in list(poisoned._lru):
        poisoned._lru[key] = stale
    second = drain(win, cohorts, rank_memo=poisoned)[1]
    assert fingerprint(second) != fingerprint(honest[1]), \
        "a stale ranking was invisible — the byte test is vacuous"


def test_T5b_full_window_runs_never_consult_the_memo():
    """§6 "what does NOT change": `cohort_keys is None` — golden wire, replay and
    every direct test call — is gated exactly like the level-2 memo, so those
    paths cannot be served a memo entry at all."""
    win = mixed_window(4)
    rm = RankMemo()
    a = run_window(win, CAT, (), CFG, rank_memo=rm)
    b = run_window(win, CAT, (), CFG, rank_memo=rm)
    assert rm.hits == 0 and rm.misses == 0 and len(rm) == 0, \
        "a full-window run consulted the level-1 memo"
    assert fingerprint(a) == fingerprint(b)
    # ...and the objects are what a run with no memo at all produces.
    assert fingerprint(a) == fingerprint(run_window(win, CAT, (), CFG))


# ═══ T6 — the LRU bound ═════════════════════════════════════════════════════

def test_T6_the_memo_is_bounded_and_evicts_least_recently_used():
    """MUTANT CHECK for "bounded": make the store an unbounded dict and the
    size/evicted assertions go red."""
    rm = RankMemo(max_entries=3)
    r = rank(CAT, tuple(component(1)))
    for i in range(3):
        rm.put(f"k{i}", r)
    assert len(rm) == 3 and rm.evicted == 0
    assert rm.get("k0") is r                     # promote k0 to most-recent
    rm.put("k3", r)                              # evicts k1, the LRU
    assert len(rm) == 3 and rm.evicted == 1
    assert rm.get("k1") is None and rm.get("k0") is r and rm.get("k3") is r
    for i in range(4, 40):
        rm.put(f"k{i}", r)
    assert len(rm) == 3, "the bound is not enforced"
    assert rm.evicted >= 34
    assert rm.stats()["max_entries"] == 3


def test_T6b_the_bound_is_read_from_the_environment_knob():
    assert RM.DEFAULT_MAX_ENTRIES == 50_000
    assert main.CORR_RANK_MEMO_MAX >= 1
    assert RankMemo(0).max_entries == 1, "a zero bound must not disable the bound"


# ═══ T7 — RSS: no evidence objects may be retained (tracker 156) ═════════════

def test_T7_the_memo_holds_no_evidence_objects():
    """The value is a RankingResult and nothing else. A memo that retained the
    snapshot (or a node, or a signal) would pin evidence the retention horizon
    has already released — the exact shape tracker 156 fought."""
    rm = RankMemo()
    drain(mixed_window(4), [keys_of(mixed_window(4))], rank_memo=rm)
    assert len(rm) > 0
    forbidden = (S.Signal, Node, ObjectSnapshot)
    seen: set[int] = set()

    def walk(o, path):
        if id(o) in seen:
            return
        seen.add(id(o))
        assert not isinstance(o, forbidden), f"memo retains {type(o).__name__} at {path}"
        if isinstance(o, (list, tuple, set, frozenset)):
            for i, x in enumerate(o):
                walk(x, f"{path}[{i}]")
        elif isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{path}[{k!r}]")
        elif hasattr(o, "__dataclass_fields__"):
            for f in dc_fields(o):
                walk(getattr(o, f.name), f"{path}.{f.name}")

    for key, value in rm._lru.items():
        assert isinstance(value, RankingResult)
        walk(value, key[:8])


def test_T7b_the_reused_result_is_immutable_and_never_mutated_downstream():
    """The same RankingResult object is handed to many components, so the
    downstream amendments must all COPY. `_cap_verdict`,
    `_break_ties_by_seam_affinity` and the unknown-hop amendment use
    `dataclasses.replace`; this pins that they leave the shared object alone.
    (Same invariant `scoring._build_inapplicable_score` has relied on since
    2026-08-22, where one HypothesisScore is shared catalog-wide.)"""
    assert RankingResult.__dataclass_params__.frozen
    assert HypothesisScore.__dataclass_params__.frozen
    win = mixed_window(4)
    rm = RankMemo()
    snaps = drain(win, [keys_of(win)] * 3, rank_memo=rm)[-1]
    # Every entry the memo still holds must equal a FRESHLY computed ranking of
    # the evidence its key describes — i.e. three cohorts of downstream caps,
    # tie-breaks and unknown-hop amendments left the shared object untouched.
    checked = 0
    for snap in snaps:
        ev = tuple(s for n in snap.nodes for s in n.signals)
        key = rank_key(snap.tenant_id, CATV, ev)
        if key is not None and key in rm._lru:
            assert rm._lru[key] == rank(CAT, ev), "the shared result was mutated"
            checked += 1
    assert checked > 0, "no memo entry was checked"


# ═══ T10 — the fail-closed guard ════════════════════════════════════════════

def test_T10_colliding_signal_ids_with_different_witnesses_are_unkeyable():
    """`verdicts.coverage` de-duplicates by `str(signal_id)`, FIRST-wins, so two
    signals sharing an id but not a witness make the outcome depend on arrival
    ORDER. No content key can describe that — the derivation returns None and
    the component is ranked in full."""
    a = sig("if_util_high", "dev1:Gi0/1", native="same-native")
    b = dc_replace(a, observer=dc_replace(a.observer, observer_id="a-different-box"))
    assert str(a.signal_id) == str(b.signal_id), "fixture must collide the ids"
    assert signal_projection(a) != signal_projection(b)
    assert rank_key(TENANT, CATV, (a, b)) is None
    # ...and the engine counts it instead of ranking from a bad key.
    rm = RankMemo()
    run_window([a, b], CAT, (), CFG, cohort_keys=keys_of([a, b]), rank_memo=rm)
    assert rm.unkeyable >= 1 and rm.hits == 0


def test_T10b_identical_duplicates_are_still_keyable():
    """The guard must fire on a genuine ambiguity only — two copies of the SAME
    signal are not one."""
    a = sig("if_util_high", "dev1:Gi0/1", native="same-native")
    assert rank_key(TENANT, CATV, (a, dc_replace(a))) is not None


# ═══ T8/T9 — wiring: flags, cross-epoch lifetime, counters ══════════════════

def test_T8_the_flags_disable_the_memo_on_one_image(monkeypatch):
    """Both knobs are read once at import (like every other CORR_* knob), so the
    A/B runs on ONE image. This pins the composition rule: the level-2 gate
    disables level 1 too (spec §3, last bullet)."""
    for env, expect in (({"CORR_RANK_MEMO": "0"}, None),
                        ({"CORR_COHORT_TOUCH_GATE": "0"}, None),
                        ({}, RankMemo)):
        code = ("import os,sys;"
                + "".join(f"os.environ[{k!r}]={v!r};" for k, v in env.items())
                + "sys.argv=['x'];import main;"
                "print(type(main.RANK_MEMO).__name__)")
        out = subprocess.run([sys.executable, "-c", code],
                             cwd=os.path.dirname(os.path.abspath(__file__)),
                             capture_output=True, text=True, timeout=300,
                             check=False)
        assert out.returncode == 0, out.stderr[-2000:]
        want = "NoneType" if expect is None else "RankMemo"
        assert out.stdout.strip().splitlines()[-1] == want, (env, out.stdout)


def test_T9_the_memo_outlives_the_epoch(monkeypatch):
    """THE difference from level 2. `_close_epoch` drops the ComponentMemo
    (its keys describe node objects that a prune rebuilds); the rank memo is
    keyed on CONTENT, so it must survive — that is where the 61 % of untouched-
    but-first-sighted components in a load epoch get their saving."""
    rm = RankMemo()
    monkeypatch.setattr(main, "RANK_MEMO", rm)
    win = mixed_window(4)
    drain(win, [keys_of(win)], rank_memo=rm)
    held = len(rm)
    assert held > 0
    ep = main._EngineEpoch(datetime.now(timezone.utc))
    ep.memos["t1"] = __import__("engine").ComponentMemo()
    main._close_epoch(ep)
    assert ep.memos == {}, "level 2 must die with the epoch"
    assert len(rm) == held, "level 1 must survive the epoch"
    assert main.RANK_MEMO is rm


def test_T9b_the_counters_reach_epoch_state_and_metrics(monkeypatch):
    rm = RankMemo()
    monkeypatch.setattr(main, "RANK_MEMO", rm)
    win = mixed_window(4)
    drain(win, [keys_of(win)] * 2, rank_memo=rm)
    assert rm.hits > 0 and rm.misses > 0

    st = main.epoch_state()
    assert st["rank_memo"] == rm.stats()
    assert st["rank_memo_enabled"] in (True, False)
    assert st["decision_memo_level1_hits_total"] == rm.hits
    assert st["decision_memo_level2_hits_total"] == main.COHORT_MEMO_HITS_TOTAL

    body = main._metrics_text()
    assert f'corr_rank_memo{{result="hit"}} {rm.hits}' in body
    assert f'corr_rank_memo{{result="miss"}} {rm.misses}' in body
    assert 'corr_rank_memo{result="evicted"}' in body
    assert 'corr_rank_memo{result="unkeyable"}' in body
    assert f"corr_rank_memo_entries {len(rm)}" in body
    assert f'corr_decision_memo_level{{level="1"}} {rm.hits}' in body
    assert f'corr_decision_memo_level{{level="2"}} {main.COHORT_MEMO_HITS_TOTAL}' in body
