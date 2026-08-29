"""Level-1 cross-epoch rank memo — P2 delivery step 2.

Spec: `docs/design/DECISION_EVIDENCE_SPLIT_P2_2026-08-28.md` §3 (and §9 item 2);
level-2 companion: `docs/design/COHORT_TOUCH_GATE_P1_2026-08-28.md` §1-§2
(`engine.ComponentMemo`). Measured brief:
`docs/scale/P2_COHORT_PROFILE_2026-08-28.md` — `rank` is 31.8 % of cohort wall
(lower bound), a memo keyed on node signal ids hits 0 % across epochs, and a
rank-level key matched 100 % of the reusable components with 0 collisions over
13,562 keys.

THE TWO LEVELS
--------------
* **Level 2** (`engine.ComponentMemo`, P1): key = the component's node-key SET,
  value = the whole materialized `ObjectSnapshot`, scope = ONE epoch. A hit
  skips everything. It cannot survive an epoch: after a prune the nodes are
  rebuilt, so the key no longer describes the same evidence.
* **Level 1** (this module, P2): key = a content-addressed projection of the
  evidence `scoring.rank` can actually SEE, value = the `RankingResult` alone,
  scope = the PROCESS. A hit skips `rank` only — the component still forms its
  edges and materializes its snapshot for THIS epoch (nodes and edges are
  per-epoch), and every downstream step that reads epoch context
  (`_break_ties_by_seam_affinity`, `_cap_verdict`, the unknown-hop amendment,
  the storm dedup, `ObjectSnapshot(...)`) still runs, unchanged.

SOUNDNESS IS PROVEN, NOT ASSUMED
--------------------------------
`rank(catalog, evidence)` (`scoring.py:489`) is pure. The key is EXACTLY the
inputs it reads — enumerated below by following every call it makes, at
`2abbf74d`+P2 steps 0-1. A field that is not in this list is proven, by the
property test `test_p2_rank_memo.py::test_T1_*`, to be invisible to `rank`.

Per-signal inputs `rank` reads (transitively):

| input | read at | via |
|---|---|---|
| `sig.kind` | `scoring.py:70` (`clause_matches`), `:89` (`_verification_corroborates`), `:233` (healthy-verification loop), `:483` (`evidence_kinds`) | clause vocabulary + verification lanes |
| `sig.entity_type` | `scoring.py:76`, `scoring.py:91` | clause `entity_type` constraint |
| `abs(sig.deviation)` | `scoring.py:78` (`abs(sig.deviation) < clause.min_deviation`) | clause `min_deviation`; only the ABSOLUTE value is ever read, so ±d are one equivalence class |
| `sig.entity_id` | `scoring.py:64` (`_same_entity`), `verdicts.py:133-135` (`_fate_of` → `_probe_target`) | verification co-identity; probe fate target |
| `sig.entity_tokens` | `scoring.py:66` (`set(a.entity_tokens) & set(b.entity_tokens)`) | verification co-identity — as a SET, order is not read |
| `probe_authority_of(sig)` | `scoring.py:102` (`_satisfying`), `scoring.py:481` (`evidence_kinds`); derived in `signals.py:296` from `modality_class` + `attrs["probe_authority"]` | the DEBUG_ONLY exclusion |
| `attrs["corroborates_kinds"]` | `scoring.py:93`, `scoring.py:485` | only for `kind == active_verification_result` |
| `attrs["refutes_kinds"]` | `scoring.py:236` | only for `kind == active_verification_healthy` |
| `verdicts.witness_of(sig)` | `verdicts.py:242` inside `coverage`, reached from `assess` (`scoring.py:270`) | THE whole verdict-gate projection — see below |

`witness_of` (`verdicts.py:147-192`) is itself the exact reader of everything
the verdict gate sees, so the key CALLS IT rather than re-listing its fields
(a re-listing could drift; a call cannot). What it reads:
`sig.modality_class`; `sig.observer.observer_id`; `sig.observer.collection_path`;
`sig.attrs["probe_authority"]`, `["probe_scope"]` (active_probe),
`["verify_method"]` (active_verification); and `_fate_of` (`verdicts.py:123`) →
`attrs["agent_host" | "agent_id" | "host_id"]`, `["source_egress" | "egress_ip"]`,
`["seam_id"]`, `["schedule_id"]`, `["target"]`, plus `entity_id` for a probe with
no explicit target. `coverage` then uses ONLY the resulting `Witness` values
(`verdicts.py:243-318`) — every derived number (`modality_count`,
`observer_count`, `independent_pair`, `fate_groups`, `trusted_modalities`,
`low_authority_probe_scopes`, `excluded_debug`) is a function of the sorted
witness SET.

Catalog / caller inputs:

| input | read at |
|---|---|
| `catalog.version_hash()` | `scoring.py:540`, `:559` — and it pins `enabled_templates()` + `_catalog_plan` (`scoring.py:497`), i.e. every template body the scorer walks |
| `tenant` | NOT read by `rank`. Folded into the key anyway — CLAUDE.md §3a: a cached verdict must be structurally unable to cross a tenant boundary, even when the two tenants' evidence projections are identical and the result would be equal by value. |

NOT in the key, and the property test perturbs every one of them:
`ts`, `signal_id` / `native_id` / `source` / `stored_signal_id` (but see ORDER
below), `severity` (nothing in `scoring.py` or `verdicts.py` reads it — the
severity floor is `engine.py`'s, before `rank`), `site`, `path_id`,
`service_id`, `metric_name`, `value`, `baseline`, the SIGN of `deviation`,
`observer.observer_type` / `.location` / `.trust_domain` / `.clock_quality`,
and every `attrs` key not listed above.

Epoch context (`storm_mode`, `topology_stale`): NOT in the key. `rank` does not
take them, and the steps that DO read them (`_cap_verdict`'s contract gates run
off `worst_data_class` and edge grounding; the snapshot's declarations) still
run on every hit — P2 §3's rule "if they only feed later steps, they are NOT in
the key and those steps still run".

ORDER, AND THE TWO PLACES `signal_id` LEAKS IN
----------------------------------------------
`rank` is order-insensitive — and independent of `signal_id` — except in two
spots. Neither is papered over, and neither is allowed into the key (a key that
carried signal ids would hit 0 % across epochs, which is the measured finding
this whole step exists to route around). Both are instead FAIL-CLOSED: the
derivation returns `None`, no key is minted, the component is ranked in full,
and the occurrence is counted as `unkeyable` — never silent.

1. `scoring.py:232-235` iterates the `active_verification_healthy` signals in
   `str(signal_id)` order, and the `contradictions` tuple it appends to is
   ORDER-SENSITIVE. The order is only OBSERVABLE when two of those witnesses
   REFUTE (non-empty `refutes_kinds`) and project differently; one refuting
   witness, or several identical ones, produce the same tuple in any order. So
   the key is refused exactly when ≥2 distinct refuting healthy witnesses are
   present.
2. `verdicts.py:242` de-duplicates by `str(signal_id)` with `setdefault`, i.e.
   FIRST-wins. That is invisible unless two signals in one component share a
   `signal_id` AND project differently (`signal_id` is
   `uuid5(NS, source|native_id|ts_ms)` — `signals.py:7` — which is NOT a
   superset of the projected fields, so a mis-stamping producer can do it). The
   key is refused there too.

With both refusals in place the key is a pure SET: shuffling the evidence, or
rebuilding it from `dataclasses.replace` copies, cannot move it.

WHY A SET AND NOT A MULTISET
----------------------------
The projections go into the key as a SET, so N signals sharing a projection
collapse to one. That is sound because `rank` is MULTIPLICITY-BLIND — audited
line by line, and pinned by `test_T1c` / `test_T1d`:

* `_satisfying`'s hit tuple is only ever a truthiness (`scoring.py:196, 208,
  244, 258, 260`), a `.extend` into `matched_signals` (`:197, :210`), a
  `{s.kind for s in hits}` set (`:259`) or an `any(...)` (`:244`). Its LENGTH is
  never read anywhere.
* Every count in the scorer counts CLAUSES or TEMPLATES, never signals:
  `coverage = (len(required) - len(missing)) / len(required)` (`:214`), the
  optional bonus per clause (`:212`), the rank sort's `-len(s.satisfied)`
  (`:506`) over clause kinds.
* Healthy-verification contradiction tags are de-duplicated on append
  (`:247-248`).
* `verdicts.coverage` collapses the evidence to `set(seen.values())`
  (`verdicts.py:243-246`) — a set of frozen `Witness` VALUES, which is exactly
  this projection (`test_T1d` pins field-for-field that `Witness` and
  `ProbeFate` hold nothing the projection omits). Every threshold downstream
  counts members of a frozenset: `modality_count` / `observer_count`
  (`verdicts.py:210-215`) against `MIN_MODALITIES` / `MIN_OBSERVERS`
  (`:371-376`); `independent_pair`, `fate_groups`, `trusted_modalities` and
  `excluded_debug` are all computed over the de-duplicated witness list.

A multiset key would ALSO be sound (strictly narrower), and was measured: it
changes no byte-identity test, only the two key-STABILITY tests — because it
loses exactly the case the memo exists for. A component that gains a NEW
INSTANCE of evidence it already had — the sustained-incident population #100
damping exists for — keeps its key under the set and loses it under the
multiset. That is the whole point: the DecisionKey (which hashes signal ids)
moves, the RankKey does not.

DETERMINISM
-----------
The key is `sha256` over canonical JSON of sorted tuples: no wall clock, no
arrival order (the projection set is sorted), no `id()`, no `hash()` (PYTHONHASH
SEED-salted), no float repr surprises beyond `repr()`'s round-trip guarantee.
The same evidence yields the same key in another process, on another day.

BOUNDS AND RSS (tracker 156)
----------------------------
TWO bounds, both enforced on every `put`, LRU eviction until BOTH hold:

* `CORR_RANK_MEMO_MAX` **entries** (default 50,000, read in `main.py`).
* `CORR_RANK_MEMO_BYTES_MAX` **bytes** (default 96 MiB, read HERE).

A `RankingResult` holds only strings, floats, bools, enums and dicts of those —
NO `Signal`, NO `Node`, NO `ObjectSnapshot`, NO window reference (pinned by
`test_T7_the_memo_holds_no_evidence_objects`). The value is shared by reference
across components: `RankingResult` and `HypothesisScore` are frozen dataclasses
and every downstream amendment (`_cap_verdict`, `_break_ties_by_seam_affinity`,
the unknown-hop `replace`) builds a NEW object — the same sharing invariant
`scoring._build_inapplicable_score` (`scoring.py:424-435`) has relied on since
2026-08-22.

WHY THE ENTRY BOUND ALONE WAS WRONG
-----------------------------------
`docs/scale/P2_MEMFLAT_ATTRIBUTION_2026-08-29.md` measured what an entry
actually costs, and it is not "a few KB":

* **12.8 KiB/entry marginal** (clearing 3,663 entries freed 46.87 MiB); 9.9
  KiB/entry on the deep-backlog leg; **25.8 KiB/entry inclusive** of the objects
  an entry shares with a live `ObjectSnapshot` (1,903 of 3,663 entries shared
  their `RankingResult` with an open object — those cost nothing extra).
* The docstring above is still true — no evidence objects — and it *still*
  leaves `hypotheses` → `HypothesisScore` → `Verdict` → `EvidenceCoverage`
  frozensets, plus the freshly-built `causal_chain` dicts.
* At 50,000 entries that licenses **500-650 MiB of RSS** on a box whose whole
  container budget is 1.25 GiB.

CONFIRMED ON THE LIVE RUN: `docs/scale/P2_STEPS012_2P5K_VERDICT_2026-08-29.md`
§3 reports 38,936 hits / 59,053 lookups, i.e. **20,117 misses = 20,117 entries
minted** with nothing ever evicted. 20,117 x 12.8 KiB = **252 MiB** — against the
+259 MiB post-input RSS growth that failed the `memflat` gate. The attribution
brief predicted exactly this ("N ~ 20,000-26,000 would explain the failure
outright"); the byte bound is the fix.

THE BYTE ESTIMATOR — CALIBRATED, NOT AN UPPER BOUND
---------------------------------------------------
`estimate_result_bytes` walks the value graph once per `put` and must answer ONE
question: **how much memory does the process give back when this entry is
evicted?** The first version (5c035667) answered a different one — it summed
`sys.getsizeof` with no id-`seen` set and no model of what the catalog already
owns, and was documented as a deliberate UPPER bound.

THE LIVE RUN PROVED THAT WRONG (2.5K run p2-s04-08290653, replica-3, /metrics
07:54 UTC). With `CORR_RANK_MEMO_BYTES_MAX` = 96 MiB the memo held **1,780
entries** (`corr_rank_memo_bytes` ~ 100.6 MB, i.e. ~56 KiB/entry by that
estimator), **evicted 38,177**, and the hit rate collapsed to **6 %** (2,510
hits / 39,957 misses) against **66 %** on the previous, unbounded run. An
inflated meter is not a conservative bound — it is a SMALLER CAP than the one
the operator configured, and it cost the memo its entire reason to exist.

The estimator now applies three rules, each measured in
`bench_memflat_p2.py --calibrate` against a `tracemalloc` reference (start
tracing, mint N real results, read `current`, drop them, read `current` again —
the difference IS the aggregate marginal, with cross-entry sharing charged once
exactly as RSS charges it):

1. **An id-`seen` walk.** An object reachable twice from one entry is charged
   once. Worth **-5.5 KiB/entry** of 33.6.
2. **Catalog ownership charged ZERO.** Everything reachable from the `Catalog`
   and from `scoring._catalog_plan`'s outputs — template titles, owner strings,
   `first_steps` tuples, seams, operator/manager phrasing, and the SHARED
   `inapplicable` `HypothesisScore` objects every RCA object points at — lives
   as long as the catalog does. Evicting an entry frees none of it. Worth
   **-12.8 KiB/entry**, the dominant term and the defect that made 96 MiB behave
   like a ~2,000-entry cap. `_owned_ids` builds the id set once per catalog
   version (6,005 ids on the built-in catalog) and revalidates it in O(1)
   against `scoring._CATALOG_PLAN_CACHE`.
3. **The per-instance `__dict__` charged.** `getsizeof` on a non-slots frozen
   dataclass does not include it, and one `RankingResult` graph holds hundreds.
   Worth **+5.0 KiB/entry** — the estimator was under-charging here while
   over-charging elsewhere.

MEASURED (400 rank-key-distinct storm-shaped results from the real drain sweep,
`bench_memflat_p2.py --calibrate`):

| shape | tracemalloc marginal | calibrated | ratio | 5c035667 |
|---|---|---|---|---|
| 400 dev / 3k sig / 2 epochs | 20.27 KiB/entry | 19.83 | **0.978x** | 32.80 (1.618x) |
| 250 dev / 5k sig / 4 epochs | 24.25 KiB/entry | 23.81 | **0.982x** | 39.22 (1.618x) |

The `gc.get_referents` deep walk agrees with `tracemalloc` to 0.002 %
(8,307,634 B walked vs 8,307,450 B freed), so the two instruments are
independent and neither is measuring itself.

COST: **0.24-0.30 ms/entry** (best of three warm passes, measured OUTSIDE the
traced window — tracemalloc roughly triples a walk that allocates a `seen` set),
against `rank()` at 2.6-5.4 ms: **5.5-9.2 %** of a call it only runs on a MISS,
and FASTER than the 0.35-0.49 ms/entry the uncalibrated walk cost, because an
owned subtree is pruned at its root instead of being summed.

WHAT IT STILL DOES NOT MODEL, on purpose:

* **Cross-entry sharing of non-catalog objects** — measured at 0.2 KiB/entry
  (1 % ). Modelling it needs a process-wide id registry, i.e. an unbounded map
  to save 1 %.
* **Sharing with the LIVE WORKING SET.** In situ (3 arrival epochs, 400 devices,
  4k signals) the memo held 2,681 entries: the estimator read 67.37 MB, the
  reference INCLUSIVE deep walk 69.12 MB (**0.975x**) — but the EXCLUSIVE walk,
  which charges the working set first, read only 35.47 MB, because **1,405 of
  2,681 entries (52 %)** shared their `RankingResult` with a still-open
  `ObjectSnapshot` and cost no marginal RSS at all. The live run measured the
  same 52 %. The memo cannot see that — an open object closes and the sharing
  ends — so it charges what it holds. This, not estimator error, is most of the
  distance between "56 KiB/entry metered" and the attribution brief's "12.8
  KiB/entry freed on clear".

Enum members are still charged 0: `VerdictTier`, `ModalityClass` and
`ProbeScope` are module-level singletons and the entry's marginal cost is the
pointer its container already paid.

DETERMINISM: `sys.getsizeof`, `len` and `id` only — no `hash()`, no clock. `id`
is a membership token for "already charged / catalog-owned", never mixed into
the number, so the SUM is a function of the graph's sharing structure — which
`rank()` reproduces exactly — and not of any address. `test_B10` pins it.

WHY 96 MiB, AND WHAT IT NOW ADMITS
----------------------------------
The 2.5K replica runs in a **1.25 GiB (1,280 MiB)** container and entered the
`memflat` window at 494 MiB, so the whole post-input growth budget the x1.3 gate
allows is ~148 MiB. The default is UNCHANGED at 96 MiB (7.5 % of the container);
what changed is that the number now means what it says.

Entries admitted at 96 MiB, by measured shape:

| shape | calibrated KiB/entry | entries admitted | was (5c035667) |
|---|---|---|---|
| 400 dev / 3k sig | 19.83 | **4,957** | 2,997 |
| 250 dev / 5k sig x4 | 23.81 | **4,128** | 2,506 |
| in-situ sweep (2,681 held) | 25.7 | **3,910** | 2,415 |
| LIVE 2.5K (56.5 KiB metered / 1.618) | ~34.9 | **~2,880** | 1,780 |

So the correction is **1.62x more entries for the same RSS**, uniformly across
shapes — NOT the 4x a naive reading of "12.8 KiB TRUE marginal" would predict.
That 12.8 KiB figure is the RSS freed by `RankMemo.clear()` divided by ALL
entries, including the 52 % that shared their result with an open object and
therefore freed nothing; per UNSHARED entry it is ~27 KiB, which is the band
this estimator now reads.

HIT RATE — STILL THE UNKNOWN, AND STILL MEASURED, NOT ASSUMED
--------------------------------------------------------------
The live run with an unbounded memo minted **20,117 entries** and reached 66 %.
With ~2,900-5,000 LRU entries the hit rate is **unknown**: neither brief carries
a hit-rate-vs-entries curve. What is known is that the rate CLIMBED (29 % early
in the storm -> 66 %) "as evidence repeats", i.e. reuse is recency-clustered,
which is the access pattern LRU is built to keep.

**`corr_rank_memo{result="evicted"}` is the readout.** It was 38,177 on the run
that collapsed to 6 %; the same counter against `corr_rank_memo{result="hit"}`
on the next run is the exact measurement of what the bound costs. Raise
`CORR_RANK_MEMO_BYTES_MAX` if evictions climb while `corr_rank_memo_bytes` sits
far under the container's headroom — the knob now moves entries roughly
linearly, which it did not before.
"""

from __future__ import annotations

import gc
import hashlib
import json
import os
import sys
import types
from collections import OrderedDict
from dataclasses import fields as dataclass_fields
from dataclasses import is_dataclass
from enum import Enum

import scoring
from scoring import (
    VERIFICATION_HEALTHY_KIND,
    VERIFICATION_RESULT_KIND,
    RankingResult,
    _attr_kinds,
)
from signals import Signal, probe_authority_of
from verdicts import Witness, witness_of

# Entry bound. Kept at the profile's reusable-component population; it is no
# longer the bound that binds — see DEFAULT_MAX_BYTES and the docstring.
DEFAULT_MAX_ENTRIES = 50_000

# Byte bound. 96 MiB — justified in the docstring (WHY 96 MiB) against the
# 1.25 GiB container, the measured 10-26 KiB/entry, and the 20,117 entries the
# live 2.5K replica minted unbounded.
DEFAULT_MAX_BYTES = max(
    1, int(os.environ.get("CORR_RANK_MEMO_BYTES_MAX", str(96 * 1024 * 1024))))


# ── the byte estimator (docstring: THE BYTE ESTIMATOR) ───────────────────────
_getsizeof = sys.getsizeof
_STR_BASE = _getsizeof("")
# One number for every float/int/bool in the graph. CPython's are 24-32 B and
# small ints are interned; a single constant keeps the walk branch-free.
_SCALAR_BYTES = 24
# type -> (the dataclass field names to walk, the per-instance `__dict__` bytes),
# derived once. Bounded by the number of distinct types in a RankingResult value
# graph (RankingResult, HypothesisScore, Verdict, EvidenceCoverage, Witness) —
# it is a memo of the SCHEMA, not of the data, so it cannot grow with traffic.
#
# The `__dict__` size is cached PER TYPE because every instance of one of these
# frozen dataclasses is built by the same generated `__init__`, in the same
# field order, with no lazily-added attribute (verified: no `object.__setattr__`
# and no `cached_property` anywhere in scoring.py / verdicts.py), so the dict's
# key set — and therefore `getsizeof` — is a property of the type.
_FIELD_NAMES: dict[type, tuple[tuple[str, ...], int]] = {}

# ── catalog ownership (docstring: THE OWNERSHIP TEST) ────────────────────────
# Traversing the catalog with `gc.get_referents` needs no per-type knowledge, so
# a template field nobody remembered cannot be missed. Classes, modules and
# functions are NOT followed: a type reference reaches the whole interpreter.
_SKIP_TYPES: tuple[type, ...] = (
    type, types.ModuleType, types.FunctionType, types.MethodType,
    types.BuiltinFunctionType, types.GetSetDescriptorType,
    types.MemberDescriptorType, types.WrapperDescriptorType,
    types.MethodDescriptorType, types.ClassMethodDescriptorType,
)
# catalog version hash -> (the plan cache's key tuple, the plan TRIPLES that
# matched, the ids of everything they own).
#
# The triples are held by STRONG reference on purpose: an id is only a valid
# ownership token while the object behind it is alive, and CPython recycles
# addresses.
#
# Revalidation is on the TRIPLE, not on the Catalog: `_catalog_plan` can be
# evicted and rebuilt for the SAME Catalog object, minting fresh `inapplicable`
# HypothesisScore objects that an older id set would no longer name.
#
# ALL matching triples are unioned. Two distinct `Catalog` objects can carry the
# same version hash (`builtin_catalog()` called twice), and a `RankingResult`
# carries only the hash — so which of them produced it is not knowable. Both are
# process-lifetime, so charging an entry for neither is correct, and a union
# cannot under-charge a live catalog's objects.
_OWNED_CACHE: dict[str, tuple[tuple[int, ...], tuple[tuple, ...],
                              frozenset[int]]] = {}
_OWNED_CACHE_MAX = 4
_EMPTY_OWNED: frozenset[int] = frozenset()


def _owned_ids(version: str) -> frozenset[int]:
    """Every object id reachable from the catalog(s) of `version` — the objects a
    memo entry POINTS AT but does not own, so evicting it frees none of them.

    HOT PATH: a dict lookup, one int-tuple compare over the plan cache's (at
    most 4) keys, and one identity check per matched triple. `version_hash()` is
    called ONLY on a rebuild — it is itself cached behind a 4-entry map that
    recomputes a sha256 over the whole template corpus when it overflows, so it
    must never be on the per-`put` path. `_catalog_plan` is never CALLED here:
    metering a value can neither build a plan nor evict one.

    When no catalog resolves (a synthetic value, a cleared plan cache) the set is
    EMPTY — the estimator falls back to charging everything, which is the
    conservative direction for a memory bound."""
    plan = scoring._CATALOG_PLAN_CACHE
    keys = tuple(plan)
    cached = _OWNED_CACHE.get(version)
    if (cached is not None and cached[0] == keys
            and all(plan.get(id(e[0])) is e for e in cached[1])):
        return cached[2]
    entries = tuple(e for e in plan.values() if e[0].version_hash() == version)
    if not entries:
        return _EMPTY_OWNED
    seen: set[int] = set()
    stack: list = []
    for entry in entries:
        stack.extend(entry)
    while stack:
        obj = stack.pop()
        oid = id(obj)
        if oid in seen or isinstance(obj, _SKIP_TYPES):
            continue
        seen.add(oid)
        stack.extend(gc.get_referents(obj))
    ids = frozenset(seen)
    if len(_OWNED_CACHE) >= _OWNED_CACHE_MAX:
        _OWNED_CACHE.clear()
    _OWNED_CACHE[version] = (keys, entries, ids)
    return ids


def _walk(obj: object, seen: set[int], owned: frozenset[int]) -> int:
    """Charge every object in the value graph ONCE, and only if the catalog does
    not already own it."""
    t = type(obj)
    # `type(obj) is str`, NOT `isinstance`: a str-subclass Enum member
    # (`VerdictTier`, `ModalityClass`) must fall through to the Enum branch and
    # be charged 0, not charged as a fresh string on every entry.
    if t is str:
        oid = id(obj)
        if oid in owned or oid in seen:
            return 0
        seen.add(oid)
        return _STR_BASE + len(obj)          # type: ignore[arg-type]
    if t is float or t is int or t is bool:
        # Not id-tracked: a float header is 24 B and small ints are interned, so
        # the bookkeeping would cost more than the number it corrects.
        return _SCALAR_BYTES
    if obj is None:
        return 0
    oid = id(obj)
    if oid in owned or oid in seen:
        return 0
    seen.add(oid)
    if t is tuple or t is list or t is set or t is frozenset:
        total = _getsizeof(obj)
        for item in obj:                       # type: ignore[attr-defined]
            total += _walk(item, seen, owned)
        return total
    if t is dict:
        total = _getsizeof(obj)
        for key, value in obj.items():         # type: ignore[attr-defined]
            total += _walk(key, seen, owned) + _walk(value, seen, owned)
        return total
    plan = _FIELD_NAMES.get(t)
    if plan is None:
        # A frozen dataclass without __slots__ carries a per-INSTANCE `__dict__`
        # that `getsizeof(instance)` does not include — 104-296 B each, and one
        # RankingResult graph holds hundreds of them. Omitting it under-charged
        # the walk by 4.9 KiB/entry. Only the dict CONTAINER is charged: its
        # keys are the type's interned attribute names, shared by every
        # instance, and its values are the fields walked below.
        inst = getattr(obj, "__dict__", None)
        plan = ((tuple(f.name for f in dataclass_fields(obj))
                 if is_dataclass(obj) and not isinstance(obj, type) else ()),
                _getsizeof(inst) if type(inst) is dict else 0)
        _FIELD_NAMES[t] = plan
    names, dict_bytes = plan
    if not names:
        # An Enum member is one module-level singleton shared by every entry:
        # the entry's marginal cost is the pointer its container already paid.
        return 0 if isinstance(obj, Enum) else _getsizeof(obj)
    total = _getsizeof(obj) + dict_bytes
    for name in names:
        total += _walk(getattr(obj, name), seen, owned)
    return total


def estimate_result_bytes(obj: object,
                          owned: frozenset[int] | None = None) -> int:
    """The bytes one memo value MARGINALLY retains — calibrated, not an upper
    bound (module docstring: THE BYTE ESTIMATOR).

    Three rules, each measured in `bench_memflat_p2.py --calibrate`:

    * **id-`seen` walk** — an object reachable twice from one entry is charged
      once. Without it the walk over-charged 5.5 KiB/entry (16 %).
    * **catalog ownership** — anything reachable from the `Catalog` (template
      titles, owner strings, first-steps tuples, the shared `inapplicable`
      `HypothesisScore` objects of `scoring._catalog_plan`) is charged 0: it
      lives as long as the catalog does, and evicting the entry frees none of
      it. Without it the walk over-charged 13.7 KiB/entry (46 %) — the defect
      that made a 96 MiB budget behave like a ~2,000-entry cap on the live 2.5K
      run.
    * **per-instance `__dict__`** — charged (+4.9 KiB/entry), because
      `getsizeof` on a non-slots dataclass instance does not include it.

    `owned` overrides the ownership set (tests, and sub-objects that carry no
    catalog version); the default resolves it from `RankingResult.catalog_version`
    against `scoring._CATALOG_PLAN_CACHE`, which is a dict lookup after the
    first call per catalog.

    DETERMINISM: `sys.getsizeof`, `len` and `id` only — no `hash()`, no clock.
    `id` is used ONLY as a set membership token for "already charged"; the SUM
    depends on the value graph's sharing structure, not on any address, so two
    `rank()` calls on the same evidence estimate identically in any process."""
    if owned is None:
        owned = (_owned_ids(obj.catalog_version)
                 if type(obj) is RankingResult else _EMPTY_OWNED)
    return _walk(obj, set(), owned)


def _witness_projection(w: Witness) -> tuple:
    """Every field of the Witness `coverage` may read. Enumerated here (rather
    than hashing the dataclass) so the canonical form is stable across
    processes — `hash()` is PYTHONHASHSEED-salted and must never reach a key."""
    fate = w.fate
    return (
        w.observer_id,
        w.modality.value,
        w.authority or "",
        w.probe_authority.value if w.probe_authority is not None else "",
        w.probe_scope.value if w.probe_scope is not None else "",
        bool(w.support_only),
        # A TUPLE, not a joined string: a delimiter could be forged inside an
        # attrs value, and two different fates must never canonicalize alike.
        (() if fate is None else
         (fate.agent_host, fate.source_egress, fate.seam_id,
          fate.target, fate.schedule_id)),
    )


def signal_projection(sig: Signal) -> tuple:
    """The part of one Signal `scoring.rank` can see — the module docstring's
    table, in canonical (JSON-serializable, sortable) form.

    It CALLS the same readers the scorer calls (`probe_authority_of`,
    `_attr_kinds`, `witness_of`) instead of re-deriving them, so the key cannot
    drift from the function it claims to describe."""
    kind = sig.kind
    pa = probe_authority_of(sig)
    return (
        kind,
        sig.entity_type.value,
        # Only |deviation| is ever compared (scoring.py:78); the sign is not read.
        repr(abs(sig.deviation)),
        sig.entity_id,
        tuple(sorted(set(sig.entity_tokens))),
        pa.value if pa is not None else "",
        (tuple(sorted(_attr_kinds(sig, "corroborates_kinds")))
         if kind == VERIFICATION_RESULT_KIND else ()),
        (tuple(sorted(_attr_kinds(sig, "refutes_kinds")))
         if kind == VERIFICATION_HEALTHY_KIND else ()),
        _witness_projection(witness_of(sig)),
    )


def rank_key(tenant: str, catalog_version: str,
             evidence: tuple[Signal, ...] | list[Signal]) -> str | None:
    """The level-1 key, or None when the evidence hits the one degenerate case
    the projection cannot describe (docstring, ORDER §2).

    Content-derived only: `sha256` over canonical JSON of
    (tenant, catalog version, the SORTED SET of signal projections)."""
    by_id: dict[object, tuple] = {}
    projections: set[tuple] = set()
    refuting: set[tuple] = set()
    for s in evidence:
        proj = signal_projection(s)
        sid = s.signal_id
        prev = by_id.get(sid)
        if prev is None:
            by_id[sid] = proj
        elif prev != proj:
            # Two signals share an id but not a projection: `verdicts.coverage`'s
            # first-wins dedup makes the outcome depend on ARRIVAL ORDER, which
            # no content key may describe. Fail closed — rank it in full.
            return None
        projections.add(proj)
        if s.kind == VERIFICATION_HEALTHY_KIND and _attr_kinds(s, "refutes_kinds"):
            refuting.add(proj)
            if len(refuting) > 1:
                # Two DISTINCT refuting healthy-verification witnesses: the
                # contradictions tuple is built in `str(signal_id)` order
                # (scoring.py:232) and is order-sensitive, so the bytes depend
                # on ids the key deliberately does not carry. Fail closed.
                return None
    payload = (tenant, catalog_version, sorted(projections))
    canon = json.dumps(payload, separators=(",", ":"), sort_keys=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


class RankMemo:
    """Bounded, process-lifetime LRU: RankKey -> RankingResult.

    PURE DATA, caller-owned, exactly like `engine.ComponentMemo`. It is NOT
    epoch-scoped: the key describes the evidence's CONTENT, not the node objects
    of one prepared window, so it stays valid across `_close_epoch`, across a
    retention prune, and across a catalog reload (the catalog version is IN the
    key, so a reload simply mints new keys and the old ones age out).

    CONCURRENCY: `run_window` runs on the thread-pool executor, so this object is
    mutated off the loop — but access is strictly SEQUENTIAL (one awaited
    `run_window` at a time), the same invariant `ComponentMemo` documents. Do not
    hand one memo to two concurrent `run_window` calls.

    §3a: the tenant is part of every key (see `rank_key`), so one shared instance
    can never serve one tenant's verdict to another.

    RSS (tracker 156): the value is a `RankingResult` and nothing else — no
    snapshot, no nodes, no signals, no window reference. BOTH bounds hold after
    every `put`: entries <= `max_entries` AND bytes <= `bytes_max` (the
    docstring's WHY THE ENTRY BOUND ALONE WAS WRONG), with ONE documented
    exception — a single entry larger than the whole byte budget is kept rather
    than evicting the memo to empty, so `bytes` can exceed `bytes_max` by at
    most the size of the newest entry.

    `_sizes` mirrors `_lru`'s keys with each entry's estimated size, so eviction
    returns the bytes without re-walking a graph that is about to be dropped.
    It is a SIDECAR rather than a `(value, size)` tuple in `_lru` on purpose:
    `_lru`'s value stays exactly the `RankingResult` the module contract (and
    `test_T7_the_memo_holds_no_evidence_objects`) reads it as. One int per entry
    against a 10-26 KiB value is noise."""

    __slots__ = ("_lru", "_sizes", "bytes_max", "bytes_used", "evicted",
                 "evicted_bytes", "hits", "max_entries", "misses", "unkeyable")

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES,
                 max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.max_entries = max(1, int(max_entries))
        self.bytes_max = max(1, int(max_bytes))
        self._lru: OrderedDict[str, RankingResult] = OrderedDict()
        self._sizes: dict[str, int] = {}   # key -> estimate_result_bytes(value)
        self.hits = 0            # keyed lookups served from the memo (rank skipped)
        self.misses = 0          # keyed lookups that had to rank
        self.evicted = 0         # entries dropped by either bound
        self.evicted_bytes = 0   # estimated bytes those entries held
        self.bytes_used = 0      # estimated bytes currently held
        self.unkeyable = 0       # components whose evidence has no sound key

    def get(self, key: str) -> RankingResult | None:
        hit = self._lru.get(key)
        if hit is None:
            self.misses += 1
            return None
        self._lru.move_to_end(key)
        self.hits += 1
        return hit

    def put(self, key: str, ranking: RankingResult) -> None:
        size = estimate_result_bytes(ranking)
        # Re-putting a key replaces its charge; it never double-counts.
        self.bytes_used -= self._sizes.get(key, 0)
        self._lru[key] = ranking
        self._lru.move_to_end(key)
        self._sizes[key] = size
        self.bytes_used += size
        while (len(self._lru) > self.max_entries
               or (self.bytes_used > self.bytes_max and len(self._lru) > 1)):
            oldest, _ = self._lru.popitem(last=False)
            dropped = self._sizes.pop(oldest, 0)
            self.bytes_used -= dropped
            self.evicted += 1
            self.evicted_bytes += dropped

    def clear(self) -> None:
        self._lru.clear()
        self._sizes.clear()
        self.bytes_used = 0

    def __len__(self) -> int:
        return len(self._lru)

    def stats(self) -> dict[str, int]:
        """§10 observable. `hits + misses` is the number of components that
        reached the memo at all; `unkeyable` is the fail-closed population;
        `bytes` / `bytes_max` / `evicted_bytes` are the tracker-156 memory
        readout — `evicted_bytes` climbing is the byte bound doing its job, and
        the exact measurement of what it costs in hit rate.

        WIRED (verified 2026-08-29 at 87973a36, no main.py change needed for
        the calibration): `epoch_state()["rank_memo"]` passes this dict through
        verbatim; `rank_memo_stats()`'s memo-OFF branch already returns
        `bytes`/`bytes_max`/`evicted_bytes` as zeros so the key set does not
        depend on the flag; and `_metrics_text()` already exports
        `corr_rank_memo_bytes`, `corr_rank_memo_bytes_max` and
        `corr_rank_memo_evicted_bytes_total` beside
        `corr_rank_memo{result="evicted"}`. Nothing about the byte bound is
        invisible on /metrics."""
        return {
            "entries": len(self._lru),
            "max_entries": self.max_entries,
            "bytes": self.bytes_used,
            "bytes_max": self.bytes_max,
            "hits": self.hits,
            "misses": self.misses,
            "evicted": self.evicted,
            "evicted_bytes": self.evicted_bytes,
            "unkeyable": self.unkeyable,
        }
