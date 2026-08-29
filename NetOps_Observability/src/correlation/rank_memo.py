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

THE BYTE ESTIMATOR
------------------
`estimate_result_bytes` walks the value graph once per `put` and sums
`sys.getsizeof` over it. It is an ESTIMATE by construction, deliberately biased
CONSERVATIVE (it may over-count, never wildly under-count):

* **No `seen` set.** The graph is a near-tree; an object reachable twice from
  one entry is charged twice. Skipping the id-set is what makes it cheap.
* **Enum members are charged 0** — `VerdictTier`, `ModalityClass`, `ProbeScope`
  are module-level singletons shared by every entry, so the entry's marginal
  cost is the pointer already counted in its container.
* **Cross-entry sharing is NOT modelled.** Strings carried verbatim from the
  catalog (`title`, `first_steps`, `operator_phrase`, ...) and the shared
  `inapplicable` `HypothesisScore` objects (`scoring._catalog_plan`) are charged
  to every entry that references them. So the total the memo reports is an
  UPPER BOUND on the RSS it is actually responsible for — the direction a memory
  bound must err in.

Measured against a reference recursive `sys.getsizeof` deep-size walk (the same
instrument the attribution brief used, with an id-`seen` set) over 400 real
`rank()` outputs on the built-in catalog: **mean ratio 1.06x, range 0.94-1.33x**,
at **0.13 ms/entry against a 3.0 ms `rank()`** (~4 % of the call it only runs on
a MISS). The reference itself reads **18.3 KiB/entry inclusive / 9.2 KiB/entry
when shared objects are charged once across all 400** — bracketing the brief's
25.8 KiB inclusive / 9.9-12.8 KiB marginal on its own (larger, real-evidence)
fixture. `test_p2_memflat_bounds.py::test_B5_*` pins the factor.

WHY 96 MiB
----------
The 2.5K replica runs in a **1.25 GiB (1,280 MiB)** container and entered the
`memflat` window at 494 MiB, so the whole post-input growth budget the ×1.3 gate
allows is ~148 MiB. Sizing the memo:

* 96 MiB of ESTIMATOR bytes ~ 90 MiB of reference-inclusive deep size (÷1.06),
  which at the brief's 25.8 KiB/entry inclusive holds **~3,600 entries**, and at
  this catalog's 18.3 KiB/entry holds **~5,100**. That is the same order as the
  "5,000 entries ~ 50-65 MiB" the brief itself proposed — but expressed in the
  unit that actually binds, so a fatter catalog cannot silently inflate it.
* Its TRUE marginal RSS is lower still: 52 % of the live entries shared their
  result with an open object, so ~43-96 MiB, i.e. **3.4-7.5 % of the container**
  against the **40-52 %** the 50,000-entry bound licensed.
* HIT-RATE COST — stated as an assumption, not a measurement. Neither brief
  carries a hit-rate-vs-entries curve, so what the live 66 % would have become
  while holding ~4,000 of its 20,117 distinct keys is NOT derivable here. What
  IS known: the hit rate CLIMBED (29 % early in the storm → 66 %) "as evidence
  repeats", i.e. reuse is recency-clustered, which is the access pattern LRU is
  built to keep. The bound is therefore set where memory is safe and the cost is
  MEASURED rather than assumed: `evicted` / `evicted_bytes` in `stats()` are 0
  today and become the exact readout of what the bound costs on the next run.
  Raise `CORR_RANK_MEMO_BYTES_MAX` if they climb while RSS has headroom.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections import OrderedDict
from dataclasses import fields as dataclass_fields
from dataclasses import is_dataclass
from enum import Enum

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
# type -> the dataclass field names to walk, derived once. Bounded by the number
# of distinct types in a RankingResult value graph (RankingResult,
# HypothesisScore, Verdict, EvidenceCoverage) — it is a memo of the SCHEMA, not
# of the data, so it cannot grow with traffic.
_FIELD_NAMES: dict[type, tuple[str, ...]] = {}


def estimate_result_bytes(obj: object) -> int:
    """Deterministic, cheap upper-ish bound on the bytes one memo value retains.

    Deliberately NOT exact: no id-`seen` set (the graph is a near-tree, and the
    set is most of the cost), enum members charged 0 (module-level singletons),
    cross-entry sharing not modelled (charged to every entry that references
    it). Measured at 1.06x a reference deep-size walk, range 0.94-1.33x — see the
    module docstring and `test_p2_memflat_bounds.py::test_B5_*`.

    Deterministic: `sys.getsizeof` and `len` only. No `hash()`, no `id()`, no
    clock — the same value graph gives the same number in any process."""
    t = type(obj)
    # `type(obj) is str`, NOT `isinstance`: a str-subclass Enum member
    # (`VerdictTier`, `ModalityClass`) must fall through to the Enum branch and
    # be charged 0, not charged as a fresh string on every entry.
    if t is str:
        return _STR_BASE + len(obj)          # type: ignore[arg-type]
    if t is float or t is int or t is bool:
        return _SCALAR_BYTES
    if obj is None:
        return 0
    if t is tuple or t is list or t is set or t is frozenset:
        total = _getsizeof(obj)
        for item in obj:                       # type: ignore[attr-defined]
            total += estimate_result_bytes(item)
        return total
    if t is dict:
        total = _getsizeof(obj)
        for key, value in obj.items():         # type: ignore[attr-defined]
            total += estimate_result_bytes(key) + estimate_result_bytes(value)
        return total
    names = _FIELD_NAMES.get(t)
    if names is None:
        names = (tuple(f.name for f in dataclass_fields(obj))
                 if is_dataclass(obj) and not isinstance(obj, type) else ())
        _FIELD_NAMES[t] = names
    if not names:
        # An Enum member is one module-level singleton shared by every entry:
        # the entry's marginal cost is the pointer its container already paid.
        return 0 if isinstance(obj, Enum) else _getsizeof(obj)
    total = _getsizeof(obj)
    for name in names:
        total += estimate_result_bytes(getattr(obj, name))
    return total


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

        NOTE (2026-08-29) — main.py is owned by another change and was NOT
        edited here. `epoch_state()["rank_memo"]` passes this dict through, so
        it picks the three new keys up for free; TWO places in main.py still
        need a one-line follow-up:
          1. `rank_memo_stats()`'s memo-OFF branch returns a hardcoded dict and
             must gain `"bytes": 0, "bytes_max": 0, "evicted_bytes": 0` so a
             dashboard never sees a key appear/disappear with the flag.
          2. `_metrics_text()` enumerates the memo series by hand
             (`corr_rank_memo{result=...}` + `corr_rank_memo_entries`); add
             `corr_rank_memo_bytes` / `corr_rank_memo_bytes_max` gauges and an
             `evicted_bytes` counter — the byte bound is invisible on /metrics
             until then."""
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
