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
`CORR_RANK_MEMO_MAX` entries (default 50,000), LRU eviction. A `RankingResult`
holds only strings, floats, bools, enums and dicts of those — NO `Signal`, NO
`Node`, NO `ObjectSnapshot`, NO window reference (pinned by
`test_T7_the_memo_holds_no_evidence_objects`). The value is shared by reference
across components: `RankingResult` and `HypothesisScore` are frozen dataclasses
and every downstream amendment (`_cap_verdict`, `_break_ties_by_seam_affinity`,
the unknown-hop `replace`) builds a NEW object — the same sharing invariant
`scoring._build_inapplicable_score` (`scoring.py:424-435`) has relied on since
2026-08-22.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict

from scoring import (
    VERIFICATION_HEALTHY_KIND,
    VERIFICATION_RESULT_KIND,
    RankingResult,
    _attr_kinds,
)
from signals import Signal, probe_authority_of
from verdicts import Witness, witness_of

# Default bound. A RankingResult is a few KB at most (top-K hypotheses of
# strings), so 50,000 entries is the size of the reusable component population
# the profile measured, not a memory gamble.
DEFAULT_MAX_ENTRIES = 50_000


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
    snapshot, no nodes, no signals, no window reference."""

    __slots__ = ("_lru", "evicted", "hits", "max_entries", "misses", "unkeyable")

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self.max_entries = max(1, int(max_entries))
        self._lru: OrderedDict[str, RankingResult] = OrderedDict()
        self.hits = 0        # keyed lookups served from the memo (rank skipped)
        self.misses = 0      # keyed lookups that had to rank
        self.evicted = 0     # entries dropped by the LRU bound
        self.unkeyable = 0   # components whose evidence has no sound key

    def get(self, key: str) -> RankingResult | None:
        hit = self._lru.get(key)
        if hit is None:
            self.misses += 1
            return None
        self._lru.move_to_end(key)
        self.hits += 1
        return hit

    def put(self, key: str, ranking: RankingResult) -> None:
        self._lru[key] = ranking
        self._lru.move_to_end(key)
        while len(self._lru) > self.max_entries:
            self._lru.popitem(last=False)
            self.evicted += 1

    def clear(self) -> None:
        self._lru.clear()

    def __len__(self) -> int:
        return len(self._lru)

    def stats(self) -> dict[str, int]:
        """§10 observable. `hits + misses` is the number of components that
        reached the memo at all; `unkeyable` is the fail-closed population."""
        return {
            "entries": len(self._lru),
            "max_entries": self.max_entries,
            "hits": self.hits,
            "misses": self.misses,
            "evicted": self.evicted,
            "unkeyable": self.unkeyable,
        }
