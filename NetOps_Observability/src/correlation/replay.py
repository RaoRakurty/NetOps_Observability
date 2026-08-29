"""Replay runner — #67 build ⑥. Re-runs the deterministic engine core over a
stored object's archived evidence window and reports drift against the stored
snapshot.

The contract (design §5 + research C6):
  * input  = corr_signals_archive rows WHERE archived_for = correlation_id
             (the FULL window slice persisted at stage [8] — no TTL, forever)
  * context = the grounding_context embedded in the snapshot's hypotheses JSON
             (seam views + topology_version) — replay never grounds against
             live state, so inventory evolution cannot fake drift
  * pins   = engine_version (semver + config hash) and catalog_version are
             COMPARED, never silently substituted: a pin mismatch is itself a
             reported finding ("replay ran on a different engine/catalog"),
             because we cannot time-travel code — honesty over pretense
  * output = DriftReport: clean, or named structural differences
             (nodes / edges incl. grounding AND asserted direction / top
             hypothesis / verdict tier / confidence beyond tolerance), stamped
             with the `comparison_schema` version those differences were
             computed under (see EDGE_COMPARISON_SCHEMA)

Drift on matching pins = a determinism bug or data corruption — a CI-grade
failure. Drift on mismatched pins = expected evolution, reported as such.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from aggregation import AGG_POLICY_VERSION, AggPlane
from catalog import Catalog, builtin_catalog
from directed_topology import DirectedTopology, frozen_oracle
from engine import (
    EngineConfig,
    ObjectSnapshot,
    PathGraphView,
    SeamView,
    TopologyAdjacency,
    engine_version,
    run_window,
)
from signals import Signal

CONFIDENCE_TOLERANCE = 1e-6   # pure float pipeline: equality up to repr rounding

# ── drift-report comparison schema (VERSIONED — tracker 178) ──────────────────
#
#   v1  (#67 build ⑥ … 2026-08-28)  an edge was compared by IDENTITY only:
#       (from_node, to_node, grounding_kind, grounding_ref). A stored object could
#       assert a DIRECTED edge (e.g. onset_order+topo_updown / 0.8) that its own
#       replay recomputed as ('none', 0.0) and still report CLEAN, because from/to
#       order is decided by onset order, never by the direction oracle.
#   v2  (tracker 178, 2026-08-28)  the direction an edge asserts —
#       (direction_basis, direction_conf) — is compared too, on every edge present
#       on BOTH sides.
#
# Emitted as `comparison_schema` in DriftReport.to_dict() so an archived report is
# self-describing: a v1 "clean" says nothing about direction, a v2 "clean" does.
# Existing keys keep their exact meaning; the new findings are ADDED
# (`direction_drift` / `direction_drift_count` / `direction_unknown`) and are also
# mirrored into `differences` so pre-v2 readers still see them.
EDGE_COMPARISON_SCHEMA = 2


@dataclass(frozen=True)
class StoredObject:
    """The slice of a corr_objects row replay needs."""

    correlation_id: str
    tenant_id: str
    version: int
    top_hypothesis: str
    top_confidence: float
    verdict_tier: str
    hypotheses_blob: str
    engine_version: str
    catalog_version: str
    topology_version: str
    node_count: int
    signal_count: int
    edges: tuple[dict, ...] = ()          # stored corr_edges rows for this version
    # #111 identity adoption: a version persisted for an ongoing incident keeps
    # the ORIGINAL open object's correlation_id while run_window over its window
    # derives the raw windowed id — the trigger signal re-identifies it exactly.
    trigger_signal: str = ""

    @classmethod
    def from_rows(cls, obj_row: dict, edge_rows: list[dict]) -> StoredObject:
        return cls(
            correlation_id=str(obj_row["correlation_id"]),
            trigger_signal=str(obj_row.get("trigger_signal", "")),
            tenant_id=str(obj_row.get("tenant_id", "")),
            version=int(obj_row["version"]),
            top_hypothesis=str(obj_row["top_hypothesis"]),
            top_confidence=float(obj_row["top_confidence"]),
            verdict_tier=str(obj_row["verdict_tier"]),
            hypotheses_blob=str(obj_row["hypotheses"]),
            engine_version=str(obj_row["engine_version"]),
            catalog_version=str(obj_row["catalog_version"]),
            topology_version=str(obj_row.get("topology_version", "")),
            node_count=int(obj_row["node_count"]),
            signal_count=int(obj_row["signal_count"]),
            edges=tuple(sorted(edge_rows, key=lambda e: (str(e["from_node"]), str(e["to_node"])))),
        )

    def grounding_context(self) -> tuple[SeamView, ...]:
        blob = json.loads(self.hypotheses_blob)
        ctx = blob.get("grounding_context") or {}
        return tuple(SeamView.from_dict(d) for d in ctx.get("seams", ()))

    def degradation(self) -> tuple[bool, bool]:
        """(topology_stale, storm_mode) embedded at score time (§8) — rehydrated so a
        snapshot scored under degradation REPLAYS under the same flags (w_topo cap is
        deterministic). Absent block = healthy (the pre-C3 default)."""
        blob = json.loads(self.hypotheses_blob)
        deg = (blob.get("grounding_context") or {}).get("degradation") or {}
        return bool(deg.get("topology_stale")), bool(deg.get("storm_mode"))

    def aggregation(self) -> dict:
        """The P3 aggregation provenance embedded at persist time (design §5),
        or `{}` for an object built on the un-aggregated path.

        Read the same way as `degradation()`/`adjacency()`: out of the snapshot's
        OWN blob, never from a live plane — a replay must be able to say which
        aggregation policy produced this object's evidence years after the
        process that ran it is gone."""
        blob = json.loads(self.hypotheses_blob)
        agg = (blob.get("grounding_context") or {}).get("aggregation") or {}
        return dict(agg) if isinstance(agg, dict) else {}

    def adjacency(self) -> TopologyAdjacency:
        """The L2/L3 adjacency this object grounded on, embedded per snapshot (C7) so
        an adjacency-grounded (fabric) edge replays against the SAME links, not the
        live topology. Absent = none used (pre-C7 / seam-only objects)."""
        blob = json.loads(self.hypotheses_blob)
        pairs = (blob.get("grounding_context") or {}).get("adjacency") or ()
        return TopologyAdjacency.from_links([{"a": p[0], "b": p[1]} for p in pairs])

    def paths(self) -> PathGraphView | None:
        """The Service Path Graph view this object grounded against (contract §2),
        embedded per snapshot so a path/route-grounded edge REPLAYS against the same
        relations — never the live inventory. Absent block = no path relation used
        (pre-contract / seam-token-only object) → None → the engine keeps its
        pre-contract behaviour minus authority. Mirrors adjacency()/directed()."""
        blob = json.loads(self.hypotheses_blob)
        pg = (blob.get("grounding_context") or {}).get("path_graph")
        return PathGraphView.from_dict(pg) if pg else None

    def directed(self) -> DirectedTopology | None:
        """A frozen oracle from the embedded directed-topology orientations (C7) — so a
        directed edge recomputes its direction from the SAME answers, never from live
        flow/route state. Absent block = undirected (pre-C7 default) → None → abstain."""
        blob = json.loads(self.hypotheses_blob)
        rows = (blob.get("grounding_context") or {}).get("orientations") or ()
        return frozen_oracle(rows) if rows else None


@dataclass
class DriftReport:
    correlation_id: str
    stored_version: int
    engine_pin_match: bool
    catalog_pin_match: bool
    clean: bool = True
    differences: list[str] = field(default_factory=list)
    # tracker 178 (schema v2): direction findings, ALSO mirrored into
    # `differences` so every pre-v2 consumer still sees them.
    direction_drift: list[str] = field(default_factory=list)
    # Edges whose STORED row carried no direction columns at all (an archive row
    # older than the columns): not comparable, so not drift — counted, never hidden.
    direction_unknown: int = 0
    comparison_schema: int = EDGE_COMPARISON_SCHEMA
    # ── P3 step 3: the aggregation-policy pin ────────────────────────────────
    # True for an un-aggregated object (nothing to pin) AND for an aggregated
    # object whose embedded policy equals the running `AGG_POLICY_VERSION`.
    # False is a LOUD finding, mirrored into `differences` exactly like the
    # engine/catalog pins: a stored object's deltas were produced by an
    # aggregation policy this process no longer implements, so its evidence
    # cannot be re-derived from raw and any structural "clean" below is a
    # statement about deltas, not about the raw stream they stand for.
    agg_pin_match: bool = True
    agg_drift: list[str] = field(default_factory=list)

    def note(self, msg: str) -> None:
        self.clean = False
        self.differences.append(msg)

    def note_aggregation(self, msg: str) -> None:
        """An aggregation-provenance finding: recorded in `agg_drift` AND in
        `differences`, so `clean` and every existing reader keep their exact
        meaning (the `note_direction` precedent)."""
        self.agg_drift.append(msg)
        self.note(msg)

    def note_direction(self, msg: str) -> None:
        """A direction finding: recorded in the schema-v2 list AND in `differences`
        (so `clean` and every existing reader keep their exact meaning)."""
        self.direction_drift.append(msg)
        self.note(msg)

    def to_dict(self) -> dict:
        return {
            "correlation_id": self.correlation_id,
            "stored_version": self.stored_version,
            "engine_pin_match": self.engine_pin_match,
            "catalog_pin_match": self.catalog_pin_match,
            "clean": self.clean,
            "differences": list(self.differences),
            # ── schema v2 additions (tracker 178) ───────────────────────────
            "comparison_schema": self.comparison_schema,
            "direction_drift": list(self.direction_drift),
            "direction_drift_count": len(self.direction_drift),
            "direction_unknown": self.direction_unknown,
            # ── P3 step 3 additions (additive, like the v2 direction keys) ───
            "agg_pin_match": self.agg_pin_match,
            "agg_policy": AGG_POLICY_VERSION,
            "agg_drift": list(self.agg_drift),
            "agg_drift_count": len(self.agg_drift),
        }


def _edge_key(row: dict) -> tuple:
    return (str(row["from_node"]), str(row["to_node"]),
            str(row["grounding_kind"]), str(row["grounding_ref"]))


def _edge_direction(row: dict) -> tuple[str, float] | None:
    """The direction an edge row ASSERTS — (direction_basis, direction_conf) —
    or None when the row carries neither column (an archive row older than them),
    which is 'not comparable', not 'undirected'.

    `direction_conf` is compared EXACTLY, no tolerance, because it is not a
    computed float: `engine._direction` returns either `cfg.direction_conf` (the
    2-of-3 claim — a config constant, and a changed config is a changed engine pin
    we already report) or literal 0.0 (abstain/conflict). Both sides also pass
    through `Edge.to_ch_row`'s `round(..., 4)`, so the comparison is between two
    4-decimal representations of the same two-valued constant. A tolerance here
    would only mask a genuinely different pin.
    """
    if "direction_basis" not in row and "direction_conf" not in row:
        return None
    return (str(row.get("direction_basis", "")),
            round(float(row.get("direction_conf") or 0.0), 4))


def _directions_by_key(rows: list[dict] | tuple[dict, ...]) -> dict[tuple, list[tuple[str, float] | None]]:
    """key → the directions of the edges sharing that key, in a stable order.
    A list (not a scalar) because `_edge_key` is not guaranteed unique; sorting
    makes the comparison order-independent, exactly like the key-set diff."""
    out: dict[tuple, list[tuple[str, float] | None]] = {}
    for r in rows:
        out.setdefault(_edge_key(r), []).append(_edge_direction(r))
    for v in out.values():
        v.sort(key=lambda d: ("", -1.0) if d is None else d)
    return out


def _fmt_dirs(dirs: list[tuple[str, float] | None]) -> str:
    """Render one key's direction list for a difference line: 'basis/conf'."""
    return ", ".join("?" if d is None else f"{d[0]}/{d[1]}" for d in dirs)


def replay(
    stored: StoredObject,
    archived_window: list[Signal] | tuple[Signal, ...],
    catalog: Catalog | None = None,
    cfg: EngineConfig | None = None,
) -> DriftReport:
    """Re-run the pure core over the archived window and diff. Pure: callers
    (HTTP endpoint, CLI, CI) do the IO and hand rows in."""
    catalog = catalog or builtin_catalog()
    cfg = cfg or EngineConfig()
    report = DriftReport(
        correlation_id=stored.correlation_id,
        stored_version=stored.version,
        engine_pin_match=(engine_version(cfg) == stored.engine_version),
        catalog_pin_match=(catalog.version_hash() == stored.catalog_version),
    )
    if not report.engine_pin_match:
        report.note(f"engine pin: stored {stored.engine_version} vs current {engine_version(cfg)}")
    if not report.catalog_pin_match:
        report.note(f"catalog pin: stored {stored.catalog_version} vs current {catalog.version_hash()}")
    # ── P3 step 3: the aggregation-policy pin, compared like the two above ───
    # We cannot time-travel an aggregation policy any more than we can
    # time-travel code (module docstring: "honesty over pretense"), so a policy
    # mismatch is REPORTED, never silently substituted. An un-aggregated object
    # embeds no policy and pins clean — pre-P3 objects must stay replayable.
    stored_agg = stored.aggregation()
    stored_policy = str(stored_agg.get("policy", ""))
    if stored_policy and stored_policy != AGG_POLICY_VERSION:
        report.agg_pin_match = False
        report.note_aggregation(
            f"aggregation policy pin: stored {stored_policy} vs current {AGG_POLICY_VERSION}")

    seams = stored.grounding_context()
    # The archive may hold the slice several times (one per persisted version);
    # identity dedup is exact because signal ids are stored verbatim.
    seen: set[str] = set()
    window: list[Signal] = []
    for s in sorted(archived_window, key=lambda s: (s.ts, str(s.signal_id))):
        sid = str(s.signal_id)
        if sid not in seen:
            seen.add(sid)
            window.append(s)
    if not window:
        report.note("archive empty: no corr_signals_archive rows for this object")
        return report

    topo_stale, storm = stored.degradation()
    snapshots = run_window(window, catalog, seams, cfg,
                           adjacency=stored.adjacency(),
                           topology_stale=topo_stale, storm_mode=storm,
                           directed=stored.directed(), paths=stored.paths())
    match = next((s for s in snapshots if s.correlation_id == stored.correlation_id), None)
    if match is None and stored.trigger_signal:
        # #111 identity adoption (main.engine_cycle + engine.find_continuation):
        # an ongoing incident whose earliest signal aged out of the window keeps
        # its ORIGINAL correlation_id, so a fresh run_window over the archived
        # window derives the raw windowed id instead. The trigger signal is
        # unique per component (components partition the window's signals), so
        # it re-identifies the adopted object exactly — the drift diff then
        # compares full content as usual, nothing is weakened.
        match = next((s for s in snapshots
                      if s.trigger_signal == stored.trigger_signal), None)
    if match is None:
        report.note(
            f"recomputation produced {len(snapshots)} object(s), none with the stored id "
            f"(ids: {sorted(s.correlation_id for s in snapshots)})")
        return report

    _diff(report, stored, match)
    return report


def _diff(report: DriftReport, stored: StoredObject, fresh: ObjectSnapshot) -> None:
    if fresh.ranking.top_hypothesis != stored.top_hypothesis:
        report.note(f"top_hypothesis: stored {stored.top_hypothesis} vs replay {fresh.ranking.top_hypothesis}")
    if fresh.ranking.verdict_tier.value != stored.verdict_tier:
        report.note(f"verdict_tier: stored {stored.verdict_tier} vs replay {fresh.ranking.verdict_tier.value}")
    if abs(fresh.top_confidence() - stored.top_confidence) > max(CONFIDENCE_TOLERANCE, 1e-4):
        # stored value is rounded to 4 decimals at persist time
        report.note(f"top_confidence: stored {stored.top_confidence} vs replay {fresh.top_confidence():.4f}")
    if len(fresh.nodes) != stored.node_count:
        report.note(f"node_count: stored {stored.node_count} vs replay {len(fresh.nodes)}")
    if fresh.signal_count() != stored.signal_count:
        report.note(f"signal_count: stored {stored.signal_count} vs replay {fresh.signal_count()}")
    _diff_aggregation(report, stored, fresh)

    stored_dir = _directions_by_key(stored.edges)
    fresh_dir = _directions_by_key(fresh.to_edge_rows(stored.version))
    stored_edges, fresh_edges = set(stored_dir), set(fresh_dir)
    for missing in sorted(stored_edges - fresh_edges):
        report.note(f"edge in store, not in replay: {missing}")
    for extra in sorted(fresh_edges - stored_edges):
        report.note(f"edge in replay, not in store: {extra}")
    # Schema v2: an edge that exists on both sides must also assert the SAME
    # direction. Without this, an object whose embedded orientations were lost
    # claims a direction its own replay cannot reproduce — and reports clean.
    for key in sorted(stored_edges & fresh_edges):
        s_dirs, f_dirs = stored_dir[key], fresh_dir[key]
        if None in s_dirs or None in f_dirs:
            report.direction_unknown += sum(1 for d in s_dirs + f_dirs if d is None)
            continue
        if s_dirs != f_dirs:
            report.note_direction(
                f"edge direction {key}: stored {_fmt_dirs(s_dirs)} vs replay {_fmt_dirs(f_dirs)}")


def _diff_aggregation(report: DriftReport, stored: StoredObject,
                      fresh: ObjectSnapshot) -> None:
    """The P3 aggregation provenance must survive the archive round-trip.

    `aggregation_block` is a PURE projection of the `agg_*` annotations that
    travel in each Signal's `attrs` into `corr_signals_archive`, so re-running
    `run_window` over the archived slice must re-derive the stored block
    field-for-field. Anything else is a real, nameable defect and gets named:

      * a block that vanished  -> the annotations did not survive persistence
        (the likeliest cause is `signals._shrink_attrs` truncating an oversize
        attrs blob, which is exactly the sort of silent evidence loss this
        check exists to expose);
      * a block that appeared  -> the stored object predates the representation;
      * a field that moved     -> a different set of deltas was archived than
        the object was built from (a sliced/merged archive), or `agg_count`
        annotations were rewritten.

    Every difference is reported per FIELD, not as one opaque "blocks differ",
    because the field that moved is the diagnosis.
    """
    want = stored.aggregation()
    got = fresh.agg_provenance()
    if not want and not got:
        return
    if want and not got:
        report.note_aggregation(
            "aggregation block: stored "
            f"{want.get('deltas', 0)} delta(s)/{want.get('keys', 0)} key(s), "
            "replay recomputed none (agg_* annotations missing from the archive slice)")
        return
    if got and not want:
        report.note_aggregation(
            "aggregation block: none stored, replay recomputed "
            f"{got.get('deltas', 0)} delta(s)/{got.get('keys', 0)} key(s)")
        return
    for field_name in sorted(set(want) | set(got)):
        a, b = want.get(field_name), got.get(field_name)
        if a != b:
            report.note_aggregation(
                f"aggregation.{field_name}: stored {a!r} vs replay {b!r}")


def rederive_deltas(raw_window: list[Signal] | tuple[Signal, ...], *,
                    horizon_s: float, lateness_s: float) -> list[Signal]:
    """Run the SAME `AggPlane` over a RAW slice, in event-time order, and return
    the deltas it forwards (design §3 "so `replay` can re-derive either level").

    Two levels exist because two things are archived. `corr_signals_archive`
    holds the DELTA signals an object was built from — that is what `replay()`
    above re-runs, and it needs no plane. `corr_signals` holds every RAW row,
    forever, and THIS is the function that turns those back into the delta
    stream the engine saw. Together they close the loop: raw -> deltas -> object.

    PURITY. A fresh plane per call (never a shared one — a plane carries state,
    and a replay must not be able to see another replay's), fed strictly in
    `(event_ts, signal_id)` order, which is the canonical order the plane's own
    ordering rule is defined against. `horizon_s`/`lateness_s` are INJECTED for
    the same reason `main` injects them: a re-derivation must age state on the
    same clock the original run did, and guessing that clock here would make the
    result depend on this module's defaults rather than on the run being
    replayed.

    NOT MUTATION-FREE FOR THE CALLER: `AggPlane.observe` stamps the annotation
    onto the Signal it is handed (its documented contract), so pass COPIES when
    the raw signals are needed un-annotated afterwards.
    """
    plane = AggPlane(horizon_s=horizon_s, lateness_s=lateness_s)
    out: list[Signal] = []
    for sig in sorted(raw_window, key=lambda s: (s.ts, str(s.signal_id))):
        got = plane.observe(sig)
        if got is not None:
            out.append(got)
    return out


def check_rederivation(archived_deltas: list[Signal] | tuple[Signal, ...],
                       raw_window: list[Signal] | tuple[Signal, ...], *,
                       horizon_s: float, lateness_s: float) -> list[str]:
    """Findings (empty == clean) from re-deriving `archived_deltas` out of
    `raw_window` with `rederive_deltas`.

    THE INVARIANT: the plane is a pure function of the event-time-ordered raw
    stream per key, so the SET of forwarded signal ids is reproducible exactly.
    A difference means one of: the raw slice is not the slice that produced
    these deltas, the policy changed under us (which `replay()`'s pin catches
    first), or the plane stopped being deterministic — all three are defects,
    none of them may be silent (§10 "no silent failures").

    Returned rather than raised, so a caller can fold them into a DriftReport
    (`note_aggregation`) or print them, and so one mismatch does not hide the
    rest.
    """
    want = {str(s.signal_id) for s in archived_deltas}
    got = {str(s.signal_id) for s in rederive_deltas(
        raw_window, horizon_s=horizon_s, lateness_s=lateness_s)}
    findings: list[str] = []
    missing, extra = sorted(want - got), sorted(got - want)
    if missing:
        findings.append(
            f"re-derivation forwarded {len(missing)} fewer delta(s) than the archive "
            f"holds (first: {missing[0]})")
    if extra:
        findings.append(
            f"re-derivation forwarded {len(extra)} delta(s) the archive does not hold "
            f"(first: {extra[0]})")
    return findings


# ── IO wrapper (ClickHouse) ───────────────────────────────────────────────────


async def replay_object(ch, correlation_id: str, version: int | None = None) -> DriftReport:  # type: ignore[no-untyped-def]
    """Load snapshot + archived window from ClickHouse and replay. `ch` is the
    main module's CH helper (duck-typed to keep this module import-light)."""
    ver_clause = f"AND version = {int(version)}" if version is not None else ""
    obj_rows = await ch.query(f"""
        SELECT * FROM netops.corr_objects
         WHERE correlation_id = '{_uuid(correlation_id)}' {ver_clause}
         ORDER BY version DESC LIMIT 1 FORMAT JSON""")  # nosec B608 -- id UUID-validated, version int()-cast
    if not obj_rows:
        raise LookupError(f"no stored object {correlation_id}")
    obj = obj_rows[0]
    edge_rows = await ch.query(f"""
        SELECT * FROM netops.corr_edges
         WHERE correlation_id = '{_uuid(correlation_id)}' AND version = {int(obj['version'])}
         FORMAT JSON""")  # nosec B608 -- id UUID-validated, version int()-cast
    archive_rows = await ch.query(f"""
        SELECT * FROM netops.corr_signals_archive
         WHERE archived_for = '{_uuid(correlation_id)}'
         ORDER BY ts, signal_id FORMAT JSON""")  # nosec B608 -- id UUID-validated
    stored = StoredObject.from_rows(obj, edge_rows)
    window = [Signal.from_ch_row(r) for r in _select_slice(archive_rows, stored.version)]
    return replay(stored, window)


def _select_slice(archive_rows: list[dict], version: int) -> list[dict]:
    """Pick the version-scoped window slice (basic-testing fix): exactly the
    rows persisted with this version. A closed version persists no slice, so
    fall back to the newest slice at or below it (its evidence by definition);
    legacy rows (archived_version 0, pre-fix) all collapse into that fallback —
    the historical union behavior, kept deliberately so old objects stay
    replayable rather than erroring."""
    by_ver: dict[int, list[dict]] = {}
    for r in archive_rows:
        by_ver.setdefault(int(r.get("archived_version") or 0), []).append(r)
    if version in by_ver:
        return by_ver[version]
    eligible = [v for v in by_ver if v <= version]
    if not eligible:
        return archive_rows
    return by_ver[max(eligible)]


def _uuid(v: str) -> str:
    """SQL-injection guard: the id must parse as a UUID before interpolation."""
    import uuid as _u
    return str(_u.UUID(v))
