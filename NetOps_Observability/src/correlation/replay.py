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
             (nodes / edges incl. grounding / top hypothesis / verdict tier /
             confidence beyond tolerance)

Drift on matching pins = a determinism bug or data corruption — a CI-grade
failure. Drift on mismatched pins = expected evolution, reported as such.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from catalog import Catalog, builtin_catalog
from engine import EngineConfig, ObjectSnapshot, SeamView, engine_version, run_window
from signals import Signal

CONFIDENCE_TOLERANCE = 1e-6   # pure float pipeline: equality up to repr rounding


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

    @classmethod
    def from_rows(cls, obj_row: dict, edge_rows: list[dict]) -> "StoredObject":
        return cls(
            correlation_id=str(obj_row["correlation_id"]),
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


@dataclass
class DriftReport:
    correlation_id: str
    stored_version: int
    engine_pin_match: bool
    catalog_pin_match: bool
    clean: bool = True
    differences: list[str] = field(default_factory=list)

    def note(self, msg: str) -> None:
        self.clean = False
        self.differences.append(msg)

    def to_dict(self) -> dict:
        return {
            "correlation_id": self.correlation_id,
            "stored_version": self.stored_version,
            "engine_pin_match": self.engine_pin_match,
            "catalog_pin_match": self.catalog_pin_match,
            "clean": self.clean,
            "differences": list(self.differences),
        }


def _edge_key(row: dict) -> tuple:
    return (str(row["from_node"]), str(row["to_node"]),
            str(row["grounding_kind"]), str(row["grounding_ref"]))


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
                           topology_stale=topo_stale, storm_mode=storm)
    match = next((s for s in snapshots if s.correlation_id == stored.correlation_id), None)
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

    stored_edges = {_edge_key(e) for e in stored.edges}
    fresh_edges = {_edge_key(e) for e in fresh.to_edge_rows(stored.version)}
    for missing in sorted(stored_edges - fresh_edges):
        report.note(f"edge in store, not in replay: {missing}")
    for extra in sorted(fresh_edges - stored_edges):
        report.note(f"edge in replay, not in store: {extra}")


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
