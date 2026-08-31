"""Tracker 155 — an incident must keep its IDENTITY across a partition handoff.

WHAT WAS MEASURED (run ownership-155a-08302235, 2026-08-30; arms: restart,
restart-keep, exit/join). Nothing DURABLE is lost when partitions move — 0
offset rewinds, 0 duplicate signals, evidence conserved. What breaks is
identity: `correlation_id = uuid5(tenant, earliest-node.key, onset_ms)` is
derived from the acquiring replica's IN-MEMORY window, which starts empty for a
partition it just acquired, so one in-flight incident re-keys into N+1
fragments and the pre-move object freezes at its last version. Detection and
specificity stayed 1.00 on every arm while the positive-story pass rate went
1.00 -> 0.00.

WHAT IS PINNED HERE — the fix is "reconstruct identity, not state":

  (a) a seeded registration is one `find_continuation` ADOPTS, and the adopted
      object continues under its ORIGINAL id at a version strictly above the
      loaded durable maximum — both through the direct id hit and through the
      re-keyed continuation path, end-to-end through `main.engine_cycle`;
  (b) FAIL-OPEN: a ClickHouse that is down/slow/nonsense at assignment counts a
      failure and leaves HEAD's behaviour exactly as it is;
  (c) §3a: the seed queries ONLY the tenants whose partitions this replica just
      acquired, and refuses an out-of-scope row even if the store returns one;
  (d) a second assignment inside the cold window is IDEMPOTENT, and a seed can
      never clobber live in-process state;
  (e) a late final version from the OLD owner is tolerated — a re-seed can
      never rewind an adopted object;
  (f) a seeded object nothing adopts is closed by QUIESCE (and by the 163 cap,
      and dropped by a lifecycle merge) — dropped, never persisted, because a
      placeholder has no verdict to publish;
  (g) tracker 187 spans the handoff: the AffectedHistory is re-seeded from the
      loaded blast radius, so the FINAL affected covers both sides of the move;
  (h) the load is BOUNDED: the cap is respected, the overflow is counted
      exactly, and it is the OLDEST durable writes that are skipped.

MUTANTS (verified by hand while writing these):
  * disable the seeding (`CORR_OWNERSHIP_SEED=0`, or make `_seed_register`
    return False) -> the adoption tests fail: a NEW correlation_id appears and
    the object count doubles.
  * drop the tenant scope (remove the `tenant_id IN (...)` clause, or the
    `tenant not in owned` refusal) -> `test_seed_query_is_tenant_scoped` /
    `test_seed_refuses_an_out_of_scope_row` fail.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import replace as dc_replace
from datetime import datetime, timedelta, timezone

import httpx
import pytest

import engine
import main
from engine import find_continuation, run_window
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from test_archive_slice import CAT
from verdicts import VerdictTier

T0 = datetime(2026, 8, 30, 22, 41, 0, tzinfo=timezone.utc)
# A correlation_id no engine derivation would ever mint for this fixture — the
# whole point is that the acquiring replica cannot re-derive it from memory.
SEED_CID = "155a0000-0000-4000-8000-000000000001"
OTHER_CID = "155a0000-0000-4000-8000-000000000002"


class _Clock(datetime):
    """The module clock under test (the test_corr_continuation pattern)."""

    current: datetime = T0

    @classmethod
    def now(cls, tz=None):
        return cls.current if tz is not None else cls.current.replace(tzinfo=None)


def _ms(dt: datetime) -> str:
    """ClickHouse quotes 64-bit integers in its JSON format — so does the stub."""
    return str(int(dt.timestamp() * 1000))


def _row(cid: str, tenant: str, *, version: int = 7,
         affected: dict | None = None, start: datetime | None = None,
         end: datetime | None = None, written: datetime | None = None,
         tier: str = "undetermined", hypothesis: str = "") -> dict:
    """One `corr_current FINAL` row exactly as `ch.query` would hand it over.

    `tier`/`hypothesis` default to the neutral pair so every pre-155b test in
    this file loads a row that arms NO verdict floor — the D3 behaviour is
    exercised only where a test asks for a durable verdict.
    """
    start = T0 - timedelta(seconds=300) if start is None else start
    end = T0 + timedelta(seconds=300) if end is None else end
    written = T0 if written is None else written
    return {
        "tenant_id": tenant,
        "correlation_id": cid,
        "version": version,
        "window_start_ms": _ms(start),
        "window_end_ms": _ms(end),
        "affected": json.dumps(affected if affected is not None
                               else {"devices": ["dev-a"]}, sort_keys=True),
        "created_at_ms": _ms(written),
        "top_hypothesis": hypothesis,
        "verdict_tier": tier,
    }


def _tenants_in(sql: str) -> set[str]:
    """The tenant IN list the seed actually asked for. Parsed rather than
    assumed — a mutant that drops the clause must be visible here."""
    head = sql.split("tenant_id IN (", 1)
    if len(head) == 1:
        return set()
    body = head[1].split(")", 1)[0]
    return {p.strip().strip("'") for p in body.split(",") if p.strip()}


def _limit_in(sql: str) -> int:
    return int(sql.rsplit("LIMIT", 1)[1].split()[0])


class _SeedCH:
    """A ClickHouse stub that enforces the scoping the real one would.

    It answers the two seed queries the way the server does — including the
    tenant IN filter, the ORDER BY created_at DESC, the LIMIT and the
    pre-LIMIT `count() OVER ()` — so a test that asserts "no foreign object was
    seeded" is testing the ENGINE's scoping, not the stub's kindness.
    """

    def __init__(self, rows=(), *, fail: bool = False, hostile: bool = False):
        self.rows = [dict(r) for r in rows]
        self.fail = fail
        # `hostile`: a broken/compromised store that returns rows the query did
        # NOT ask for. §3 — never trust upstream, not even our own database.
        self.hostile = hostile
        self.queries: list[str] = []
        self.inserted: dict[str, list] = {}

    async def query(self, sql: str) -> list[dict]:
        self.queries.append(sql)
        if self.fail:
            raise httpx.ConnectError("clickhouse unreachable")
        if "SELECT DISTINCT tenant_id" in sql:
            return [{"tenant_id": t}
                    for t in sorted({r["tenant_id"] for r in self.rows})]
        wanted = _tenants_in(sql)
        rows = self.rows if self.hostile else [r for r in self.rows
                                               if r["tenant_id"] in wanted]
        # Honour the ORDER BY the SQL actually asked for — the cap keeps the
        # PREFIX of that order, so which rows survive the LIMIT is the engine's
        # decision, not the stub's (a mutant that flips DESC must be visible).
        desc = "created_at DESC" in sql
        rows = sorted(rows, key=lambda r: ((-1 if desc else 1) * int(r["created_at_ms"]),
                                           r["correlation_id"]))
        cap = _limit_in(sql)
        return [dict(r, open_total=str(len(rows))) for r in rows[:cap]]

    async def insert(self, table: str, rows: list, dedup_token: str = "") -> None:
        self.inserted.setdefault(table, []).extend(rows)

    def objects(self) -> list[dict]:
        return self.inserted.get("netops.corr_objects", [])


def _sig(tenant: str, entity: str, *, offset_s: float, kind: str = "device_cpu_high",
         at: datetime | None = None) -> Signal:
    at = T0 if at is None else at
    return Signal(
        tenant_id=tenant, ts=at + timedelta(seconds=offset_s), source=Source.METRIC,
        kind=kind, observer=Observer(observer_id="obs-155",
                                     observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY,
        entity_type=EntityType.DEVICE, entity_id=entity, severity=Severity.CRIT,
        native_id=f"155|{kind}|{entity}|{offset_s}",
        attrs={"onset_uncertainty_s": 5.0},
    )


def _owned_tenant(partition: int, total: int, stem: str = "t-155-") -> str:
    """A tenant id that hashes onto `partition` — the producers' own keying."""
    for i in range(10_000):
        t = f"{stem}{i}"
        if main.tenant_partition(main.canon_tenant(t), total) == partition:
            return t
    raise AssertionError("no tenant found for that partition")


def _assign(partitions: set[int], total: int = 4) -> None:
    """Pretend the last rebalance handed this replica `partitions`."""
    main.CONSUMER_PARTITION_TOTALS.clear()
    main.CONSUMER_PARTITION_TOTALS.update({t: total for t in main.TOPICS})
    main.CONSUMER_ASSIGNMENT.clear()
    main.CONSUMER_ASSIGNMENT.update({t: sorted(partitions) for t in main.TOPICS})


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    main.OPEN_OBJECTS.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear()
    main.TENANT_WATERMARK.clear()
    # P2 step 4a's cross-epoch merge candidate space is module-level and
    # survives a test; leaving it dirty makes a later lifecycle pass merge
    # objects an earlier test named. Reset it with everything else.
    main._LIFECYCLE_SEEN_WINDOW.clear()
    for counter in ("OWNERSHIP_SEED_RUNS_TOTAL", "OWNERSHIP_SEEDED_OBJECTS_TOTAL",
                    "OWNERSHIP_ADOPTIONS_TOTAL", "OWNERSHIP_SEED_FAILURES_TOTAL",
                    "OWNERSHIP_SEED_SKIPPED_TOTAL", "OWNERSHIP_SEED_EXPIRED_TOTAL",
                    "OWNERSHIP_SEED_REVOKED_TOTAL",
                    "OWNERSHIP_SEED_UNOWNED_DROPPED_TOTAL",
                    "OWNERSHIP_SEED_VERDICT_CARRIED_TOTAL",
                    # Tracker 155 completion: flush-and-release + the two guards.
                    "OWNERSHIP_HANDOFF_FLUSHED_TOTAL",
                    "OWNERSHIP_HANDOFF_UNFLUSHED_TOTAL",
                    "OWNERSHIP_HANDOFF_RELEASED_TOTAL",
                    "OWNERSHIP_UNOWNED_PERSIST_DROPPED_TOTAL",
                    "OWNERSHIP_UNOWNED_ADMISSION_DROPPED_TOTAL",
                    "OPEN_OBJECTS_FORCE_CLOSED", "VERSIONS_PERSISTED"):
        monkeypatch.setattr(main, counter, 0)
    monkeypatch.setattr(main, "_OWNERSHIP_SEED_TASK", None)
    main._OWNERSHIP_PENDING_RELEASE.clear()
    _Clock.current = T0
    yield
    main.OPEN_OBJECTS.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main.CONSUMER_ASSIGNMENT.clear()
    main.CONSUMER_PARTITION_TOTALS.clear()
    main.CONSUMER_PARTITION_ACQUIRED_AT.clear()
    main._OWNERSHIP_PENDING_RELEASE.clear()
    main.CONSUMER_ASSIGNMENT_SEEN = False


# ── (a) the seed builds a registration find_continuation adopts ──────────────

def test_seeded_registration_is_a_continuation_candidate(monkeypatch):
    """The unit contract: a placeholder built from a durable row is an object
    the EXACT continuation predicate picks — same tenant, overlapping window,
    entity set recovered from `affected`."""
    tenant = "t-155-unit"
    reg_made = main._seed_register(
        _row(SEED_CID, tenant, affected={"devices": ["dev-a", "dev-b"]}),
        T0, frozenset({tenant}))
    assert reg_made and SEED_CID in main.OPEN_OBJECTS
    seeded = main.OPEN_OBJECTS[SEED_CID]["snapshot"]

    fresh = run_window(
        (_sig(tenant, "dev-a", offset_s=10), _sig(tenant, "dev-b", offset_s=20)),
        CAT, (), main.ENGINE_CFG)
    assert fresh, "fixture must produce at least one object"
    for snap in fresh:
        assert find_continuation(snap, [seeded]) == SEED_CID, (
            "a reconstructed identity must be adoptable by the same predicate "
            "an in-process re-key uses")


def test_seeded_placeholder_asserts_no_verdict():
    """`reconstruct identity, not state`: the placeholder carries identity and
    nothing that could be mistaken for reasoning this replica never did."""
    tenant = "t-155-unit"
    main._seed_register(_row(SEED_CID, tenant), T0, frozenset({tenant}))
    reg = main.OPEN_OBJECTS[SEED_CID]
    snap = reg["snapshot"]
    assert main._seed_only(reg)
    assert reg["version"] == 7
    assert reg["hash"] == "" and reg["material"] == "", (
        "sentinel hashes: the first arriving snapshot must always take the "
        "material-moved persist branch, never the damped one")
    assert snap.edges == () and snap.seams == ()
    assert snap.ranking.top_hypothesis == "undetermined"
    assert snap.ranking.hypotheses == ()
    assert {n.kind for n in snap.nodes} == {main._SEED_NODE_KIND}
    assert all(n.signals == () for n in snap.nodes)


def _run_seeded_cycle(monkeypatch, stub, *, tenant, partition, signals,
                      at: datetime | None = None):
    """Seed for `partition`, then run ONE engine cycle over `signals`."""
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "datetime", _Clock)
    _assign({partition})
    asyncio.run(main._run_ownership_seed(frozenset({partition})))
    if at is not None:
        _Clock.current = at
    for s in signals:
        main.buffer_signal(s)
    asyncio.run(main.engine_cycle())


def test_arriving_evidence_continues_the_original_id(monkeypatch):
    """(a) END-TO-END, the measured failure inverted. The replica acquires a
    partition, reconstructs the in-flight object's identity, and the next
    evidence for it lands on the ORIGINAL correlation_id at version 8 —
    NOT on a freshly minted fragment."""
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH([_row(SEED_CID, tenant, version=7,
                         affected={"devices": ["dev-a"]})])
    _run_seeded_cycle(monkeypatch, stub, tenant=tenant, partition=2,
                      signals=[_sig(tenant, "dev-a", offset_s=o)
                               for o in (0, 30, 60)])

    assert list(main.OPEN_OBJECTS) == [SEED_CID], (
        "the incident fragmented: a new correlation_id was minted instead of "
        f"continuing {SEED_CID[:8]} — {list(main.OPEN_OBJECTS)}")
    reg = main.OPEN_OBJECTS[SEED_CID]
    assert not main._seed_only(reg), "adoption must clear the placeholder flag"
    assert reg["version"] == 8, "the continuation must start ABOVE the loaded max"
    assert main.OWNERSHIP_ADOPTIONS_TOTAL == 1
    assert main.OWNERSHIP_SEEDED_OBJECTS_TOTAL == 1
    versions = [(r["correlation_id"], r["version"], r["state"])
                for r in stub.objects()]
    assert versions == [(SEED_CID, 8, "open")], versions


def test_adoption_survives_a_rekeyed_window(monkeypatch):
    """The find_continuation half specifically: the arriving snapshot's own
    derived id differs from the seeded one (a re-keyed window is exactly what
    a cold replica produces), and it is still the same incident."""
    tenant = _owned_tenant(1, 4)
    stub = _SeedCH([_row(SEED_CID, tenant, version=3,
                         affected={"devices": ["dev-a", "dev-b"]})])
    # Derive what the engine WOULD mint from a cold window, to prove the ids
    # genuinely differ and the test is not passing by coincidence.
    fresh_sigs = [_sig(tenant, "dev-a", offset_s=o) for o in (5, 45)]
    minted = {s.correlation_id for s in run_window(tuple(fresh_sigs), CAT, (),
                                                   main.ENGINE_CFG)}
    assert SEED_CID not in minted, "fixture invalid: the ids must differ"

    _run_seeded_cycle(monkeypatch, stub, tenant=tenant, partition=1,
                      signals=fresh_sigs)
    assert list(main.OPEN_OBJECTS) == [SEED_CID]
    assert main.OWNERSHIP_ADOPTIONS_TOTAL == 1
    assert main.OPEN_OBJECTS[SEED_CID]["version"] == 4


def test_a_seed_landing_mid_cycle_is_not_clobbered(monkeypatch):
    """The seed task runs on the SAME event loop as the engine cycle, so it can
    register an identity in the window between "no registration for this id"
    and the fresh registration being written (content_hash is offloaded across
    an await). The cycle must re-read and ADOPT, not overwrite a placeholder
    that carries the object's real version and pre-handoff blast radius."""
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH()
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "datetime", _Clock)
    sigs = [_sig(tenant, "dev-a", offset_s=o) for o in (0, 30)]
    minted = run_window(tuple(sigs), CAT, (), main.ENGINE_CFG)[0].correlation_id

    real_snap_call = main._snap_call
    fired = {"yes": False}

    async def _racing_snap_call(snap, fn, /, *args, **kwargs):
        if not fired["yes"] and getattr(fn, "__name__", "") == "content_hash":
            fired["yes"] = True                     # the seed lands right here
            main._seed_register(_row(minted, tenant, version=11),
                                _Clock.current, frozenset({tenant}))
        return await real_snap_call(snap, fn, *args, **kwargs)

    monkeypatch.setattr(main, "_snap_call", _racing_snap_call)
    for sig in sigs:
        main.buffer_signal(sig)
    asyncio.run(main.engine_cycle())

    assert fired["yes"], "fixture: the race was never triggered"
    assert list(main.OPEN_OBJECTS) == [minted]
    assert main.OPEN_OBJECTS[minted]["version"] == 12, (
        "the cycle clobbered a concurrently seeded placeholder with a fresh v1")
    assert main.OWNERSHIP_ADOPTIONS_TOTAL == 1


# ── (b) fail-open ────────────────────────────────────────────────────────────

def test_clickhouse_down_at_assignment_falls_back_to_head_behaviour(monkeypatch, caplog):
    tenant = _owned_tenant(0, 4)
    stub = _SeedCH([_row(SEED_CID, tenant)], fail=True)
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "CORR_OWNERSHIP_SEED_ATTEMPTS", 1)
    _assign({0})
    with caplog.at_level("WARNING", logger="correlation"):
        asyncio.run(main._run_ownership_seed(frozenset({0})))
    assert main.OPEN_OBJECTS == {}, "a failed seed must leave no partial state"
    assert main.OWNERSHIP_SEED_FAILURES_TOTAL == 1
    assert main.OWNERSHIP_SEEDED_OBJECTS_TOTAL == 0
    msg = " ".join(r.getMessage() for r in caplog.records)
    assert "ownership seed FAILED" in msg and "not" in msg and "outage" in msg, (
        f"the fallback must be named honestly in the log: {msg}")


def test_a_failed_seed_does_not_stop_the_engine(monkeypatch):
    """Fail-open means the cycle after it behaves EXACTLY as HEAD does — a new
    object under a freshly derived id, and no exception anywhere."""
    tenant = _owned_tenant(0, 4)
    stub = _SeedCH([_row(SEED_CID, tenant)], fail=True)
    monkeypatch.setattr(main, "CORR_OWNERSHIP_SEED_ATTEMPTS", 1)
    _run_seeded_cycle(monkeypatch, stub, tenant=tenant, partition=0,
                      signals=[_sig(tenant, "dev-a", offset_s=0)])
    assert main.OWNERSHIP_SEED_FAILURES_TOTAL == 1
    assert SEED_CID not in main.OPEN_OBJECTS
    assert len(main.OPEN_OBJECTS) == 1, "HEAD's behaviour: one fresh object"


def test_no_clickhouse_means_no_task(monkeypatch):
    """A dev/offline process (ch is None) must not schedule anything."""
    monkeypatch.setattr(main, "ch", None)

    async def _go():
        main._schedule_ownership_seed(frozenset({0, 1}))
        return main._OWNERSHIP_SEED_TASK

    assert asyncio.run(_go()) is None


def test_master_switch_off_schedules_nothing(monkeypatch):
    monkeypatch.setattr(main, "ch", _SeedCH())
    monkeypatch.setattr(main, "CORR_OWNERSHIP_SEED", False)

    async def _go():
        main._schedule_ownership_seed(frozenset({0}))
        return main._OWNERSHIP_SEED_TASK

    assert asyncio.run(_go()) is None


# ── (c) §3a tenant isolation ─────────────────────────────────────────────────

def test_seed_query_is_tenant_scoped(monkeypatch):
    """The row query names ONLY the tenants whose partitions were acquired.
    Mutant: drop the `tenant_id IN (...)` clause -> this fails."""
    mine = _owned_tenant(3, 4, stem="t-mine-")
    theirs = _owned_tenant(0, 4, stem="t-theirs-")
    assert main.tenant_partition(theirs, 4) != 3
    stub = _SeedCH([_row(SEED_CID, mine), _row(OTHER_CID, theirs)])
    monkeypatch.setattr(main, "ch", stub)
    _assign({3})
    asyncio.run(main._run_ownership_seed(frozenset({3})))

    row_sql = [q for q in stub.queries if "corr_current FINAL" in q]
    assert len(row_sql) == 1
    assert _tenants_in(row_sql[0]) == {mine}, (
        "the seed asked for a tenant this replica does not own")
    assert list(main.OPEN_OBJECTS) == [SEED_CID]
    assert OTHER_CID not in main.OPEN_OBJECTS


def test_seed_refuses_an_out_of_scope_row(monkeypatch):
    """Zero trust (§3), including in our own store: a ClickHouse that answers
    with a tenant the query did not ask for is REFUSED, counted and logged.
    Mutant: drop the `tenant not in owned` guard -> this fails."""
    mine = _owned_tenant(3, 4, stem="t-mine-")
    theirs = _owned_tenant(0, 4, stem="t-theirs-")
    stub = _SeedCH([_row(SEED_CID, mine), _row(OTHER_CID, theirs)], hostile=True)
    monkeypatch.setattr(main, "ch", stub)
    _assign({3})
    asyncio.run(main._run_ownership_seed(frozenset({3})))

    assert list(main.OPEN_OBJECTS) == [SEED_CID], (
        "a foreign tenant's object entered this replica's working memory")
    assert main.OWNERSHIP_SEED_SKIPPED_TOTAL == 1


def test_a_seeded_identity_never_crosses_tenants(monkeypatch):
    """The adoption path keeps §3a default-closed: identical entities in
    ANOTHER tenant are never the same incident."""
    mine = _owned_tenant(3, 4, stem="t-mine-")
    theirs = _owned_tenant(0, 4, stem="t-theirs-")
    main._seed_register(_row(SEED_CID, theirs), T0, frozenset({theirs}))
    seeded = main.OPEN_OBJECTS[SEED_CID]["snapshot"]
    for snap in run_window((_sig(mine, "dev-a", offset_s=0),), CAT, (),
                           main.ENGINE_CFG):
        assert find_continuation(snap, [seeded]) == ""


# ── (d) idempotency ──────────────────────────────────────────────────────────

def test_second_assignment_inside_the_cold_window_does_not_double_seed(monkeypatch):
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH([_row(SEED_CID, tenant)])
    monkeypatch.setattr(main, "ch", stub)
    _assign({2})
    asyncio.run(main._run_ownership_seed(frozenset({2})))
    first = dict(main.OPEN_OBJECTS[SEED_CID])
    asyncio.run(main._run_ownership_seed(frozenset({2})))

    assert list(main.OPEN_OBJECTS) == [SEED_CID]
    assert main.OWNERSHIP_SEEDED_OBJECTS_TOTAL == 1, "the second seed re-registered"
    assert main.OPEN_OBJECTS[SEED_CID]["snapshot"] is first["snapshot"], (
        "an idempotent re-seed must leave the existing registration untouched")


def test_a_seed_never_clobbers_live_state(monkeypatch):
    """A cycle running concurrently with the seed task may already have opened
    the object. Live in-process state always wins."""
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH([_row(SEED_CID, tenant, version=7)])
    monkeypatch.setattr(main, "ch", stub)
    _assign({2})
    main.OPEN_OBJECTS[SEED_CID] = {"version": 42, "hash": "live", "material": "m",
                                   "last_seen": T0, "last_persist": T0,
                                   "snapshot": None, "opened_at": T0}
    asyncio.run(main._run_ownership_seed(frozenset({2})))
    assert main.OPEN_OBJECTS[SEED_CID]["version"] == 42
    assert main.OPEN_OBJECTS[SEED_CID]["hash"] == "live"
    assert not main._seed_only(main.OPEN_OBJECTS[SEED_CID])


# ── (e) a late final version from the old owner ──────────────────────────────

def test_a_late_old_owner_version_cannot_rewind_an_adopted_object(monkeypatch):
    """155a saw revoke-hook commits land after the move. The old owner may
    persist one more version while (or after) this replica seeds; a later
    re-seed reading that row must NOT rewind the adopted object's version."""
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH([_row(SEED_CID, tenant, version=7)])
    _run_seeded_cycle(monkeypatch, stub, tenant=tenant, partition=2,
                      signals=[_sig(tenant, "dev-a", offset_s=0)])
    assert main.OPEN_OBJECTS[SEED_CID]["version"] == 8

    # The old owner's late write lands: corr_current now says v9.
    stub.rows = [_row(SEED_CID, tenant, version=9,
                      written=T0 + timedelta(seconds=5))]
    asyncio.run(main._run_ownership_seed(frozenset({2})))
    reg = main.OPEN_OBJECTS[SEED_CID]
    assert reg["version"] == 8, "a durable row must never rewind live state"
    assert not main._seed_only(reg)
    assert main.OWNERSHIP_ADOPTIONS_TOTAL == 1


def test_the_first_adopted_version_is_above_the_loaded_maximum(monkeypatch):
    """Version-collision reasoning, pinned: whatever the durable maximum is,
    this replica's first persisted version is loaded+1 — never a restart at 1
    (which is what HEAD does on every handoff)."""
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH([_row(SEED_CID, tenant, version=137)])
    _run_seeded_cycle(monkeypatch, stub, tenant=tenant, partition=2,
                      signals=[_sig(tenant, "dev-a", offset_s=0)])
    assert [r["version"] for r in stub.objects()] == [138]


# ── (f) a seeded object nothing adopts ───────────────────────────────────────

def _seed_and_sweep(monkeypatch, stub, tenant, partition, *, at):
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "datetime", _Clock)
    _assign({partition})
    asyncio.run(main._run_ownership_seed(frozenset({partition})))
    _Clock.current = at
    asyncio.run(main.engine_cycle())      # empty window: lifecycle passes only


def test_a_silent_seeded_object_is_closed_by_quiesce(monkeypatch):
    """(f) It must not be frozen open forever — and it must be DROPPED, not
    persisted: a placeholder has no verdict this replica may publish."""
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH([_row(SEED_CID, tenant, written=T0 - timedelta(hours=1))])
    _seed_and_sweep(monkeypatch, stub, tenant, 2,
                    at=T0 + timedelta(seconds=main.CORR_QUIESCE_S + 60))
    assert main.OPEN_OBJECTS == {}
    assert main.OWNERSHIP_SEED_EXPIRED_TOTAL == 1
    assert stub.objects() == [], (
        "an unadopted placeholder must never write a terminal version — that "
        "would publish an empty verdict over the previous owner's real one")


def test_a_seeded_object_gets_one_cold_window_before_quiesce(monkeypatch):
    """The clamp: the window has not refilled inside RETENTION_REQUIRED_S, so
    closing a placeholder sooner would judge it on evidence this replica
    structurally could not have seen."""
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH([_row(SEED_CID, tenant, written=T0 - timedelta(days=2))])
    _seed_and_sweep(monkeypatch, stub, tenant, 2,
                    at=T0 + timedelta(seconds=main.RETENTION_REQUIRED_S / 2))
    assert SEED_CID in main.OPEN_OBJECTS, (
        "a placeholder was quiesced before the window could refill")
    assert main.OWNERSHIP_SEED_EXPIRED_TOTAL == 0


def test_the_163_cap_drops_a_placeholder_without_force_closing_it(monkeypatch):
    """Terminal path 3 of 3. The count cap's bound still holds (the entry
    leaves OPEN_OBJECTS), but a dropped placeholder is not a force-CLOSED
    object and is never counted or persisted as one."""
    tenant = _owned_tenant(2, 4)
    # DISJOINT blast radii, so the lifecycle MERGE pass can never take one of
    # them first and leave the cap with nothing to do.
    stub = _SeedCH([_row(SEED_CID, tenant, written=T0,
                         affected={"devices": ["dev-a"]}),
                    _row(OTHER_CID, tenant, written=T0 - timedelta(seconds=30),
                         affected={"devices": ["dev-z"]})])
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "datetime", _Clock)
    monkeypatch.setattr(main, "CORR_QUIESCE_S", 10 ** 9)   # quiesce must not fire
    _assign({2})
    asyncio.run(main._run_ownership_seed(frozenset({2})))
    assert len(main.OPEN_OBJECTS) == 2

    monkeypatch.setattr(main, "CORR_OPEN_OBJECTS_MAX", 1)
    asyncio.run(main.engine_cycle())
    assert len(main.OPEN_OBJECTS) == 1, "the 163 bound must still be enforced"
    assert main.OWNERSHIP_SEED_EXPIRED_TOTAL == 1
    assert main.OPEN_OBJECTS_FORCE_CLOSED == 0, (
        "a dropped placeholder is not a force-closed object")
    assert stub.objects() == []


def test_a_lifecycle_merge_drops_a_placeholder_instead_of_tombstoning_it(monkeypatch):
    """Terminal path 1 of 3. `state='merged'` on a placeholder would publish
    its empty content as that id's last durable word."""
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH()
    monkeypatch.setattr(main, "ch", stub)
    main._seed_register(_row(SEED_CID, tenant,
                             affected={"devices": ["dev-a", "dev-b"]}),
                        T0, frozenset({tenant}))
    survivor = run_window((_sig(tenant, "dev-a", offset_s=0),
                           _sig(tenant, "dev-b", offset_s=20)),
                          CAT, (), main.ENGINE_CFG)[0]
    main.OPEN_OBJECTS[survivor.correlation_id] = {
        "version": 1, "hash": "h", "material": "m", "last_seen": T0,
        "last_persist": T0, "snapshot": survivor, "opened_at": T0,
        "affected_hist": main.AffectedHistory(main.CORR_AFFECTED_HISTORY_MAX),
    }
    epoch = main._EngineEpoch(T0)
    asyncio.run(main._epoch_lifecycle(epoch, main._noop_yield,
                                      seen={survivor.correlation_id}))
    assert SEED_CID not in main.OPEN_OBJECTS
    assert main.OWNERSHIP_SEED_EXPIRED_TOTAL == 1
    assert not [r for r in stub.objects() if r["state"] == "merged"], (
        "a placeholder was tombstoned with content this replica never saw")


# ── (g) tracker 187: the monotone blast radius spans the handoff ─────────────

def test_final_affected_spans_the_handoff(monkeypatch):
    """The AffectedHistory is re-seeded from the loaded radius, so the object's
    FINAL affected covers what it touched BEFORE the move as well as after."""
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH([_row(SEED_CID, tenant, version=4,
                         affected={"devices": ["dev-a", "dev-b"]})])
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "datetime", _Clock)
    _assign({2})
    asyncio.run(main._run_ownership_seed(frozenset({2})))
    # Post-move evidence names dev-a ONLY (dev-b has already aged out of the
    # window) — 0.5 Jaccard, so it still adopts.
    for s in (_sig(tenant, "dev-a", offset_s=0), _sig(tenant, "dev-a", offset_s=30)):
        main.buffer_signal(s)
    asyncio.run(main.engine_cycle())
    assert list(main.OPEN_OBJECTS) == [SEED_CID]
    assert main.OPEN_OBJECTS[SEED_CID]["snapshot"].affected() == {
        "devices": ["dev-a"]}, "fixture: the live radius must have shrunk"

    # Go silent; quiesce closes the now-REAL object with the monotone union.
    _Clock.current = T0 + timedelta(seconds=main.CORR_QUIESCE_S + 120)
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    asyncio.run(main.engine_cycle())
    closed = [r for r in stub.objects() if r["state"] == "closed"]
    assert len(closed) == 1, closed
    assert json.loads(closed[0]["affected"]) == {"devices": ["dev-a", "dev-b"]}, (
        "tracker 187's monotone final radius must span the partition handoff, "
        "not restart at it")


# ── (h) bounded ──────────────────────────────────────────────────────────────

def test_cap_is_respected_and_the_oldest_are_skipped(monkeypatch):
    """The seed is bounded; the overflow is EXACT (`count() OVER ()` is
    evaluated before LIMIT); and the rows kept are the freshest durable writes,
    because an object close to quiesce is the one least likely to receive
    further evidence — the same staleness order the 163 cap evicts in."""
    tenant = _owned_tenant(2, 4)
    rows = [_row(f"155a0000-0000-4000-8000-00000000000{i}", tenant,
                 written=T0 - timedelta(seconds=60 * i)) for i in range(5)]
    stub = _SeedCH(rows)
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "CORR_OWNERSHIP_SEED_MAX", 3)
    _assign({2})
    asyncio.run(main._run_ownership_seed(frozenset({2})))

    assert len(main.OPEN_OBJECTS) == 3
    assert main.OWNERSHIP_SEEDED_OBJECTS_TOTAL == 3
    assert main.OWNERSHIP_SEED_SKIPPED_TOTAL == 2, "the overflow must be exact"
    assert set(main.OPEN_OBJECTS) == {r["correlation_id"] for r in rows[:3]}, (
        "the cap must skip the OLDEST durable writes, not the newest")


def test_an_unreconstructable_or_oversized_radius_is_skipped(monkeypatch):
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH([
        _row(SEED_CID, tenant, affected={}),                      # no entities
        _row(OTHER_CID, tenant,
             affected={"devices": [f"d{i}" for i in range(50)]}),  # over the cap
    ])
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "CORR_OWNERSHIP_SEED_ENTITIES_MAX", 10)
    _assign({2})
    asyncio.run(main._run_ownership_seed(frozenset({2})))
    assert main.OPEN_OBJECTS == {}
    assert main.OWNERSHIP_SEED_SKIPPED_TOTAL == 2


def test_seed_sql_shape_is_pinned():
    """The query's correctness properties, asserted rather than assumed."""
    sql = main._seed_sql(("t-a", "t-b"))
    assert "netops.corr_current FINAL" in sql, (
        "without FINAL a superseded 'open' row can outlive the 'closed' row "
        "that replaced it and the seed would resurrect a closed object")
    assert "state = 'open'" in sql
    assert "count() OVER ()" in sql
    assert _tenants_in(sql) == {"t-a", "t-b"}
    assert _limit_in(sql) == main.CORR_OWNERSHIP_SEED_MAX
    assert f"toIntervalSecond({main.CORR_OWNERSHIP_SEED_HORIZON_S:.3f})" in sql


def test_horizon_is_derived_from_the_lifecycle_constants():
    """Not a chosen number: quiesce (how long an object can stay open unseen)
    plus one engine window (how far back evidence can still attach)."""
    assert main.CORR_OWNERSHIP_SEED_HORIZON_S == pytest.approx(
        main.CORR_QUIESCE_S + main.RETENTION_REQUIRED_S)


def test_a_tenant_id_with_sql_metacharacters_is_refused():
    """`ch.query` posts raw SQL and ClickHouse honours backslash escapes, so
    the charset validation is the injection guard (§3/§8)."""
    assert main._seed_safe_tenant("t_acme-1.2")
    assert main._seed_safe_tenant("")            # the legacy platform-global id
    for hostile in ("t'; DROP TABLE netops.corr_objects; --", "t\\'", "a b", "t\n"):
        assert not main._seed_safe_tenant(hostile), hostile


# ── the rebalance callback itself ────────────────────────────────────────────

def test_the_rebalance_callback_does_no_io(monkeypatch):
    """`on_partitions_assigned` runs INSIDE the rejoin. It must schedule and
    return: not one ClickHouse round-trip before the group re-forms."""
    stub = _SeedCH()
    monkeypatch.setattr(main, "ch", stub)

    class _Recorder:
        def partitions_for_topic(self, topic):
            return {0, 1, 2, 3}

    class _TP:
        def __init__(self, topic, partition):
            self.topic, self.partition = topic, partition

    main.CONSUMER_PARTITION_ACQUIRED_AT.clear()
    listener = main._AssignmentLogger(_Recorder())

    async def _drive():
        await listener.on_partitions_assigned([_TP(t, 2) for t in main.TOPICS])
        queries_at_return = list(stub.queries)
        task = main._OWNERSHIP_SEED_TASK
        assert task is not None, "the seed must have been scheduled"
        await task
        return queries_at_return

    assert asyncio.run(_drive()) == [], (
        "the rebalance callback performed I/O — every millisecond here is a "
        "millisecond the consumer group is not re-forming")


def test_only_newly_acquired_partitions_are_seeded(monkeypatch):
    """A RETAINED partition's objects are already in this process's memory."""
    stub = _SeedCH()
    monkeypatch.setattr(main, "ch", stub)
    seen: list[frozenset[int]] = []
    monkeypatch.setattr(main, "_schedule_ownership_seed", seen.append)

    class _Recorder:
        def partitions_for_topic(self, topic):
            return {0, 1, 2, 3}

    class _TP:
        def __init__(self, topic, partition):
            self.topic, self.partition = topic, partition

    main.CONSUMER_PARTITION_ACQUIRED_AT.clear()
    listener = main._AssignmentLogger(_Recorder())
    asyncio.run(listener.on_partitions_assigned([_TP(t, 0) for t in main.TOPICS]))
    asyncio.run(listener.on_partitions_assigned(
        [_TP(t, 0) for t in main.TOPICS] + [_TP(t, 1) for t in main.TOPICS]))
    assert seen == [frozenset({0}), frozenset({1})], seen


# ═════════════════════════════════════════════════════════════════════════════
# TRACKER 155b — the three defects the LIVE validation measured
# (run /var/tmp/scale-runs/ownership-155b-08310318, 2026-08-31; arms: control,
# restart, exit/join). The seeding above ran perfectly — every acquiring replica
# seeded, 0 failures, 0 fabricated content — and the incident STILL fragmented:
# 1 adoption in 32 placeholders, and the one adoption landed on the WRONG
# replica and demoted the row it continued. What follows pins the three fixes.
# ═════════════════════════════════════════════════════════════════════════════
#
# MUTANTS (verified by hand while writing these):
#   * drop `match_slack_s` from `_seed_snapshot` (or make `_match_window_end`
#     return `s.window_end`) -> test_a_placeholder_is_admitted_across_the_cold_
#     window_gap fails: the placeholder is not a candidate and a fragment id is
#     minted.
#   * remove the `_seed_discard_revoked` call from `on_partitions_revoked` ->
#     test_revoking_a_partition_discards_its_placeholders fails.
#   * make `_ownership_persist_guard` return True unconditionally ->
#     test_an_adopted_seed_will_not_persist_on_an_unowned_partition fails: the
#     thin first version is written and the counter stays 0.
#   * remove the expiry branch from `_seed_verdict_floor` ->
#     test_the_verdict_floor_expires_and_a_weaker_tier_publishes fails.


def _placeholder(tenant: str, *, end: datetime, start: datetime | None = None,
                 cid: str = SEED_CID, **kw):
    """Register ONE placeholder and hand back the snapshot it stands on."""
    start = end - timedelta(seconds=300) if start is None else start
    assert main._seed_register(
        _row(cid, tenant, start=start, end=end,
             affected={"devices": ["dev-a"]}, **kw),
        T0, frozenset({tenant}))
    return main.OPEN_OBJECTS[cid]["snapshot"]


def _cold_snapshot(tenant: str, at: datetime):
    """What a replica that acquired the partition at `at` would emit once its
    window started refilling — a genuinely cold window, so its own derived id
    differs from the durable one."""
    fresh = run_window((_sig(tenant, "dev-a", offset_s=0, at=at),
                        _sig(tenant, "dev-a", offset_s=30, at=at)),
                       CAT, (), main.ENGINE_CFG)
    assert fresh, "fixture must produce at least one object"
    return fresh[0]


# ── D1: the placeholder's match window must bridge the cold window ───────────

def test_a_placeholder_is_admitted_across_the_cold_window_gap():
    """THE MEASURED MISS. `corr_current.window_end` is the last WRITTEN evidence
    time of a still-open incident; the acquiring replica's first snapshot begins
    AFTER it by however long the cold window lasted (155b measured 10.1 / 18.0 /
    35.4 s). Frozen there, the placeholder was never a continuation candidate."""
    tenant = "t-155b-slack"
    gap = timedelta(seconds=main.CORR_OWNERSHIP_SEED_SLACK_S / 2)
    seeded = _placeholder(tenant, end=T0)
    arriving = _cold_snapshot(tenant, T0 + gap)

    assert arriving.window_start > seeded.window_end, (
        "fixture invalid: the arriving window must start AFTER the durable end "
        "— that gap IS the defect")
    assert arriving.correlation_id != SEED_CID, "fixture invalid: ids must differ"
    assert find_continuation(arriving, [seeded]) == SEED_CID, (
        "a cold replica's first snapshot must still adopt the identity the "
        "seed reconstructed — otherwise the incident fragments")


def test_a_placeholder_is_not_admitted_beyond_the_slack():
    """The bridge is BOUNDED. Past the horizon on which evidence can still
    attach, a placeholder is a stale identity and adopting it would weld two
    unrelated incidents together."""
    tenant = "t-155b-slack"
    gap = timedelta(seconds=main.CORR_OWNERSHIP_SEED_SLACK_S + 60)
    seeded = _placeholder(tenant, end=T0)
    arriving = _cold_snapshot(tenant, T0 + gap)
    assert find_continuation(arriving, [seeded]) == "", (
        "the slack must be a bounded bridge, not an open-ended one")


def test_the_seed_slack_is_derived_from_the_retention_constant():
    """Not a chosen number (and emphatically not the literal 516): the engine's
    OWN statement of how far back evidence can still attach to a window, which
    is exactly how long the acquiring replica needs to refill it."""
    assert main.CORR_OWNERSHIP_SEED_SLACK_S == pytest.approx(
        main.RETENTION_REQUIRED_S)
    seeded = _placeholder("t-155b-derived", end=T0)
    assert seeded.match_slack_s == pytest.approx(main.RETENTION_REQUIRED_S)
    assert seeded.window_end == T0, (
        "the placeholder must report the DURABLE window it was built from — "
        "only the MATCHING is extended")


def test_live_object_matching_is_oracle_unchanged():
    """The slack may not leak into ordinary matching. Oracle: for snapshots
    with no slack — every snapshot `run_window` emits — `_windows_overlap` is
    the pre-155b predicate, over a grid that brackets every boundary case."""
    tenant = "t-155b-oracle"
    base = _cold_snapshot(tenant, T0)
    assert base.match_slack_s == 0.0, (
        "run_window must never emit a slacked snapshot — the slack belongs to "
        "the ownership seed alone")

    def _win(start_s: float, end_s: float):
        return dc_replace(base,
                          window_start=T0 + timedelta(seconds=start_s),
                          window_end=T0 + timedelta(seconds=end_s))

    grid = [(0, 10), (10, 20), (20, 30), (-30, -10), (5, 25), (10, 10)]
    checked = 0
    for a_bounds in grid:
        for b_bounds in grid:
            a, b = _win(*a_bounds), _win(*b_bounds)
            expected = (a.window_start <= b.window_end
                        and b.window_start <= a.window_end)
            assert engine._windows_overlap(a, b) is expected, (a_bounds, b_bounds)
            checked += 1
    assert checked == len(grid) ** 2

    # And the slack is what makes the seeded case differ — so the oracle above
    # is passing because live objects carry none, not because it is inert.
    far = _win(600, 620)
    slacked = dc_replace(_win(0, 10), match_slack_s=1000.0)
    assert not engine._windows_overlap(_win(0, 10), far)
    assert engine._windows_overlap(slacked, far)


def test_the_cold_window_gap_is_bridged_end_to_end(monkeypatch):
    """(D1) THE 155b FAILURE INVERTED, through `main.engine_cycle`: a replica
    acquires a partition, seeds, and the evidence that arrives AFTER the cold
    window continues the ORIGINAL id instead of minting a fragment."""
    tenant = _owned_tenant(2, 4)
    gap = timedelta(seconds=120)
    stub = _SeedCH([_row(SEED_CID, tenant, version=7,
                         start=T0 - timedelta(seconds=300), end=T0,
                         affected={"devices": ["dev-a"]})])
    _run_seeded_cycle(monkeypatch, stub, tenant=tenant, partition=2,
                      signals=[_sig(tenant, "dev-a", offset_s=o, at=T0 + gap)
                               for o in (0, 30, 60)],
                      at=T0 + gap + timedelta(seconds=60))

    assert list(main.OPEN_OBJECTS) == [SEED_CID], (
        "the incident fragmented across the cold window — "
        f"{list(main.OPEN_OBJECTS)}")
    assert main.OWNERSHIP_ADOPTIONS_TOTAL == 1
    assert [(r["correlation_id"], r["version"]) for r in stub.objects()] == [
        (SEED_CID, 8)]


# ── D2a: a revoked partition's placeholders are discarded ────────────────────

class _TP:
    """The TopicPartition shape the rebalance callbacks are handed."""

    def __init__(self, topic: str, partition: int) -> None:
        self.topic, self.partition = topic, partition


class _NullConsumer:
    def partitions_for_topic(self, topic):
        return {0, 1, 2, 3}


def test_revoking_a_partition_discards_its_placeholders():
    """(D2a) A placeholder is a promise to continue an incident THIS replica
    owns. The moment the partition moves away the promise belongs to another
    replica — and 155b measured what keeping it costs: a replica that held
    partitions for ~5 s adopted one and wrote a thin version 19 s after
    revoking, demoting a confirmed row through corr_current latest-write-wins."""
    _assign({2, 3})
    leaving = _owned_tenant(2, 4)
    staying = _owned_tenant(3, 4)
    _placeholder(leaving, end=T0, cid=SEED_CID)
    _placeholder(staying, end=T0, cid=OTHER_CID)

    listener = main._AssignmentLogger(_NullConsumer())
    asyncio.run(listener.on_partitions_revoked([_TP(t, 2) for t in main.TOPICS]))

    assert SEED_CID not in main.OPEN_OBJECTS, (
        "the revoked partition's placeholder must be discarded")
    assert OTHER_CID in main.OPEN_OBJECTS, (
        "a RETAINED partition's placeholder must survive the revoke")
    assert main.OWNERSHIP_SEED_REVOKED_TOTAL == 1
    assert main.OWNERSHIP_SEED_EXPIRED_TOTAL == 0, (
        "a revoke-discard is its own outcome, not an unadopted expiry")


def test_a_revoke_never_discards_a_live_object():
    """Scoped to UNADOPTED placeholders. An ordinary open object (and an already
    adopted one) is live state — dropping it would lose evidence, and the
    pre-existing orphan half of tracker 155 is not this change's business."""
    _assign({2})
    tenant = _owned_tenant(2, 4)
    _placeholder(tenant, end=T0, cid=SEED_CID)
    main._seed_adopted(main.OPEN_OBJECTS[SEED_CID], SEED_CID, T0)
    assert not main._seed_only(main.OPEN_OBJECTS[SEED_CID])

    listener = main._AssignmentLogger(_NullConsumer())
    asyncio.run(listener.on_partitions_revoked([_TP(t, 2) for t in main.TOPICS]))

    assert SEED_CID in main.OPEN_OBJECTS
    assert main.OWNERSHIP_SEED_REVOKED_TOTAL == 0


# ── D2b: an adopted seed may not persist onto a partition it no longer owns ──

def _seed_adopt_then_reassign(monkeypatch, *, tenant, partition, owned_after):
    """Seed + adopt on `partition`, then rewrite the assignment to
    `owned_after` before the cycle that would persist the first version."""
    stub = _SeedCH([_row(SEED_CID, tenant, version=7,
                         affected={"devices": ["dev-a"]})])
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "datetime", _Clock)
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", True)
    _assign({partition})
    asyncio.run(main._run_ownership_seed(frozenset({partition})))
    _assign(owned_after)
    for s in (_sig(tenant, "dev-a", offset_s=o) for o in (0, 30, 60)):
        main.buffer_signal(s)
    asyncio.run(main.engine_cycle())
    return stub


def test_an_adopted_seed_will_not_persist_on_an_unowned_partition(monkeypatch):
    """(D2b) THE MEASURED WRITE. The transient owner's first version for an
    adopted identity is a corr_current latest-write-wins OVERWRITE of another
    replica's durable row. Written from a replica that has handed the partition
    back, it does not continue the incident — it demotes it."""
    tenant = _owned_tenant(2, 4)
    stub = _seed_adopt_then_reassign(monkeypatch, tenant=tenant, partition=2,
                                     owned_after=set())

    assert stub.objects() == [], (
        "a replica that no longer owns the partition persisted a version for "
        "an identity it adopted — this is the 155b demotion")
    assert SEED_CID not in main.OPEN_OBJECTS, (
        "the registration must be dropped, not left to persist later")
    assert main.OWNERSHIP_SEED_UNOWNED_DROPPED_TOTAL == 1
    assert main.OWNERSHIP_ADOPTIONS_TOTAL == 1, (
        "the adoption itself still happened and is still counted")


def test_an_adopted_seed_persists_while_the_partition_is_still_owned(monkeypatch):
    """The other half: the guard must not cost the TRUE owner its continuation."""
    tenant = _owned_tenant(2, 4)
    stub = _seed_adopt_then_reassign(monkeypatch, tenant=tenant, partition=2,
                                     owned_after={2, 3})

    assert [(r["correlation_id"], r["version"], r["state"])
            for r in stub.objects()] == [(SEED_CID, 8, "open")]
    assert main.OWNERSHIP_SEED_UNOWNED_DROPPED_TOTAL == 0
    assert not main.OPEN_OBJECTS[SEED_CID].get("seed_pending_first_persist"), (
        "the guard is spent once the object has written a version of its own")


def test_the_155b_guard_is_now_the_155c_general_one(monkeypatch):
    """SUPERSEDED ORACLE, kept as the record of what changed.

    Until 155c this file asserted the OPPOSITE of what it asserts now: that an
    object this replica opened ITSELF persists on a partition it does not own
    "exactly as HEAD does", because 155b deliberately scoped its guard to
    seed-descended registrations and left the orphan-write half of tracker 155
    alone. Run ownership-155c-08311027 measured what that costs (F1 and F2
    below), so the guard is now asked of EVERY object — and the seed-scoped
    counter survives as the labelled SUBSET, which is what this pins.
    """
    tenant = _owned_tenant(2, 4)
    stub = _seed_adopt_then_reassign(monkeypatch, tenant=tenant, partition=2,
                                     owned_after=set())
    assert stub.objects() == []
    assert main.OWNERSHIP_SEED_UNOWNED_DROPPED_TOTAL == 1, (
        "the seed-first-version subset must still be counted on its own "
        "counter — 155b commissioned it to mean exactly that")
    assert main.OWNERSHIP_UNOWNED_PERSIST_DROPPED_TOTAL == 1, (
        "and on the general one, which is what 155c added")


# ── D3: the verdict may not weaken merely because the owner changed ──────────

def _armed(tenant: str, *, tier: str, hypothesis: str, at: datetime = T0):
    """A registration that has ADOPTED a placeholder loaded with `tier`."""
    _placeholder(tenant, end=T0, tier=tier, hypothesis=hypothesis)
    reg = main.OPEN_OBJECTS[SEED_CID]
    main._seed_adopted(reg, SEED_CID, at)
    return reg


def _ranked(tenant: str, tier, hypothesis: str):
    """A live snapshot for SEED_CID whose recomputation says `tier`."""
    snap = _cold_snapshot(tenant, T0)
    return dc_replace(
        snap, correlation_id=SEED_CID,
        ranking=dc_replace(snap.ranking, verdict_tier=tier,
                           top_hypothesis=hypothesis))


def test_a_weaker_recomputation_publishes_the_carried_verdict(monkeypatch):
    """(D3) THE MEASURED DEMOTION, on the CORRECT owner. The first persist after
    an adoption recomputes from a window that has only partially refilled, so it
    can publish a strictly weaker tier than the durable row it continues
    (155b: confirmed -> suspected). The durable evidence that earned `confirmed`
    did not evaporate; this replica just cannot see it yet."""
    monkeypatch.setattr(main, "datetime", _Clock)
    tenant = "t-155b-floor"
    _armed(tenant, tier="confirmed", hypothesis="private-interconnect-bgp-down")
    weak = _ranked(tenant, VerdictTier.SUSPECTED, "saas-experience-degraded")

    published = main._seed_verdict_floor(weak)
    assert published.ranking.verdict_tier is VerdictTier.CONFIRMED
    assert published.ranking.top_hypothesis == "private-interconnect-bgp-down"
    assert main.OWNERSHIP_SEED_VERDICT_CARRIED_TOTAL == 1

    # HONEST, not fabricated: the row's verdict columns carry the floor, the
    # version's own internals record what this replica actually computed.
    ctx = json.loads(published.hypotheses_blob())["grounding_context"]["ownership_handoff"]
    assert ctx["recomputed_verdict_tier"] == "suspected"
    assert ctx["recomputed_top_hypothesis"] == "saas-experience-degraded"
    assert "pending window refill" in ctx["note"]
    row = published.to_object_row(8, "open")
    assert row["verdict_tier"] == "confirmed"
    assert row["signal_count"] == weak.signal_count(), "no fabricated evidence"
    assert row["node_count"] == len(weak.nodes), "no fabricated blast radius"


def test_a_stronger_recomputation_publishes_immediately(monkeypatch):
    """The floor is a FLOOR, never a damper: a recomputation at least as strong
    as the durable row publishes untouched, byte for byte."""
    monkeypatch.setattr(main, "datetime", _Clock)
    tenant = "t-155b-floor"
    _armed(tenant, tier="suspected", hypothesis="saas-experience-degraded")
    strong = _ranked(tenant, VerdictTier.CONFIRMED, "private-interconnect-bgp-down")

    assert main._seed_verdict_floor(strong) is strong
    assert main.OWNERSHIP_SEED_VERDICT_CARRIED_TOTAL == 0


def test_the_verdict_floor_never_raises_above_the_durable_tier(monkeypatch):
    """The published tier is max(recomputed, durable) and can never exceed the
    durable row's own word. A durable `undetermined` arms nothing at all."""
    monkeypatch.setattr(main, "datetime", _Clock)
    tenant = "t-155b-floor"
    _armed(tenant, tier="suspected", hypothesis="saas-experience-degraded")
    weak = _ranked(tenant, VerdictTier.UNDETERMINED, "undetermined")
    assert main._seed_verdict_floor(weak).ranking.verdict_tier is (
        VerdictTier.SUSPECTED), "floored to the durable tier, and no further"

    main.OPEN_OBJECTS.clear()
    reg = _armed(tenant, tier="undetermined", hypothesis="undetermined")
    assert "verdict_floor" not in reg, (
        "the bottom tier can never change a published row — it must arm no "
        "state and no expiry")
    assert main._seed_verdict_floor(weak) is weak


def test_the_verdict_floor_expires_and_a_weaker_tier_publishes(monkeypatch):
    """It must EXPIRE. Once the window has refilled, recomputation rules
    unconditionally — a genuine recovery has to be able to downgrade."""
    monkeypatch.setattr(main, "datetime", _Clock)
    tenant = "t-155b-floor"
    reg = _armed(tenant, tier="confirmed",
                 hypothesis="private-interconnect-bgp-down")
    weak = _ranked(tenant, VerdictTier.SUSPECTED, "saas-experience-degraded")

    _Clock.current = T0 + timedelta(
        seconds=main.CORR_OWNERSHIP_SEED_SLACK_S + 1)
    assert main._seed_verdict_floor(weak) is weak, (
        "past the refill horizon the recomputation is the truth")
    assert "verdict_floor" not in reg, "an expired floor must disarm itself"
    assert main.OWNERSHIP_SEED_VERDICT_CARRIED_TOTAL == 0


def test_the_verdict_floor_horizon_is_the_refill_horizon(monkeypatch):
    """One constant, one interval: the floor holds for exactly as long as the
    D1 match slack bridges, because both answer the same question — how long
    until this replica's window has refilled."""
    monkeypatch.setattr(main, "datetime", _Clock)
    reg = _armed("t-155b-floor", tier="confirmed", hypothesis="h")
    assert reg["verdict_floor_until"] == pytest.approx(
        T0.timestamp() + main.CORR_OWNERSHIP_SEED_SLACK_S)


def test_a_non_seed_object_is_never_floored(monkeypatch):
    """Oracle: an object that did not descend from a seed is returned by
    identity, so its persisted row is byte-for-byte what it always was."""
    monkeypatch.setattr(main, "datetime", _Clock)
    tenant = "t-155b-plain"
    snap = _cold_snapshot(tenant, T0)
    main.OPEN_OBJECTS[snap.correlation_id] = {
        "version": 1, "hash": "", "material": "", "last_seen": T0,
        "last_persist": T0, "snapshot": snap, "opened_at": T0,
    }
    assert main._seed_verdict_floor(snap) is snap
    assert main._seed_verdict_floor(_ranked(tenant, VerdictTier.SUSPECTED,
                                            "x")) is not None
    assert main.OWNERSHIP_SEED_VERDICT_CARRIED_TOTAL == 0


def test_the_carried_verdict_reaches_the_persisted_row(monkeypatch):
    """END-TO-END through `main.engine_cycle`: the durable row said `confirmed`,
    the refilling window says less, and the version this replica publishes
    carries the durable tier — the same incident must not appear to weaken
    merely because its owner changed."""
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH([_row(SEED_CID, tenant, version=7,
                         affected={"devices": ["dev-a"]},
                         tier="confirmed",
                         hypothesis="private-interconnect-bgp-down")])
    _run_seeded_cycle(monkeypatch, stub, tenant=tenant, partition=2,
                      signals=[_sig(tenant, "dev-a", offset_s=o)
                               for o in (0, 30, 60)])

    rows = stub.objects()
    assert [(r["correlation_id"], r["version"]) for r in rows] == [(SEED_CID, 8)]
    assert rows[0]["verdict_tier"] == "confirmed", (
        "the continuation published a WEAKER tier than the row it continues — "
        "this is the 155b demotion")
    assert rows[0]["top_hypothesis"] == "private-interconnect-bgp-down"
    assert main.OWNERSHIP_SEED_VERDICT_CARRIED_TOTAL == 1
    carried = json.loads(rows[0]["hypotheses"])["grounding_context"]["ownership_handoff"]
    assert carried["recomputed_verdict_tier"] != "confirmed", (
        "fixture invalid: the recomputation must actually be weaker")


# ═════════════════════════════════════════════════════════════════════════════
# TRACKER 155 — COMPLETION: STATE FOLLOWS PARTITION OWNERSHIP
# (run /var/tmp/scale-runs/ownership-155c-08311027, 2026-08-31; arms control /
# restart / exit-join). 931efffb fixed the ACQUIRING side and 557dbef7 the
# transient owner's FIRST post-adoption version. 155c then measured the half
# neither covered — THE OLD OWNER STILL WRITING FOR PARTITIONS IT HAD LOST:
#
#   F1 (restart). c5 held the partitions ~10 s during the bounce and minted a
#      FRESH object (3eec17dd) for the story's entities 13 s AFTER revoking
#      them — the consume/reconcile cycle already in flight ran to completion.
#      Two objects for one story: `single_incident` failed.
#
#   F2 (exit/join). c5 had ADOPTED a placeholder and persisted v6, which
#      DISARMED the D2b first-version guard, and D2a discards only UNADOPTED
#      placeholders. So c5 kept the live object and continued it every 30 s for
#      six minutes on a partition it no longer owned, writing a DUPLICATE
#      (b0f0fd7f, 7) with different content; latest-write-wins made the orphan
#      current. `seam_owner` wrong, durability assertion 8 failed.
#
# WHAT IS PINNED BELOW: flush-and-release on revoke, the persist-time ownership
# guard on EVERY object, the new-object admission guard, and the full two-owner
# round trip through them.
#
# MUTANTS (verified by hand while writing these):
#   * remove the `_handoff_flush` call from `on_partitions_revoked` ->
#     test_the_handoff_round_trip_carries_the_flushed_version fails: the
#     acquiring replica seeds from the pre-move version and the flushed content
#     (and its blast radius) is lost.
#   * make `_ownership_persist_guard` return True unconditionally ->
#     test_f2_an_established_object_cannot_write_after_losing_its_partition
#     fails: the duplicate version is written.
#   * make `_ownership_admission_guard` return True unconditionally ->
#     test_f1_a_post_revoke_cycle_cannot_mint_a_new_object fails: the fresh
#     fragment is minted exactly as 155c measured it.
#   * drop the `_LIFECYCLE_SEEN_WINDOW` discard from `_forget_object` ->
#     test_forgetting_an_object_clears_every_index_keyed_by_it fails.
# ═════════════════════════════════════════════════════════════════════════════


def _tps(partitions):
    """The TopicPartition list a rebalance callback is handed."""
    return [_TP(t, p) for t in main.TOPICS for p in sorted(partitions)]


def _listener():
    return main._AssignmentLogger(_NullConsumer())


def _revoke(partitions):
    asyncio.run(_listener().on_partitions_revoked(_tps(partitions)))


def _reassign(partitions):
    """The assignment callback, which is where the RELEASE half completes."""
    asyncio.run(_listener().on_partitions_assigned(_tps(partitions)))


def _open_object(monkeypatch, tenant, partition, *, stub=None, offsets=(0, 30, 60),
                 at=None):
    """Let this replica OPEN an ordinary object of its own for `tenant` while it
    owns `partition`, and return (stub, correlation_id)."""
    stub = _SeedCH() if stub is None else stub
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "datetime", _Clock)
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", True)
    _assign({partition})
    for s in (_sig(tenant, "dev-a", offset_s=o, at=at) for o in offsets):
        main.buffer_signal(s)
    asyncio.run(main.engine_cycle())
    assert len(main.OPEN_OBJECTS) == 1, main.OPEN_OBJECTS
    return stub, next(iter(main.OPEN_OBJECTS))


def _versions(stub):
    return [(r["correlation_id"], r["version"], r["state"]) for r in stub.objects()]


def _seed_row_from(row: dict, *, written: datetime | None = None) -> dict:
    """The `corr_current FINAL` row an ACQUIRING replica's seed reads for a
    version the departing replica just wrote.

    A re-labelling, not a fabrication: every field below is a column
    `_persist_snapshot` dual-writes into corr_current from this very row (see
    CORR_CURRENT_FIELDS), rendered the way ClickHouse's JSON format hands it
    back (64-bit integers quoted).
    """
    return {
        "tenant_id": row["tenant_id"],
        "correlation_id": row["correlation_id"],
        "version": row["version"],
        "window_start_ms": str(row["window_start"]),
        "window_end_ms": str(row["window_end"]),
        "affected": row["affected"],
        "created_at_ms": _ms(_Clock.current if written is None else written),
        "top_hypothesis": row["top_hypothesis"],
        "verdict_tier": row["verdict_tier"],
    }


# ── F1: an in-flight cycle may not MINT an object for a partition it lost ────

def test_f1_a_post_revoke_cycle_cannot_mint_a_new_object(monkeypatch):
    """THE MEASURED MINT. Evidence buffered BEFORE the move keeps re-deriving
    objects until it ages out of the window, and 155c's restart arm caught one
    landing 13 s after the revoke: a second object for a story that has exactly
    one incident. Nothing is wrong with the evidence — the cycle simply outlived
    the ownership — so the check belongs where objects ENTER OPEN_OBJECTS.

    This test replaces the pre-155c oracle that asserted the OPPOSITE (an
    ordinary object persisting on an unowned partition, deliberately unchanged
    by 155b). That behaviour IS the defect; it is now fixed.
    """
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH()
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "datetime", _Clock)
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", True)
    _assign(set())                       # the partition has moved away
    for s in (_sig(tenant, "dev-a", offset_s=o) for o in (0, 30, 60)):
        main.buffer_signal(s)
    asyncio.run(main.engine_cycle())

    assert main.OPEN_OBJECTS == {}, (
        "a replica that does not own the tenant's partition registered a new "
        "object — this is 155c F1, the fragment that broke single_incident")
    assert stub.objects() == [], "and it must not have persisted one either"
    assert main.OWNERSHIP_UNOWNED_ADMISSION_DROPPED_TOTAL >= 1
    assert main.OWNERSHIP_UNOWNED_PERSIST_DROPPED_TOTAL == 0, (
        "there was no registration to drop — the admission guard is what fires")


def test_the_true_owner_still_opens_new_objects(monkeypatch):
    """The other half, and the one that matters more: the guard must not cost
    the OWNING replica a single incident."""
    tenant = _owned_tenant(2, 4)
    stub, cid = _open_object(monkeypatch, tenant, 2)
    assert _versions(stub) == [(cid, 1, "open")]
    assert main.OWNERSHIP_UNOWNED_ADMISSION_DROPPED_TOTAL == 0


def test_the_admission_guard_is_default_open_before_any_assignment(monkeypatch):
    """A process that has never had an assignment callback (single-replica dev,
    a unit invocation, a broker-less run) has no partitions to lose, so it
    behaves EXACTLY as it always has."""
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH()
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "datetime", _Clock)
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", False)
    _assign(set())
    for s in (_sig(tenant, "dev-a", offset_s=o) for o in (0, 30, 60)):
        main.buffer_signal(s)
    asyncio.run(main.engine_cycle())

    assert len(main.OPEN_OBJECTS) == 1 and stub.objects()
    assert main.OWNERSHIP_UNOWNED_ADMISSION_DROPPED_TOTAL == 0


# ── F2: an ESTABLISHED object may not keep writing after the partition moves ─

def test_f2_an_established_object_cannot_write_after_losing_its_partition(monkeypatch):
    """THE MEASURED DUPLICATE. 155b's D2b guard covered only a seed-descended
    object's FIRST version and disarmed as soon as one landed; 155c's exit/join
    arm walked through the hole — c5 kept a live object on a partition it no
    longer owned and continued it for six minutes, writing a (correlation_id,
    version) pair the true owner had ALSO written, with different content, which
    latest-write-wins then made current."""
    tenant = _owned_tenant(2, 4)
    stub, cid = _open_object(monkeypatch, tenant, 2)
    before = _versions(stub)
    assert before == [(cid, 1, "open")]
    assert not main.OPEN_OBJECTS[cid].get("seed_pending_first_persist"), (
        "fixture invalid: this is an ORDINARY object, so 155b's first-version "
        "guard was never armed — that is exactly why F2 escaped it")

    _assign({3})                          # partition 2 has moved to another replica
    for s in (_sig(tenant, "dev-b", offset_s=o) for o in (90, 120)):
        main.buffer_signal(s)
    asyncio.run(main.engine_cycle())

    assert _versions(stub) == before, (
        "the old owner wrote a version for a partition it no longer owns — "
        "this is the 155c F2 duplicate")
    assert main.OPEN_OBJECTS == {}, "and the registration must not survive"
    assert main.OWNERSHIP_UNOWNED_PERSIST_DROPPED_TOTAL == 1
    assert main.OWNERSHIP_SEED_UNOWNED_DROPPED_TOTAL == 0, (
        "155b's counter keeps its exact meaning: the seed-first-version subset")
    seen = [(r["correlation_id"], r["version"]) for r in stub.objects()]
    assert len(seen) == len(set(seen)), f"duplicate (cid, version): {seen}"


def test_the_persist_guard_also_refuses_the_heartbeat_touch(monkeypatch):
    """A heartbeat TOUCH writes `corr_current` and nothing else — which is
    precisely the row an operator reads and the row latest-write-wins resolves.
    An unowned touch is therefore the same harm as an unowned version, so the
    guard sits ABOVE the touch/version branch, not inside it."""
    tenant = _owned_tenant(2, 4)
    stub, _cid = _open_object(monkeypatch, tenant, 2)
    monkeypatch.setattr(main, "CORR_HEARTBEAT_TOUCH_ONLY", True)
    monkeypatch.setattr(main, "CORR_VERSION_HEARTBEAT_S", 0.001)
    current_before = len(stub.inserted.get("netops.corr_current", []))

    _assign({3})
    _Clock.current = T0 + timedelta(seconds=120)
    for s in (_sig(tenant, "dev-a", offset_s=o, at=_Clock.current) for o in (0, 30)):
        main.buffer_signal(s)
    asyncio.run(main.engine_cycle())

    assert len(stub.inserted.get("netops.corr_current", [])) == current_before, (
        "an unowned replica touched corr_current — latest-write-wins makes "
        "that touch the row the operator reads")
    assert main.OWNERSHIP_UNOWNED_PERSIST_DROPPED_TOTAL == 1


def test_the_persist_guard_is_default_open_before_any_assignment(monkeypatch):
    """Same default-open rule as the admission guard, for the same reason."""
    tenant = _owned_tenant(2, 4)
    _stub, cid = _open_object(monkeypatch, tenant, 2)
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", False)
    _assign(set())
    for s in (_sig(tenant, "dev-b", offset_s=o) for o in (90, 120)):
        main.buffer_signal(s)
    asyncio.run(main.engine_cycle())

    assert cid in main.OPEN_OBJECTS
    assert main.OWNERSHIP_UNOWNED_PERSIST_DROPPED_TOTAL == 0


def test_the_terminal_paths_refuse_an_unowned_close(monkeypatch):
    """A tombstone is the WORST version to write from the wrong replica: it is
    that id's last durable word. Quiesce must drop, never close."""
    tenant = _owned_tenant(2, 4)
    stub, cid = _open_object(monkeypatch, tenant, 2)
    before = _versions(stub)

    _assign({3})
    _Clock.current = T0 + timedelta(seconds=main.CORR_QUIESCE_S + 600)
    asyncio.run(main.engine_cycle())

    assert _versions(stub) == before, "an unowned replica closed another's object"
    assert cid not in main.OPEN_OBJECTS
    assert main.OWNERSHIP_UNOWNED_PERSIST_DROPPED_TOTAL == 1
    assert main.OPEN_OBJECTS_FORCE_CLOSED == 0


# ── flush-and-release ────────────────────────────────────────────────────────

def test_revoking_a_partition_flushes_its_open_objects(monkeypatch):
    """THE HANDOFF WRITE. The departing owner persists one more version of the
    object's CURRENT snapshot, state `open` — the incident is not over, it has
    changed owner — so the acquiring replica's seed reads the freshest state
    this replica had rather than whatever damping last let through."""
    tenant = _owned_tenant(2, 4)
    stub, cid = _open_object(monkeypatch, tenant, 2)
    assert _versions(stub) == [(cid, 1, "open")]

    _revoke({0, 1, 2, 3})

    assert _versions(stub) == [(cid, 1, "open"), (cid, 2, "open")], (
        "the flush must write a further OPEN version, never a close")
    assert main.OWNERSHIP_HANDOFF_FLUSHED_TOTAL == 1
    assert main.OWNERSHIP_HANDOFF_UNFLUSHED_TOTAL == 0
    assert main.OPEN_OBJECTS[cid]["version"] == 2, (
        "the in-memory version must follow the durable one — a retained "
        "partition continues ABOVE it")


def test_the_flush_publishes_the_monotone_blast_radius(monkeypatch):
    """Tracker 187 across the handoff. This is this owner's LAST word for the
    object, so the row carries the union it accumulated, not just the current
    window's projection — which is what makes the acquiring replica's
    AffectedHistory re-seed lossless."""
    tenant = _owned_tenant(2, 4)
    stub, cid = _open_object(monkeypatch, tenant, 2)
    # A second cycle whose window has moved on from dev-a to dev-b: the live
    # projection no longer names dev-a, the HISTORY still does.
    hist = main.OPEN_OBJECTS[cid]["affected_hist"]
    hist.note({"devices": ["dev-gone"]})

    _revoke({2})

    flushed = stub.objects()[-1]
    assert "dev-gone" in json.loads(flushed["affected"])["devices"], (
        "the handoff row must publish the object's whole blast radius")


def test_an_unflushable_object_is_released_on_its_last_durable_version(monkeypatch):
    """THE RESIDUE BOUND, made visible. Out of budget (or with no ClickHouse to
    write to) the object is RELEASED anyway — state must follow ownership — and
    the acquiring replica seeds from its last DURABLE version instead of its
    last in-memory snapshot. Identity, version monotonicity and the durable
    verdict are not at risk; only the un-persisted window residue is."""
    tenant = _owned_tenant(2, 4)
    stub, cid = _open_object(monkeypatch, tenant, 2)
    before = _versions(stub)
    monkeypatch.setattr(main, "CORR_REVOKE_BUDGET_S", 0.0)

    _revoke({0, 1, 2, 3})
    assert _versions(stub) == before, "no budget, no flush"
    assert main.OWNERSHIP_HANDOFF_FLUSHED_TOTAL == 0
    assert main.OWNERSHIP_HANDOFF_UNFLUSHED_TOTAL == 1
    assert cid in main.OPEN_OBJECTS, "release waits for the assignment callback"

    _reassign({3})
    assert main.OPEN_OBJECTS == {}, "released anyway — unflushed is not unowned"
    assert main.OWNERSHIP_HANDOFF_RELEASED_TOTAL == 1


def test_no_clickhouse_still_releases(monkeypatch):
    """Fail-open on the WRITE, never on the ownership: a store that is not there
    cannot take the handoff row, and that is not a reason to keep writing for a
    partition this replica lost."""
    tenant = _owned_tenant(2, 4)
    _open_object(monkeypatch, tenant, 2)
    monkeypatch.setattr(main, "ch", None)

    _revoke({2})
    assert main.OWNERSHIP_HANDOFF_UNFLUSHED_TOTAL == 1
    _reassign({3})
    assert main.OPEN_OBJECTS == {}


def test_a_failing_flush_is_counted_and_never_raises(monkeypatch):
    """§16.1 / §10: a write that fails is COUNTED as unflushed and logged; a
    raise out of this callback would kill the rejoin."""
    tenant = _owned_tenant(2, 4)
    _open_object(monkeypatch, tenant, 2)

    async def _boom(*a, **kw):
        raise httpx.ConnectError("clickhouse unreachable")

    monkeypatch.setattr(main, "_persist_snapshot", _boom)
    _revoke({2})
    assert main.OWNERSHIP_HANDOFF_UNFLUSHED_TOTAL == 1
    assert main.OWNERSHIP_HANDOFF_FLUSHED_TOTAL == 0


def test_the_flush_order_is_most_recently_updated_first(monkeypatch):
    """The order is a CHOICE with a reason: under budget pressure the objects
    that get flushed are the ones whose in-memory state has moved most recently
    — the in-flight incidents an operator is watching, furthest ahead of their
    durable row, most likely to receive further evidence on the new owner."""
    tenant = _owned_tenant(2, 4)
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", True)
    _assign({2})
    for i, age in enumerate((300, 0, 120)):
        _placeholder(tenant, end=T0, cid=f"155c0000-0000-4000-8000-00000000000{i}")
        reg = main.OPEN_OBJECTS[f"155c0000-0000-4000-8000-00000000000{i}"]
        reg["seed_only"] = False          # ordinary open objects for this test
        reg["last_seen"] = T0 - timedelta(seconds=age)

    order = main._handoff_candidates(frozenset({2}), placeholders=False)
    assert order == ["155c0000-0000-4000-8000-000000000001",
                     "155c0000-0000-4000-8000-000000000002",
                     "155c0000-0000-4000-8000-000000000000"], order


def test_the_flush_stops_at_the_budget_and_counts_the_rest(monkeypatch):
    """OPERATION-COUNT bound rather than a wall clock the CI can perturb: with a
    monotonic clock that advances one budget-worth per persist, exactly ONE
    object is flushed and every other is counted unflushed — and released."""
    tenant = _owned_tenant(2, 4)
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", True)
    monkeypatch.setattr(main, "CORR_REVOKE_BUDGET_S", 1.0)
    _assign({2})
    for i in range(5):
        cid = f"155c0000-0000-4000-8000-00000000010{i}"
        _placeholder(tenant, end=T0, cid=cid)
        main.OPEN_OBJECTS[cid]["seed_only"] = False
        main.OPEN_OBJECTS[cid]["last_seen"] = T0 - timedelta(seconds=i)

    ticks = {"t": 1000.0}

    def _mono():
        return ticks["t"]

    persists = []

    async def _persist(snap, version, state, window, **kw):
        persists.append((snap.correlation_id, version, state))
        ticks["t"] += 1.0                 # one whole budget per write

    monkeypatch.setattr(main.time, "monotonic", _mono)
    monkeypatch.setattr(main, "_persist_snapshot", _persist)
    monkeypatch.setattr(main, "ch", _SeedCH())

    flushed, unflushed = asyncio.run(main._handoff_flush(frozenset({2})))
    assert (flushed, unflushed) == (1, 4), (flushed, unflushed, persists)
    assert len(persists) == 1, persists
    assert main.OWNERSHIP_HANDOFF_FLUSHED_TOTAL == 1
    assert main.OWNERSHIP_HANDOFF_UNFLUSHED_TOTAL == 4


def test_a_retained_partition_is_flushed_but_never_released(monkeypatch):
    """aiokafka rebalances EAGERLY — `_on_join_prepare` revokes the WHOLE
    previous assignment on every rebalance, including the common one that hands
    the same partitions straight back. Releasing on revoke would therefore throw
    away live state for partitions that never moved and make a FAIL-OPEN
    ClickHouse read a correctness dependency of a no-op rebalance."""
    tenant = _owned_tenant(2, 4)
    _stub, cid = _open_object(monkeypatch, tenant, 2)

    _revoke({0, 1, 2, 3})
    _reassign({0, 1, 2, 3})

    assert cid in main.OPEN_OBJECTS, (
        "an eager revoke followed by the SAME assignment must not cost this "
        "replica the live state of a partition it never lost")
    assert main.OWNERSHIP_HANDOFF_RELEASED_TOTAL == 0
    assert main.OWNERSHIP_HANDOFF_FLUSHED_TOTAL == 1, (
        "it is still flushed: a durable checkpoint is never wrong")


def test_only_the_partitions_that_actually_left_are_released(monkeypatch):
    """The release is EXACT, and it is the assignment callback that knows."""
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", True)
    _assign({2, 3})
    leaving = _owned_tenant(2, 4)
    staying = _owned_tenant(3, 4)
    _placeholder(leaving, end=T0, cid=SEED_CID)
    _placeholder(staying, end=T0, cid=OTHER_CID)
    for cid in (SEED_CID, OTHER_CID):
        main.OPEN_OBJECTS[cid]["seed_only"] = False

    monkeypatch.setattr(main, "ch", None)   # flush is not what this test is about
    _revoke({0, 1, 2, 3})
    _reassign({3})

    assert OTHER_CID in main.OPEN_OBJECTS, "a retained partition keeps its state"
    assert SEED_CID not in main.OPEN_OBJECTS, "a lost partition releases its state"
    assert main.OWNERSHIP_HANDOFF_RELEASED_TOTAL == 1


def test_the_release_also_drops_placeholders_of_lost_partitions(monkeypatch):
    """A seed task racing the rebalance can register a placeholder for the OLD
    assignment after `_seed_discard_revoked` has already run. The release is the
    backstop."""
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", True)
    monkeypatch.setattr(main, "ch", None)
    _assign({2})
    tenant = _owned_tenant(2, 4)
    _revoke({0, 1, 2, 3})               # nothing registered yet
    _placeholder(tenant, end=T0, cid=SEED_CID)   # the racing seed lands here
    _reassign({3})

    assert SEED_CID not in main.OPEN_OBJECTS
    assert main.OWNERSHIP_HANDOFF_RELEASED_TOTAL == 1


def test_the_assignment_callback_still_does_no_io(monkeypatch):
    """The release half is pure in-memory dict work — the durable half already
    happened in the revoke callback. This hook runs INSIDE the rejoin."""
    tenant = _owned_tenant(2, 4)
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", True)
    _assign({2})
    _placeholder(tenant, end=T0, cid=SEED_CID)
    main.OPEN_OBJECTS[SEED_CID]["seed_only"] = False
    monkeypatch.setattr(main, "ch", None)
    _revoke({0, 1, 2, 3})

    calls = []

    class _Forbidden:
        async def query(self, sql):
            calls.append(sql)
            return []

        async def insert(self, *a, **kw):
            calls.append(a)

    monkeypatch.setattr(main, "ch", _Forbidden())
    monkeypatch.setattr(main, "CORR_OWNERSHIP_SEED", False)
    _reassign({3})
    assert calls == [], f"the assignment callback performed I/O: {calls}"
    assert SEED_CID not in main.OPEN_OBJECTS


def test_ordinary_and_seed_descended_objects_flush_alike(monkeypatch):
    """PARITY. The flush is not a seed feature — it is what a departing owner
    owes every object it holds. An object this replica opened itself and one it
    adopted from a placeholder are flushed by the same path, in the same order,
    onto the same counter."""
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH([_row(SEED_CID, tenant, version=7,
                         affected={"devices": ["dev-a"]})])
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "datetime", _Clock)
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", True)
    _assign({2})
    asyncio.run(main._run_ownership_seed(frozenset({2})))
    for s in (_sig(tenant, "dev-a", offset_s=o) for o in (0, 30, 60)):
        main.buffer_signal(s)
    asyncio.run(main.engine_cycle())
    adopted = _versions(stub)
    assert adopted == [(SEED_CID, 8, "open")]

    # ...and an ordinary object of this replica's own, same tenant/partition.
    other = dc_replace(main.OPEN_OBJECTS[SEED_CID]["snapshot"],
                       correlation_id=OTHER_CID)
    main.OPEN_OBJECTS[OTHER_CID] = dict(main.OPEN_OBJECTS[SEED_CID],
                                        snapshot=other, version=3,
                                        affected_hist=main.AffectedHistory(0))

    _revoke({2})
    assert main.OWNERSHIP_HANDOFF_FLUSHED_TOTAL == 2
    assert _versions(stub)[1:] == [(SEED_CID, 9, "open"), (OTHER_CID, 4, "open")] \
        or _versions(stub)[1:] == [(OTHER_CID, 4, "open"), (SEED_CID, 9, "open")], \
        _versions(stub)


# ── the full two-owner round trip ────────────────────────────────────────────

def test_the_handoff_round_trip_carries_the_flushed_version(monkeypatch):
    """FLUSH -> SEED -> ADOPT -> CONTINUE, end to end, as two owners.

    Owner A opens the incident and is then revoked: it flushes a final OPEN
    version and releases. Owner B seeds from THAT row — strictly fresher than
    anything A had durably written before the move — adopts it with its own
    cold-window evidence, and continues it. What must hold at the end:
    ONE object for the whole story, versions strictly monotone with no
    duplicate (correlation_id, version) anywhere, and a blast radius that spans
    both owners.
    """
    tenant = _owned_tenant(2, 4)
    # ── owner A ──────────────────────────────────────────────────────────────
    stub_a, cid = _open_object(monkeypatch, tenant, 2)
    main.OPEN_OBJECTS[cid]["affected_hist"].note({"devices": ["dev-owner-a"]})
    _revoke({0, 1, 2, 3})
    flushed = stub_a.objects()[-1]
    assert (flushed["correlation_id"], flushed["version"], flushed["state"]) == \
        (cid, 2, "open")
    _reassign({3})
    assert main.OPEN_OBJECTS == {}, "owner A must have released the object"

    # ── owner B, a different process: cold memory, the same durable store ────
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear()
    gap = timedelta(seconds=180)
    stub_b = _SeedCH([_seed_row_from(flushed)])
    _Clock.current = T0 + gap
    _run_seeded_cycle(monkeypatch, stub_b, tenant=tenant, partition=2,
                      signals=[_sig(tenant, "dev-a", offset_s=o, at=T0 + gap)
                               for o in (0, 30, 60)],
                      at=T0 + gap + timedelta(seconds=60))

    assert list(main.OPEN_OBJECTS) == [cid], (
        "the story fragmented across the handoff — "
        f"{list(main.OPEN_OBJECTS)} instead of [{cid[:8]}]")
    assert main.OWNERSHIP_ADOPTIONS_TOTAL == 1
    assert _versions(stub_b) == [(cid, 3, "open")], (
        "owner B must continue ABOVE the flushed version, not beside it")

    everything = _versions(stub_a) + _versions(stub_b)
    assert everything == [(cid, 1, "open"), (cid, 2, "open"), (cid, 3, "open")]
    pairs = [(c, v) for c, v, _ in everything]
    assert len(pairs) == len(set(pairs)), f"duplicate (cid, version): {pairs}"

    radius = main.OPEN_OBJECTS[cid]["affected_hist"].merged_with({})
    assert "dev-owner-a" in radius["devices"], (
        "tracker 187 must span the handoff: the flushed row carried owner A's "
        "monotone union and owner B re-seeded its history from it")
    assert "dev-a" in radius["devices"]


def test_the_round_trip_loses_the_radius_without_the_flush(monkeypatch):
    """THE MUTANT, made a test rather than a note: seed owner B from the version
    that stood BEFORE the flush and owner A's later blast radius is simply
    gone — which is exactly what `_handoff_flush` exists to prevent."""
    tenant = _owned_tenant(2, 4)
    stub_a, cid = _open_object(monkeypatch, tenant, 2)
    main.OPEN_OBJECTS[cid]["affected_hist"].note({"devices": ["dev-owner-a"]})
    pre_flush = stub_a.objects()[-1]
    main.OPEN_OBJECTS.clear()

    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear()
    gap = timedelta(seconds=180)
    _Clock.current = T0 + gap
    _run_seeded_cycle(monkeypatch, _SeedCH([_seed_row_from(pre_flush)]),
                      tenant=tenant, partition=2,
                      signals=[_sig(tenant, "dev-a", offset_s=o, at=T0 + gap)
                               for o in (0, 30, 60)],
                      at=T0 + gap + timedelta(seconds=60))

    radius = main.OPEN_OBJECTS[cid]["affected_hist"].merged_with({})
    assert "dev-owner-a" not in radius.get("devices", []), (
        "if this ever passes, the pre-flush row already carried the union and "
        "the flush test above proves nothing")


# ── bounds, indices and cost ─────────────────────────────────────────────────

def test_forgetting_an_object_clears_every_index_keyed_by_it(monkeypatch):
    """The enumeration in `_forget_object`, pinned. Every structure this module
    keys by correlation_id is cleared; the ones it does not clear are the ones
    that are REBUILT from OPEN_OBJECTS (the continuation index) or filtered
    through it (the seen sets), and that is asserted here too."""
    tenant = _owned_tenant(2, 4)
    _placeholder(tenant, end=T0, cid=SEED_CID)
    main._ARCHIVE_SLICE_HASH[SEED_CID] = "slice-hash"
    main._LIFECYCLE_SEEN_WINDOW.append({SEED_CID, OTHER_CID})

    main._forget_object(SEED_CID)

    assert SEED_CID not in main.OPEN_OBJECTS
    assert SEED_CID not in main._ARCHIVE_SLICE_HASH
    assert not any(SEED_CID in s for s in main._LIFECYCLE_SEEN_WINDOW)
    assert any(OTHER_CID in s for s in main._LIFECYCLE_SEEN_WINDOW), (
        "only the released id is discarded")


def test_the_revoke_hook_stays_inside_its_stated_bound(monkeypatch):
    """The revoke callback runs INSIDE the rejoin, so this is a hard operational
    contract, not a preference: the flush gets ONE CORR_REVOKE_BUDGET_S, on top
    of the flush/commit hook's own 2x backstop. 5 + 10 = 15 s against a 60 s
    rebalance timeout. Measured as operation counts against a fake clock so the
    assertion cannot flake on CI."""
    assert 3 * main.CORR_REVOKE_BUDGET_S <= main.CORR_REBALANCE_TIMEOUT_MS / 1000.0

    tenant = _owned_tenant(2, 4)
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", True)
    monkeypatch.setattr(main, "CORR_REVOKE_BUDGET_S", 5.0)
    _assign({2})
    for i in range(40):
        cid = f"155c0000-0000-4000-8000-0000000002{i:02d}"
        _placeholder(tenant, end=T0, cid=cid)
        main.OPEN_OBJECTS[cid]["seed_only"] = False

    # 0.25 s is exactly representable, so the count below is arithmetic rather
    # than a float race: 5.0 / 0.25 = 20 writes and then the deadline.
    cost = 0.25
    ticks = {"t": 0.0}
    monkeypatch.setattr(main.time, "monotonic", lambda: ticks["t"])

    async def _persist(*a, **kw):
        ticks["t"] += cost

    monkeypatch.setattr(main, "_persist_snapshot", _persist)
    monkeypatch.setattr(main, "ch", _SeedCH())
    flushed, unflushed = asyncio.run(main._handoff_flush(frozenset({2})))

    assert flushed + unflushed == 40, "every object is accounted for"
    assert flushed == 20, (flushed, unflushed)
    assert ticks["t"] <= main.CORR_REVOKE_BUDGET_S + cost, (
        "the flush overran its budget by more than one in-flight write")


def test_the_ownership_check_is_negligible_per_persist(monkeypatch):
    """COST, measured rather than asserted. The guard adds ONE
    `_seed_tenant_owned` to every persist: `canon_tenant` + a murmur2 over a
    short tenant string plus an `any()` over at most len(TOPICS) small lists —
    13.0 us measured over 200k calls on the development box. A persist is
    MILLISECONDS of serialization plus a ClickHouse round trip, so the check is
    two to three orders of magnitude below the thing it guards. The bound here
    is deliberately loose (50 us, ~4x the measurement) so it can only fail on a
    real algorithmic regression — an ownership answer that started scanning
    something."""
    tenant = _owned_tenant(2, 4)
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", True)
    _assign({0, 1, 2, 3})
    assert main._seed_tenant_owned(tenant) is True
    n = 20_000
    started = time.perf_counter()
    for _ in range(n):
        main._seed_tenant_owned(tenant)
    per_call = (time.perf_counter() - started) / n
    assert per_call < 50e-6, f"{per_call * 1e6:.1f} us per ownership check"


# ═════════════════════════════════════════════════════════════════════════════
# TRACKER 199 — THE GRACEFUL SHUTDOWN IS AN OWNERSHIP CHANGE TOO
#
# WHAT 155d MEASURED (run ownership-155d-08311609, assertion
# 3_handoff_counters.GAP). `_handoff_flush` is wired to
# `on_partitions_revoked`, and aiokafka calls that hook when the GROUP
# rebalances — never when THIS member leaves it. On `docker stop -t 30` /
# `docker restart` (i.e. every rolling restart and every deploy) SIGTERM
# reaches uvicorn, uvicorn runs the lifespan shutdown, `consume()`'s
# cancellation handler calls `consumer.stop()`, aiokafka issues LeaveGroup, and
# the departing replica flushes NOTHING: netops-correlation-6 went "Shutting
# down" 16:35:14.198Z -> "LeaveGroup request succeeded" 16:35:14.318Z (120 ms)
# holding 14 open objects, with zero flush lines in its whole log. Every flush
# that run observed came from the SURVIVING replica's eager revoke.
#
# The arms still PASSED — the acquirer seeds from the last ORDINARY durable
# version, so identity, version monotonicity and the durable verdict are never
# at risk. What was lost is the FRESHNESS half of the handoff, on exactly the
# ownership change that happens most often in production.
#
# WHAT IS PINNED BELOW: the flush runs on the SIGTERM path with no rebalance
# callback in sight, over the FULL assignment, BEFORE LeaveGroup and before the
# two drains and the offload plane that its writes depend on; the budget is the
# same one the revoke path uses and overrunning it releases anyway; an empty
# assignment does nothing at all.
#
# MUTANTS (verified by hand while writing these):
#   * delete the `await _shutdown_handoff_flush()` call from `lifespan` ->
#     test_a_graceful_shutdown_flushes_every_open_object_before_leavegroup
#     fails: no handoff version is written and the departing replica exits
#     holding its objects, exactly as 155d measured.
#   * move that call BELOW `consume_task.cancel()` (or below `offload_stop`) ->
#     the same test's ordering assertions fail.
#   * drop the `_release_lost_partitions` call from `_shutdown_handoff_flush` ->
#     test_an_over_budget_shutdown_releases_anyway and the released-counter
#     assertion in the flush test fail (conservation breaks: N flushed, 0
#     released).
# ═════════════════════════════════════════════════════════════════════════════


class _ShutdownCH(_SeedCH):
    """The seed stub plus the two things a lifespan teardown touches: an
    ordered trace of the writes, and `close()`."""

    def __init__(self, order: list, **kw):
        super().__init__(**kw)
        self.order = order

    async def insert(self, table: str, rows: list, dedup_token: str = "") -> None:
        if table == "netops.corr_objects":
            self.order.append("persist_version")
        await super().insert(table, rows, dedup_token)

    async def close(self) -> None:
        self.order.append("ch_close")


def _open_objects_on(monkeypatch, partition, stems, *, stub=None):
    """Open one ORDINARY object per stem, all on `partition`, the way this
    replica would while it owns it. Returns (stub, [correlation_id, ...])."""
    stub = _SeedCH() if stub is None else stub
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "datetime", _Clock)
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", True)
    _assign({partition})
    for i, stem in enumerate(stems):
        tenant = _owned_tenant(partition, 4, stem=stem)
        # A distinct entity per tenant: `_sig` derives `native_id` from the
        # entity, and the intake dedups on it, so a shared one would silently
        # drop the second tenant's evidence.
        for s in (_sig(tenant, f"dev-{i}", offset_s=o) for o in (0, 30, 60)):
            main.buffer_signal(s)
    asyncio.run(main.engine_cycle())
    assert len(main.OPEN_OBJECTS) == len(stems), main.OPEN_OBJECTS
    return stub, sorted(main.OPEN_OBJECTS)


def _lifespan_stubs(monkeypatch, order, *, ch_stub):
    """Drive the REAL `main.lifespan` with every loop task replaced by a
    recorder. Only the plumbing is stubbed — the teardown SEQUENCE under test,
    including `_shutdown_handoff_flush` itself, is the shipping one."""
    # monkeypatch owns the restore: `lifespan` assigns the module-global `ch`.
    monkeypatch.setattr(main, "ch", ch_stub)
    monkeypatch.setattr(main, "CH", lambda *a, **k: ch_stub)
    monkeypatch.setattr(main, "dlq_startup_check", lambda: None)
    monkeypatch.setattr(main, "gc_tune_startup", lambda: None)
    monkeypatch.setattr(main.diagnostics, "start", lambda: None)
    monkeypatch.setattr(main.diagnostics, "enabled", lambda: False)
    monkeypatch.setattr(main, "_start_health_sidecar", lambda: None)
    monkeypatch.setattr(main, "_evidence_ensure_consumer", lambda: None)

    def _recorder(name):
        async def run():
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                order.append(name)
                raise
        return run

    async def _consume():
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            # What the real `consume()` does on its way out: the final commit,
            # then `consumer.stop()` — which is aiokafka's LeaveGroup, the
            # moment after which this replica's partitions belong to someone
            # else and a handoff version can no longer inform their seed.
            order.append("leave_group")
            raise

    monkeypatch.setattr(main, "consume", _consume)
    for name in ("engine_loop", "cloud_log_tailer", "batch_flush_loop",
                 "loop_lag_watchdog", "health_snapshot_loop"):
        monkeypatch.setattr(main, name, _recorder(name))

    async def _evidence_stop():
        order.append("evidence_stop")

    async def _signal_flush():
        order.append("signal_batch_flush")

    async def _offload_stop(*, drain_s=None):
        order.append("offload_stop")
        return {}

    monkeypatch.setattr(main, "_evidence_stop", _evidence_stop)
    monkeypatch.setattr(main.SIGNAL_BATCH, "flush", _signal_flush)
    monkeypatch.setattr(main, "offload_stop", _offload_stop)


def _run_lifespan():
    async def enter():
        async with main.lifespan(None):
            # Let the loop tasks actually START. A task cancelled before its
            # first step never enters its coroutine, so it would record nothing
            # — the process this models runs for hours before the SIGTERM.
            await asyncio.sleep(0.05)
    asyncio.run(enter())


def test_a_graceful_shutdown_flushes_every_open_object_before_leavegroup(monkeypatch):
    """THE MEASURED GAP, closed. SIGTERM -> uvicorn -> lifespan teardown, with
    NO rebalance callback anywhere in the path: every open object this replica
    holds must still get its final open version, and it must be written while
    the write can still reach ClickHouse and still reach the acquiring replica's
    seed — i.e. before LeaveGroup, before the Evidence drain, before the signal
    flush, before `offload_stop` and before `ch.close()`.
    """
    order: list[str] = []
    stub = _ShutdownCH(order)
    _, cids = _open_objects_on(monkeypatch, 2, ("t-155-", "t-199-"), stub=stub)
    assert sorted(_versions(stub)) == [(c, 1, "open") for c in sorted(cids)], (
        "fixture invalid: both objects must be ORDINARY and already durable")
    order.clear()                       # the opening writes are not under test
    persisted_before = main.VERSIONS_PERSISTED
    _lifespan_stubs(monkeypatch, order, ch_stub=stub)

    _run_lifespan()

    # ── the flush happened at all (this is what 155d found missing) ──────────
    final = {r["correlation_id"]: r for r in stub.objects() if r["version"] == 2}
    assert set(final) == set(cids), (
        "a departing replica exited holding open objects — 155d's measured gap: "
        f"handoff versions written for {sorted(final)} of {sorted(cids)}")
    assert all(r["state"] == "open" for r in final.values()), (
        "a handoff is a change of owner, never a close")
    assert main.OWNERSHIP_HANDOFF_FLUSHED_TOTAL == len(cids)
    assert main.OWNERSHIP_HANDOFF_UNFLUSHED_TOTAL == 0
    # Conservation: what was flushed was also released, so the shutdown path
    # balances the same way every rebalance does.
    assert main.OWNERSHIP_HANDOFF_RELEASED_TOTAL == len(cids)
    assert main.VERSIONS_PERSISTED == persisted_before + len(cids)
    assert main.OPEN_OBJECTS == {}

    # ── and it happened in the only order that is any use ────────────────────
    assert "persist_version" in order and "leave_group" in order, order
    assert order.index("persist_version") < order.index("leave_group"), (
        "the handoff version was written AFTER LeaveGroup — the partitions were "
        f"already someone else's: {order}")
    for later in ("evidence_stop", "signal_batch_flush", "offload_stop",
                  "ch_close"):
        assert order.index("persist_version") < order.index(later), (
            f"the handoff flush ran after {later}, which it depends on: {order}")
    # The engine is quiesced FIRST, so the flush is this owner's genuine last
    # word and no post-release cycle can re-mint the objects it just handed off.
    assert order.index("engine_loop") < order.index("persist_version"), order


def test_an_over_budget_shutdown_releases_anyway_and_still_exits(monkeypatch):
    """The released-anyway policy, unchanged from the revoke path: a ClickHouse
    that cannot answer inside CORR_REVOKE_BUDGET_S costs the acquirer freshness
    (it seeds from the last durable row — the residue bound stated in
    `_handoff_flush`), never the exit. Nothing is waited for beyond the budget
    and every object is still accounted for."""
    stub, cids = _open_objects_on(monkeypatch, 2, ("t-155-", "t-199-"))
    monkeypatch.setattr(main, "CORR_REVOKE_BUDGET_S", 0.0)
    before = len(stub.objects())

    started = time.perf_counter()
    flushed, unflushed = asyncio.run(main._shutdown_handoff_flush())
    elapsed = time.perf_counter() - started

    assert (flushed, unflushed) == (0, len(cids))
    assert main.OWNERSHIP_HANDOFF_UNFLUSHED_TOTAL == len(cids)
    assert len(stub.objects()) == before, "no version was written out of budget"
    # The exit is never blocked on the flush, and the state still follows the
    # ownership: released, counted, gone.
    assert main.OPEN_OBJECTS == {}
    assert main.OWNERSHIP_HANDOFF_RELEASED_TOTAL == len(cids)
    assert elapsed < 1.0, f"an out-of-budget shutdown flush took {elapsed:.2f}s"


def test_a_shutdown_with_no_assignment_flushes_nothing(monkeypatch):
    """The idle replica (beyond BUS_PARTITIONS with the range assignor), and the
    process that never joined a group at all: there is no partition to hand off,
    so the shutdown must not write, must not count and must not touch the
    store."""
    stub, _cids = _open_objects_on(monkeypatch, 2, ("t-155-",))
    before = len(stub.objects())
    held = dict(main.OPEN_OBJECTS)
    _assign(set())

    assert asyncio.run(main._shutdown_handoff_flush()) == (0, 0)

    assert len(stub.objects()) == before
    assert main.OWNERSHIP_HANDOFF_FLUSHED_TOTAL == 0
    assert main.OWNERSHIP_HANDOFF_UNFLUSHED_TOTAL == 0
    assert main.OWNERSHIP_HANDOFF_RELEASED_TOTAL == 0
    assert main.OPEN_OBJECTS == held, "nothing was handed off, nothing changes"


def test_the_crash_path_keeps_todays_behaviour_and_is_out_of_scope(monkeypatch):
    """OUT OF SCOPE, DELIBERATELY — the residual, stated rather than implied.

    Only a PLANNED stop can be fixed here. SIGKILL (the docker stop grace period
    expiring on a wedged teardown), an OOM kill or a host loss runs no lifespan
    teardown at all, so no shutdown flush happens and none can: there is no code
    path left to run one from. On that path the acquiring replica seeds from the
    object's last ORDINARY durable version — correct, merely staler by the
    un-persisted window residue — which is exactly HEAD's behaviour and exactly
    what 155d graded PASS.

    What this test pins is the precondition that makes that acceptable: an open
    object ALWAYS has a durable row to be seeded from, written when it opened,
    with no flush involved. There is nothing to assert about the flush itself
    on a path where the process is already gone.
    """
    stub, cids = _open_objects_on(monkeypatch, 2, ("t-155-",))
    # No teardown, no revoke, no flush — the process simply stops existing here.
    durable = [(r["correlation_id"], r["version"], r["state"])
               for r in stub.objects()]
    assert durable == [(cids[0], 1, "open")], (
        "the crash path's whole safety net is this row: the acquiring replica "
        "seeds the incident's identity and version from it")
    assert main.OWNERSHIP_HANDOFF_FLUSHED_TOTAL == 0
