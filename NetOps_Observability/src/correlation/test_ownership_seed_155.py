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
                    "OPEN_OBJECTS_FORCE_CLOSED", "VERSIONS_PERSISTED"):
        monkeypatch.setattr(main, counter, 0)
    monkeypatch.setattr(main, "_OWNERSHIP_SEED_TASK", None)
    _Clock.current = T0
    yield
    main.OPEN_OBJECTS.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main.CONSUMER_ASSIGNMENT.clear()
    main.CONSUMER_PARTITION_TOTALS.clear()
    main.CONSUMER_PARTITION_ACQUIRED_AT.clear()
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
#   * make `_seed_owner_guard` return True unconditionally ->
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


def test_an_ordinary_object_is_never_touched_by_the_owner_guard(monkeypatch):
    """Oracle: the guard is scoped to seed-descended registrations. An object
    this replica opened itself persists on a partition it does not own exactly
    as HEAD does — that orphan-write behaviour is tracker 155's other half and
    is deliberately unchanged here."""
    tenant = _owned_tenant(2, 4)
    stub = _SeedCH()
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "datetime", _Clock)
    monkeypatch.setattr(main, "CONSUMER_ASSIGNMENT_SEEN", True)
    _assign(set())
    for s in (_sig(tenant, "dev-a", offset_s=o) for o in (0, 30, 60)):
        main.buffer_signal(s)
    asyncio.run(main.engine_cycle())

    assert stub.objects(), "an ordinary object must still persist"
    assert main.OWNERSHIP_SEED_UNOWNED_DROPPED_TOTAL == 0


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
