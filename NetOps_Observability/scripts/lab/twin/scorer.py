"""RCA accuracy scorer (tracker 152, design §5/§8.4 — closing G-2).

Joins the run's `ground_truth.jsonl` labels against the engine's output in
ClickHouse (verdict_tier / top_hypothesis / top_confidence / node_count /
affected / hypotheses; seam grounding from `netops.corr_edges`
grounding_kind='seam'). Produces `accuracy-report.json` and a human
`accuracy-report.md`.

Scoring contract (design §5): story PASS = every `expect` clause holds and no
`forbid` clause fires. Negative controls count toward accuracy as SPECIFICITY
— a false positive there is an accuracy failure exactly like a miss. A miss is
reported with its EVIDENCE TRAIL (events journaled? signals formed? object
formed but wrong verdict?) so an engine gap and a twin bug are tellable apart.

── 2026-08-29 storm incident (this module) ──────────────────────────────────

Scoring a 345-story mini-ladder run ran 65 minutes, issued 329 SELECTs worth
3,639 s of ClickHouse time (worst single query 82 s) and was killed without
producing a report. Measured from `system.query_log` over that window:

  | shape                                   |  q  | total s |  read_bytes |
  |-----------------------------------------|-----|---------|-------------|
  | phase-2 versions (`IN (...)` + blobs)    | 186 |  4088.5 |    8.88 TiB |
  | phase-1 membership (`multiSearchAny`)    | 185 |   102.5 |   65.44 GiB |
  | evidence-trail signals (`LIKE '%n%'`)    | 906 |    19.7 |    1.07 GiB |
  | seam edges (`toString(correlation_id)=`) |   7 |     0.4 |      976  B |

Three defects, all of them shape defects, none of them about the data:

 1. `WHERE toString(correlation_id) IN ('...')` casts the KEY, so the
    `(tenant_id, correlation_id, version)` primary key cannot be used at all:
    every one of those 186 queries folded the whole 2 M-row table AND
    decompressed the 48 GiB `hypotheses` column — 48.91 GiB read apiece,
    1.22 GiB peak, twice refused at the memory cap.
 2. Nothing was bounded to the RUN. No tenant, no time window: each query paid
    for the entire retained history to answer a question about 15 minutes of
    it.
 3. One query per story (three, for a failing one) instead of one per batch.

The repair follows `src/backend/timeintel_backfill.go`, which fixed the SAME
shape on the SAME table the same day (see its header comment):

  * the latest version comes from `netops.corr_current FINAL`, the narrow hot
    projection (454 MiB uncompressed vs 51.6 GiB), never from a `LIMIT 1 BY`
    fold of the history table;
  * every read is bounded by tenant AND by the run's time window, so
    ClickHouse prunes partitions instead of touching the whole table;
  * key lookups lead with `tenant_id` so they ride the primary-key prefix, and
    the id goes in as `toUUID(...)` rather than a cast of the column;
  * `hypotheses` is read ONLY for the objects a `seam.owner` clause actually
    needs, and that read carries `max_block_size` / `max_threads` for the same
    measured reason the backfill does;
  * every read carries `max_memory_usage` / `max_execution_time` / `max_threads`
    so a pathological object fails LOUDLY instead of taking the box down;
  * stories are batched — one membership query per N stories per tenant.

Results are unchanged by construction: membership is still evaluated over
EVERY version's `affected` (an object whose blast radius later shrank is still
a candidate), and the per-story assignment is still "the object's affected set
names one of the story's entities".
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone

from stack import StackError, warn

_TIER_RANK = {"undetermined": 0, "suspected": 1, "confirmed": 2}
_SAFE = re.compile(r"^[A-Za-z0-9._/:-]+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                   r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_CH_TS = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")

# ── bounds ───────────────────────────────────────────────────────────────────

# Per-query containment, mirroring timeintel_backfill.go's measured values.
CH_MAX_MEMORY = 1 << 30          # 1 GiB — the cap the storm run blew past
CH_MAX_EXECUTION_S = 60          # a scorer read that needs a minute is broken
CH_MAX_THREADS = 2               # a lab tool must not monopolise the box
# The wide `hypotheses` read only: 8192-row blocks of a 26 KB/row column are
# ~256 MiB PER THREAD (backfill measured 1.8 GiB with the defaults).
CH_BLOB_BLOCK_ROWS = 1024

# multiSearchAny / multiSearchAllPositions accept fewer than 2^8 needles.
MAX_NEEDLES = 200
# Stories per membership query. The needle cap binds first at realistic blast
# radii (345 stories x ~5 entities = 1,705 needles -> ~9 queries).
STORY_BATCH = 40
# Ids per keyed lookup. 1,200 ids measured 246 ms / 34.7 MiB on the live table.
ID_BATCH = 500

# Window slack. `window_start` is DEVICE event time and `created_at` is engine
# wall time, so the bound must be non-narrowing in both directions — the same
# reason ai_datasource.go widens its created_at bound by a day.
WINDOW_SLACK_S = 900             # before the run's first recorded moment
WINDOW_SETTLE_S = 3600           # after its last: the engine writes on for a
#                                  while past the last injected event

_TAG = "twin-scorer"


class ScorerError(RuntimeError):
    """The scorer cannot produce a TRUSTWORTHY verdict. Raised instead of
    returning an all-miss report, because "the engine found nothing" and "the
    scorer could not look" must never render identically."""


def _lit(s: str) -> str:
    """Refuse to embed anything but our own run-tagged identifiers in SQL —
    zero-trust even on our own state files."""
    if not _SAFE.match(s or ""):
        raise ValueError(f"identifier {s!r} is not SQL-embed safe")
    return s


def _uuid(s: str) -> str:
    if not _UUID.match(s or ""):
        raise ValueError(f"{s!r} is not a correlation UUID")
    return s


def _ts(s: str) -> str:
    if not _CH_TS.match(s or ""):
        raise ValueError(f"{s!r} is not a ClickHouse datetime literal")
    return s


def _needles(names) -> str:
    return ", ".join(f"'{_lit(n)}'" for n in names)


def _settings(tag: str, **extra) -> dict[str, object]:
    s: dict[str, object] = {
        "max_memory_usage": CH_MAX_MEMORY,
        "max_execution_time": CH_MAX_EXECUTION_S,
        "max_threads": CH_MAX_THREADS,
        "log_comment": f"{_TAG}:{tag}",
    }
    s.update(extra)
    return s


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


# ── the run window ───────────────────────────────────────────────────────────

class Window:
    """The [start, end] every corr_objects / corr_edges / corr_signals read is
    bounded to, plus where those bounds came from (it goes in the report: a
    window nobody can audit is a window nobody should trust)."""

    __slots__ = ("end", "source", "start")

    def __init__(self, start: str, end: str, source: str):
        self.start = _ts(start)
        self.end = _ts(end)
        self.source = source
        if self.end <= self.start:
            raise ScorerError(f"run window {source} is empty or inverted: "
                              f"{self.start} .. {self.end}")

    def as_dict(self) -> dict:
        return {"start": self.start, "end": self.end, "source": self.source}


def _parse_iso(value) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    txt = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(txt)
    except ValueError:
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(
        tzinfo=timezone.utc)


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def run_window(state: dict, ground_truth: list[dict],
               run_dir: str | None = None,
               slack_s: int = WINDOW_SLACK_S,
               settle_s: int = WINDOW_SETTLE_S) -> Window:
    """Derive the run's ClickHouse read window, widest-evidence-first.

    Sources, in order of directness:
      1. an explicit `window` / `burst_start`+`burst_end` in state.json;
      2. the stories' own `fired_at` stamps (the twin's native runs set them);
      3. `state["created"]` (twin) as the start anchor;
      4. the harness report's phase stamps (`report.json`, what the mini-ladder
         writes — its stories carry no fired_at);
      5. the run directory's own artifact mtimes, last resort and LOUD.

    Raises ScorerError when NOTHING dates the run: an unbounded read of a
    46 GiB table is not an acceptable fallback (that is the defect this
    function exists to prevent), and neither is scoring against a guess.
    """
    lo: datetime | None = None
    hi: datetime | None = None
    source = ""

    win = state.get("window") if isinstance(state.get("window"), dict) else {}
    explicit_lo = _parse_iso(win.get("start") or state.get("burst_start"))
    explicit_hi = _parse_iso(win.get("end") or state.get("burst_end"))
    if explicit_lo and explicit_hi:
        lo, hi, source = explicit_lo, explicit_hi, "state.json window"

    if lo is None:
        fired = [d for d in (_parse_iso(g.get("fired_at"))
                             for g in ground_truth) if d]
        if fired:
            lo, hi = min(fired), max(fired)
            source = "ground_truth fired_at"
            created = _parse_iso(state.get("created"))
            if created and created < lo:
                lo = created
                source = "state.created + ground_truth fired_at"

    if lo is None and run_dir:
        phases = _report_phase_times(run_dir)
        if phases:
            lo, hi = min(phases), max(phases)
            source = "report.json phase stamps"

    if lo is None and run_dir:
        mtimes = _run_dir_mtimes(run_dir)
        if mtimes:
            lo, hi = min(mtimes), max(mtimes)
            source = "run-dir artifact mtimes"
            warn(f"run window derived from FILE MTIMES ({_fmt(lo)} .. "
                 f"{_fmt(hi)}) — neither state.json, ground truth nor "
                 f"report.json dates this run; verify the verdicts")

    if lo is None or hi is None:
        raise ScorerError(
            "cannot date this run: state.json has no window/burst_start and "
            "no `created`, no story carries `fired_at`, and the run dir has "
            "no report.json — refusing to fall back to an unbounded "
            "corr_objects scan (the 2026-08-29 storm defect)")
    if hi < lo:
        lo, hi = hi, lo
    return Window(_fmt(lo - timedelta(seconds=slack_s)),
                  _fmt(hi + timedelta(seconds=settle_s)), source)


def _report_phase_times(run_dir: str) -> list[datetime]:
    out: list[datetime] = []
    for name in ("report.json", "twin-report.json"):
        try:
            with open(os.path.join(run_dir, name), encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for phase in doc.get("phases") or []:
            dt = _parse_iso((phase or {}).get("at"))
            if dt:
                out.append(dt)
        dt = _parse_iso(doc.get("generated"))
        if dt:
            out.append(dt)
    return out


def _run_dir_mtimes(run_dir: str) -> list[datetime]:
    out: list[datetime] = []
    try:
        entries = os.listdir(run_dir)
    except OSError:
        return out
    for name in entries:
        try:
            st = os.stat(os.path.join(run_dir, name))
        except OSError:
            continue
        out.append(datetime.fromtimestamp(st.st_mtime, timezone.utc))
    return out


# ── tenants ──────────────────────────────────────────────────────────────────

def run_tenants(stack, state: dict, window: Window) -> list[str]:
    """The tenant ids every read is scoped to (CLAUDE.md §3a: no data-returning
    read without a tenant bound).

    The twin's own runs record the tenancy it created; a mini-ladder run does
    not, so the tenants are DISCOVERED from the narrow hot projection inside
    the run window — still a bounded read, still tenant-led afterwards."""
    ids = sorted({t.get("tenant_id")
                  for t in (state.get("tenants") or {}).values()
                  if isinstance(t, dict) and t.get("tenant_id")})
    if ids:
        return [_lit(t) for t in ids]
    rows = stack.ch_json(
        "SELECT DISTINCT toString(tenant_id) AS tenant_id "
        "FROM netops.corr_current "
        f"WHERE window_start BETWEEN '{window.start}' AND '{window.end}' "
        f"AND created_at BETWEEN '{window.start}' AND '{window.end}'",
        settings=_settings("tenants"), strict=True)
    ids = sorted({str(r.get("tenant_id", "")) for r in rows})
    ids = [_lit(t) for t in ids if t]
    if not ids:
        raise ScorerError(
            f"no correlation object of ANY tenant exists in the run window "
            f"{window.start} .. {window.end} ({window.source}). Either the "
            f"window is wrong or the engine produced nothing — REFUSING to "
            f"render that as a 0% accuracy report. Put an explicit "
            f'"window": {{"start": ..., "end": ...}} in state.json if the '
            f"window is what is wrong.")
    return ids


# ── the bounded reads ────────────────────────────────────────────────────────

class ScoreContext:
    """Every ClickHouse read the scorer makes, bounded to ONE run.

    `prefetch()` turns the per-story reads into per-batch reads; without it the
    context still answers each story on its own (the shapes are identical, so
    the two paths are testably equivalent — see tests/test_scorer_bounds.py).
    """

    def __init__(self, stack, window: Window, tenants: list[str],
                 story_batch: int = STORY_BATCH,
                 max_needles: int = MAX_NEEDLES):
        if not tenants:
            raise ScorerError(
                "no tenant to scope the scorer's reads to — refusing an "
                "unscoped corr_objects read (CLAUDE.md §3a)")
        self.stack = stack
        self.window = window
        self.tenants = list(tenants)
        self.story_batch = max(1, int(story_batch))
        self.max_needles = max(1, int(max_needles))
        self.queries = 0
        self.projection_gaps = 0
        # score_run knows which stories FAILED only after every clause is
        # evaluated, so it defers the evidence-trail read and then does it in
        # one batch. A standalone score_story (no deferral) still fetches.
        self.defer_signals = False
        self._objects: dict[str, list[dict]] | None = None
        self._seam_refs: dict[str, set[str]] = {}
        self._hypotheses: dict[str, str] = {}
        self._signals: dict[str, dict[str, int]] = {}

    # -- helpers -----------------------------------------------------------
    def _q(self, sql: str, tag: str, **extra) -> list[dict]:
        self.queries += 1
        return self.stack.ch_json(sql, settings=_settings(tag, **extra),
                                  strict=True)

    def _units(self, items: list[tuple[str, list[str]]]):
        """(key, names) → (key, names-chunk) units no wider than the needle
        cap. A story with more entities than one query may carry is SPLIT
        across queries; membership is a union over the parts, so splitting
        changes nothing about the result."""
        for key, names in items:
            uniq = list(dict.fromkeys(names))
            if not uniq:
                continue
            for chunk in _chunks(uniq, self.max_needles):
                yield key, chunk

    def _batch(self, items: list[tuple[str, list[str]]]):
        """Group units into batches bounded by BOTH the story count and
        ClickHouse's multiSearch* needle limit (fewer than 2^8 needles).
        Yields (units, needles) — the units carry the names each one
        contributed, so a split story is never counted twice."""
        units: list[tuple[str, list[str]]] = []
        needles: dict[str, None] = {}
        for key, chunk in self._units(items):
            fresh = [n for n in chunk if n not in needles]
            if units and (len(units) >= self.story_batch
                          or len(needles) + len(fresh) > self.max_needles):
                yield units, list(needles)
                units, needles = [], {}
                fresh = chunk
            for n in fresh:
                needles[n] = None
            units.append((key, chunk))
        if units:
            yield units, list(needles)

    # -- objects -----------------------------------------------------------
    def prefetch(self, story_names: list[tuple[str, list[str]]]) -> None:
        """One membership query per batch per tenant, then one keyed lookup per
        chunk of matched ids — instead of two queries per story."""
        self._objects = self._objects_for_many(story_names)

    def objects_for(self, story_id: str, names: list[str]) -> list[dict]:
        if self._objects is not None:
            return self._objects.get(story_id, [])
        return self._objects_for_many([(story_id, names)]).get(story_id, [])

    def _objects_for_many(
            self, story_names: list[tuple[str, list[str]]],
    ) -> dict[str, list[dict]]:
        # id -> the names ANY version of that object named (the old per-story
        # `multiSearchAny` semantics, evaluated once for the whole batch).
        hits: dict[tuple[str, str], set[str]] = {}
        for tenant in self.tenants:
            for _, needles in self._batch(story_names):
                if not needles:
                    continue
                lst = _needles(needles)
                for row in self._q(
                        "SELECT toString(correlation_id) AS id, "
                        f"arrayFilter((n, p) -> p > 0, [{lst}], "
                        f"multiSearchAllPositions(affected, [{lst}])) AS hits "
                        "FROM netops.corr_objects "
                        f"WHERE tenant_id = '{_lit(tenant)}' "
                        f"AND window_start BETWEEN '{self.window.start}' "
                        f"AND '{self.window.end}' "
                        f"AND created_at BETWEEN '{self.window.start}' "
                        f"AND '{self.window.end}' "
                        f"AND multiSearchAny(affected, [{lst}])",
                        "membership"):
                    key = (tenant, _uuid(str(row["id"])))
                    hits.setdefault(key, set()).update(
                        str(h) for h in row.get("hits") or [])
        rows = self._latest(sorted(hits))
        out: dict[str, list[dict]] = {sid: [] for sid, _ in story_names}
        for story_id, names in story_names:
            want = set(names)
            out[story_id] = [rows[key] for key in sorted(rows)
                             if hits.get(key, set()) & want]
        return out

    def _latest(self, keys: list[tuple[str, str]]) -> dict:
        """Newest version of each (tenant, correlation_id) — from the narrow
        `corr_current` hot projection, keyed on the primary-key prefix. Never
        a `LIMIT 1 BY` fold of the 46 GiB history table."""
        cols = ("SELECT toString(correlation_id) AS id, "
                "toString(state) AS state, "
                "toString(verdict_tier) AS verdict_tier, top_hypothesis, "
                "round(top_confidence,3) AS conf, node_count, version, "
                "affected ")
        found: dict[tuple[str, str], dict] = {}
        by_tenant: dict[str, list[str]] = {}
        for tenant, oid in keys:
            by_tenant.setdefault(tenant, []).append(oid)
        for tenant, oids in by_tenant.items():
            for chunk in _chunks(oids, ID_BATCH):
                tup = ", ".join(f"('{_lit(tenant)}', toUUID('{_uuid(o)}'))"
                                for o in chunk)
                for row in self._q(
                        cols + "FROM netops.corr_current FINAL "
                        f"WHERE (tenant_id, correlation_id) IN ({tup})",
                        "latest"):
                    row["tenant"] = tenant
                    found[(tenant, str(row["id"]))] = row
        missing = [k for k in keys if k not in found]
        if missing:
            # corr_current is a maintained PROJECTION; a gap in it must not
            # silently cost the scorer an object (§10). Fall back to the
            # history table for exactly those ids, still key-bounded.
            self.projection_gaps += len(missing)
            warn(f"{len(missing)} object(s) are in corr_objects but not in "
                 f"corr_current — falling back to the history table for them "
                 f"(hot-projection gap; see corr_current_reconcile.go)")
            by_tenant = {}
            for tenant, oid in missing:
                by_tenant.setdefault(tenant, []).append(oid)
            for tenant, oids in by_tenant.items():
                for chunk in _chunks(oids, ID_BATCH):
                    tup = ", ".join(
                        f"('{_lit(tenant)}', toUUID('{_uuid(o)}'))"
                        for o in chunk)
                    for row in self._q(
                            cols + "FROM netops.corr_objects "
                            f"WHERE (tenant_id, correlation_id) IN ({tup}) "
                            f"AND window_start BETWEEN '{self.window.start}' "
                            f"AND '{self.window.end}' "
                            f"AND created_at BETWEEN '{self.window.start}' "
                            f"AND '{self.window.end}' "
                            "ORDER BY version DESC LIMIT 1 BY correlation_id",
                            "latest-fallback",
                            max_block_size=CH_BLOB_BLOCK_ROWS):
                        row["tenant"] = tenant
                        found[(tenant, str(row["id"]))] = row
        return found

    # -- seam edges --------------------------------------------------------
    def prefetch_seam_refs(self, objects: list[dict]) -> None:
        by_tenant: dict[str, list[str]] = {}
        for obj in objects:
            oid = str(obj["id"])
            if oid in self._seam_refs:
                continue
            self._seam_refs[oid] = set()
            by_tenant.setdefault(str(obj.get("tenant") or self.tenants[0]),
                                 []).append(oid)
        for tenant, oids in by_tenant.items():
            for chunk in _chunks(sorted(set(oids)), ID_BATCH):
                lst = ", ".join(f"toUUID('{_uuid(o)}')" for o in chunk)
                for row in self._q(
                        "SELECT toString(correlation_id) AS id, "
                        "grounding_ref FROM netops.corr_edges "
                        f"WHERE tenant_id = '{_lit(tenant)}' "
                        f"AND correlation_id IN ({lst}) "
                        "AND grounding_kind = 'seam' "
                        f"AND created_at BETWEEN '{self.window.start}' "
                        f"AND '{self.window.end}' "
                        "GROUP BY id, grounding_ref", "seam-edges"):
                    self._seam_refs.setdefault(
                        str(row["id"]), set()).add(str(row["grounding_ref"]))

    def seam_refs(self, obj: dict) -> set[str]:
        oid = str(obj["id"])
        if oid not in self._seam_refs:
            self.prefetch_seam_refs([obj])
        return self._seam_refs.get(oid, set())

    # -- hypotheses (the 48 GiB column: read only when a clause needs it) ---
    def prefetch_hypotheses(self, objects: list[dict]) -> None:
        by_tenant: dict[str, list[tuple[str, int]]] = {}
        for obj in objects:
            oid = str(obj["id"])
            if oid in self._hypotheses:
                continue
            self._hypotheses[oid] = ""
            by_tenant.setdefault(str(obj.get("tenant") or self.tenants[0]),
                                 []).append((oid, int(obj.get("version") or 0)))
        for tenant, pairs in by_tenant.items():
            for chunk in _chunks(sorted(set(pairs)), ID_BATCH):
                tup = ", ".join(
                    f"('{_lit(tenant)}', toUUID('{_uuid(o)}'), {int(v)})"
                    for o, v in chunk)
                for row in self._q(
                        "SELECT toString(correlation_id) AS id, hypotheses "
                        "FROM netops.corr_objects "
                        "WHERE (tenant_id, correlation_id, version) IN "
                        f"({tup}) "
                        f"AND window_start BETWEEN '{self.window.start}' "
                        f"AND '{self.window.end}' "
                        f"AND created_at BETWEEN '{self.window.start}' "
                        f"AND '{self.window.end}'",
                        "hypotheses", max_block_size=CH_BLOB_BLOCK_ROWS):
                    self._hypotheses[str(row["id"])] = str(
                        row.get("hypotheses") or "")

    def hypotheses(self, obj: dict) -> str:
        oid = str(obj["id"])
        if oid not in self._hypotheses:
            self.prefetch_hypotheses([obj])
        return self._hypotheses.get(oid, "")

    # -- evidence trail signals --------------------------------------------
    def prefetch_signals(self, story_names: list[tuple[str, list[str]]]) -> None:
        """Signals per kind for the stories' entities, one query per batch.

        The old shape was `entity_id LIKE '%<name>%'` ONCE PER ENTITY (906
        queries on the storm run) — and `LIKE` reads `_` as a wildcard, so an
        entity name containing one over-matched. This counts DISTINCT signal
        rows via a literal multi-substring match instead: an entity_id naming
        two of the story's entities is one signal, not two."""
        pending = [(sid, names) for sid, names in story_names
                   if sid not in self._signals]
        for sid, _ in pending:
            self._signals[sid] = {}
        for tenant in self.tenants:
            for units, needles in self._batch(pending):
                if not needles:
                    continue
                lst = _needles(needles)
                rows = self._q(
                    f"SELECT arrayFilter((n, p) -> p > 0, [{lst}], "
                    f"multiSearchAllPositions(entity_id, [{lst}])) AS hits, "
                    "kind, count() AS n FROM netops.corr_signals "
                    f"WHERE tenant_id = '{_lit(tenant)}' "
                    f"AND ts BETWEEN '{self.window.start}' "
                    f"AND '{self.window.end}' "
                    f"AND multiSearchAny(entity_id, [{lst}]) "
                    "GROUP BY hits, kind", "signals")
                for sid, chunk in units:
                    want = set(chunk)
                    acc = self._signals.setdefault(sid, {})
                    for row in rows:
                        if not ({str(h) for h in row.get("hits") or []}
                                & want):
                            continue
                        kind = str(row["kind"])
                        acc[kind] = acc.get(kind, 0) + int(row["n"])

    def signals_for(self, story_id: str, names: list[str]) -> dict[str, int]:
        if story_id not in self._signals:
            if self.defer_signals:
                return {}
            self.prefetch_signals([(story_id, names)])
        return self._signals.get(story_id, {})


# ── clause evaluation ────────────────────────────────────────────────────────

def _top_owner(obj: dict, blob: str) -> str:
    """verdict.owner of the ranked-top hypothesis in the hypotheses JSON."""
    try:
        doc = json.loads(blob or "{}")
    except json.JSONDecodeError:
        return ""
    # Live column shape (verified 2026-08-17 on-stack): a dict
    # {"grounding_context": {...}, "ranking": {"hypotheses": [...],
    #  "top_hypothesis": ..., ...}} — each ranked entry carries
    # verdict.owner (scoring.py HypothesisScore.to_dict).
    if isinstance(doc, dict):
        hyps = (doc.get("ranking") or {}).get("hypotheses") or []
    elif isinstance(doc, list):  # tolerate a bare ranked list
        hyps = doc
    else:
        return ""
    hyps = [h for h in hyps if isinstance(h, dict)]
    for h in hyps:
        if h.get("id") == obj.get("top_hypothesis"):
            return str((h.get("verdict") or {}).get("owner") or "")
    if hyps:
        return str((hyps[0].get("verdict") or {}).get("owner") or "")
    return ""


def story_entities(gt: dict, prefix: str) -> list[str]:
    """The run-tagged entity names one story is about — devices first, then
    the template's extra (cloud/circuit) entities, de-duplicated in order."""
    names = [prefix + d for d in gt["affected"].get("devices") or []]
    names += [prefix + e for e in gt.get("extra_entities") or []]
    return list(dict.fromkeys(names))


def score_story(stack, gt: dict, prefix: str,
                device_tenants: dict[str, str],
                journal_counts: dict[str, int],
                ctx: ScoreContext | None = None) -> dict:
    """One ground-truth record → clause-by-clause verdict.

    `ctx` carries the run's window/tenant bounds and (when `score_run`
    prefetched) the batch's already-fetched rows. It is REQUIRED: without it
    there is no window to bound the reads to, and an unbounded read of this
    table is the defect this module was rewritten to remove."""
    if ctx is None:
        raise ScorerError("score_story needs a ScoreContext (the run window "
                          "and tenant bounds); an unbounded scorer read is "
                          "not an option")
    expect = gt.get("expect") or {}
    rca = expect.get("rca") or {}
    seam_exp = expect.get("seam") or {}
    forbid = expect.get("forbid") or {}

    names = story_entities(gt, prefix)
    objects = [o for o in ctx.objects_for(gt["story_id"], names)
               if o.get("state") != "merged"]

    clauses: list[dict] = []

    def clause(name: str, ok: bool, detail: str) -> None:
        clauses.append({"clause": name, "ok": bool(ok), "detail": detail})

    positive = bool(rca) or bool(seam_exp)
    best = max(objects,
               key=lambda o: _TIER_RANK.get(o["verdict_tier"], 0),
               default=None)

    if positive:
        clause("detected", best is not None,
               f"{len(objects)} object(s) touch the story's entities")
    if rca.get("verdict_tier_at_least"):
        want = _TIER_RANK[rca["verdict_tier_at_least"]]
        have = _TIER_RANK.get(best["verdict_tier"], 0) if best else -1
        clause("verdict_tier_at_least",
               best is not None and have >= want,
               f"want ≥ {rca['verdict_tier_at_least']}, got "
               f"{best['verdict_tier'] if best else 'NO OBJECT'}")
    if rca.get("hypothesis_matches"):
        pat = re.compile(rca["hypothesis_matches"])
        hyp = best["top_hypothesis"] if best else ""
        clause("hypothesis_matches", bool(best and pat.search(hyp)),
               f"pattern {rca['hypothesis_matches']!r} vs "
               f"top_hypothesis {hyp!r}")
    if rca.get("affected_includes"):
        missing = []
        if best:
            for d in rca["affected_includes"]:
                if (prefix + d) not in (best.get("affected") or ""):
                    missing.append(d)
        clause("affected_includes",
               best is not None and not missing,
               f"missing from object.affected: {missing or 'none'}"
               if best else "no object")
    if rca.get("single_incident"):
        clause("single_incident", len(objects) == 1,
               f"{len(objects)} non-merged object(s) span the story "
               f"(cascade must fold to ONE)")

    if seam_exp:
        seam_id = prefix + seam_exp["seam_id"]
        refs: set[str] = set()
        if best:
            refs = ctx.seam_refs(best)
        clause("seam_grounded",
               best is not None and seam_id in refs,
               f"want seam edge ref {seam_id!r}, object has "
               f"{sorted(refs) or 'none'}")
        if seam_exp.get("owner"):
            owner = _top_owner(best, ctx.hypotheses(best)) if best else ""
            clause("seam_owner", owner == seam_exp["owner"],
                   f"want owner {seam_exp['owner']!r}, hypothesis verdict "
                   f"names {owner!r}")

    if forbid.get("cross_tenant_merge"):
        violators = []
        for o in objects:
            tenants_hit = {t for d, t in device_tenants.items()
                           if (prefix + d) in (o.get("affected") or "")}
            if len(tenants_hit) > 1:
                violators.append({"object": o["id"],
                                  "tenants": sorted(tenants_hit)})
        clause("forbid.cross_tenant_merge", not violators,
               f"objects spanning tenants: {violators or 'none'}")
    if forbid.get("confirmed"):
        confirmed = [o["id"] for o in objects
                     if o["verdict_tier"] == "confirmed"]
        clause("forbid.confirmed", not confirmed,
               f"confirmed objects: {confirmed or 'none'}")

    ok = all(c["ok"] for c in clauses)
    out = {
        "story_id": gt["story_id"],
        "template": gt["template"],
        "kind": "positive" if positive else "negative_control",
        "status": "PASS" if ok else "FAIL",
        "fired_at": gt.get("fired_at"),
        "clauses": clauses,
        "objects": [{k: o[k] for k in
                     ("id", "verdict_tier", "top_hypothesis", "conf",
                      "node_count")} for o in objects],
    }
    if not ok:
        out["evidence_trail"] = {
            "events_journaled": journal_counts,
            "signals_by_kind": ctx.signals_for(gt["story_id"], names),
        }
    return out


# ── the run ──────────────────────────────────────────────────────────────────

def score_run(stack, ground_truth: list[dict], state: dict,
              journal_by_story: dict[str, dict[str, int]],
              run_dir: str | None = None,
              ctx: ScoreContext | None = None,
              notes: list[str] | None = None) -> dict:
    """Score every story against a run-bounded view of ClickHouse.

    A read that FAILS aborts the whole score (ScorerError / StackError
    propagate): an all-miss report that is really "the query was refused" is
    the single worst thing this tool could hand back."""
    prefix = state["prefix"]
    device_tenants = state.get("device_tenants") or {}
    if ctx is None:
        window = run_window(state, ground_truth, run_dir)
        state_tenants = bool(state.get("tenants") or {})
        ctx = ScoreContext(stack, window, run_tenants(stack, state, window))
        if not state_tenants:
            # run_tenants had to DISCOVER them, and that read is a query too:
            # the report counts every read this scorer issued, not only the
            # ones the context itself made.
            ctx.queries += 1

    story_names = [(g["story_id"], story_entities(g, prefix))
                   for g in ground_truth if g.get("story_id")]
    # Batched object fetch first. Any SQL-unsafe entity name is caught HERE,
    # for the whole run, before a single query goes out.
    try:
        ctx.prefetch(story_names)
    except ValueError as exc:
        raise ScorerError(f"ground truth carries an entity name that is not "
                          f"SQL-embed safe: {exc}") from exc

    # Seam clauses need corr_edges (and, for `owner`, the wide hypotheses
    # column). Fetch them for the objects those stories actually picked —
    # never for the whole run.
    seam_objs, owner_objs = [], []
    for gt in ground_truth:
        seam_exp = (gt.get("expect") or {}).get("seam") or {}
        if not seam_exp:
            continue
        objs = [o for o in ctx.objects_for(gt["story_id"],
                                           story_entities(gt, prefix))
                if o.get("state") != "merged"]
        if not objs:
            continue
        best = max(objs, key=lambda o: _TIER_RANK.get(o["verdict_tier"], 0))
        seam_objs.append(best)
        if seam_exp.get("owner"):
            owner_objs.append(best)
    if seam_objs:
        ctx.prefetch_seam_refs(seam_objs)
    if owner_objs:
        ctx.prefetch_hypotheses(owner_objs)

    results = []
    failing: list[tuple[str, list[str]]] = []
    ctx.defer_signals = True       # trails are read in ONE batch, at the end
    for gt in ground_truth:
        try:
            r = score_story(stack, gt, prefix, device_tenants,
                            journal_by_story.get(gt["story_id"], {}), ctx=ctx)
        except (ScorerError, StackError):
            raise            # a refused/unbounded READ is never a story miss
        except Exception as exc:  # noqa: BLE001 — one story's scoring crash
            # must not lose every other story's verdict (and previously lost
            # the whole report to teardown); it is recorded as a LOUD failure.
            results.append({
                "story_id": gt.get("story_id", "?"),
                "template": gt.get("template", "?"),
                "kind": "positive",
                "status": "FAIL",
                "fired_at": gt.get("fired_at"),
                "clauses": [{"clause": "scorer_error", "ok": False,
                             "detail": f"scoring crashed: {exc!r}"}],
                "objects": [],
            })
            continue
        if r["status"] == "FAIL":
            failing.append((gt["story_id"], story_entities(gt, prefix)))
        results.append(r)

    # Evidence trails last, in one batch over the FAILING stories only.
    ctx.defer_signals = False
    if failing:
        ctx.prefetch_signals(failing)
        by_id = {r["story_id"]: r for r in results}
        for sid, names in failing:
            trail = by_id[sid].get("evidence_trail")
            if trail is not None:
                trail["signals_by_kind"] = ctx.signals_for(sid, names)

    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    positives = [r for r in results if r["kind"] == "positive"]
    negatives = [r for r in results if r["kind"] == "negative_control"]

    def _rate(items: list[dict]) -> float:
        return round(sum(1 for r in items if r["status"] == "PASS")
                     / len(items), 4) if items else 1.0

    def _clause_rate(items: list[dict], clause: str) -> float:
        hits = ok = 0
        for r in items:
            for c in r["clauses"]:
                if c["clause"] == clause:
                    hits += 1
                    ok += 1 if c["ok"] else 0
        return round(ok / hits, 4) if hits else 1.0

    per_template: dict[str, dict[str, int]] = {}
    for r in results:
        t = per_template.setdefault(r["template"], {"pass": 0, "fail": 0})
        t["pass" if r["status"] == "PASS" else "fail"] += 1

    return {
        "runid": state["runid"],
        "accuracy_slo": round(passed / total, 4) if total else None,
        "stories_total": total,
        "stories_passed": passed,
        "detection_rate": _clause_rate(positives, "detected"),
        "positive_pass_rate": _rate(positives),
        "specificity": _rate(negatives),
        "per_template": per_template,
        "read_bounds": {
            "window": ctx.window.as_dict(),
            "tenants": ctx.tenants,
            "clickhouse_queries": ctx.queries,
            "story_batch": ctx.story_batch,
            "hot_projection_gaps": ctx.projection_gaps,
        },
        "notes": list(notes or []),
        "stories": results,
    }


def render_md(report: dict) -> str:
    bounds = report.get("read_bounds") or {}
    window = bounds.get("window") or {}
    lines = [
        f"# Twin accuracy report — run {report['runid']}",
        "",
        (f"- **RCA accuracy SLO: "
         f"{report['stories_passed']}/{report['stories_total']} stories "
         f"({(report['accuracy_slo'] or 0) * 100:.0f}%)**"),
        (f"- Positive stories pass rate: "
         f"{report['positive_pass_rate'] * 100:.0f}% · "
         f"specificity (negative controls): "
         f"{report['specificity'] * 100:.0f}%"),
    ]
    if window:
        lines.append(
            f"- Read bounds: `{window.get('start')}` .. `{window.get('end')}` "
            f"({window.get('source')}) · tenants "
            f"{bounds.get('tenants')} · "
            f"{bounds.get('clickhouse_queries')} ClickHouse queries")
    for note in report.get("notes") or []:
        lines.append(f"- Note: {note}")
    lines += [
        "",
        "| Story | Template | Kind | Status |",
        "|---|---|---|---|",
    ]
    for r in report["stories"]:
        lines.append(f"| {r['story_id']} | {r['template']} | {r['kind']} | "
                     f"{r['status']} |")
    lines.append("")
    for r in report["stories"]:
        lines.append(f"## {r['story_id']} ({r['status']})")
        for c in r["clauses"]:
            mark = "✔" if c["ok"] else "✘"
            lines.append(f"- {mark} `{c['clause']}` — {c['detail']}")
        if r.get("objects"):
            lines.append("- objects: "
                         + "; ".join(f"{o['id'][:8]} "
                                     f"{o['verdict_tier']}/"
                                     f"{o['top_hypothesis']} "
                                     f"conf={o['conf']} nodes={o['node_count']}"
                                     for o in r["objects"]))
        if r.get("evidence_trail"):
            lines.append(f"- evidence trail: "
                         f"{json.dumps(r['evidence_trail'], sort_keys=True)}")
        lines.append("")
    return "\n".join(lines) + "\n"
