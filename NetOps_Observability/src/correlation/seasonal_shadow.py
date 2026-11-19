# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Seasonal SHADOW score — a side channel beside pipeline stage [2] (tracker 337
N-H6 step 4).

Owner ruling (2026-11-19): "the correlation engine's truest intention shouldn't
be diverted." So this module INFORMS and never DECIDES:

  * It reads the episode detector's output and the sample, and nothing reads
    what it computes back. No Signal, attrs, corr_signals row, archive slice,
    hash, score, template, verdict or object is touched — not even with the
    flag ON. Its only outputs are counters (/metrics, /healthz). That is a
    stronger guarantee than "identical except added attrs": Signal attrs are
    persisted, archived for replay and capped at 4 KiB with the biggest key
    truncated, so adding keys there could, in principle, push a clause key out
    (signals.py truncation) — a path to a diverted decision this design does
    not have.
  * Flag CORR_SEASONAL_SHADOW, default OFF: OFF, the hot path makes one boolean
    check and returns.

What it measures, for the owner's December step-5 decision: for every episode
the existing CUSUM detector OPENS, whether the observed value was also unusual
for this time of week/day (seasonal robust z ≥ ABOVE_Z) — `seasonal_confirms` —
or within its usual seasonal range — `seasonal_quiet`, i.e. a routine peak the
seasonal reading would not have called anomalous — or whether there was not
enough history (`no_baseline`). Counted only; never acted on.

The maths is the twin of the Go package src/backend/internal/nlquery/seasonal
(Iris's seasonal answers) so the two never disagree: the same tiers (A hour of
week ≥3 weeks, B hour of day ≥5 days, C none), median centre, 1.4826 × MAD
scale floored at 5 % of |centre| and a per-unit floor. A shared fixture
(src/backend/internal/nlquery/seasonal/testdata/parity.json) is checked by both
test suites.

Profile source: the tenant's rows of netops.series_hourly (the api's hourly
roll-up, FEATURE_SEASONAL_ROLLUP), read at tenant_scope=<tenant> so the table's
STRICT row policy decides visibility, fetched OFF the hot path (an asyncio task
per tenant and hour), bounded per tenant and across tenants (§9). A sample whose
tenant profile is not loaded yet, failed to load, or does not cover the series
gets no seasonal z — counted, never guessed.
"""

from __future__ import annotations

import math
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# --- constants: the Go seasonal package's, verbatim (parity-tested) -----------
MAX_WEEKS = 4
MAX_DAYS = 7
MIN_WEEKS = 3
MIN_DAYS = 5
MAD_SCALE = 1.4826
REL_FLOOR = 0.05
ABOVE_Z = 3.0

TIER_WEEK = "hour_of_week"  # A
TIER_DAY = "hour_of_day"    # B
TIER_NONE = "none"          # C

TIER_LETTER = {TIER_WEEK: "A", TIER_DAY: "B", TIER_NONE: "C"}


def _flag(name: str, default: str) -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "on", "yes")


def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return min(max(v, lo), hi)


CORR_SEASONAL_SHADOW = _flag("CORR_SEASONAL_SHADOW", "0")
# §9 bounds: series profiles held per tenant, tenants held, concurrent fetches.
SHADOW_MAX_SERIES = _int_env("CORR_SEASONAL_SHADOW_MAX_SERIES", 10000, 1, 200000)
SHADOW_MAX_TENANTS = _int_env("CORR_SEASONAL_SHADOW_MAX_TENANTS", 16, 1, 1024)
SHADOW_MAX_INFLIGHT = _int_env("CORR_SEASONAL_SHADOW_MAX_INFLIGHT", 2, 1, 32)
# A failed read is retried no sooner than this (seconds).
SHADOW_RETRY_S = float(_int_env("CORR_SEASONAL_SHADOW_RETRY_S", 300, 10, 86400))


# --- the pure maths (twin of internal/nlquery/seasonal) -----------------------
@dataclass(frozen=True)
class Ref:
    """One reference observation: the same value at an earlier instant."""

    at: datetime
    value: float = 0.0
    present: bool = False
    excluded: bool = False


@dataclass(frozen=True)
class Profile:
    tier: str
    centre: float = 0.0
    scale: float = 0.0
    used: int = 0
    considered: int = 0
    excluded: int = 0
    history_days: int = 0

    def z(self, x: float) -> float | None:
        """Robust z of x; None for tier C (or a non-finite x)."""
        if self.tier == TIER_NONE or self.scale <= 0 or not math.isfinite(x):
            return None
        return (x - self.centre) / self.scale


def median(vals: list[float]) -> float:
    n = len(vals)
    if n == 0:
        return 0.0
    s = sorted(vals)
    if n % 2 == 1:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2


def unit_floor(unit: str) -> float:
    u = (unit or "").strip().lower()
    if u in ("percent", "pct", "%"):
        return 0.5
    if u in ("bps", "bits/s", "bit/s"):
        return 1000.0
    if u in ("bytes", "byte", "b"):
        return 1024.0
    if u in ("ms", "milliseconds"):
        return 1.0
    if u in ("s", "seconds"):
        return 0.001
    if u in ("pps", "packets/s", "count", "errors", "per_second", "/s", "prefixes"):
        return 1.0
    if u == "score":
        return 0.5
    return 1e-9


def hour_of_week(t: datetime) -> int:
    """Monday 00:00 UTC = 0 … Sunday 23:00 = 167 (Go HourOfWeek)."""
    t = t.astimezone(timezone.utc)
    return t.weekday() * 24 + t.hour


def _usable(refs: list[Ref]) -> tuple[list[float], int]:
    vals: list[float] = []
    excl = 0
    for r in refs:
        if r.excluded:
            excl += 1
        elif r.present and math.isfinite(r.value):
            vals.append(r.value)
    return vals, excl


def _centre_scale(vals: list[float], floor: float) -> tuple[float, float]:
    c = median(vals)
    s = MAD_SCALE * median([abs(v - c) for v in vals])
    s = max(s, REL_FLOOR * abs(c))
    s = max(s, floor)
    return c, s


def _history_days(now: datetime, *sets: list[Ref]) -> int:
    oldest = timedelta(0)
    for refs in sets:
        for r in refs:
            if r.present and now - r.at > oldest:
                oldest = now - r.at
    return int(oldest // timedelta(days=1))


def fit(now: datetime, weekly: list[Ref], daily: list[Ref], floor: float) -> Profile:
    """The best tier the references support (Go seasonal.Fit)."""
    hist = _history_days(now, weekly, daily)
    vals, excl = _usable(weekly)
    if len(vals) >= MIN_WEEKS:
        c, s = _centre_scale(vals, floor)
        return Profile(TIER_WEEK, c, s, len(vals), len(weekly), excl, hist)
    vals, excl = _usable(daily)
    if len(vals) >= MIN_DAYS:
        c, s = _centre_scale(vals, floor)
        return Profile(TIER_DAY, c, s, len(vals), len(daily), excl, hist)
    _, ew = _usable(weekly)
    _, ed = _usable(daily)
    return Profile(TIER_NONE, excluded=ew + ed, history_days=hist)


# --- engine metric → roll-up series -------------------------------------------
@dataclass(frozen=True)
class SeriesMap:
    series_metric: str  # netops.series_hourly.metric (the catalog name)
    key: str            # "device" | "iface"
    scale: float        # engine value × scale = roll-up unit
    unit: str           # unit_floor() unit of the roll-up value


# The metric lane's names (after counter_rate: cumulative octets/errors/discards
# arrive as PER-SECOND rates) onto the api's seasonalRollMetrics()
# (src/backend/path_health_baselines.go). Octets/s × 8 = the roll-up's bits/s.
METRIC_MAP: dict[str, SeriesMap] = {
    "device_cpu_percent": SeriesMap("cpu_util_pct", "device", 1.0, "percent"),
    "device_mem_percent": SeriesMap("mem_util_pct", "device", 1.0, "percent"),
    "device_if_in_octets": SeriesMap("if_in_bps", "iface", 8.0, "bps"),
    "device_if_out_octets": SeriesMap("if_out_bps", "iface", 8.0, "bps"),
    "device_if_in_errors": SeriesMap("if_in_errors", "iface", 1.0, "per_second"),
    "device_if_out_errors": SeriesMap("if_out_errors", "iface", 1.0, "per_second"),
    "device_if_in_discards": SeriesMap("if_in_discards", "iface", 1.0, "per_second"),
    "device_if_out_discards": SeriesMap("if_out_discards", "iface", 1.0, "per_second"),
}


def entity_key(entity_id: str, key: str) -> str | None:
    """The roll-up's entity_key (labels joined by U+001F) for an engine entity:
    a device id as is; an interface `device:ifName` → `device\\x1fifName`. None
    when the entity cannot be split unambiguously (no profile, never a guess)."""
    if not entity_id:
        return None
    if key == "device":
        return entity_id
    dev, sep, iface = entity_id.partition(":")
    if not sep or not dev or not iface:
        return None
    return dev + "\x1f" + iface


def hour_start(ts: datetime) -> datetime:
    return ts.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)


def reference_hours(h: datetime) -> tuple[list[datetime], list[datetime]]:
    """The weekly and daily reference hour starts for the hour starting at h."""
    weekly = [h - timedelta(days=7 * (i + 1)) for i in range(MAX_WEEKS)]
    daily = [h - timedelta(days=i + 1) for i in range(MAX_DAYS)]
    return weekly, daily


_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")


def profile_sql(h: datetime, limit: int) -> str:
    """The one read for a tenant's references at hour h. Only integers and this
    module's literals are rendered; the tenant is NOT in the SQL — it rides as
    the request's tenant_scope, and the STRICT row policy filters by it."""
    weekly, daily = reference_hours(h)
    hours = ",".join(f"toDateTime({int(x.timestamp())})" for x in sorted(set(weekly + daily)))
    metrics = ",".join(f"'{m.series_metric}'" for m in sorted(METRIC_MAP.values(), key=lambda m: m.series_metric))
    # Only int()-cast hours, this module's metric literals and an int LIMIT are
    # rendered — no caller text reaches the statement.
    return (
        "SELECT metric, entity_key, toUnixTimestamp(hour) AS h, p50 "  # nosec B608
        "FROM netops.series_hourly FINAL "
        f"WHERE metric IN ({metrics}) AND hour IN ({hours}) "
        "ORDER BY metric, entity_key, hour "
        f"LIMIT {int(limit)} FORMAT JSON"
    )


# --- the shadow ---------------------------------------------------------------
OUTCOMES = ("seasonal_confirms", "seasonal_quiet", "no_baseline")


@dataclass
class _TenantProfiles:
    hour: datetime                                   # the hour these references serve
    rows: dict[tuple[str, str], dict[int, float]]    # (series metric, key) → {hour ts → p50}
    fitted: dict[tuple[str, str], Profile] = field(default_factory=dict)
    failed_at: float = 0.0                           # monotonic time of a failed read; 0 = loaded


class SeasonalShadow:
    """Per-replica shadow state. Every structure is keyed by tenant (§3a): a
    tenant's profile is only ever looked up for that tenant's own series."""

    def __init__(self, enabled: bool = CORR_SEASONAL_SHADOW,
                 max_series: int = SHADOW_MAX_SERIES,
                 max_tenants: int = SHADOW_MAX_TENANTS,
                 max_inflight: int = SHADOW_MAX_INFLIGHT,
                 retry_s: float = SHADOW_RETRY_S,
                 clock=time.monotonic) -> None:
        self.enabled = enabled
        self.max_series = max_series
        self.max_tenants = max_tenants
        self.max_inflight = max_inflight
        self.retry_s = retry_s
        self._clock = clock
        self._tenants: OrderedDict[str, _TenantProfiles] = OrderedDict()
        self._inflight: set[tuple[str, int]] = set()
        # counters (closed label sets)
        self.samples = {"A": 0, "B": 0, "C": 0, "pending": 0, "unmapped": 0}
        self.onsets = {(o, t): 0 for o in OUTCOMES for t in ("A", "B", "C", "pending")}
        self.reads = {"ok": 0, "failed": 0, "truncated": 0, "skipped": 0}
        self.errors = 0

    # -- hot path ------------------------------------------------------------
    def observe(self, tenant: str, entity_id: str, metric: str, ts: datetime,
                value: float, onset: bool) -> tuple[str, int] | None:
        """Score one sample (and, when `onset`, classify the episode the
        detector just opened). Returns (tenant, hour_ts) when that tenant's
        profile for this hour must be fetched — the caller schedules
        `refresh` off the hot path — else None. Never raises on bad input;
        never reads or writes anything the engine decides with."""
        m = METRIC_MAP.get(metric)
        if m is None:
            self.samples["unmapped"] += 1
            return None
        h = hour_start(ts)
        tp = self._tenants.get(tenant)
        need: tuple[str, int] | None = None
        if tp is None or tp.hour != h:
            # Not loaded for this hour. Only a NEWER hour replaces what is held:
            # a late sample from an earlier hour must not thrash the profile.
            if tp is None or h > tp.hour:
                need = (tenant, int(h.timestamp()))
            self.samples["pending"] += 1
            if onset:
                self.onsets[("no_baseline", "pending")] += 1
            return need
        if tp.failed_at and self._clock() - tp.failed_at >= self.retry_s:
            need = (tenant, int(h.timestamp()))  # retry a failed load; scored as C meanwhile
        self._tenants.move_to_end(tenant)
        key = entity_key(entity_id, m.key)
        prof = self._profile(tp, m, key, h) if key is not None else Profile(TIER_NONE)
        letter = TIER_LETTER[prof.tier]
        self.samples[letter] += 1
        if onset:
            z = prof.z(value * m.scale)
            if z is None:
                outcome = "no_baseline"
            elif abs(z) >= ABOVE_Z:
                outcome = "seasonal_confirms"
            else:
                outcome = "seasonal_quiet"
            self.onsets[(outcome, letter)] += 1
        return need

    def _profile(self, tp: _TenantProfiles, m: SeriesMap, key: str, h: datetime) -> Profile:
        k = (m.series_metric, key)
        prof = tp.fitted.get(k)
        if prof is not None:
            return prof
        pts = tp.rows.get(k)
        if not pts:
            prof = Profile(TIER_NONE)
        else:
            weekly_h, daily_h = reference_hours(h)

            def refs(hours: list[datetime]) -> list[Ref]:
                out = []
                for x in hours:
                    v = pts.get(int(x.timestamp()))
                    out.append(Ref(at=x, value=v if v is not None else 0.0, present=v is not None))
                return out

            prof = fit(h, refs(weekly_h), refs(daily_h), unit_floor(m.unit))
        if len(tp.fitted) < self.max_series:
            tp.fitted[k] = prof
        return prof

    # -- off the hot path ----------------------------------------------------
    def claim(self, tenant: str, hour_ts: int) -> bool:
        """True when the caller may start this fetch (not already in flight and
        under the concurrency bound)."""
        k = (tenant, hour_ts)
        if k in self._inflight or len(self._inflight) >= self.max_inflight:
            return False
        if not _TENANT_RE.match(tenant) or tenant == "global":
            # The platform partition owns no roll-up rows (series_hourly never
            # stores an untagged row); an unrecognised tenant is not read.
            self.reads["skipped"] += 1
            self._store(tenant, datetime.fromtimestamp(hour_ts, timezone.utc), {}, failed=True)
            return False
        self._inflight.add(k)
        return True

    def release(self, tenant: str, hour_ts: int) -> None:
        """Give back a claim whose fetch could not be started."""
        self._inflight.discard((tenant, hour_ts))

    async def refresh(self, tenant: str, hour_ts: int, query) -> None:
        """Fetch one tenant's references for one hour through `query(sql,
        tenant)` (an async tenant-scoped read). A failure is counted, stored as
        a failed load (retried after retry_s) and never raised."""
        h = datetime.fromtimestamp(hour_ts, timezone.utc)
        try:
            limit = self.max_series * (MAX_WEEKS + MAX_DAYS)
            data = await query(profile_sql(h, limit), tenant)
            rows: dict[tuple[str, str], dict[int, float]] = {}
            for r in data or []:
                try:
                    k = (str(r["metric"]), str(r["entity_key"]))
                    if k not in rows and len(rows) >= self.max_series:
                        continue
                    rows.setdefault(k, {})[int(r["h"])] = float(r["p50"])
                except (KeyError, TypeError, ValueError):
                    continue
            if len(data or []) >= limit:
                self.reads["truncated"] += 1
            self.reads["ok"] += 1
            self._store(tenant, h, rows, failed=False)
        except Exception:  # noqa: BLE001 — a shadow read must never escape
            self.reads["failed"] += 1
            self._store(tenant, h, {}, failed=True)
        finally:
            self._inflight.discard((tenant, hour_ts))

    def _store(self, tenant: str, h: datetime, rows, failed: bool) -> None:
        held = self._tenants.get(tenant)
        if held is not None and held.hour > h:
            return  # a slow read of an older hour never replaces a newer profile
        self._tenants[tenant] = _TenantProfiles(hour=h, rows=rows, failed_at=self._clock() if failed else 0.0)
        self._tenants.move_to_end(tenant)
        while len(self._tenants) > self.max_tenants:
            self._tenants.popitem(last=False)

    # -- observability -------------------------------------------------------
    def health(self) -> dict:
        return {
            "enabled": self.enabled,
            "tenants_loaded": len(self._tenants),
            "samples": dict(self.samples),
            "onsets": {f"{o}_{t}": n for (o, t), n in self.onsets.items()},
            "reads": dict(self.reads),
            "errors": self.errors,
        }

    def metrics_lines(self) -> list[str]:
        lines = [
            "# HELP corr_seasonal_shadow_enabled Seasonal shadow score on (CORR_SEASONAL_SHADOW); it never decides anything.",
            "# TYPE corr_seasonal_shadow_enabled gauge",
            f"corr_seasonal_shadow_enabled {1 if self.enabled else 0}",
            "# HELP corr_seasonal_shadow_samples_total Metric samples by the seasonal tier their series had (A week, B day, C none).",
            "# TYPE corr_seasonal_shadow_samples_total counter",
        ]
        for k in ("A", "B", "C", "pending", "unmapped"):
            lines.append(f'corr_seasonal_shadow_samples_total{{tier="{k}"}} {self.samples[k]}')
        lines += [
            "# HELP corr_seasonal_shadow_onsets_total Episodes the CUSUM detector opened, by what the seasonal reading said (counted only, never acted on).",
            "# TYPE corr_seasonal_shadow_onsets_total counter",
        ]
        for (o, t), n in sorted(self.onsets.items()):
            lines.append(f'corr_seasonal_shadow_onsets_total{{outcome="{o}",tier="{t}"}} {n}')
        lines += [
            "# HELP corr_seasonal_shadow_profile_reads_total Tenant profile reads of netops.series_hourly, by result.",
            "# TYPE corr_seasonal_shadow_profile_reads_total counter",
        ]
        for k in ("ok", "failed", "truncated", "skipped"):
            lines.append(f'corr_seasonal_shadow_profile_reads_total{{result="{k}"}} {self.reads[k]}')
        lines += [
            "# HELP corr_seasonal_shadow_errors_total Shadow evaluations that raised (contained; the episode lane is unaffected).",
            "# TYPE corr_seasonal_shadow_errors_total counter",
            f"corr_seasonal_shadow_errors_total {self.errors}",
        ]
        return lines
