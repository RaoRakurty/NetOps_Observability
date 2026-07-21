"""Time normalization + clock-skew detection for the correlation engine.

Implements the platform log-time standard (docs/design/log-time-standard.md):

  * Every event carries three time facts: event_time (source time
    normalized to UTC), ingest_time (Correlix receive time) and
    raw_timestamp (the original string, verbatim).
  * Timezone resolution happens exactly once, at first parse, using the
    hierarchy: explicit offset in the payload → per-device timezone
    config → site default → UTC fallback flagged tz_assumed=True.
    This module applies the same hierarchy for events that arrive
    WITHOUT an already-normalized time (older producers, raw vendor
    payloads); events normalized upstream pass through untouched.
  * Skew detection compares ingest_time − event_time per device.
    Stable deltas near whole/quarter-hour offsets are flagged as
    probable timezone misconfiguration — DISTINCT from clock drift —
    and surfaced as data-quality findings. Nothing is ever silently
    "corrected".

Everything here is pure (no IO) so it is directly unit-testable.
"""

from __future__ import annotations

import re
import statistics
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Deque, Dict, Mapping, Optional
from zoneinfo import ZoneInfo

__all__ = [
    "ResolvedTime",
    "parse_any_timestamp",
    "parse_rfc3164_timestamp",
    "resolve_event_time",
    "resolve_tz",
    "SkewTracker",
    "SkewVerdict",
]

UTC = timezone.utc

# ---------------------------------------------------------------------------
# Timezone resolution
# ---------------------------------------------------------------------------

_OFFSET_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


def resolve_tz(spec: str) -> tzinfo:
    """Turn a device/site timezone spec into a tzinfo.

    Accepts IANA names ("America/Chicago", "Asia/Kolkata" — DST-correct)
    and fixed offsets ("+05:30", "-0600", "+05:45"). Raises ValueError on
    anything else so a config typo fails loudly instead of silently
    mis-stamping a fleet.
    """
    m = _OFFSET_RE.match(spec.strip())
    if m:
        sign = 1 if m.group(1) == "+" else -1
        hours, minutes = int(m.group(2)), int(m.group(3))
        if hours > 14 or minutes > 59:
            raise ValueError(f"implausible UTC offset: {spec!r}")
        return timezone(sign * timedelta(hours=hours, minutes=minutes))
    try:
        return ZoneInfo(spec.strip())
    except Exception as exc:  # zoneinfo raises several types
        raise ValueError(f"unknown timezone spec: {spec!r}") from exc


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# RFC 3164 header timestamp: "Mmm [d]d hh:mm:ss", optionally with
# fractional seconds (some vendors emit them). NO year, NO zone.
_RFC3164_RE = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})(?:\.(?P<frac>\d{1,6}))?$"
)
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_rfc3164_timestamp(
    raw: str,
    *,
    reference: datetime,
    tz: tzinfo = UTC,
) -> Optional[datetime]:
    """Parse an RFC 3164 timestamp ("Jul 17 06:30:00") into UTC.

    RFC 3164 carries neither year nor zone, so both must be inferred:

      * zone: `tz` — the caller supplies the device/site zone from the
        resolution hierarchy (fixed offsets and DST-aware IANA zones both
        work; the wall time is localized in that zone, then converted).
      * year: chosen from {ref-1, ref, ref+1} as the candidate closest to
        `reference` (the receive time). That makes the December→January
        rollover correct in both directions: "Dec 31 23:59:58" received
        on Jan 1 resolves to LAST year; "Jan 1 00:00:05" received on
        Dec 31 resolves to NEXT year. Slightly future-dated events are
        preserved as-is — never clamped or "corrected".

    Returns None when `raw` is not an RFC 3164 timestamp. Feb 29 in a
    candidate non-leap year is skipped rather than mis-mapped.
    """
    m = _RFC3164_RE.match(raw.strip())
    if not m:
        return None
    mon = _MONTHS[m.group("mon")]
    day = int(m.group("day"))
    h, mi, s = int(m.group("h")), int(m.group("m")), int(m.group("s"))
    micro = int((m.group("frac") or "0").ljust(6, "0"))

    ref = reference.astimezone(UTC)
    best: Optional[datetime] = None
    best_delta: Optional[float] = None
    for year in (ref.year - 1, ref.year, ref.year + 1):
        try:
            local = datetime(year, mon, day, h, mi, s, micro, tzinfo=tz)
        except ValueError:
            continue  # e.g. Feb 29 in a non-leap candidate year
        candidate = local.astimezone(UTC)
        delta = abs((candidate - ref).total_seconds())
        if best_delta is None or delta < best_delta:
            best, best_delta = candidate, delta
    return best


# Epoch-unit inference thresholds: each is the unit's value at 1971-01-01,
# so every instant from 1971 through year ~5138 maps to exactly one unit.
_EPOCH_NS = 100_000_000_000_000_000  # ≥ 1e17 → nanoseconds
_EPOCH_US = 100_000_000_000_000     # ≥ 1e14 → microseconds
_EPOCH_MS = 100_000_000_000         # ≥ 1e11 → milliseconds


def _from_epoch(n: float) -> datetime:
    a = abs(n)
    if a >= _EPOCH_NS:
        n /= 1_000_000_000
    elif a >= _EPOCH_US:
        n /= 1_000_000
    elif a >= _EPOCH_MS:
        n /= 1_000
    return datetime.fromtimestamp(n, tz=UTC)


_ISO_ZONELESS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?$"
)

# Sub-second field of an ISO timestamp. datetime.fromisoformat accepts only 3
# or 6 digits on Python 3.10, but the wire carries whatever the producer emits:
# gNMI/OpenConfig sources stamp NANOseconds ("…:00.123456789Z") and some agents
# emit two. Rejecting those shapes is what pushed real event times back to
# receive time, so normalize the field to exactly 6 digits (truncate, never
# round — a timestamp must not move forward) instead of failing the parse.
_FRACTION_RE = re.compile(r"\.(\d+)")


def _normalize_fraction(s: str) -> str:
    m = _FRACTION_RE.search(s)
    if m is None or len(m.group(1)) == 6:
        return s
    return s[:m.start()] + "." + m.group(1)[:6].ljust(6, "0") + s[m.end():]


def parse_any_timestamp(
    value: object,
    *,
    reference: datetime,
    tz: tzinfo = UTC,
) -> Optional[tuple[datetime, bool]]:
    """Parse one timestamp value of unknown shape.

    Returns (utc_datetime, tz_assumed) or None if unparseable.
    tz_assumed is True whenever the value itself carried no offset and we
    had to apply `tz` (the hierarchy's device/site/UTC answer) — epochs
    and offset-bearing ISO strings are unambiguous, so False for those.
    """
    if isinstance(value, bool):  # bool is an int subclass — reject explicitly
        return None
    if isinstance(value, (int, float)):
        try:
            return _from_epoch(float(value)), False
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if raw == "":
        return None

    # Numeric string → epoch.
    try:
        return _from_epoch(float(raw)), False
    except ValueError:
        pass

    # ISO 8601 / RFC 3339. fromisoformat in 3.11+ handles "Z"; normalize
    # for 3.10 compatibility.
    iso = _normalize_fraction(raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw)
    try:
        dt = datetime.fromisoformat(iso.replace(" ", "T", 1) if _ISO_ZONELESS_RE.match(raw) else iso)
    except ValueError:
        dt = None
    if dt is not None:
        if dt.tzinfo is None:
            # Zoneless ISO — apply the hierarchy zone, flag the assumption.
            return dt.replace(tzinfo=tz).astimezone(UTC), True
        return dt.astimezone(UTC), False

    # RFC 3164 header time (no year, no zone) — always an assumption.
    r3164 = parse_rfc3164_timestamp(raw, reference=reference, tz=tz)
    if r3164 is not None:
        return r3164, True
    return None


# ---------------------------------------------------------------------------
# Event-time resolution (the hierarchy, applied to one event dict)
# ---------------------------------------------------------------------------

# Producer fields consulted for the event's source time, best first.
# event_time/timestamp are what the Vector tier stamps; ts is the Go API
# app-log field; @timestamp appears on OpenSearch-shaped events.
_TIME_FIELDS = ("event_time", "timestamp", "@timestamp", "ts", "time")
_DEVICE_FIELDS = ("hostname", "device", "agent_host", "sampler_address")


@dataclass(frozen=True)
class ResolvedTime:
    event_time: datetime      # UTC, always tz-aware
    ingest_time: datetime     # UTC, always tz-aware
    tz_assumed: bool          # True when a zone had to be assumed
    raw_timestamp: str        # verbatim original ("" when none found)

    @property
    def skew_seconds(self) -> float:
        """ingest − event; positive = event time lags the receive clock."""
        return (self.ingest_time - self.event_time).total_seconds()


def resolve_event_time(
    event: Mapping[str, object],
    *,
    received_at: datetime,
    device_tz_map: Mapping[str, str] | None = None,
    default_tz: str = "UTC",
) -> ResolvedTime:
    """Resolve one event's time facts per the standard's hierarchy.

    1. explicit offset (or epoch) in the payload — trusted as-is;
    2. per-device timezone from `device_tz_map` (keyed by the event's
       device/hostname field) for zoneless payload timestamps;
    3. site/collector default (`default_tz`);
    4. UTC fallback — and if the payload had NO parseable time at all,
       event_time falls back to ingest_time with tz_assumed=True.

    An upstream tz_assumed flag (stamped by Vector) is honored: we never
    downgrade an upstream "assumed" to "trusted".
    """
    ingest = received_at.astimezone(UTC)

    # Hierarchy stages 2–3: which zone applies to zoneless strings.
    tz: tzinfo = UTC
    for spec in (_device_tz(event, device_tz_map), default_tz):
        if not spec:
            continue
        try:
            tz = resolve_tz(spec)
            break
        except ValueError:
            continue  # bad config entry → fall through to next stage

    upstream_assumed = event.get("tz_assumed") is True

    for field in _TIME_FIELDS:
        value = event.get(field)
        if value is None:
            continue
        parsed = parse_any_timestamp(value, reference=ingest, tz=tz)
        if parsed is None:
            continue
        event_time, assumed = parsed
        raw = event.get("raw_timestamp")
        return ResolvedTime(
            event_time=event_time,
            ingest_time=ingest,
            tz_assumed=assumed or upstream_assumed,
            raw_timestamp=str(raw) if raw is not None else str(value),
        )

    # Stage 4: nothing parseable — receive time, flagged.
    raw = event.get("raw_timestamp")
    return ResolvedTime(
        event_time=ingest,
        ingest_time=ingest,
        tz_assumed=True,
        raw_timestamp=str(raw) if raw is not None else "",
    )


def _device_tz(
    event: Mapping[str, object], device_tz_map: Mapping[str, str] | None
) -> Optional[str]:
    if not device_tz_map:
        return None
    for field in _DEVICE_FIELDS:
        dev = event.get(field)
        if isinstance(dev, str) and dev in device_tz_map:
            return device_tz_map[dev]
    return None


# ---------------------------------------------------------------------------
# Skew detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SkewVerdict:
    device: str
    kind: str            # "tz_misconfig" | "clock_drift"
    median_skew_s: float
    sample_count: int
    nearest_offset_s: int  # for tz_misconfig: the quarter-hour it matches

    def summary(self) -> str:
        mins = self.median_skew_s / 60.0
        if self.kind == "tz_misconfig":
            return (
                f"Probable timezone misconfiguration on {self.device}: "
                f"event times run a stable {mins:+.0f} min from receive time "
                f"(≈ {self.nearest_offset_s // 60:+d} min zone offset)."
            )
        return (
            f"Clock drift on {self.device}: event times run a stable "
            f"{mins:+.1f} min from receive time."
        )


class SkewTracker:
    """Per-device rolling stats over (ingest_time − event_time).

    A STABLE delta near a whole/quarter-hour (±15/30/45/60… min, which
    also covers +05:30 and +05:45 zones) is a timezone-misconfiguration
    signature; a stable delta elsewhere is clock drift (NTP problem).
    Deltas are observed and REPORTED only — event times are never
    rewritten (the standard forbids silent correction).
    """

    QUARTER_HOUR = 900.0     # tz offsets are multiples of 15 min
    TOLERANCE_S = 120.0      # |median − nearest quarter-hour| to call it tz
    MIN_OFFSET_S = 1500.0    # ignore medians under 25 min (pipeline lag,
                             # small drift) — smallest real zone step is 30m
    DRIFT_MIN_S = 300.0      # stable ≥5 min but not zone-shaped → drift
    STABLE_STDEV_S = 60.0    # "stable" = samples agree within a minute

    def __init__(self, window: int = 50, min_samples: int = 20) -> None:
        self._window = window
        self._min_samples = min_samples
        self._series: Dict[str, Deque[float]] = {}

    def observe(self, device: str, resolved: ResolvedTime) -> Optional[SkewVerdict]:
        """Record one event's skew; returns a verdict when the device's
        recent skew is stable and anomalous, else None."""
        if not device:
            return None
        series = self._series.setdefault(
            device, deque(maxlen=self._window)
        )
        series.append(resolved.skew_seconds)
        if len(series) < self._min_samples:
            return None

        med = statistics.median(series)
        stdev = statistics.pstdev(series)
        if stdev > self.STABLE_STDEV_S:
            return None  # noisy — no confident verdict

        nearest = round(med / self.QUARTER_HOUR) * self.QUARTER_HOUR
        if (
            abs(med) >= self.MIN_OFFSET_S
            and nearest != 0
            and abs(med - nearest) <= self.TOLERANCE_S
        ):
            return SkewVerdict(
                device=device,
                kind="tz_misconfig",
                median_skew_s=med,
                sample_count=len(series),
                nearest_offset_s=int(nearest),
            )
        if abs(med) >= self.DRIFT_MIN_S:
            return SkewVerdict(
                device=device,
                kind="clock_drift",
                median_skew_s=med,
                sample_count=len(series),
                nearest_offset_s=0,
            )
        return None

    def reset(self, device: str) -> None:
        """Forget a device's window (used after reporting a verdict so the
        same misconfiguration isn't re-reported every event)."""
        self._series.pop(device, None)
