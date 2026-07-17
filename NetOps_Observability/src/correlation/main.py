"""NetOps Observability — Correlation + AI Engine.

A FastAPI service that:

  * Consumes the netops.syslog, netops.flows, netops.metrics Redpanda
    topics (Kafka-compatible).
  * Runs lightweight stream processing — rolling z-score anomaly
    detection over per-device metric series, severity-weighted event
    correlation, and a stub for RCA.
  * Writes findings into ClickHouse (netops.findings table) so the UI
    can render them as ranked incident cards.
  * Exposes a REST API for the Go layer to query findings and trigger
    on-demand analyses.

The implementation is intentionally minimal — replace the algorithms
with sklearn / Prophet / a real CEP engine as the workload demands. The
service contract (consume from Kafka, emit findings to ClickHouse,
serve /findings) stays stable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque, Dict, Iterable

import httpx
from aiokafka import AIOKafkaConsumer
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from timenorm import ResolvedTime, SkewTracker, resolve_event_time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG_LEVEL        = os.environ.get("LOG_LEVEL", "info").upper()
KAFKA_BOOTSTRAP  = os.environ.get("KAFKA_BOOTSTRAP", "redpanda:9092")
CLICKHOUSE_URL   = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
CLICKHOUSE_USER  = os.environ.get("CLICKHOUSE_USER", "netops")
CLICKHOUSE_PASS  = os.environ.get("CLICKHOUSE_PASSWORD", "")

TOPICS = ["netops.syslog", "netops.flows", "netops.metrics"]

# Timezone resolution config (docs/design/log-time-standard.md). Events
# normalized upstream (Vector stamps event_time/tz_assumed) pass through;
# these settings only govern events whose timestamps still need a zone:
#   DEVICE_TZ_MAP   — JSON object {"hostname": "America/Chicago" | "+05:30"}
#                     (per-device stage of the hierarchy; a settings UI and
#                     bulk import are tracked follow-ups)
#   SITE_DEFAULT_TZ — site/collector default stage; default "UTC"
try:
    DEVICE_TZ_MAP: dict[str, str] = json.loads(os.environ.get("DEVICE_TZ_MAP", "{}"))
    if not isinstance(DEVICE_TZ_MAP, dict):
        DEVICE_TZ_MAP = {}
except ValueError:
    DEVICE_TZ_MAP = {}
SITE_DEFAULT_TZ = os.environ.get("SITE_DEFAULT_TZ", "UTC")

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("correlation")


# ---------------------------------------------------------------------------
# In-memory state for anomaly detection.
#
# Per-(device, metric) rolling window of recent samples. We keep a fixed
# window size so memory stays bounded; once the window has 20 samples
# we start scoring new arrivals against its mean + stddev.
# ---------------------------------------------------------------------------

WINDOW_SIZE = 200
Z_THRESHOLD = 3.0


@dataclass
class Series:
    values: Deque[float] = field(default_factory=lambda: deque(maxlen=WINDOW_SIZE))

    def mean(self) -> float:
        return sum(self.values) / len(self.values) if self.values else 0.0

    def stddev(self) -> float:
        n = len(self.values)
        if n < 2:
            return 0.0
        m = self.mean()
        return (sum((v - m) ** 2 for v in self.values) / (n - 1)) ** 0.5

    def push(self, v: float) -> None:
        self.values.append(v)


SERIES: Dict[tuple[str, str], Series] = {}


def score(device: str, metric: str, value: float) -> float | None:
    """Return a |z-score| if the value is anomalous, else None."""
    key = (device, metric)
    s = SERIES.setdefault(key, Series())
    if len(s.values) < 20:
        s.push(value)
        return None
    sigma = s.stddev()
    if sigma == 0:
        s.push(value)
        return None
    z = abs((value - s.mean()) / sigma)
    s.push(value)
    if z >= Z_THRESHOLD:
        return z
    return None


# ---------------------------------------------------------------------------
# ClickHouse helpers (HTTP interface).
# ---------------------------------------------------------------------------


class CH:
    def __init__(self, base_url: str, user: str, password: str) -> None:
        self.base = base_url.rstrip("/")
        self.auth = (user, password)
        self.client = httpx.AsyncClient(timeout=10.0)

    async def insert(self, table: str, rows: Iterable[dict]) -> None:
        body = "\n".join(json.dumps(r) for r in rows)
        if not body:
            return
        params = {"query": f"INSERT INTO {table} FORMAT JSONEachRow"}
        r = await self.client.post(
            self.base, params=params, content=body, auth=self.auth,
            headers={"Content-Type": "application/x-ndjson"},
        )
        if r.status_code >= 300:
            log.error("clickhouse insert failed: %s %s", r.status_code, r.text)

    async def query(self, sql: str) -> list[dict]:
        r = await self.client.post(
            self.base, params={"default_format": "JSON"}, content=sql, auth=self.auth,
        )
        if r.status_code >= 300:
            raise HTTPException(status_code=502, detail=r.text)
        return r.json().get("data", [])

    async def close(self) -> None:
        await self.client.aclose()


ch: CH | None = None


# ---------------------------------------------------------------------------
# Kafka consumer loop.
# ---------------------------------------------------------------------------


async def consume() -> None:
    consumer = AIOKafkaConsumer(
        *TOPICS,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id="netops-correlation",
        auto_offset_reset="latest",
        value_deserializer=lambda v: json.loads(v.decode("utf-8")) if v else None,
        enable_auto_commit=True,
    )
    await consumer.start()
    log.info("consuming topics=%s bootstrap=%s", TOPICS, KAFKA_BOOTSTRAP)
    try:
        async for msg in consumer:
            await handle(msg.topic, msg.value)
    finally:
        await consumer.stop()


# Per-device skew stats over ingest−event: stable whole/quarter-hour
# offsets are flagged as probable timezone misconfiguration (distinct
# from clock drift) and surfaced as data-quality findings. Event times
# are never rewritten.
SKEW = SkewTracker()


async def handle(topic: str, event: dict | None) -> None:
    if not event or ch is None:
        return

    # One receive stamp per event; resolution of the event's source time
    # happens here, once — downstream handlers only consume the result.
    when = resolve_event_time(
        event,
        received_at=datetime.now(timezone.utc),
        device_tz_map=DEVICE_TZ_MAP,
        default_tz=SITE_DEFAULT_TZ,
    )
    await watch_skew(event, when)

    if topic == "netops.metrics":
        await handle_metric(event, when)
    elif topic == "netops.syslog":
        await handle_syslog(event, when)
    elif topic == "netops.flows":
        await handle_flow(event, when)


def event_device(ev: dict) -> str:
    return str(ev.get("hostname") or ev.get("device") or ev.get("agent_host") or "")


async def watch_skew(ev: dict, when: ResolvedTime) -> None:
    """Feed the skew tracker; emit a data-quality finding on a verdict."""
    verdict = SKEW.observe(event_device(ev), when)
    if verdict is None:
        return
    SKEW.reset(verdict.device)  # don't re-report every subsequent event
    await emit(
        kind="data_quality",
        severity="warning" if verdict.kind == "tz_misconfig" else "info",
        device=verdict.device,
        component="time",
        summary=verdict.summary(),
        description=(
            f"Median ingest−event skew {verdict.median_skew_s:+.0f}s over "
            f"{verdict.sample_count} events. Timestamps are reported as "
            f"received — never auto-corrected. Fix the device clock/zone "
            f"or set its timezone in DEVICE_TZ_MAP."
        ),
        score=abs(verdict.median_skew_s) / 60.0,
        labels={
            "device": verdict.device,
            "skew_kind": verdict.kind,
            "median_skew_s": f"{verdict.median_skew_s:.0f}",
        },
        when=when,
    )


async def handle_metric(ev: dict, when: ResolvedTime) -> None:
    """Score numeric metric samples for anomalies."""
    device = event_device(ev) or "unknown"
    name = str(ev.get("name") or ev.get("metric") or "")
    if not name:
        return
    # Find the first numeric field value.
    value = None
    for k, v in ev.items():
        if isinstance(v, (int, float)) and k not in {"timestamp", "time"}:
            value = float(v); name = name or k; break
    if value is None:
        return
    z = score(device, name, value)
    if z is None:
        return
    await emit(
        kind="anomaly",
        severity="warning" if z < 5 else "critical",
        device=device,
        component=name,
        summary=f"{name} on {device} z={z:.1f}",
        description=f"Rolling z-score over last {WINDOW_SIZE} samples exceeded threshold.",
        score=float(z),
        labels={"metric": name, "device": device},
        when=when,
    )


# Severity weights for syslog correlation. A burst of high-severity
# events from one device within a short window is itself a finding.
SEVERITY_WEIGHT = {"emerg": 8, "alert": 7, "crit": 6, "err": 5, "warning": 3, "notice": 2, "info": 1, "debug": 0}
SYSLOG_BUCKET: Dict[str, list[tuple[float, int]]] = {}
SYSLOG_WINDOW = 60.0   # seconds
SYSLOG_THRESHOLD = 30  # cumulative weight


async def handle_syslog(ev: dict, when: ResolvedTime) -> None:
    host = event_device(ev) or "unknown"
    sev  = str(ev.get("severity") or "info").lower()
    weight = SEVERITY_WEIGHT.get(sev, 0)
    if weight == 0:
        return
    # The burst window is relative bookkeeping — the monotonic-ish wall
    # clock is fine here; event_time is what gets PERSISTED (see emit).
    now = time.time()
    bucket = SYSLOG_BUCKET.setdefault(host, [])
    bucket.append((now, weight))
    # Drop expired entries.
    cutoff = now - SYSLOG_WINDOW
    SYSLOG_BUCKET[host] = [(t, w) for t, w in bucket if t >= cutoff]
    total = sum(w for _, w in SYSLOG_BUCKET[host])
    if total >= SYSLOG_THRESHOLD:
        await emit(
            kind="correlation",
            severity="warning",
            device=host,
            component="syslog",
            summary=f"Syslog burst on {host}: weighted={total}",
            description=f"≥{SYSLOG_THRESHOLD} severity-points within {int(SYSLOG_WINDOW)}s window.",
            score=float(total),
            labels={"host": host},
            when=when,
        )
        SYSLOG_BUCKET[host] = []   # reset so we don't spam


async def handle_flow(_ev: dict, _when: ResolvedTime) -> None:
    # Placeholder: NetFlow correlation (DDoS detection, top-talker
    # sudden shift, port-scan signatures) goes here.
    return


def _iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


async def emit(**kwargs) -> None:
    """Write one finding row.

    `when` (ResolvedTime) stamps the row's ts with the triggering event's
    SOURCE time as fractional epoch seconds — unambiguous for ClickHouse
    DateTime64(3) regardless of server timezone. Previously ts was
    omitted and the column DEFAULT now64(3) recorded the INSERT time,
    discarding the event's real occurrence time entirely. The full time
    provenance (event_time / ingest_time / tz_assumed) rides in labels —
    the findings schema needs no migration.
    """
    when: ResolvedTime | None = kwargs.get("when")
    labels = dict(kwargs.get("labels", {}))
    row = {
        "id":          str(uuid.uuid4()),
        "kind":        kwargs["kind"],
        "severity":    kwargs["severity"],
        "score":       kwargs["score"],
        "device":      kwargs.get("device", ""),
        "component":   kwargs.get("component", ""),
        "summary":     kwargs.get("summary", ""),
        "description": kwargs.get("description", ""),
    }
    if when is not None:
        row["ts"] = round(when.event_time.timestamp(), 3)
        labels["event_time"] = _iso_utc(when.event_time)
        labels["ingest_time"] = _iso_utc(when.ingest_time)
        labels["tz_assumed"] = "true" if when.tz_assumed else "false"
        if when.raw_timestamp:
            labels["raw_timestamp"] = when.raw_timestamp[:128]
    row["labels"] = labels
    assert ch is not None
    await ch.insert("netops.findings", [row])
    log.info("finding: %s %s %s", row["severity"], row["kind"], row["summary"])


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global ch
    ch = CH(CLICKHOUSE_URL, CLICKHOUSE_USER, CLICKHOUSE_PASS)
    task = asyncio.create_task(consume())
    try:
        yield
    finally:
        task.cancel()
        try: await task
        except asyncio.CancelledError: pass
        await ch.close()


app = FastAPI(title="netops-correlation", version="0.1.0", lifespan=lifespan)


class Finding(BaseModel):
    ts: str
    id: str
    kind: str
    severity: str
    score: float
    device: str
    component: str
    summary: str
    description: str


@app.get("/healthz")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/findings", response_model=list[Finding])
async def findings(limit: int = 100, severity: str | None = None) -> list[dict]:
    assert ch is not None
    where = ""
    if severity:
        sev = severity.replace("'", "")
        where = f"WHERE severity = '{sev}'"
    # ts is rendered timezone-EXPLICIT: RFC 3339 UTC with a Z suffix.
    # A bare toString(ts) yields a zoneless server-timezone string that
    # JS clients then re-interpret as viewer-local time.
    sql = f"""
      SELECT concat(replaceOne(toString(ts, 'UTC'), ' ', 'T'), 'Z') AS ts,
             id, kind, severity, score, device,
             component, summary, description
        FROM netops.findings
        {where}
       ORDER BY ts DESC
       LIMIT {int(limit)}
       FORMAT JSON
    """
    return await ch.query(sql)


@app.post("/analyze")
async def analyze() -> dict:
    """On-demand RCA stub. Replace with a real implementation that
    correlates recent findings into incident clusters."""
    return {"status": "scheduled", "note": "RCA is a stub in this scaffold."}
