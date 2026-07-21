"""Per-exchange self-metrics for the cloud-ingest poller (Wave 4 #13).

The poller's provider exchanges all flow through the platform Identity Broker
(broker_client.credentials); this module counts those exchanges per provider
and outcome (success / auth_fail / throttled / api_error) with latency, and
serves them on a minimal /metrics endpoint in the stack's Prometheus text
format — the same exposition VictoriaMetrics already scrapes for every other
component (src/config/vmscrape.yml). The poller container is a lab-site
sidecar, so the scrape job is optional: an absent target is a silent no-op
under VM's suppressScrapeErrors.

Honesty + safety contract: counters carry ONLY provider + outcome labels
(bounded label set — never a tenant, connector id, account, or any credential);
serving metrics is best-effort and must never take a poll lane down.

stdlib-only (http.server + threading).
"""
from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OUTCOME_SUCCESS = "auth_success"
OUTCOME_AUTH_FAIL = "auth_fail"
OUTCOME_THROTTLED = "throttled"
OUTCOME_API_ERROR = "api_error"

# CLOUD_INGEST_METRICS_PORT: TCP port for /metrics; "off" or "0" disables.
PORT_ENV = "CLOUD_INGEST_METRICS_PORT"
DEFAULT_PORT = 9109

_lock = threading.Lock()
_exchange: dict[tuple[str, str], int] = {}   # (provider, outcome) -> count
_lat_sum: dict[str, float] = {}              # provider -> seconds
_lat_count: dict[str, int] = {}
# Records whose Kafka delivery is known to have FAILED, by topic. Produce
# failures used to be invisible (send() is async and every lane discarded the
# future), so "no data downstream" was indistinguishable from "no data
# upstream". Topic is the ONLY label — bounded by the topic list, never a
# tenant/account/payload.
_produce_failed: dict[str, int] = {}
_flush_failed: dict[str, int] = {}           # component -> failed flushes


def classify_error(exc: BaseException) -> str:
    """Map a broker/exchange failure to an outcome label. BrokerError carries
    the terminal HTTP status (0 = transport error) — 401/403 is an auth
    failure, 429 a throttle, everything else an API error."""
    status = getattr(exc, "status", None)
    if isinstance(status, int):
        if status in (401, 403):
            return OUTCOME_AUTH_FAIL
        if status == 429:
            return OUTCOME_THROTTLED
    return OUTCOME_API_ERROR


def record_exchange(provider: str, outcome: str, seconds: float | None = None) -> None:
    """Count one credential exchange. Bounded labels; never raises."""
    p = str(provider or "unknown")
    with _lock:
        _exchange[(p, outcome)] = _exchange.get((p, outcome), 0) + 1
        if seconds is not None and seconds >= 0:
            _lat_sum[p] = _lat_sum.get(p, 0.0) + float(seconds)
            _lat_count[p] = _lat_count.get(p, 0) + 1


def record_produce_failure(topic: str) -> None:
    """Count one record whose Kafka delivery failed. Never raises."""
    t = str(topic or "unknown")
    with _lock:
        _produce_failed[t] = _produce_failed.get(t, 0) + 1


def record_flush_failure(component: str) -> None:
    """Count one failed producer flush (component = the lane that flushed).
    A failed flush means unacknowledged records: whatever checkpoint that lane
    was about to advance must NOT advance."""
    c = str(component or "unknown")
    with _lock:
        _flush_failed[c] = _flush_failed.get(c, 0) + 1


def produce_failures() -> dict[str, int]:
    """Snapshot of the per-topic produce-failure counts (test/introspection)."""
    with _lock:
        return dict(_produce_failed)


def render() -> str:
    """Prometheus text exposition of the current counters."""
    lines = [
        "# HELP netops_cloud_ingest_exchange_total Poller credential exchanges by provider and outcome.",
        "# TYPE netops_cloud_ingest_exchange_total counter",
    ]
    with _lock:
        for (p, outcome) in sorted(_exchange):
            lines.append(
                f'netops_cloud_ingest_exchange_total{{provider="{p}",outcome="{outcome}"}} '
                f"{_exchange[(p, outcome)]}")
        lines.append("# HELP netops_cloud_ingest_exchange_latency_seconds Total latency of poller credential exchanges.")
        lines.append("# TYPE netops_cloud_ingest_exchange_latency_seconds summary")
        for p in sorted(_lat_count):
            lines.append(f'netops_cloud_ingest_exchange_latency_seconds_sum{{provider="{p}"}} {_lat_sum[p]:.6f}')
            lines.append(f'netops_cloud_ingest_exchange_latency_seconds_count{{provider="{p}"}} {_lat_count[p]}')
        lines.append("# HELP netops_cloud_ingest_produce_failures_total Records whose Kafka delivery failed (data lost).")
        lines.append("# TYPE netops_cloud_ingest_produce_failures_total counter")
        for t in sorted(_produce_failed):
            lines.append(f'netops_cloud_ingest_produce_failures_total{{topic="{t}"}} {_produce_failed[t]}')
        lines.append("# HELP netops_cloud_ingest_flush_failures_total Producer flushes that did not complete (checkpoint held back).")
        lines.append("# TYPE netops_cloud_ingest_flush_failures_total counter")
        for c in sorted(_flush_failed):
            lines.append(f'netops_cloud_ingest_flush_failures_total{{component="{c}"}} {_flush_failed[c]}')
    return "\n".join(lines) + "\n"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        if self.path.split("?", 1)[0] != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        body = render().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence per-request stderr noise
        return


def serve(port: int | None = None) -> ThreadingHTTPServer | None:
    """Start the /metrics endpoint on a daemon thread. Returns the server (its
    bound port is server.server_address[1]) or None when disabled/failed —
    metrics must never take the poller down."""
    if port is None:
        raw = os.environ.get(PORT_ENV, str(DEFAULT_PORT)).strip().lower()
        if raw in ("off", "0", ""):
            return None
        try:
            port = int(raw)
        except ValueError:
            return None
    try:
        srv = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    except OSError:
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def reset() -> None:
    """Test hook: forget all counters."""
    with _lock:
        _exchange.clear()
        _lat_sum.clear()
        _lat_count.clear()
        _produce_failed.clear()
        _flush_failed.clear()
