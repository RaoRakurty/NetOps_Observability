#!/usr/bin/env python3
"""cloud_edge_traffic.py — end-to-end demo HTTP traffic generator.

This is the END-USER hop for the Cloud Demo Traffic Program (docs/design/
cloud-demo-traffic-program.md §1). It runs on a LAB CLIENT VM that sits behind a
clos-fabric leaf, so every request it makes traverses the REAL path:

    lab client (this host, behind leaf1/leaf2)
      -> leaf -> spine -> lab edge (.122) -> Internet egress
      -> provider public DNS  (cloud_dns_log)
      -> WAF / Cloud Armor    (cloud_waf_log)
      -> L7 load balancer     (cloud_lb_log)
      -> cloud firewall layer (cloud_flow_log)
      -> app VM (/ , /health , /boom)   (cloud_metric / app-experience)

That means one steady stream of genuine TCP/HTTP lights up EVERY component's
logs honestly, per provider. It is deliberately a plain stdlib client (no
third-party deps): `http.client` over :80 so it is trivially installable on any
lab client and produces real sockets, not synthesised flow records.

Design constraints (CLAUDE.md + program §7):
  * Bounded rollups are law -> per-provider rate is HARD-CLAMPED to <= 5 req/s
    (RATE_MAX_HARD below). Config can only ask for LESS, never more.
  * All IO has a timeout; connection errors are caught and counted, never fatal
    (we WANT to observe 5xx/timeouts during fault scenarios).
  * No secrets: endpoints come from a config file the owner fills post-apply.
  * Structured stdout logging; a 1/interval summary line per provider.

The /boom target-error surface (scenario D<p>3, "LB target kill") is armed and
cleared out-of-band with the `boom` / `heal` subcommands (see __main__); the
steady stream then simply observes the resulting 5xx.
"""

from __future__ import annotations

import argparse
import http.client
import logging
import os
import random
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# --- Bounded-rollup law: no provider stream may exceed this, ever. -----------
RATE_MAX_HARD = 5.0   # requests/second/provider (program §7: demo rates only)
RATE_MIN_FLOOR = 0.2  # keep at least a trickle so lanes stay warm

DEFAULT_TIMEOUT = 5.0      # seconds; every socket op is bounded
SUMMARY_EVERY = 30.0       # seconds between per-provider summary log lines
HEALTH_RATIO = 0.25        # fraction of requests sent to /health vs /
USER_AGENT = "correlix-edge-demo/1.0 (+lab-client)"

log = logging.getLogger("cloud-edge-traffic")


# =============================================================================
# Config
# =============================================================================
@dataclass
class ProviderCfg:
    name: str          # aws | azure | gcp
    endpoint: str      # host or host:port or http://host  (public app FQDN / LB IP)
    rate: float        # requests/second (already clamped)


def _clamp_rate(raw: str, provider: str) -> float:
    try:
        r = float(raw)
    except (TypeError, ValueError):
        log.warning("provider=%s bad RATE %r -> using 1.0", provider, raw)
        r = 1.0
    if r > RATE_MAX_HARD:
        log.warning("provider=%s RATE %.2f exceeds hard cap -> clamped to %.2f "
                    "(bounded-rollup law)", provider, r, RATE_MAX_HARD)
        r = RATE_MAX_HARD
    if r < RATE_MIN_FLOOR:
        r = RATE_MIN_FLOOR
    return r


def load_config(path: str) -> list[ProviderCfg]:
    """Parse a KEY=VALUE endpoints file. Recognised keys:

        AWS_ENDPOINT / AZURE_ENDPOINT / GCP_ENDPOINT   (required to enable a lane)
        AWS_RATE / AZURE_RATE / GCP_RATE               (optional, default 2 req/s)

    A lane whose *_ENDPOINT is empty/unset/placeholder is skipped (down cloud).
    """
    values: dict[str, str] = {}
    if not os.path.exists(path):
        log.error("config file not found: %s", path)
        return []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            values[k.strip().upper()] = v.strip().strip('"').strip("'")

    out: list[ProviderCfg] = []
    for prov in ("aws", "azure", "gcp"):
        ep = values.get(f"{prov.upper()}_ENDPOINT", "").strip()
        # Skip unset or obvious placeholders (endpoints are known only post-apply).
        if not ep or ep.upper().startswith("FILL") or "example.com" in ep.lower() \
                or ep.startswith("<"):
            log.info("provider=%s endpoint not set -> lane skipped", prov)
            continue
        rate = _clamp_rate(values.get(f"{prov.upper()}_RATE", "2"), prov)
        out.append(ProviderCfg(name=prov, endpoint=ep, rate=rate))
    return out


def _split_endpoint(endpoint: str) -> tuple[str, int]:
    """Accept 'host', 'host:port', or 'http://host[:port]' -> (host, port)."""
    if "://" in endpoint:
        parts = urlsplit(endpoint)
        host = parts.hostname or endpoint
        port = parts.port or 80
        return host, port
    if ":" in endpoint:
        host, _, p = endpoint.partition(":")
        try:
            return host, int(p)
        except ValueError:
            return host, 80
    return endpoint, 80


# =============================================================================
# Per-provider worker
# =============================================================================
@dataclass
class Counters:
    ok: int = 0            # 2xx
    err5xx: int = 0        # 5xx (the fault surface we WANT to see)
    err4xx: int = 0        # 4xx (WAF blocks land here as 403)
    fail: int = 0          # connect/timeout/DNS failures
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, kind: str) -> None:
        with self.lock:
            setattr(self, kind, getattr(self, kind) + 1)

    def snapshot_and_reset(self) -> dict[str, int]:
        with self.lock:
            snap = {"ok": self.ok, "err5xx": self.err5xx,
                    "err4xx": self.err4xx, "fail": self.fail}
            self.ok = self.err5xx = self.err4xx = self.fail = 0
            return snap


def _one_request(host: str, port: int, path: str, timeout: float) -> int:
    """Issue one GET; return the HTTP status, or 0 on transport failure.

    A fresh connection per request is intentional: it makes each request a full
    TCP handshake through the fabric + cloud chain, so flow logs and LB logs see
    a genuine connection (not a kept-alive multiplex), matching what a real
    end-user browser burst looks like at this low rate.
    """
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": USER_AGENT,
                                            "Host": host, "Connection": "close"})
        resp = conn.getresponse()
        resp.read()  # drain so the socket closes cleanly
        return resp.status
    except (OSError, http.client.HTTPException) as exc:
        log.debug("request failed host=%s path=%s err=%s", host, path, exc)
        return 0
    finally:
        try:
            conn.close()
        except OSError:
            pass


def provider_worker(cfg: ProviderCfg, counters: Counters,
                    stop: threading.Event, timeout: float) -> None:
    host, port = _split_endpoint(cfg.endpoint)
    interval = 1.0 / cfg.rate
    log.info("provider=%s stream up host=%s port=%d rate=%.2f req/s",
             cfg.name, host, port, cfg.rate)
    while not stop.is_set():
        started = time.monotonic()
        path = "/health" if random.random() < HEALTH_RATIO else "/"
        status = _one_request(host, port, path, timeout)
        if status == 0:
            counters.add("fail")
        elif status >= 500:
            counters.add("err5xx")
        elif status >= 400:
            counters.add("err4xx")
        else:
            counters.add("ok")
        # Jittered pacing around the target interval (+/-20%) so we don't emit a
        # perfectly periodic signal, and never exceed the clamped rate on average.
        sleep_for = max(0.0, interval - (time.monotonic() - started))
        sleep_for *= random.uniform(0.8, 1.2)
        stop.wait(sleep_for)


def summary_loop(cfgs: list[ProviderCfg], counters: dict[str, Counters],
                 stop: threading.Event) -> None:
    while not stop.wait(SUMMARY_EVERY):
        for cfg in cfgs:
            s = counters[cfg.name].snapshot_and_reset()
            total = sum(s.values())
            rate = total / SUMMARY_EVERY
            log.info("summary provider=%s window=%.0fs total=%d rate=%.2f/s "
                     "2xx=%d 5xx=%d 4xx=%d fail=%d",
                     cfg.name, SUMMARY_EVERY, total, rate,
                     s["ok"], s["err5xx"], s["err4xx"], s["fail"])


# =============================================================================
# One-shot boom / heal (LB target-error scenario D<p>3)
# =============================================================================
def toggle(endpoint: str, arm: bool, timeout: float) -> int:
    """Hit /boom (arm 500 on /) or /heal (clear). Returns HTTP status."""
    host, port = _split_endpoint(endpoint)
    path = "/boom" if arm else "/heal"
    status = _one_request(host, port, path, timeout)
    verb = "ARM boom" if arm else "HEAL"
    log.info("%s provider-endpoint=%s -> HTTP %d", verb, endpoint, status)
    return status


# =============================================================================
# Entrypoint
# =============================================================================
def cmd_run(args: argparse.Namespace) -> int:
    cfgs = load_config(args.config)
    if not cfgs:
        log.error("no provider lanes enabled — fill %s with real endpoints "
                  "(from `terraform output` after apply)", args.config)
        return 2

    stop = threading.Event()

    def _handle(signum, _frame):
        log.info("signal %d -> draining", signum)
        stop.set()
    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    counters = {c.name: Counters() for c in cfgs}
    threads = [threading.Thread(target=provider_worker,
                                args=(c, counters[c.name], stop, args.timeout),
                                name=f"tgen-{c.name}", daemon=True) for c in cfgs]
    threads.append(threading.Thread(target=summary_loop,
                                    args=(cfgs, counters, stop),
                                    name="summary", daemon=True))
    for t in threads:
        t.start()
    log.info("cloud-edge-traffic running: %d lane(s) [%s]",
             len(cfgs), ", ".join(f"{c.name}@{c.rate:.1f}/s" for c in cfgs))
    while not stop.is_set():
        time.sleep(0.5)
    log.info("stopped")
    return 0


def cmd_boom(args: argparse.Namespace) -> int:
    cfgs = {c.name: c for c in load_config(args.config)}
    cfg = cfgs.get(args.provider)
    if not cfg:
        log.error("provider %s not enabled in %s", args.provider, args.config)
        return 2
    return 0 if toggle(cfg.endpoint, arm=True, timeout=args.timeout) else 1


def cmd_heal(args: argparse.Namespace) -> int:
    cfgs = {c.name: c for c in load_config(args.config)}
    cfg = cfgs.get(args.provider)
    if not cfg:
        log.error("provider %s not enabled in %s", args.provider, args.config)
        return 2
    return 0 if toggle(cfg.endpoint, arm=False, timeout=args.timeout) else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    default_cfg = os.environ.get(
        "CLOUD_EDGE_TRAFFIC_CONFIG",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "endpoints.conf"))
    p.add_argument("--config", default=default_cfg,
                   help="endpoints file (KEY=VALUE); default: %(default)s")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help="per-request socket timeout seconds (default %(default)s)")
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("run", help="run the steady end-to-end traffic streams")
    r.set_defaults(func=cmd_run)

    b = sub.add_parser("boom", help="arm /boom on a provider (LB target-error, D<p>3)")
    b.add_argument("provider", choices=["aws", "azure", "gcp"])
    b.set_defaults(func=cmd_boom)

    h = sub.add_parser("heal", help="clear /boom on a provider (revert D<p>3)")
    h.add_argument("provider", choices=["aws", "azure", "gcp"])
    h.set_defaults(func=cmd_heal)
    return p


def main(argv: list[str]) -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        args.func = cmd_run  # bare invocation == run
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
