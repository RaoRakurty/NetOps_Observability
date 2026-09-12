#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Live end-to-end regression smoke — the metric/trap correlation path.

Proves, against the RUNNING stack (Layer 5 + the 5 critical tests), that the
finalized architecture is wired correctly — not by checking that a topic exists,
but by injecting FRESH, uniquely-tagged events through the real pipeline and
asserting the downstream signal actually appears:

  C1  Go-collector-shaped MetricEvent → Vector :8690 → netops.metrics →
      correlation → corr_signals (proves the live metric design path)
  C3  a metric ANOMALY sequence → a device_telemetry signal with CANONICAL
      identity (device:ifName), correct observer/modality/collection provenance
  C4  a linkDown trap → Vector :8688 → a control_plane signal bound to the same
      interface identity; an UNKNOWN trap → NO signal (the anti-noise guardrail)
  +   a malformed metric (missing identity) → DROPPED, never a signal

Each run uses a unique device id so its evidence is unambiguous and re-runnable.
Endpoints are resolved from the compose project (override with env). Exit 0 only
when every assertion holds.

  python3 scripts/regression_correlation_smoke.py
  python3 scripts/regression_correlation_smoke.py --json
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

PROJECT = os.environ.get("COMPOSE_PROJECT", "netops")
HERE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(HERE, "..", "deployment", "docker", ".env")

GREEN, RED, YEL, DIM, RST = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
if not sys.stdout.isatty():
    GREEN = RED = YEL = DIM = RST = ""

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    mark = f"{GREEN}PASS{RST}" if ok else f"{RED}FAIL{RST}"
    print(f"  [{mark}] {name}" + (f"  {DIM}— {detail}{RST}" if detail else ""))
    return ok


def docker_ip(container: str) -> str | None:
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", container],
            capture_output=True, text=True, timeout=15, check=False)
        ip = (out.stdout or "").split()
        return ip[0] if ip else None
    except Exception:  # noqa: BLE001 — best-effort probe: no IP is a normal answer
        return None


def read_env(key: str) -> str:
    try:
        with open(ENV_FILE) as fh:
            for ln in fh:
                if ln.startswith(key + "="):
                    return ln.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


def http_post(url: str, body: bytes, ctype: str) -> int:
    req = urllib.request.Request(url, data=body, headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except Exception as e:  # noqa: BLE001
        print(f"  {RED}POST {url} failed: {e}{RST}")
        return 0


def http_get_json(url: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.loads(r.read())
    except Exception:  # noqa: BLE001 — best-effort probe: empty doc is the degraded answer
        return {}


def iso(ts: float) -> str:
    # RFC3339 UTC from an epoch float (no tz libs needed).
    import datetime
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--timeout", type=float, default=40.0, help="seconds to await signals")
    args = ap.parse_args()

    vec = os.environ.get("VECTOR_URL") or (f"http://{docker_ip(f'{PROJECT}-vector-aggregator-1')}")
    ch_ip = docker_ip(f"{PROJECT}-clickhouse-1")
    ch = os.environ.get("CH_URL") or (f"http://{ch_ip}:8123" if ch_ip else "")
    corr_ip = docker_ip(f"{PROJECT}-correlation-1")
    corr = f"http://{corr_ip}:8000" if corr_ip else ""
    ch_user = os.environ.get("CH_USER") or read_env("CLICKHOUSE_USER") or "default"
    ch_pass = os.environ.get("CH_PASS") or read_env("CLICKHOUSE_PASSWORD") or ""
    if not vec or "None" in vec or not ch:
        print(f"{RED}FATAL: cannot resolve stack endpoints (run on the stack host).{RST}")
        return 2

    run_id = str(int(time.time()))
    device = f"smoke-{run_id}"
    ifname = "eth-smoke0"
    entity = f"{device}:{ifname}"
    print(f"{DIM}vector={vec} ch={ch} corr={corr} device={device}{RST}\n")

    def ch_query(sql: str) -> str:
        req = urllib.request.Request(
            ch + "/", data=(sql + " SETTINGS tenant_scope='__all__'").encode(),
            headers={"X-ClickHouse-User": ch_user, "X-ClickHouse-Key": ch_pass})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.read().decode().strip()
        except Exception as e:  # noqa: BLE001
            return f"__ERR__ {e}"

    def await_signal(where: str) -> dict | None:
        deadline = time.time() + args.timeout
        sql = ("SELECT observer_type, modality_class, collection_path, entity_type, "
               f"entity_id, kind, source FROM netops.corr_signals WHERE {where} "
               "ORDER BY ts DESC LIMIT 1 FORMAT JSONEachRow")
        while time.time() < deadline:
            out = ch_query(sql)
            if out and not out.startswith("__ERR__"):
                return json.loads(out.splitlines()[0])
            time.sleep(2)
        return None

    metrics_dropped_before = http_get_json(corr + "/healthz").get("ingest", {}).get("metrics_dropped", 0)

    # ── C1+C3: metric anomaly → canonical device_telemetry signal ─────────────
    print("C1/C3 — metric anomaly → device_telemetry signal (canonical identity)")
    now = time.time()
    base, anomaly = [], []
    # 24 jittered baseline samples (std>0) then a large step → CUSUM onset.
    for i in range(24):
        base.append({
            "observer_type": "device", "modality_class": "device_telemetry",
            "collection_path": "snmp_poll", "device": device, "vendor": "smoke",
            "if_name": ifname, "index": "1", "signal_family": "interface",
            "metric": "device_if_in_errors", "value": 10 + (i % 3), "unit": "errors",
            "ts": iso(now - (30 - i) * 2),
        })
    for j in range(4):
        anomaly.append({**base[-1], "value": 100000 + j, "ts": iso(now - 1 + j * 0.1)})
    ndjson = ("\n".join(json.dumps(e) for e in base + anomaly) + "\n").encode()
    sent_ok = http_post(vec + ":8690/", ndjson, "application/x-ndjson") in (200, 204)
    check("MetricEvent batch accepted by Vector :8690", sent_ok)
    sig = await_signal(f"entity_id='{entity}' AND modality_class='device_telemetry'")
    check("device_telemetry signal appeared in corr_signals", sig is not None,
          json.dumps(sig) if sig else "no signal within timeout")
    if sig:
        check("signal carries canonical provenance + identity",
              sig.get("observer_type") == "device"
              and sig.get("modality_class") == "device_telemetry"
              and sig.get("collection_path") == "snmp_poll"
              and sig.get("entity_type") == "interface"
              and sig.get("entity_id") == entity,
              f"observer={sig.get('observer_type')} modality={sig.get('modality_class')} "
              f"path={sig.get('collection_path')} entity={sig.get('entity_id')}")

    # ── C4: linkDown trap → control_plane signal; unknown trap → none ─────────
    print("\nC4 — trap normalization (classified → signal, unknown → none)")
    link_trap = {
        "_signal": "snmptrap", "timestamp": iso(now), "device": device,
        "host": "203.0.113.9", "snmp_version": "2c", "authenticated": False,
        "trap_oid": "1.3.6.1.6.3.1.1.5.3", "trap_name": "linkDown", "severity": "warning",
        "varbinds": [{"oid": "1.3.6.1.2.1.31.1.1.1.1.1", "value": ifname}],
    }
    http_post(vec + ":8688/", (json.dumps(link_trap) + "\n").encode(), "application/json")
    tsig = await_signal(f"entity_id='{entity}' AND source='trap' AND kind='link_state_change'")
    check("linkDown trap → control_plane signal (bound to interface)", tsig is not None,
          f"entity={tsig.get('entity_id')} modality={tsig.get('modality_class')}" if tsig else "none")

    unknown_trap = {**link_trap, "trap_oid": "1.3.6.1.4.1.9.9.999.0.7",
                    "trap_name": "enterpriseSpecific", "varbinds": []}
    drop_before = http_get_json(corr + "/healthz").get("ingest", {}).get("traps_dropped", 0)
    http_post(vec + ":8688/", (json.dumps(unknown_trap) + "\n").encode(), "application/json")
    time.sleep(5)
    drop_after = http_get_json(corr + "/healthz").get("ingest", {}).get("traps_dropped", 0)
    check("unknown trap dropped (no RCA signal)", drop_after > drop_before,
          f"traps_dropped {drop_before}→{drop_after}")

    # ── malformed metric → dropped, never a signal ───────────────────────────
    print("\nGuardrail — malformed metric dropped, never a signal")
    bad = {"observer_type": "device", "modality_class": "device_telemetry",
           "signal_family": "interface", "metric": "device_if_in_errors", "value": 5}  # no device
    http_post(vec + ":8690/", (json.dumps(bad) + "\n").encode(), "application/x-ndjson")
    time.sleep(5)
    dropped_after = http_get_json(corr + "/healthz").get("ingest", {}).get("metrics_dropped", 0)
    check("malformed metric increments metrics_dropped", dropped_after > metrics_dropped_before,
          f"metrics_dropped {metrics_dropped_before}→{dropped_after}")

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    if args.json:
        print(json.dumps({"passed": passed, "total": total,
                          "results": [{"name": n, "ok": ok, "detail": d} for n, ok, d in results]}))
    else:
        verdict = f"{GREEN}ALL PASS{RST}" if passed == total else f"{RED}{total - passed} FAILED{RST}"
        print(f"\n  {verdict}  ({passed}/{total})")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
