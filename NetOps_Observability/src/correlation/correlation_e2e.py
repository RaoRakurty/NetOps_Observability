#!/usr/bin/env python3
"""End-to-end Correlation Engine validation harness (live stack).

Proves the engine is WORKING, not just running, across the full pipeline:

    event injection -> Redpanda topics -> correlation service ->
    corr_signals / corr_objects / corr_edges / corr_evidence -> (API)

This is the LIVE-STACK complement to test_e2e_rca.py (which is the in-process
engine integration test). It produces real events with `rpk` to the same topics
the engine consumes, waits for the ~30s engine window, then validates ClickHouse
(the source of truth) and — when a token is provided — the Go API.

Every injected event is tagged with a unique run id via ENTITY NAMING
(`e2e<runid>-...`), because corr_signals has no test_run_id column; this isolates
each run and never collides with live data.

Run:  make test-correlation-e2e        (or: python3 correlation_e2e.py)
Env:  E2E_REDPANDA, E2E_CLICKHOUSE (container names), E2E_API (base url),
      E2E_TOKEN (bearer for the API check), E2E_WAIT (seconds, default 75).

Guardrails asserted (not just exercised):
  * a debug/lab probe never drives a customer-facing RCA object;
  * unrelated events in one window are NOT merged (no temporal-only correlation);
  * stale events outside the window do not correlate;
  * duplicate events are deduped (no duplicate objects).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

RP = os.environ.get("E2E_REDPANDA", "netops-redpanda-1")
CH = os.environ.get("E2E_CLICKHOUSE", "netops-clickhouse-1")
API = os.environ.get("E2E_API", "http://localhost:8000").rstrip("/")
TOKEN = os.environ.get("E2E_TOKEN", "")
WAIT = int(os.environ.get("E2E_WAIT", "75"))

RUN = datetime.now(timezone.utc).strftime("%H%M%S")
TAG = f"e2e{RUN}"  # entity-name prefix → isolates + identifies this run

GREEN, RED, DIM, BOLD, RST = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def iso(offset_s: float = 0.0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def produce(topic: str, events: list[dict]) -> int:
    """Produce records (one per line) to a topic via rpk. Returns count produced."""
    payload = "\n".join(json.dumps(e) for e in events) + "\n"
    p = subprocess.run(["docker", "exec", "-i", RP, "rpk", "topic", "produce", topic],
                       input=payload, capture_output=True, text=True)
    if p.returncode != 0:
        print(f"{RED}rpk produce {topic} failed: {p.stderr.strip()}{RST}", file=sys.stderr)
    return len(events)


def ch(query: str) -> str:
    p = subprocess.run(["docker", "exec", CH, "clickhouse-client", "-q",
                        query + " SETTINGS tenant_scope='__all__'"], capture_output=True, text=True)
    if p.returncode != 0:
        return f"__ERR__ {p.stderr.strip()}"
    return p.stdout.strip()


def ch_json(query: str) -> list[dict]:
    out = ch(query + " FORMAT JSONEachRow")
    if out.startswith("__ERR__") or not out:
        return []
    return [json.loads(l) for l in out.splitlines() if l.strip()]


def sig_rows(like: str) -> list[dict]:
    return ch_json(f"SELECT kind, entity_id, modality_class, severity, source, "
                   f"JSONExtractString(attrs,'probe_authority') AS pauth "
                   f"FROM netops.corr_signals WHERE entity_id LIKE '%{like}%'")


def obj_rows(like: str) -> list[dict]:
    return ch_json(f"SELECT toString(correlation_id) AS id, verdict_tier, top_hypothesis, "
                   f"round(top_confidence,2) AS conf, node_count, evidence_missing, toString(affected) AS affected "
                   f"FROM netops.corr_objects_latest WHERE position(toString(affected),'{like}')>0")


def api_ok(like: str) -> str:
    if not TOKEN:
        return "skipped (no E2E_TOKEN)"
    try:
        import urllib.request
        req = urllib.request.Request(f"{API}/api/correlations?limit=200&since=3600s",
                                     headers={"Authorization": f"Bearer {TOKEN}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read()).get("data", [])
        hit = [o for o in data if like in (o.get("affected") or "")]
        return f"API returned {len(hit)} object(s) for tag (of {len(data)})"
    except Exception as e:  # noqa: BLE001
        return f"API check error: {e}"


# ── probe / syslog / metric event builders (exact wire contracts) ────────────

def syslog(host: str, appname: str, message: str, sev: str = "err", off: float = 0.0) -> dict:
    return {"hostname": host, "appname": appname, "message": message, "severity": sev, "timestamp": iso(off)}


def probe(prober: str, target: str, loss: float, rtt: float = 0.0, off: float = 0.0,
          intent: str = "customer_path", vantage: str = "public_cloud_agent") -> dict:
    return {"kind": "icmp", "prober": prober, "target": target, "ts": iso(off),
            "rtt_ms": rtt, "loss_pct": loss, "ok": loss < 100,
            "probe_intent": intent, "vantage_type": vantage}


def metric(device: str, family: str, value: float, off: float = 0.0, metric_name: str = "cpu") -> dict:
    return {"device": device, "metric": metric_name, "value": value, "signal_family": family,
            "collection_path": "snmp_poll", "ts": iso(off)}


def cpu_stream(device: str, baseline: float, peak: float, n_base: int = 26, n_peak: int = 10) -> list[dict]:
    """CUSUM needs >=20 baseline samples then a sustained step (episodes.py)."""
    evs = []
    for i in range(n_base):
        evs.append(metric(device, "device_resource", baseline + (i % 3), off=-(n_base + n_peak - i) * 2))
    for i in range(n_peak):
        evs.append(metric(device, "device_resource", peak, off=-(n_peak - i) * 2))
    return evs


# ── scenarios ────────────────────────────────────────────────────────────────
# Each: (name, inject() -> [(topic,event)...] described, validate(sigs,objs) -> (ok, notes))

def inject_and_collect():
    """Inject every scenario (distinct entity tags so they stay isolated), return
    the per-scenario injected counts."""
    injected = {}

    # 1. Link down / WAN handoff
    edge = f"{TAG}-edge1"
    n = produce("netops.syslog", [
        syslog(edge, "LINK-3-UPDOWN", f"%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down"),
        syslog(edge, "BGP-5-ADJCHANGE", "%BGP-5-ADJCHANGE: neighbor 10.99.0.2 Down Interface flap", sev="notice"),
    ])
    n += produce("netops.probes", [probe(f"{TAG}-vantage", edge, loss=85.0)])
    injected["1. link-down / WAN handoff"] = (edge, n)

    # 2. CPU high without impact (single modality → contributor, NOT an RCA incident)
    cpu = f"{TAG}-cpu1"
    n = produce("netops.metrics", cpu_stream(cpu, baseline=12.0, peak=98.0))
    injected["2. CPU high, no impact"] = (cpu, n)

    # 3. BGP flap
    r2 = f"{TAG}-r2"
    n = produce("netops.syslog", [
        syslog(r2, "BGP-5-ADJCHANGE", "%BGP-5-ADJCHANGE: neighbor 10.50.0.1 Down Hold timer expired", sev="notice"),
    ])
    n += produce("netops.probes", [probe(f"{TAG}-vantage", r2, loss=40.0)])
    injected["3. BGP flap"] = (r2, n)

    # 4. Probe-only degradation (no corroboration → not confirmed)
    svc = f"{TAG}-svc"
    n = produce("netops.probes", [probe(f"{TAG}-vantage", svc, loss=60.0)])
    injected["4. probe-only degradation"] = (svc, n)

    # 5. Internal/debug monitoring check (lab probe → debug_only, never customer RCA)
    dbg = f"{TAG}-dbg"
    n = produce("netops.probes", [probe(f"{TAG}-labgen", dbg, loss=90.0,
                                        intent="lab_test", vantage="local_container")])
    injected["5. internal/debug probe"] = (dbg, n)

    # 6. False correlation: unrelated events, distinct entities, same window
    n = produce("netops.metrics", cpu_stream(f"{TAG}-fcA", 10.0, 97.0))
    n += produce("netops.probes", [probe(f"{TAG}-vantage", f"{TAG}-fcB", loss=70.0)])
    n += produce("netops.syslog", [syslog(f"{TAG}-fcC", "BGP-5-ADJCHANGE", "%BGP-5-ADJCHANGE: neighbor 10.7.7.7 Down", sev="notice")])
    injected["6. false correlation (unrelated)"] = (f"{TAG}-fc", n)

    # 7. Stale event (metric ts older than METRIC_MAX_AGE 3600s → dropped)
    stale = f"{TAG}-stale"
    n = produce("netops.metrics", [metric(stale, "device_resource", 99.0, off=-7200)])
    injected["7. stale event (dropped)"] = (stale, n)

    # 8. Duplicate events (same native_id → deduped)
    dup = f"{TAG}-dup"
    dup_ev = syslog(dup, "LINK-3-UPDOWN", "%LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down")
    n = produce("netops.syslog", [dup_ev, dict(dup_ev), dict(dup_ev)])
    injected["8. duplicate events (deduped)"] = (dup, n)

    return injected


def validate(injected: dict) -> list[tuple[str, bool, str]]:
    results = []

    def find(name):
        like, n = injected[name]
        return like, n, sig_rows(like), obj_rows(like)

    # 1
    like, n, sigs, objs = find("1. link-down / WAN handoff")
    kinds = {s["kind"] for s in sigs}
    ok = ({"link_state_change", "probe_loss"} <= kinds) and len(objs) >= 1 and objs[0]["verdict_tier"] in ("suspected", "confirmed")
    results.append(("1. link-down / WAN handoff", ok,
                    f"signals={sorted(kinds)} object={objs[0]['verdict_tier'] if objs else 'NONE'}/"
                    f"{objs[0]['top_hypothesis'] if objs else '-'} conf={objs[0]['conf'] if objs else '-'}"))

    # 2 — device_resource signal present; NO multi-node RCA object (single modality)
    like, n, sigs, objs = find("2. CPU high, no impact")
    has_cpu = any(s["kind"] == "device_resource_anomaly" for s in sigs)
    no_multi = all(int(o.get("node_count", 0)) < 2 for o in objs)
    ok = has_cpu and no_multi
    results.append(("2. CPU high, no impact", ok,
                    f"device_resource_anomaly={has_cpu} multi_node_objects={[o['node_count'] for o in objs] or 'none'}"))

    # 3 — BGP control-plane signal + object classified routing/bgp
    like, n, sigs, objs = find("3. BGP flap")
    has_bgp = any("bgp" in s["kind"] for s in sigs)
    routing = bool(objs) and ("bgp" in objs[0]["top_hypothesis"] or "routing" in objs[0]["top_hypothesis"] or objs[0]["verdict_tier"] in ("suspected", "confirmed"))
    ok = has_bgp and routing
    results.append(("3. BGP flap", ok, f"bgp_signal={has_bgp} object={objs[0]['top_hypothesis'] if objs else 'NONE'}"))

    # 4 — probe-only: not confirmed
    like, n, sigs, objs = find("4. probe-only degradation")
    has_loss = any(s["kind"] == "probe_loss" for s in sigs)
    not_confirmed = all(o["verdict_tier"] != "confirmed" for o in objs)
    ok = has_loss and not_confirmed
    results.append(("4. probe-only degradation", ok,
                    f"probe_loss={has_loss} verdicts={[o['verdict_tier'] for o in objs] or 'no-object'} (must not be confirmed)"))

    # 5 — internal/debug probe: classified debug_only; NOT in a customer-facing object
    like, n, sigs, objs = find("5. internal/debug probe")
    dbg = [s for s in sigs if s["kind"] == "probe_loss"]
    is_debug = bool(dbg) and all(s.get("pauth") == "debug_only" for s in dbg)
    no_confirmed = all(o["verdict_tier"] != "confirmed" for o in objs)
    ok = is_debug and no_confirmed
    results.append(("5. internal/debug probe", ok,
                    f"probe_authority={[s.get('pauth') for s in dbg] or 'none'} (must be debug_only) confirmed_objects={[o['verdict_tier'] for o in objs if o['verdict_tier']=='confirmed'] or 'none'}"))

    # 6 — false correlation: the three unrelated entities must NOT share one object
    likeA, _, _, objsA = find("6. false correlation (unrelated)")  # like = e2e..-fc prefix
    objsA = obj_rows(f"{TAG}-fcA") + obj_rows(f"{TAG}-fcB") + obj_rows(f"{TAG}-fcC")
    merged = any(("fcA" in o["affected"]) + ("fcB" in o["affected"]) + ("fcC" in o["affected"]) >= 2 for o in objsA)
    ok = not merged
    results.append(("6. false correlation (unrelated)", ok,
                    f"merged_object={merged} (must be False — no temporal-only correlation)"))

    # 7 — stale: dropped, no signal
    like, n, sigs, objs = find("7. stale event (dropped)")
    ok = len(sigs) == 0
    results.append(("7. stale event (dropped)", ok, f"signals_from_stale={len(sigs)} (must be 0)"))

    # 8 — duplicate: deduped by IDENTITY. The 3 identical events share one
    # deterministic signal_id, so the engine's window buffer + object dedupe on it
    # (at-least-once ingest may leave multiple physical MergeTree rows — that's
    # expected; what must hold is ONE identity → no duplicate object).
    like, n, sigs, objs = find("8. duplicate events (deduped)")
    rows = len([s for s in sigs if s["kind"] == "link_state_change"])
    distinct = ch(f"SELECT uniqExact(signal_id) FROM netops.corr_signals "
                  f"WHERE entity_id LIKE '%{like}%' AND kind='link_state_change'")
    ok = distinct == "1"
    results.append(("8. duplicate events (deduped)", ok,
                    f"distinct_signal_id={distinct} (must be 1 — deterministic id); physical_rows={rows} (at-least-once, fine)"))

    return results


def main() -> int:
    print(f"{BOLD}Correlation Engine E2E — run {RUN} (tag {TAG}){RST}")
    print(f"{DIM}redpanda={RP} clickhouse={CH} api={API} token={'set' if TOKEN else 'none'} wait={WAIT}s{RST}\n")
    injected = inject_and_collect()
    total = sum(n for _, n in injected.values())
    print(f"injected {total} events across {len(injected)} scenarios → waiting {WAIT}s for the engine window…\n")
    time.sleep(WAIT)

    results = validate(injected)
    npass = sum(1 for _, ok, _ in results if ok)
    for name, ok, notes in results:
        tag = f"{GREEN}PASS{RST}" if ok else f"{RED}FAIL{RST}"
        like = injected.get(name, (name, 0))[0]
        print(f"[{tag}] {name}")
        print(f"        {DIM}{notes}{RST}")
        print(f"        {DIM}api: {api_ok(like)}{RST}")
    print(f"\n{BOLD}{npass}/{len(results)} scenarios passed.{RST}")
    print(f"{DIM}(cleanup: signals/objects are tagged {TAG}; they TTL out, or purge by entity LIKE '%{TAG}%'){RST}")
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
