"""Wire-payload builders + bus injector (tracker 152, design §4 — T1 core).

T1-CORE lanes only: syslog, probes, cloud, metrics — all injected bus-direct
via the broker's console producer over the TLS listener (the PROVEN
`correlation_e2e.py` / mini-ladder path). SNMP agents, traps-over-UDP, IPFIX
and gNMI are a LATER wave; attribution here rides the per-NAME registry rows
(`hostname` fallback mode, design §3.4) — every hostname / probe target /
metric device / cloud resource carries the `twx-<runid>-` prefixed name, which
is also what makes verified teardown (purge by entity LIKE) possible.

Every payload is byte-shaped after the live-proven builders in
`src/correlation/correlation_e2e.py` (syslog / probe / metric) and the
`cloud_producers.cloud_signal_from_event` wire contract (cloud). The injector
KEYS every record by the owning tenant's opaque id so the Java-murmur2
partitioner contract holds (design §6 — unkeyed injection would void the
partition-spread proof).
"""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone

from stack import Stack, log

LANE_TOPIC = {
    "syslog": "netops.syslog",
    "probes": "netops.probes",
    "metrics": "netops.metrics",
    "cloud": "netops.cloud",
}


def iso(offset_s: float = 0.0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_s)
            ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def build_payload(item: dict, prefix: str, tenant_ids: dict[str, str]) -> str:
    """One schedule item (stories.py shape) → the wire JSON string.

    `prefix` is the run's `twx-<runid>-`; `tenant_ids` maps scenario aliases →
    real opaque tenant ids (cloud events carry the tenant EXPLICITLY — the
    engine drops untenanted cloud events by design)."""
    lane = item["lane"]
    if lane == "syslog":
        return json.dumps({
            "hostname": prefix + item["device"],
            "appname": item["appname"],
            "message": item["message"],
            "severity": item["severity"],
            "timestamp": iso(),
        })
    if lane == "probes":
        loss = float(item["loss_pct"])
        return json.dumps({
            "kind": "icmp",
            "prober": prefix + item["prober"],
            "target": prefix + item["device"],
            "ts": iso(),
            "rtt_ms": float(item.get("rtt_ms") or 0.0),
            "loss_pct": loss,
            "ok": loss < 100,
            "probe_intent": item["probe_intent"],
            "vantage_type": item["vantage_type"],
        })
    if lane == "metrics":
        return json.dumps({
            "device": prefix + item["device"],
            "metric": item.get("metric", "cpu"),
            "value": float(item["value"]),
            "signal_family": item["signal_family"],
            "collection_path": "snmp_poll",
            "ts": iso(float(item.get("ts_off") or 0.0)),
        })
    if lane == "cloud":
        return json.dumps({
            "kind": item["kind"],
            "tenant_id": tenant_ids[item["tenant"]],
            "resource_id": prefix + item["resource_id"],
            "account": item["account"],
            "region": item["region"],
            "severity": item["severity"],
            "value": float(item.get("value") or 0.0),
            "metric_name": item.get("metric_name") or "",
            "ts": iso(),
        })
    raise ValueError(f"unknown lane {lane!r} — T1 core supports "
                     f"{sorted(LANE_TOPIC)}")


class Injector:
    """Paced, journaled injection of a deterministic plan.

    Chunks due items every `tick_s`, groups per topic, produces each group
    KEYED by tenant id, journals every produced event to events.jsonl and
    tallies per-lane / per-tenant counts (the emission-side half of the
    design's accounting). Produce failures are counted AND fatal after a small
    tolerance — a run that cannot inject honestly has no verdict."""

    def __init__(self, stack: Stack, prefix: str, tenant_ids: dict[str, str],
                 journal_path: str, tick_s: float = 5.0):
        self.stack = stack
        self.prefix = prefix
        self.tenant_ids = tenant_ids
        self.journal_path = journal_path
        self.tick_s = tick_s
        self.emitted: dict[str, int] = {}          # lane -> count
        self.emitted_by_tenant: dict[str, dict[str, int]] = {}  # lane->tenant->n
        self.emitted_by_story: dict[str, dict[str, int]] = {}   # story->lane->n
        self.produce_failures: list[str] = []

    def _journal(self, fh, item: dict, payload: str) -> None:
        fh.write(json.dumps({
            "ts": iso(),
            "lane": item["lane"],
            "topic": LANE_TOPIC[item["lane"]],
            "story_id": item.get("story_id"),
            "device": self.prefix + item["device"],
            "tenant": item["tenant"],
            "payload_digest": hashlib.sha256(payload.encode()).hexdigest()[:16],
        }) + "\n")

    def emit_batch(self, items: list[dict], fh) -> bool:
        """Produce one due batch. Returns False when failures exceed
        tolerance (caller aborts the emission loop loudly)."""
        by_topic: dict[str, list[tuple[str, str, dict]]] = {}
        for it in items:
            payload = build_payload(it, self.prefix, self.tenant_ids)
            key = self.tenant_ids[it["tenant"]]
            by_topic.setdefault(LANE_TOPIC[it["lane"]], []).append(
                (key, payload, it))
        for topic, rows in sorted(by_topic.items()):
            ok, err = self.stack.produce_keyed(
                topic, [(k, p) for k, p, _ in rows])
            if not ok:
                self.produce_failures.append(f"{topic}: {err}")
                if len(self.produce_failures) >= 3:
                    return False
                continue
            for _k, payload, it in rows:
                self.emitted[it["lane"]] = self.emitted.get(it["lane"], 0) + 1
                lt = self.emitted_by_tenant.setdefault(it["lane"], {})
                lt[it["tenant"]] = lt.get(it["tenant"], 0) + 1
                sid = it.get("story_id")
                if sid:
                    ls = self.emitted_by_story.setdefault(sid, {})
                    ls[it["lane"]] = ls.get(it["lane"], 0) + 1
                self._journal(fh, it, payload)
        return True

    def run_schedule(self, items: list[dict], t_start: float,
                     ground_truth_cb=None,
                     heartbeat_cb=None) -> bool:
        """Emit `items` (sorted by relative t) paced against wall clock
        anchored at `t_start` (time.monotonic value). Returns overall
        success. `ground_truth_cb(story_id)` fires when a story's FIRST event
        is emitted (records fired-at)."""
        idx = 0
        fired: set[str] = set()
        with open(self.journal_path, "a", encoding="utf-8") as fh:
            while idx < len(items):
                now_rel = time.monotonic() - t_start
                due = []
                while idx < len(items) and items[idx]["t"] <= now_rel:
                    due.append(items[idx])
                    idx += 1
                if due:
                    for it in due:
                        sid = it.get("story_id")
                        if sid and sid not in fired and ground_truth_cb:
                            fired.add(sid)
                            ground_truth_cb(sid)
                    if not self.emit_batch(due, fh):
                        log(f"ABORTING emission: {len(self.produce_failures)} "
                            f"produce failures (first: "
                            f"{self.produce_failures[0][:160]})")
                        return False
                    fh.flush()
                if heartbeat_cb:
                    heartbeat_cb()
                if idx < len(items):
                    ahead = items[idx]["t"] - (time.monotonic() - t_start)
                    if ahead > 0:
                        time.sleep(min(ahead, self.tick_s))
        return not self.produce_failures
