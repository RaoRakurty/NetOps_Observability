"""Partition-spread measurement (tracker 152, design §6 — closing G-1).

During the run the twin samples the correlation group's per-partition consumed
offsets (`kafka-consumer-groups.sh --describe`, the mini-ladder's proven lag
tooling) and each replica's `/healthz` partition assignment. Afterwards it
joins three facts:

  1. COMPUTED tenant→partition placement (murmur2 over the real tenant ids —
     the exact producer keying contract, murmur.py);
  2. the run's own per-tenant emitted counts on the measured lane (from the
     emission journal — equal-per-tenant by scenario construction);
  3. the MEASURED per-partition consumed-offset deltas per replica.

Balance gate (design §6): every replica's observed consumed share must sit
within ±20% (relative) of its expected share, and no partition with expected
traffic may starve. Absolute offsets include the canary and any organic
traffic — the report carries the raw numbers so the verdict is auditable.
"""
from __future__ import annotations

import json
import time

from stack import Stack, warn

MEASURED_TOPIC = "netops.syslog"   # the equal-per-tenant baseline lane
GROUP = "netops-correlation"
TOLERANCE = 0.20


class SpreadSampler:
    """Bounded periodic sampler; call sample() from the emission loop."""

    def __init__(self, stack: Stack, path: str, every_s: float = 30.0):
        self.stack = stack
        self.path = path
        self.every_s = every_s
        self._last = 0.0
        self.samples: list[dict] = []

    def sample(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and (now - self._last) < self.every_s:
            return
        self._last = now
        g = self.stack.group_partitions(GROUP)
        parts = g.get(MEASURED_TOPIC, {})
        row = {"t_mono": round(now, 1),
               "members": g.get("_members", 0),
               "lag_total": g.get("_total", -1),
               "partitions": {str(p): dict(v) for p, v in parts.items()}}
        self.samples.append(row)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")


def organic_rates(samples: list[dict]) -> dict[int, float]:
    """Per-partition ORGANIC consumed rate (events/s) from a pre-run sample
    window. The lab stack's own syslog is untenanted → keyed "global" → ONE
    partition (murmur2("global") % P), measured live at ~3 ev/s on this rig —
    left uncorrected it would swamp that partition's twin delta and fail the
    ±20% gate spuriously. Assumed steady across the run; the report carries
    the estimate so the correction is auditable."""
    if len(samples) < 2:
        return {}
    first, last = samples[0], samples[-1]
    window = max(last["t_mono"] - first["t_mono"], 1e-9)
    rates: dict[int, float] = {}
    for p, v in last["partitions"].items():
        c0 = int(first["partitions"].get(p, {}).get("current", -1))
        c1 = int(v.get("current", -1))
        if c0 >= 0 and c1 >= 0:
            rates[int(p)] = (c1 - c0) / window
    return rates


def replica_assignment(stack: Stack) -> dict[str, list[int]]:
    """replica short-cid → owned partitions of the measured topic."""
    out: dict[str, list[int]] = {}
    for cid, h in stack.corr_healthz_all().items():
        if "_error" in h:
            warn(f"replica {cid} healthz unreachable during spread capture: "
                 f"{h['_error']}")
            continue
        parts = h.get("consumer", {}).get("assignment", {}).get(
            MEASURED_TOPIC, [])
        out[cid] = sorted(int(p) for p in parts)
    return out


def spread_report(samples: list[dict], assignment: dict[str, list[int]],
                  tenant_partitions: dict[str, int],
                  emitted_by_tenant: dict[str, int],
                  organic: dict[int, float] | None = None) -> dict:
    """Join samples + assignment + computed placement → the ±20% verdict.

    `organic`: pre-run per-partition organic rates (organic_rates()); their
    contribution over the window is subtracted from the raw deltas before the
    balance gate. Raw AND corrected deltas are reported."""
    if len(samples) < 2:
        return {"status": "FAIL",
                "problems": [(f"only {len(samples)} offset samples captured "
                              f"— cannot measure a spread")],
                "samples": len(samples)}
    first, last = samples[0], samples[-1]
    window = last["t_mono"] - first["t_mono"]
    raw_deltas: dict[int, int] = {}
    deltas: dict[int, int] = {}
    for p, v in last["partitions"].items():
        c0 = int(first["partitions"].get(p, {}).get("current", -1))
        c1 = int(v.get("current", -1))
        pi = int(p)
        if c0 >= 0 and c1 >= 0:
            raw_deltas[pi] = c1 - c0
            correction = (organic or {}).get(pi, 0.0) * window
            deltas[pi] = max(round(raw_deltas[pi] - correction), 0)
        else:
            raw_deltas[pi] = -1
            deltas[pi] = -1

    total_emitted = sum(emitted_by_tenant.values())
    expected_by_partition: dict[int, int] = {}
    for tenant, n in emitted_by_tenant.items():
        part = tenant_partitions[tenant]
        expected_by_partition[part] = expected_by_partition.get(part, 0) + n

    problems: list[str] = []
    starved = [p for p, exp in expected_by_partition.items()
               if exp > 0 and deltas.get(p, -1) == 0]
    if starved:
        problems.append(f"partition(s) {sorted(starved)} expected traffic but "
                        f"consumed ZERO — starved")

    total_delta = sum(d for d in deltas.values() if d > 0)
    replicas = []
    for cid, parts in sorted(assignment.items()):
        exp = sum(expected_by_partition.get(p, 0) for p in parts)
        obs = sum(max(deltas.get(p, 0), 0) for p in parts)
        exp_share = exp / total_emitted if total_emitted else 0.0
        obs_share = obs / total_delta if total_delta else 0.0
        within = True
        if exp_share > 0:
            within = abs(obs_share - exp_share) <= TOLERANCE * exp_share
            if not within:
                problems.append(
                    f"replica {cid} consumed share {obs_share:.3f} vs expected "
                    f"{exp_share:.3f} — outside ±{TOLERANCE:.0%}")
        replicas.append({"replica": cid, "partitions": parts,
                         "expected_events": exp, "consumed_delta": obs,
                         "expected_share": round(exp_share, 4),
                         "observed_share": round(obs_share, 4),
                         "within_tolerance": within})

    return {
        "status": "PASS" if not problems else "FAIL",
        "problems": problems,
        "topic": MEASURED_TOPIC,
        "tolerance": TOLERANCE,
        "samples": len(samples),
        "window_s": round(samples[-1]["t_mono"] - samples[0]["t_mono"], 1),
        "tenant_partitions": dict(sorted(tenant_partitions.items())),
        "emitted_by_tenant": dict(sorted(emitted_by_tenant.items())),
        "expected_by_partition": {str(k): v for k, v in
                                  sorted(expected_by_partition.items())},
        "consumed_delta_by_partition_raw": {str(k): v for k, v in
                                            sorted(raw_deltas.items())},
        "organic_rate_by_partition": {str(k): round(v, 3) for k, v in
                                      sorted((organic or {}).items())},
        "consumed_delta_by_partition": {str(k): v for k, v in
                                        sorted(deltas.items())},
        "replicas": replicas,
        "note": ("consumed deltas are group-committed offsets on the measured "
                 "topic; raw deltas include the canary + organic traffic, the "
                 "gated deltas subtract the pre-run organic rate estimate; "
                 "expected counts are the run's own journaled emissions"),
    }
