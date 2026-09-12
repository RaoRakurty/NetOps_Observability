# Metrics & performance standards alignment

Where our telemetry stands against the relevant standards, and the gaps. Goal:
performance metrics that are standards-grade so correlation/automation can trust
them.

## Standards mapping

| Signal | Standard | Our source today | Status |
|---|---|---|---|
| Interface octets/errors/discards/pkts | **SNMP IF-MIB** (RFC 2863), 64-bit ifHC* | SNMP poll (`snmp_profiles.json`, `ifHCInOctets`/`ifHCOutOctets`/`ifInErrors`…) | ✅ compliant |
| BGP/OSPF session/adjacency state | BGP4-MIB / OSPF-MIB (IETF) | SNMP poll (added build-order Phase 3) | ✅ compliant |
| One-way delay | **RFC 2679 / 7679** | — (overlay latency from the tunnel collector is round-trip-ish, vendor-derived) | ❌ needs active probe + synced clocks |
| One-way packet loss | **RFC 2680** | tunnel `loss_pct` (vendor) | ⚠️ partial — not IPPM one-way |
| Packet delay variation (jitter) | **RFC 3393** | tunnel `jitter_ms` | ⚠️ partial |
| Delay variation (IPDV/PDV) | **RFC 5481** | — | ❌ needs active probe |
| Advanced perf framework | **RFC 7312** | — | ❌ (informational framework) |
| Metric/label naming | **OpenTelemetry semconv** | custom `device_*` names | ⚠️ could align (`network.io.*`, `net.*`) |
| Service performance objectives | **MEF** (e.g. MEF 10.x) | — | ❌ |
| Streaming telemetry paths | **OpenConfig** | gNMI collector can consume OC paths | ⚠️ partial (Tier-2) |

**The honest gap:** true IPPM one-way metrics (RFC 2679/2680/3393/5481) require
**active, two-point, time-synchronized measurement** — i.e. the active-probe
pipeline (Flow Trace / Network Path, build-order #12). Our current
latency/jitter/loss come from the overlay/tunnel collector and SNMP, which are
useful but not IPPM one-way. So: SNMP-counter metrics are standards-compliant
today; one-way path metrics become RFC-grade when the probe pipeline lands, and
that pipeline will be built to emit RFC-2679/2680/3393/5481 metrics directly.

## Path Health composite (implemented)

Per the spec:

```
Path Health = 40% packet loss + 30% latency + 20% jitter + 10% route stability
```

Each component is scored 0–100 against thresholds (ITU-T G.1010 / MEF-aligned
defaults; configurable later), then weighted:

| Component | 100 (good) | 0 (bad) | Weight |
|---|---|---|---|
| Packet loss | 0% | ≥ 3% | 0.40 |
| Latency | ≤ 50 ms | ≥ 300 ms | 0.30 |
| Jitter (PDV) | ≤ 10 ms | ≥ 60 ms | 0.20 |
| Route stability | stable ≥ 1 h | flapped < 5 min | 0.10 |

`health = 0.4·lossScore + 0.3·latScore + 0.2·jitterScore + 0.1·stabilityScore`,
clamped 0–100. Tone: ≥ 80 healthy · ≥ 60 degraded · < 60 unhealthy.

**v1 inputs** (Quality board, overlay/tunnel paths): loss/latency/jitter from the
tunnel collector; route stability proxied from tunnel uptime (transitions once
the probe pipeline supplies route changes). **v2**: recompute on RFC-grade
one-way measurements from the active-probe pipeline; extend "route stability" to
BGP/OSPF flap counts (`device_bgp_fsm_transitions`, `changes(device_ospf_nbr_state)`)
and interface flaps (`changes(device_if_oper_status)`).

See [[build-order]] · [[device-monitoring-dashboards]].
