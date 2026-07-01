# WAN Measurement Source Ranking (5-tier)

Status: SHIPPED 2026-07-01. Replaces the old "STAMP-first fidelity ladder" for
computing WAN circuit metrics (latency, jitter, loss, QoE, availability).

## Principle

Rank a metric's source by **proximity to the user / application experience**, not
by protocol precision. What the application actually experienced is the most
authoritative SLA number; a device-native probe is precise but a step removed; a
flow-derived indicator is only an inference. Highest tier with data for a
destination wins that field (per field, first-with-data-wins).

## Tiers

| Tier | Class | Sources |
|------|-------|---------|
| **1** | Application / user experience | HTTP synthetic · DNS synthetic · TLS handshake · RUM · DB transaction probe |
| **2** | Agent-to-agent active path probes | ICMP/UDP/TCP · custom timestamped UDP · TCP connect · HTTP-through-path (our wan-echo, synthetic ICMP, synthetic TCP-connect, traceroute) |
| **3** | Device-native active probes | STAMP · TWAMP · OWAMP · IP SLA · RPM |
| **4** | Passive network telemetry | iface drops/errors · queue drops · tunnel stats · firewall drops · SD-WAN path stats · BGP/OSPF/ISIS state |
| **5** | Flow-derived indicators | TCP retransmits · retry rates · byte/packet deltas · app-to-DB degradation · east-west anomalies |

**Key change vs. the old design:** agent probes (Tier 2) now outrank STAMP
(Tier 3), and app synthetics (Tier 1) outrank both. The old ladder put STAMP first.

## Implementation

`src/backend/path_metric_resolver.go` is the one resolver every surface reads
(path-health API, topology path-trace, WAN circuit table).

- `MeasurementTier` (1..5) + `PathSource.Tier()` map every method to its rank by
  protocol. `PathSource.Label()` (method) + `TierLabel()` (rank) drive provenance.
- `resolveCurrentByDst` runs the tier cascade per field via `fold` + a setter; a
  dst already filled by a higher tier is left untouched.
- **Availability** is a new metric: % of the window the path was reachable
  (distinct from loss — a path can be 100% available but lossy). Derived from
  `synthetic_up{check}` (T1/T2), echo `circuit_recv>0` (T2), STAMP `probe_recv>0`
  (T3). Interface oper-status availability is carried at the row level (OperUp).
- Sources with no collector yet (RUM, DB probe, DNS/TLS as standalone, UDP-timestamped,
  TWAMP, OWAMP, IP SLA, RPM, tunnel/firewall/SD-WAN/routing as SLA, flow-derived)
  are declared in the taxonomy so provenance is complete and future collectors
  slot in by tier — but emit no query today.

### Source → metric → tier (wired today)

| Tier | Source | Latency | Jitter | Loss | Availability | QoE |
|------|--------|---------|--------|------|--------------|-----|
| 1 | HTTP synthetic | `synthetic_http_total_ms` | — | `1-synthetic_up{http}` | `synthetic_up{http}` | — |
| 2 | wan-echo | `circuit_latency_ms` | `circuit_jitter_ms` | `circuit_loss_pct` | `circuit_recv>0` | `circuit_qoe` |
| 2 | synthetic ICMP | `synthetic_icmp_rtt_ms` | — | `synthetic_icmp_loss_pct` | `synthetic_up{icmp}` | — |
| 2 | synthetic TCP | `synthetic_tcp_connect_ms` | — | — | `synthetic_up{tcp}` | — |
| 2 | traceroute | `probe_hop_rtt_ms{tcp}` | — | `1-probe_path_reached{tcp}` | — | — |
| 3 | STAMP | `probe_rtt_ms` | `probe_pdv_ms` | `probe_loss_pct` | `probe_recv>0` | — |

## Provenance surface

`ResolvedPathMetric` carries per-field sources + availability; `WanInterfaceRow`
exposes `source`/`source_label`/`tier`/`tier_label`/`availability_pct`. The WAN
Interface Metrics table renders an **Availability** column and a tier chip (T1..T5)
+ method in **Measured by**.

## Per-interface measurement targets (no hub/spoke — 2026-07-01)

The earlier SD-WAN hub-and-spoke circuit-mesh model was **removed entirely**
(no `WanRole`, no topology-policy hubs, no `wanMesh`). Every WAN interface is
measured on its own, to a **target derived per interface** (`wan_circuits.go`,
`wanDeriveTarget`), ranked first-wins:

1. **Operator next-hop override** — `WanMeasurementPolicy.NextHops[device]` or
   `[device/ifName]`. The prod ISP next-hop when you know it.
2. **Directly-connected peer** — the LLDP/CDP neighbor's interface IP
   (`FetchTopologyLinks` joined to the interface-IP table). This is the lab case
   (WAN router ⇄ Spine) and any internal point-to-point link.
3. **Reachability anchor** — a public-DNS anchor (`Anchors`, default `1.1.1.1`,
   `8.8.8.8`). The prod internet-facing case where the ISP speaks no LLDP: you
   measure internet reachability to a well-known anchor.

**Interface scope** = every interface on a WAN-pattern device (`wan|edge|gw|dmz`)
**plus** every interface directly connected to a WAN device (gated by
`include_connected`, default true). That is what makes the lab correct: the WAN
router's interfaces **and** the Spine's interface toward it are both measured.

The SLA (latency/jitter/loss/QoE/**availability**) is then resolved for the
derived target host through the 5-tier ranking above — identical provenance
everywhere. The echo collector probes the published per-interface targets.
