# Path-Causality RCA — discover the path, then find the broken link

**Owner direction (2026-07-16):** RCA's job is to correlate **network issues ↔ app
issues**. Any device on the way (WAF, LB, firewall, DNS, tunnel, router) is just a
device **on the traffic path** and must be included in RCA *when it's on the path*.
Real-world flows are never exactly as we'd draw them — we need the **essence**.
Therefore: **discovering the devices along SRC→DST is one of the EARLIEST steps,
before concluding RCA.** We must not statically define how seams connect — there
are numerous ways — we **discover** them and **classify** segments by **pattern**
(cloud vs LAN vs WAN vs DC …).

This inverts the usual model. We don't start from a fixed topology and check
health. We start from a **symptom at a destination**, **discover the path** the
affected traffic takes, **classify each segment**, then **walk the path to find the
broken link**. The path is the correlation substrate.

---

## 1. The model in one line
> **Incident = a symptom at a DST, caused by a broken link on the SRC→DST path.
> RCA = discover that path (typed by segment), then attribute to the on-path device
> whose fault best explains the symptom.**

A device fault (LB 5xx, WAF block, FW reject, DNS NXDOMAIN, tunnel down, interface
down) is only a root cause **if it lies on the path between the affected SRC and
DST**. Off-path faults are coincidence, not cause. That single rule is what turns
"saas-experience-degraded, suspected" into "LB `x` 5xx on the client→app path,
confirmed."

## 2. Four stages (discovery precedes conclusion)
1. **Observe SRC→DST relationships** from whatever telemetry exists — never assume:
   flow logs / NetFlow / IPFIX / VPC flow (5-tuples), path-trace / traceroute
   (hop-by-hop, incl. the STAMP work), synthetic probes (vantage→target), DNS
   resolution chains, cloud inventory edges (LB→backend, WAF↔LB, SG↔subnet↔host),
   device telemetry (interfaces, routes, BGP/BFD, CDP/LLDP neighbors).
2. **Classify each hop/segment by PATTERN** → segment *type* + device *role*
   (§3). This is the "cloud vs LAN vs WAN vs DC" step. Rules-driven and extensible,
   never a hardcoded map.
3. **Assemble the typed causal path (the ESSENCE)** — the ordered sequence of
   segment transitions and the *key* devices on each. We do NOT require exact
   hop-by-hop fidelity; we require the right abstraction: e.g.
   `client(LAN) → leaf/spine(DC) → edge → WAN → cloud(DNS→WAF→LB→FW→app)`.
4. **RCA = walk the path, find the broken link.** For an app symptom, walk SRC→DST;
   the on-path device carrying a fault signal in the incident window, closest to the
   break, is the probable cause. Confidence rises with on-path corroboration across
   planes; stays *suspected* when the path is partially unknown (honesty rule).

## 3. Pattern-based segment/device classification (the heart of it)
We can't enumerate every topology, so we **recognize** segments by matching
observable patterns. A segment inherits a **type** and each node a **role**:

| Evidence / pattern | → classifies as |
|---|---|
| RFC1918 space + fabric neighbors (CDP/LLDP), switch/router roles | **LAN / DC fabric** |
| Cloud-provider published CIDRs; resource has `provider=aws/azure/gcp`, region/AZ | **CLOUD** |
| Transit ASN / public next-hop / CGNAT; internet egress on the flow | **WAN / Internet** |
| IPsec/GRE/SD-WAN/NVA/DX/ExpressRoute/VPN-GW device or tunnel telemetry | **WAN seam** (site↔site / on-prem↔cloud) |
| Device role = LB / WAF / firewall / DNS resolver | on-path **service device** (belongs to whichever segment hosts it) |
| Hostname/tag/role-prefix patterns (`web01`, `payments-api`, `edge-fw`) | role hint (weak alone; corroborates) |

Rules: **default-closed** (unknown pattern → `unknown` segment, never guessed as
healthy or as a specific type); **multi-signal** (a lone hostname is weak — the same
`service_infer` discipline already in the codebase); **extensible** (new provider
CIDR sets, new device families, new seam types are data, not code rewrites).

## 4. Why "essence," not exact hops
Two runs of the same service rarely traverse identical hops (ECMP, failover, NAT,
proxies, cloud frontends). RCA doesn't need the exact hops — it needs the
**segment-type sequence + the key devices** so it can reason: *"the break is at the
CLOUD segment's WAF, not the LAN."* We collapse hop noise into typed segments; the
causal claim lives at the segment/device level, which is stable across runs.

## 5. Cloud Service View — how it should look (item 1)
The view is a **path-first RCA surface**, not a device inventory:
- **Per service/app: the discovered SRC→DST path(s)**, drawn as typed segments
  (distinct treatment per CLOUD / LAN / WAN / DC / WAN-seam), with the key on-path
  devices labeled by role (DNS · WAF · LB · FW · app for cloud; client · leaf ·
  spine · edge for LAN; NVA · tunnel for WAN).
- **Live health per segment/device**; during an incident the **broken link is
  highlighted** and the path shows where causality snaps.
- **RCA reads as path causality**: "client→app broke at CLOUD/WAF (block rule X)"
  with the device's own fault signal + log as inline evidence.
- **Device logs in path context** — clicking a device on the path opens its logs
  (ties to the family-tagged unified Cloud Logs lane: DNS/WAF/LB/FW/flow).
- **Discovery status is honest**: segments we couldn't classify render `unknown`
  with the reason; a partial path caps the verdict at suspected.
This is the same surface for cloud, LAN, WAN, DC — the *path* is the unifier, which
is exactly the network↔app correlation goal.

## 5a. IA — what belongs in the Cloud Service View, what doesn't (item 2)
Principle: the Cloud Service View answers ONE question — **"what broke on the way
from the user to the app?"** So it holds the **path + RCA + health**, and everything
raw / setup / inventory-heavy lives elsewhere and is **linked from the path**, not
hosted here.

**Belongs IN the Cloud Service View:**
- **Overview** — degraded services + open **path-causality investigations**
  (network↔app), honest data-readiness (are the path-feeding sources flowing).
- **Service → its discovered SRC→DST path(s)** — segment-typed, per-device health,
  broken-link highlighted. This is the centerpiece.
- **Investigations** — RCA as path causality (which link broke, on which segment,
  why), with the on-path device's fault signal + log inline.
- **Device-in-path drill** — a device's key signals/logs *in path context* (opens
  the family-tagged Cloud Logs, doesn't reproduce it).

**Does NOT belong here (move/keep elsewhere; link in):**
- **Raw log search** → the **Logs** view (device-in-path deep-links into it).
- **Full cloud inventory tables / resource CRUD** → a **Resources/Inventory**
  surface (the path references resources; it isn't an asset browser).
- **Connector onboarding wizard** → **Data Sources / Admin** (it's setup, not
  observability — the wizard we just built stays there).
- **Flow explorer / top-talkers** → **Flows** (the path *consumes* flow-derived
  edges; it doesn't show the 5-tuple firehose).
- **Generic metric dashboards / boards** → the boards framework.
- **The unified Cloud Logs lanes** → their own surface; reached from a device on the
  path (evidence in context), not the primary Service-View content.

Net: today's Service View mixes readiness tiles + investigation lists + resource
counts. Under this model it becomes **path-first**: the path is the hero, tiles are
supporting, and inventory/logs/setup are one click away, not co-resident.

## 6. How this reshapes current work
- **Dependency-graph work → becomes PATH DISCOVERY + segment classification.** Not a
  static edge chain — a discovery pipeline (flow/probe/inventory/trace) feeding the
  pattern classifier (§3), producing typed causal paths. Reuse `path_graph.py`,
  `path_direction.py`, `service_infer.py`.
- **Unified Cloud Logs lanes** = the per-device evidence surfaced *in path context*.
- **RCA attribution** = §2.4 on-path walk; extends the existing grounding/verdict
  model (an on-path device fault is corroborating cross-plane evidence).

## 7. Build order (proposed; owner to steer)
1. **Nail the Cloud Service View design** (this doc §5) — the path-first surface.
2. **Segment/device classifier** (§3) — pattern rules over address space, provider
   CIDRs, ASN, device role, tunnel telemetry; default-closed; tested per pattern.
3. **Path discovery** (§2.1–2.3) — assemble typed causal paths from live telemetry.
4. **On-path RCA attribution** (§2.4) — break-detection + verdict lift, honest when
   the path is unknown.
5. **Render** the path + broken-link + in-context logs in the Cloud Service View.

Honesty rules inherited: never invent a path edge or a segment type; unknown stays
unknown; partial path → suspected, never confirmed. See [[netops-rca-evidence-accounting]],
[[netops-service-path-graph]], [[netops-cloud-platform-backlog]].
