# Cloud Network Telemetry Ingestion — 3-Tier Progressive Model

Status: **DESIGN — direction set by owner (2026-06-11), implementation not started**
Related: `correlation-engine.md` (#67 — consumes every tier), `front-page.md` (cloud
seam panels), memory `netops-frontpage-rca-direction`, parked per-tenant ingest-URL
direction (`netops-tenant-ingest-isolation-direction` — this doc activates it).

---

## 0. Principle (owner's framing, verbatim intent)

> Most tools ingest everything, then try to make sense of it later. We define
> **causal relevance first** and ingest only what strengthens causality.

Cloud application traffic never comes to the platform — *telemetry about it* does,
over five distinct paths (flow logs, in-cloud probes, gateway/service APIs, NVA
syslog, mirroring/eBPF). This doc fixes which paths, in what order, with what scope.

## 1. Deployment model — agent preferred, tiered onboarding

Decision: **"Both, agent preferred"** + **"varies who owns the cloud account"** ⇒
three onboarding tiers, each honestly labeled in coverage (unrun ≠ covered):

| Tier | Customer effort | What we get | Coverage label |
|---|---|---|---|
| **T0 — NVA syslog** | Point their cloud firewalls/NVAs at the tenant syslog endpoint (zero cloud access granted) | FW session/drop/VPN events from in-cloud NVAs — they're just devices to us | "cloud: firewall events only" |
| **T1 — API role** | Read-only cross-account role / service principal, narrowly scoped | Gateway + seam metrics via provider APIs: TGW/VGW, DX/ER **BGP state**, VPN tunnel state, NAT port pressure, LB health/5xx/latency; flow-log *streams* if exported | "cloud: seam metrics, no vantage point" |
| **T2 — Cloud collector agent** (full product) | Deploy our collector VM/container per VPC/VNet (or per transit/network account) | Everything in T1 **plus** in-cloud STAMP/ICMP/HTTP probes (middle-mile bracketing from the far end) + local flow-log reading + policy-filtered forwarding | full |

The **cloud collector** is the site vantage-point agent (correlation-engine.md §1,
probe placement) grown up: one static Go binary/container that probes, polls, reads,
filters (per §2 policy), and ships **outbound-only over a single mTLS connection**
to the tenant's unique ingest URL — tenant identity established at first entry in
the customer's cloud, never inferred downstream. This activates the parked
ingest-isolation model C.

### 1.1 HARD CONSTRAINT — the collector is not a platform (owner, 2026-06-11)

The collector is, permanently:
- a **deterministic telemetry forwarder** (normalize, stamp, ship — same input ⇒ same output),
- a **probe executor** (runs exactly the probe assignments the platform pushes),
- a **filter engine** (applies the §2 ingestion policy it is *given*, versioned).

It is **never**:
- ❌ a correlation engine (no episode detection, no edges, no windows),
- ❌ an analytics engine (no aggregation beyond bounded batching/compression),
- ❌ a decision maker (no local alerting, no adaptive sampling it invents, no
  policy it didn't receive from the platform).

Rationale: scale and maintainability. N collectors × M versions in customer clouds
we don't control — any intelligence pushed to the edge becomes an unmaintainable,
unupgradable fleet of divergent behaviors and an audit nightmare (which collector
decided what, on which policy?). All judgment lives in the platform; the collector's
entire contract is: *given policy P and assignments A, emit telemetry T,
deterministically*. Corollaries: collector config is 100% platform-pushed and
versioned (policy hash echoed in every batch header, so the platform can prove
which policy produced which data); collector upgrades change *capabilities*, never
*judgment*; a collector that cannot reach the platform buffers (bounded ring, drop
oldest counted+declared) — it never starts deciding locally.

## 2. Flow scope — the 3-tier hierarchical ingestion model (owner's design)

Never full-VPC by default. An **ingestion policy engine** in the collector (and in
the platform-side reader for T1 streams) admits flows by causal relevance:

```
            CLOUD FLOW LOG STREAMS
                     ↓
        ┌────────────────────────────┐
        │   Ingestion Policy Engine  │   (declarative policy, versioned like
        └───────────┬────────────────┘    selectors; changes never silent)
        ↓           ↓                ↓
   LAYER 1        LAYER 2         LAYER 3
   SEAM FLOWS     SELECTIVE ENIs  SERVICE-SCOPED
   (MVP core)     (enrichment)    (semantic moat)
```

**Layer 1 — Seam flows (MUST HAVE, MVP core).** Traffic crossing network
boundaries: TGW/VGW attachments, DX/ER, NAT GW, VPN GW, Internet GW, LBs
(ALB/NLB/AppGW). Low volume, stable, highest signal — this is where
network-vs-cloud-vs-ISP-vs-SaaS blame separation happens. Powers middle-mile
isolation, outage boundary detection, routing-vs-application fault separation.

**Layer 2 — Selective internal flows (smart expansion).** Only *structurally
important* ENIs/subnets: DB subnets, service-tier ENIs, shared platform services,
NAT-adjacent subnets. Yields a partial dependency graph + intra-cloud propagation
visibility without the noise explosion.

**Layer 3 — Dynamic service-scoped flows (future moat).** Admission driven by the
**service catalog selectors** (front-page Phase 2): Teams ⇒ only 443 to MS prefixes;
SAP ⇒ RFC/DB/app-tier ports; VPN ⇒ tunnel traffic. Grows with product usage; zero
waste; perfect alignment with service-aware observability.

**Sequencing: ship Layer 1 ONLY first.** Fastest to deploy, lowest cost, highest
incident relevance, easiest to correlate with probes + gateway metrics. Layers 2–3
follow as the catalog matures.

## 3. How each tier feeds the correlation engine (#67)

Each layer contributes a different correlation strength — the engine's edge/hypothesis
model consumes them differently:

| Layer | Correlation question | Strength |
|---|---|---|
| Seam flows + gateway metrics | **WHERE did it break?** | strongest causal boundary signal (entity_type `segment`/`prefix`, joins probe segments) |
| Selective ENIs | **WHAT structure is impacted?** | intermediate; topology inference, propagation visibility |
| Service-scoped | **WHO is impacted?** | weak causal, strong semantic — fills `service_id` on cloud-side signals |

Normalization: cloud flows → the existing flow schema (+ `cloud_provider`,
`boundary_kind` columns); gateway metrics/events → `corr_signals` kinds
(`dx_bgp_down`, `vpn_tunnel_down`, `nat_port_pressure`, `lb_5xx`, …); NVA syslog →
the existing syslog pipeline untouched. DX/ER BGP state from T1 APIs is the cloud
side of the `bgp_path_change` discriminator several failure signatures depend on.

## 4. Canonical seam inventory (owner-specified, 2026-06-11 — FINAL)

**The design insight (owner):** we are not modeling network paths — we are modeling
**ownership transitions in packet-forwarding responsibility**. Each seam is a
boundary where control-plane authority, forwarding behavior, and observability
boundaries change; **all correlation is computed relative to these seams.** Five
canonical seam types, chosen because each is a distinct control plane, failure
domain, observability blind spot, and correlation behavior:

| # | `seam_type` | Character | Why first-class | Correlation signature | Probe strategy |
|---|---|---|---|---|---|
| 1 | `DX` (DX/ER/MPLS colo) | **Deterministic backbone seam** — physically provisioned, BGP-controlled, colo-mediated | Cleanest causal-inference boundary; highest business criticality; strongest this-vs-cloud-vs-ISP separation | BGP state changes; latency-baseline departures on a normally flat path | Bidirectional STAMP (on-prem ↔ cloud PoP), latency baseline tracking |
| 2 | `VPN` (IPsec/GRE/SSL) | **Noisy fallback seam** — encapsulation hides the real underlay; ISP behavior leaks into the enterprise view | MTU/fragmentation artifacts dominate; underlay invisible through the tunnel | Jitter spikes, tunnel flaps, asymmetric loss | Synthetic ICMP + HTTP from BOTH ends; tunnel health as a first-class metric |
| 3 | `SDWAN` (fabric cloud on-ramp) | **Policy-driven opaque routing seam** — controller-driven dynamic path selection over multiple simultaneous underlays | "Best path" logic invisible to observability tools — detecting bad steering, per-transport brownouts, control-plane misbehavior is a differentiator | Per-transport divergence (one underlay brownouts while policy keeps steering into it) | Multi-path probing (simulate path-selection outcomes); per-overlay correlation tagging |
| 4 | `DIA` (direct breakout → SaaS) | **Visibility cliff seam** — enterprise control ends completely; branch → ISP → SaaS | No internal telemetry beyond the edge; dominates user-experience complaints; heavily ISP-dependent | DNS degradation, regional SaaS latency shifts, ISP congestion signatures | Branch + cloud synthetic pairs (critical); SaaS endpoint probing from multiple vantage points |
| 5 | `CLOUD_BACKBONE` (inter-region / cross-AZ) | **Invisible cloud failure domain** — missing in most models; modern outages frequently live here | Region↔region routing, backbone congestion, cross-AZ dependencies, hidden provider control-plane issues | Multi-region divergence with clean enterprise-side telemetry | Cloud vantage agents only; multi-region synthetic RTT meshes (cross-cloud = future) |

**Explicitly NOT seam types** (demoted to roles within seams):
- Cloud NVA / firewalls → **signal sources inside** seams (T0 syslog feeds whatever seam the NVA sits on)
- NAT gateways / LBs → **seam instrumentation**, not seam types
- TGW / VGW / VPN gateways → **control-plane attributes** of seam 1 or 2
- Service mesh / app flows → Layer 3 (service-scoped ingestion), never the seam model

**Unified seam object** (platform schema; each seam instance is an entity the
correlation engine scores against — supersedes the bare `segment` notion):

```jsonc
{
  "seam_id": "dallas-dx-equinix-use1",
  "seam_type": "DX | VPN | SDWAN | DIA | CLOUD_BACKBONE",
  "endpoints": { "on_prem": "...", "cloud": "...", "provider": "aws|azure|gcp|internet" },
  "control_plane_owner": "enterprise | isp | cloud | sdwan_controller",
  "visibility": "full | partial | blind",      // honest, drives coverage labels
  "probe_strategy": ["stamp", "icmp", "http_synthetic"]
}
```

`control_plane_owner` is what makes hypothesis verdicts assignable (owner =
netops/carrier/cloud_provider/app team maps directly from the seam where causality
localizes); `visibility` keeps the coverage honesty rule enforceable per seam.

### 4.1 Seam bootstrap engine — P1, required (owner, 2026-06-11)

An empty seam inventory makes the grounding gate ground against nothing
(`rca-market-research.md` C5: dependence on hand-authored seams is the model's
existential risk). The inventory therefore must not wait for the engine or for
manual entry: **P1 ships a bootstrap engine** that auto-suggests seam instances
from telemetry we already collect — suggest → owner confirms/edits → active.
Minimum P1 rules:

| Source signal (exists today) | Suggested seam |
|---|---|
| traceroute hop crossing an ASN transition | underlay/provider seam (DX vs DIA candidate, split by path stability + provider metadata) |
| BGP neighbor / provider metadata on edge devices | carrier/cloud seam (DX/ER) |
| flow ingress/egress boundary (private↔public crossing at an exporter edge interface) | LAN/WAN seam |
| SD-WAN tunnel endpoints (tunnel discovery) | SDWAN seam (overlay + each underlay it rides) |

Suggestions carry provenance (which rule, which evidence) and a suggestion
confidence; rejected suggestions are remembered and never re-raised; confirmed
seams enter the inventory with `visibility` defaulted honestly (DIA = partial at
best). Runs in the topology/discovery plane and shares its UI surface with #67's
topology-gap hints — they are one workflow (unmodeled co-occurrence → "define a
seam?" → pre-filled bootstrap suggestion).

## 5. Phasing

- **CI-P1** (with correlation-engine P1): NVA syslog tier (works today, document
  runbook) + collector skeleton = vantage-point agent with STAMP/ICMP/HTTP +
  outbound mTLS registration to per-tenant ingest URL + **seam bootstrap engine**
  (§4.1 — required input to #67 P1 grounding).
- **CI-P2**: T1 API pollers (AWS first: TGW/VGW/DX + VPC Flow Logs seam slice from
  Kinesis/S3; then Azure ER/VPN GW/NSG; GCP later) + Layer-1 policy engine +
  normalization into flows/corr_signals.
- **CI-P3**: Layer 2 selective ENIs (policy UI) ; Layer 3 lands with service-catalog
  selectors automatically (same selector objects drive both CH attribution and
  cloud admission).

Non-goals: full-VPC ingestion as default (never), traffic mirroring/eBPF (revisit
post-P3), per-cloud marketplace packaging (later).
