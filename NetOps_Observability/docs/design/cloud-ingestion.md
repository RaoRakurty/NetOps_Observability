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

## 4. Seam inventory (segment model — first-class crossing kinds)

Pending owner trim (question outstanding); until then ALL four are modeled:
1. **DX/ER private peering at colo** (Equinix cage — the leased-line middle mile)
2. **IPsec site-to-site over internet underlay**
3. **SD-WAN cloud gateways / on-ramps** (NVA in VPC)
4. **SaaS direct via local internet breakout (DIA)** — never touches the DC path

Each crossing kind = a `segment` entity with its own probe pair (site-side ↔
cloud-side where T2 deployed) so differential measurement brackets it.

## 5. Phasing

- **CI-P1** (with correlation-engine P1): NVA syslog tier (works today, document
  runbook) + collector skeleton = vantage-point agent with STAMP/ICMP/HTTP +
  outbound mTLS registration to per-tenant ingest URL.
- **CI-P2**: T1 API pollers (AWS first: TGW/VGW/DX + VPC Flow Logs seam slice from
  Kinesis/S3; then Azure ER/VPN GW/NSG; GCP later) + Layer-1 policy engine +
  normalization into flows/corr_signals.
- **CI-P3**: Layer 2 selective ENIs (policy UI) ; Layer 3 lands with service-catalog
  selectors automatically (same selector objects drive both CH attribution and
  cloud admission).

Non-goals: full-VPC ingestion as default (never), traffic mirroring/eBPF (revisit
post-P3), per-cloud marketplace packaging (later).
