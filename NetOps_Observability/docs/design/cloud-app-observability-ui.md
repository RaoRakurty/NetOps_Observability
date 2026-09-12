# Cloud App Observability — UI Navigation (#81 P3F)

> Today there is **no cloud UI**. This is the information architecture, designed
> **ingestion-first**: the nav order follows the data lifecycle so a new user is
> walked from "connect your cloud" to "here's the app RCA" top-to-bottom. Built in
> P3F after the backend phases land; every screen maps to a real endpoint (no
> screen invents data). Visual bar = the standing premium-NOC standard
> (instrument-grade, tabular-mono, **honest empty states** — "not measured" never
> "healthy").

## Where it lives in the Correlix nav

A new top-level **Cloud** section (cloud is a distinct pillar, like Infrastructure).
The actual credential/role setup reuses the existing connector control plane
(Admin → Integrations), deep-linked from here — we don't fork that.

```
CLOUD  (new section — the journey, in data-flow order)
│
├─ ① Overview              posture at a glance: accounts · apps · health · coverage% · active RCA
│
├─ ② Connections  ◀── INGESTION STARTS HERE
│   ├─ Accounts           connect/scope AWS·Azure·GCP (role/creds, account+region scope,
│   │                     least-priv IAM doc) — deep-links Admin→Integrations
│   ├─ Sources            per account, toggle what to ingest:
│   │                     Inventory · Flow Logs · LB Logs · Metrics · Health · Change/Audit · Traces
│   └─ Ingestion Status   ★ the per-account × per-source MATRIX:
│                         ✓ flowing / ⚠ stale / ✗ off · last-sync · volume · errors
│                         — "is my data actually arriving?" the SRE's first stop
│
├─ ③ Attribution Coverage  confirmed-by-tag / strong-by-graph / suspected-by-catalog / UNKNOWN
│                          top unknown by bytes·errors·flows · "tag these 12 ENIs (app/owner/env)"
│
├─ ④ Apps                  the observability list — one row per app:
│   │                      health · owner/env · provider/account/region · traffic · error% ·
│   │                      latency · unknown% · last change · active RCA
│   └─ App detail (drill)  ◀── the six-part story, as tabs:
│        • Identity        attribution evidence (tag/graph/firewall/…), confidence, reason
│        • Resources       the app→resource map (ALB·ECS·RDS·…) with confidence
│        • Dependencies    traffic graph (who it talks to, in/out)
│        • Health          cloud_health timeline (degraded/down + symptom)
│        • Changes         cloud_change timeline (deploy/config/security/route)
│        • Network/Underlay seam impact: NAT·TGW·VPN·DX·ExpressRoute·Interconnect + BGP/iface/probe
│        • RCA             verdict cards: domain · confidence · evidence chain · why
│
├─ ⑤ Resources             cloud inventory: resource · type · app · tags · account/region · confidence
│                          (filter: unattributed / untagged)
│
└─ ⑥ App RCA               cloud app RCA groups — unifies with the existing Event Management /
                           correlation incidents (cloud + network RCA in one place)
```

## The ingestion-first principle (why this order)

1. **Connect** (②) — you can't observe what isn't connected; this is the entry.
2. **Verify** (② Ingestion Status) — *before any dashboard claims health*, the matrix
   proves which sources are arriving per account. An empty Health column later isn't a
   mystery — it traces to "Metrics source: off" here. This is the literal "start from
   ingestion."
3. **Trust** (③ Coverage) — how much traffic is confidently attributed vs unknown,
   surfaced as a feature (tag-coverage gap = untagged resources to fix).
4. **Observe** (④ Apps) — the per-app health/traffic/error/latency list.
5. **Diagnose** (④ App detail → ⑥ RCA) — the six-part story to a domain-owned verdict.

Each step is honest: if metrics/health aren't ingested, the app shows **"not
measured,"** not "healthy"; the unknown% column and the unknown bucket are always
visible. Same honesty contract as the rest of the platform.

## Screen → backend mapping (no screen invents data)

| Screen | Feeds from | Phase |
|---|---|---|
| Connections · Accounts/Sources | connector config (reuses Integrations control plane) | P3A+ |
| Ingestion Status matrix | per-source freshness/volume (ingestion observability) | P3A+ |
| Attribution Coverage | `GET /api/cloud/attribution/coverage` | P3A |
| Apps list | `GET /api/cloud/apps` (+ health rollup) | P3A + P3C |
| App detail · Identity/Resources | `GET /api/cloud/apps/{id}`, `/api/cloud/resources` | P3A |
| App detail · Health/Changes | `cloud_health` / `cloud_change` signals | P3C |
| App detail · Network/Underlay · RCA | app-to-underlay RCA join | P3D |
| Resources | `GET /api/cloud/resources` | P3A |
| App RCA | cloud RCA groups (unified with Event Mgmt) | P3D |

## Notes
- **Connections** is the only "write" surface (connect/scope/toggle); everything else is
  read-only observability — keeps PBAC simple (write = admin; read = operator).
- Tenant isolation: every screen is principal-scoped; an operator sees only its tenant's
  accounts/apps/resources.
- Build order: the IA + the **Ingestion Status** and **Attribution Coverage** screens are
  the highest-value first UI (they make the backend visible and prove honesty); App
  detail's Health/Change/RCA tabs follow their backend phases.
