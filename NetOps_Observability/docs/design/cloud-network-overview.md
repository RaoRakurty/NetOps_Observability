# Cloud Network Overview — region → VPC → component, roll-up not dump

**Owner direction (2026-07-16):** *"We do not want to overwhelm, but we should give the
customer an overview of their cloud network: are they up/down, how's performance,
possible issues, WHERE are the issues — are issues in specific VPCs, subnets, or
FW/LB and so on. I think we should also segregate based on VPC inside each region."*

The whole design follows from one rule: **summarize what's healthy, surface what's
broken, and localize it.** A customer with 400 cloud resources must never see 400
rows. They see a handful of regions, and the one VPC that's red.

---

## 1. The four questions the overview must answer
| Question | Answered by |
|---|---|
| **Are we up/down?** | availability roll-up per region → VPC → component |
| **How's performance?** | throughput / latency / error-rate (5xx) roll-up on the same axis |
| **Are there issues?** | open investigations + on-path device faults, counted per level |
| **WHERE is the issue?** | the hierarchy itself — region → **VPC** → subnet / LB / WAF / FW / instance |

If the UI can't answer "where" by pointing at a VPC and a component, it has failed.

## 2. The hierarchy (the segregation axis)
```
Provider (AWS · Azure · GCP)
└── Region (us-west-2 · westus2 · us-west1)
    └── VPC / VNet            ← the PRIMARY unit (owner's call)
        ├── Subnets (per AZ/zone)
        └── Components: LB · WAF · Firewall/SG · DNS · NAT/IGW/Gateway · NVA · Instances
```
**VPC is the unit** because it is the real network boundary: routing, security groups,
flow logs, and blast radius all stop at it. "Region" alone is too coarse (multiple
unrelated networks); "resource" alone is too fine (the dump we're avoiding).

## 3. Anti-overwhelm rules (binding)
1. **Green collapses, red expands.** Default view = regions as compact cards with a
   health badge + issue count. A healthy region is ONE row. A region with a problem
   auto-expands to the offending VPC.
2. **Every level is a roll-up, never a sum of noise.** A VPC's status = the worst of
   its components, with the *reason* named ("degraded — ALB target unhealthy"), not a
   count of 47 signals.
3. **Drill, don't scroll.** Region → VPC → component → device detail (logs/path). Each
   click narrows; nothing is a wall of rows.
4. **Only show what's real.** A component with no telemetry says "not measured", never
   a fake green. Unknown ≠ healthy (the standing honesty rule).
5. **Issues are localized, not listed.** An investigation belongs to a VPC/component;
   it renders *at* that node, not in a detached global list.

## 4. What each level shows
- **Region card:** provider+region, health badge (worst-of), #VPCs, #components,
  open issues, "last measured" age. Collapsed when green.
- **VPC card (inside region):** VPC id/name + CIDR, health badge + the *reason*,
  performance strip (throughput · 5xx rate · latency where measured), component
  counts by type with per-type health dots, open issues scoped to this VPC.
- **Component row (inside VPC):** type (LB/WAF/Firewall/DNS/Gateway/Instance), name,
  status (+ why), the perf metric that matters for that type (LB→5xx/target health;
  FW→reject rate; DNS→NXDOMAIN rate; instance→CPU/health), link to its logs
  (family-tagged Cloud Logs) and its position on the discovered path.
- **Subnet** is a grouping *within* a VPC (per AZ/zone), used to localize a fault
  ("rejects concentrated in subnet data-a"), not its own top-level surface.

## 4a. Tunnels / seams — the LATERAL dimension (owner, 2026-07-16)
*"If there are any tunnels between region to region via firewalls or any other devices."*

The hierarchy in §2 is a tree, but a real cloud network is a tree **plus lateral links**:
region↔region, VPC↔VPC (peering / TGW / vWAN), and VPC↔on-prem — almost always
**traversing a device**: an NVA, a firewall, a VPN/DX gateway. These are **seams**, and
the platform already models them: `seams.go` kinds (**DX · VPN · SDWAN · DIA ·
CLOUD_BACKBONE**), live seam telemetry (VPN/DX tunnel state, ExpressRoute/VPN-GW,
Cloud Router BGP/BFD), and the P0 classifier's `wan_seam` segment + `seam_kind`.

**A seam is first-class in the overview — not a VPC attribute:**
- **Endpoints**: region/VPC **A ↔ B** (or VPC ↔ on-prem site).
- **Traversed devices**: the NVA / firewall / VPN-GW / DX router it rides — each with
  its own status (this is the "via firewalls or any other devices" part).
- **Status**: tunnel up/down, **BGP session state + learned routes**, loss/latency
  across the seam.
- **Localization**: *"where is the issue"* must be answerable as **"the seam"** — a
  region-to-region tunnel down belongs to the LINK, not to either VPC. Rendering it
  inside one VPC would misattribute it.

**Render:** seams draw as links **between** region/VPC cards, colored by status; a
broken seam is highlighted on the link itself; drill → the seam's traversed devices +
its telemetry (tunnel/BGP) + its position on the discovered path (the `wan_seam`
segment from path-causality). A seam with no telemetry reads "not measured", never green.

**Inventory implication:** §5's component collection must also capture the seam
endpoints and their devices — VPN/DX/ER gateways, TGW/peering attachments, NVAs —
each tagged with the VPCs/regions it joins, so the lateral links are discoverable
rather than assumed. (Consistent with path-causality: discover the seam, don't
hardcode it.)

## 5. Hard dependency — component inventory with VPC/region tags
This view is **not buildable today**: cloud discovery collects **compute instances
only** (`ec2:instance` / `compute:instance` / `compute:virtualMachine`). LB, WAF,
firewall/SG, DNS zones, target groups are **not inventoried** — they exist only as
fault signals when they break, so we can never render "the LB is healthy".

**Prerequisite (P0 of this program):** extend discovery to collect every component as
a first-class resource carrying **provider · region · VPC · subnet · type · status ·
the type's key metric**. All three providers expose it (`describe_load_balancers` +
target health, `list_web_acls`, `describe_security_groups`, Route53/Cloud DNS zones,
`forwardingRules`/backend services, Front Door profiles). Without the **VPC tag on
every component**, the segregation axis doesn't exist.

## 6. Build order
1. **P0 — component inventory + status + VPC/region tagging** (the foundation; also
   fixes "Resources is VM-only", "the LB isn't a device", and gives the path-causality
   render real per-device health).
2. **P1 — roll-up model**: per-VPC and per-region health/performance/issue aggregation
   (worst-of + named reason), tenant-scoped, bounded.
3. **P2 — the Overview surface**: region cards → VPC cards → component rows, green-
   collapses/red-expands, issues rendered at their node.
4. **P3 — wire the drills**: component → family-tagged Cloud Logs; component → its
   place on the discovered path ([[path-causality-rca]]); VPC → its open investigations.

Honesty inherited: unknown/not-measured is rendered as such and never rolls up as
green; a roll-up always names its reason. Ties to `path-causality-rca.md` (the path
render colors devices by the status this program provides) and the cloud platform
backlog (Wave 5 "inventory is VM-only" is subsumed by P0 here).
