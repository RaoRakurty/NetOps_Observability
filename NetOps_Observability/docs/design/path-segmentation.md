# Path Segmentation — canonical taxonomy, completeness rule, seams & roles

Owner P1 directive (2026-07-19), verbatim intent: *"clean segmentation with
visible borders/boundaries between seams. Between a site LAN and cloud there is
ALWAYS a WAN construct — a path rendered as `LAN … CLOUD` with nothing between
is wrong."*

This document is the contract for how the RCA "Network path & causality" view
segments a path, where the boundaries sit, who owns each side of every seam,
and how device roles are derived from discovery. Implementation:

- Frontend derivation: `src/frontend/src/components/rca/pathModel.ts`
  (the single derivation; `RcaPathCausality.tsx` is the only renderer)
- Backend role classifier: `src/backend/topology/roles.go`
- Fact gathering / payload stamping: `src/backend/device_roles.go`,
  `src/backend/topology_view.go`, `src/backend/path_graph_api.go`

---

## 1. Canonical segment taxonomy

The enterprise connectivity chain a NOC operator recognizes. Every rendered
segment canonicalizes onto exactly one of these:

| segment_type    | NOC display label      | Owner class | What it is |
|-----------------|------------------------|-------------|------------|
| `site_lan`      | Site LAN               | enterprise  | access switches → distribution → core router inside a site |
| `edge_security` | Edge security          | enterprise  | DMZ firewalls, WAFs, internal load balancers at the site edge |
| `wan_edge`      | WAN edge               | enterprise  | SD-WAN CPE / CE routers — the site's WAN attachment |
| `carrier`       | Carrier / middle mile  | carrier     | ISP transit / middle mile — often silent hops |
| `dc_wan_edge`   | DC WAN edge            | enterprise  | the data-center side SD-WAN / CE termination |
| `dc_fabric`     | DC fabric              | enterprise  | VXLAN EVPN leaf–spine (RoCE fabrics in GPU environments) |
| `cloud_edge`    | Cloud edge             | provider    | the cloud attachment landing point (VGW/TGW, ER gateway, VPN gateway) |
| `cloud`         | Cloud                  | provider    | provider services + workloads behind the edge |

Cloud attachment from the **site or DC WAN edge** takes one of these flavors,
rendered on the `cloud_edge` segment cap **only when the backend supplies it**
(`attachment` field; unknown values are omitted, never guessed):

`dia` → "DIA breakout" · `direct_connect` → "Direct Connect" ·
`expressroute` → "ExpressRoute" · `ipsec_vpn` → "IPsec VPN"

### Legacy vocabulary mapping

The correlation engine and the §7 spine still emit the older segment tokens.
`pathModel.ts` canonicalizes (`LEGACY_CANON`):

`lan`→`site_lan` · `dc`→`dc_fabric` · `wan`/`wan_seam`→`wan_edge` ·
`internet`→`carrier` · `cloud`→`cloud` · `unknown`→`unknown`

Discovery device roles then **refine** the placement (never contradict it
across an ownership line):

- a `site_lan` span whose devices are all firewalls/WAFs → `edge_security`
- a span with `dc_leaf`/`dc_spine` roles → `dc_fabric`
- a carrier-boundary span whose responding devices are all enterprise WAN
  edges (the SD-WAN CPE answering from carrier-assigned space) → `wan_edge`
- a `cloud` span whose devices are all edge constructs (gateway/tunnel/NVA) →
  `cloud_edge`
- a `dc_wan_edge` role anywhere in a WAN/DC span → `dc_wan_edge`

Unknown roles never force a refinement.

---

## 2. Topological completeness rule

**Measurement absence ≠ topological absence.** When the derived path spans
site LAN → cloud (or site LAN → DC), the intermediate WAN constructs are
ALWAYS rendered, even with zero responding hops:

1. A measured-but-unclassified (`unknown`) span sitting **between** the site
   side and the far side *is* the WAN/carrier leg topologically: it is
   reclassified to `carrier`, marked **inferred**, and keeps its measured
   unknown-hop count (honesty: the silence is stated, not erased).
2. Any still-missing required construct is inserted as a **zero-hop inferred
   segment**: `wan_edge` + `carrier` for a LAN→cloud span; `wan_edge` +
   `carrier` + `dc_wan_edge` for a LAN→DC span. A WAN-edge **device** already
   measured inside a site-side segment satisfies the `wan_edge` requirement
   (the construct is drawn where it was measured, not duplicated).
3. Inferred segments are drawn **dotted** with the body text
   *"no responding hops — carrier path inferred"* (per-construct wording) —
   never dressed as measured, never omitted.

Paths that do not span (purely intra-site, cloud-only, adjacency-only,
internal self-probe) get nothing added. Inferred segments carry synthetic
negative indexes so segment health and device identity stay keyed to real
engine segments only.

## 3. Boundaries, seams and ownership

Every adjacent segment pair renders a **visible vertical boundary divider**.
The seam is labeled where the **owner class changes**:

- Site LAN / Edge security / WAN edge → **enterprise**
- Carrier / middle mile → **carrier**
- DC WAN edge / DC fabric → **enterprise**
- Cloud edge / Cloud → **provider**

giving the canonical handoffs `enterprise ↔ carrier`, `carrier ↔ provider`,
`carrier ↔ enterprise` (DC side), `enterprise ↔ provider` (private handoff).

**Break-hero placement** (one hero, never two):

- **WITHIN a segment** — the attributed device carries the red break glyph
  (unchanged owner rules: red hero, "Possible break here"/"Break here").
- **ON a boundary** — when the seam between the parties is the suspect:
  - the blamed segment has **no responding devices** (an opaque/inferred
    carrier span) → the hero sits on the boundary INTO that segment; or
  - (spine-derived paths) the fault mark sits on the **last responding device**
    of its segment, the next segment is dark, and ownership changes across
    that boundary → the measurement died exactly at the parties' handoff; the
    hero sits ON the seam and the last-responding device is not blamed.

Everything else from the owner rules is preserved: per-segment health as toned
words only where measured, no grey "observed" chips, "To engage:" ownership
line, honest "possibly because of X", WCAG list/figure semantics + sr-only
mirrors + contrast.

---

## 4. Device-role classification (backend)

`topology.ClassifyDeviceRole` (pure, stdlib-only, DI'd facts) assigns:

`access_switch · distribution_switch · core_router · firewall ·
load_balancer · wan_edge · carrier_hop · dc_wan_edge · dc_leaf · dc_spine ·
cloud_edge · unknown`

Every assignment carries **evidence** (which facts fired, operator-readable)
and a **word-tier confidence** (strong / medium / weak — never percentages).
Unknown stays unknown.

### Signal table (what is wired today)

| Signal | Facts consumed | Role(s) | Confidence | Status |
|--------|----------------|---------|------------|--------|
| Operator declaration | `labels["role"]` naming an exact canonical role | any | strong | **wired** |
| SD-WAN identity | Viptela/vEdge/cEdge, VeloCloud, Versa, Silver Peak, Meraki MX, "sd-wan" in vendor/model/sysDescr | `wan_edge` | strong | **wired** |
| Model identity | sysDescr device-type classifier (`inferDeviceType`): firewall / load-balancer / cloud-gw strings | `firewall`, `load_balancer`, `cloud_edge` | strong | **wired** |
| Cloud tunnel | tunnel interface whose remote end is in published cloud space | `cloud_edge` | strong | classifier wired; **fact gathering deferred** (tunnel rows live in ClickHouse; not yet joined into the topology gather) |
| Site-to-site tunnel | tunnel interfaces on a router | `wan_edge` | medium | classifier wired; same gathering gap |
| Leaf/spine naming + fabric OS | hostname `leaf`/`spine`/`tor` tokens; VXLAN/EVPN/NX-OS/Nexus/Cumulus/SONiC strings | `dc_leaf`, `dc_spine` | medium | **wired** |
| IGP participation + fan-out | BGP-LS presence on any adjacency; LLDP/CDP neighbor counts by type | `distribution_switch`, `core_router` | medium/strong | **wired** |
| Access shape | switch with ≤2 upstream network neighbors, outside the IGP | `access_switch` | weak | **wired** (weak on purpose — see gaps) |

### Honest gaps — needs richer discovery

- **MAC/FDB endpoint density** (the *strong* access-switch signal): the SNMP
  collectors do not walk `dot1dTpFdb`/`dot1qTpFdb` today. Until they do,
  access classification rests on adjacency shape alone and stays **weak**.
- **VTEP/VXLAN tables** (the strong leaf/spine signal): no VXLAN OIDs or
  EVPN route tables are collected; leaf/spine rests on naming convention +
  fabric OS strings (**medium** ceiling).
- **Per-device eBGP sessions/ASNs** (public-ASN eBGP ⇒ wan_edge; private-ASN
  fabric ⇒ leaf/spine): BGP-LS gives the IGP topology, not per-device eBGP
  peering. Not collected; not classified from it.
- **DX/ER virtual-interface inventory**: the cloud connectivity work (Wave 4)
  authenticates to providers but does not yet inventory Direct Connect VIFs /
  ExpressRoute circuits per device; the `attachment` flavor therefore renders
  only where the engine/backend already stamps it.
- **`dc_wan_edge` vs `wan_edge`**: needs a site-kind fact (which site is a DC).
  Only the operator declaration assigns `dc_wan_edge` today.
- **`carrier_hop`** applies to unmanaged path hops; managed inventory never
  classifies into it (the ingest segment classifier owns transit-hop
  classification by ASN/address space). Only an operator declaration can
  assign it to a managed device.

### Payload surfaces (extended, not broken; tenant-scoped)

- `/api/topology/view` nodes: `device_role`, `role_confidence`,
  `role_evidence[]` (omitted when unknown). Facts are gathered from the
  caller-visible device set + links only.
- RCA timeline §7 spine nodes: `device_role`, `role_confidence` stamped in
  `rcaPathBlock` via a tenant-scoped index (entity_ref → address → label
  resolution; a hop resolving to no caller-visible device stays role-less —
  the §3a test `TestSpineRolesNeverStampFromOutsideTheVisibleIndex` pins it).
- Typed-path key devices (`rca_path_attribution.go`): `device_role`,
  `role_confidence`, segment `attachment` — passthrough fields the engine can
  populate.

`pathModel.ts` prefers `device_role` for segment placement and falls back to
the existing boundary grouping when roles are absent.

---

## 5. Test anchors

- `src/frontend/src/components/rca/pathModel.test.ts` — canonicalization,
  completeness, boundary/seam ownership, seam-break placement, attachment
  vocabulary.
- `src/frontend/src/components/rca/RcaPathCausality.test.tsx` — rendered
  chain, inferred dotted segments, boundary labels, boundary-break hero,
  no-observed-chip guards.
- `src/backend/topology/roles_test.go` — per-signal + combined classifier
  fixtures; unknown-stays-unknown; words-not-percentages.
- `src/backend/device_roles_test.go` — adjacency summaries, spine stamping,
  §3a visible-index isolation property.
