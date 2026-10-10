# SD-WAN overlay topology inference — design (2026-10-10)

**Status:** PROPOSED — awaiting owner sign-off before build.
**Owner requirement (2026-10-10):** SD-WAN edges discovered over SNMP/gNMI must show as connected
over the WAN even though the ISP underlay is invisible (no LLDP/CDP across it). Correlix must tell an
**SD-WAN edge** from a **data-centre edge** and from a **plain enterprise WAN/branch edge without
SD-WAN**, and the design must hold for **hundreds to thousands of edges per tenant**. An SD-WAN
Manager (vManage) connector is a SEPARATE discovery method (NMS integrations); this design is the
SNMP/gNMI-only path, and its fact contract is source-agnostic so that connector can feed it later.

Research: Fable `researcher` agent, 2026-10-10. Spot-verified in the main session against the code
(SD-WAN strings in `topology/roles.go`, the silent 4,096-row walk cap in `collectors/tunnels.go` and
`collectors/snmpv3.go`, `carrierOverlay.ts` hard-coding `status: "up"`, `DeviceFact.TunnelCount`
read but never produced). Everything marked UNVERIFIED needs a live walk once the lab edges are
reachable again (the host's second NIC lost its config at the 2026-10-10 reboot).

## Lab facts (2026-10-10)

8 edges: cEDGE-40/60/80/81 (IOS XE SD-WAN, 192.168.222.105-108) and vEdge-20/51/52/100 (Viptela OS,
.101-.104). `topology_nodes` holds 8 rows, all `kind='switch'`, tenant `''`; cEdge vendor `cisco`,
vEdge vendor empty; `topology_edges` holds 0 rows. SNMP metrics flow (interfaces incl. `Sdwan-intf`,
`Tu1/Tu2`, `NV0`, `Lo65528` on cEdge; `system`, `loopback6553x` on vEdge; BGP peer and OSPF neighbour
state). No SSH account is configured, so CLI is not a source.

## Why they are islands today

Topology edges come only from LLDP/CDP/BGP-LS neighbour records (`collectors.FetchTopologyLinks`,
`topology/links.go`). Nothing turns overlay/tunnel state into graph edges. `nodeKind`
(`topology/project.go:240-269`) ignores the role classifier, so these devices default to `switch`.

## What already exists (reuse, do not duplicate)

| Asset | Where | Gap |
|---|---|---|
| Device-role classifier (`wan_edge`, `dc_wan_edge`, `dc_leaf`, `dc_spine`, `carrier_hop`, `cloud_edge`, …) | `topology/roles.go:43-226` | SD-WAN strings ⇒ `wan_edge`; `dc_wan_edge`/`carrier_hop` only via operator label; `wan_edge` mixes SD-WAN CPE and plain CE; tunnel facts never filled; result used only by `/view` and RCA spine stamping, never by `kind` or the persisted graph |
| Seam model incl. `SDWAN`, `DIA`, `DX`, `VPN`; owners `isp`, `sdwan_controller`; redundancy groups | `internal/seam/seam.go` | — |
| Seam rules R2 (BGP peers → DX), R4 (tunnels → VPN) | `internal/seam/bootstrap_rules.go` | R2 types public-internet peers as DX (should be DIA); R4 matches cEdge TLOC tunnels (`^tu[0-9]`) and has already suggested 7 bogus VPN seams on the lab |
| Engine grounding rank for "SD-WAN policy relation: INFERRED" | `src/correlation/engine.py` | — |
| Frontend `wan` node kind (`CloudNode`), `inferred` edge variant, 1,000-node canvas cap with aggregation/sigma overview | `features/topology/*` | carrier overlay invents `status: "up"` |
| Vendor detection | `collectors/vendor.go`, `internal/vendorprofile` | enterprise 41916 (Viptela) absent |

Display vocabulary per `docs/design/research/cloud-ingestion.md` §4.0: "WAN" is the umbrella, DIA
displays "ISP", "handoff" not "boundary", topology variation lives in the instance, never the type.

## Data sources (SNMP; from MIB definitions — not yet walked live)

- **BFD sessions** — identical layout on both platforms. vEdge `VIPTELA-BFD::bfdSessionsListTable`
  `.1.3.6.1.4.1.41916.6.1.1.1.N`; cEdge `CISCO-SDWAN-BFD-MIB` `.1.3.6.1.4.1.9.9.1002.1.1.1.1.N`
  (IOS XE ≥ 17.6.1a; CSCvz23024 fixed in 17.6.2). INDEX = SrcIp, DstIp, Proto(gre/ipsec), SrcPort,
  DstPort. Columns: SystemIp(6), SiteId(7), LocalColor(8), Color(9), State(10: 3 = up),
  DetectMultiplier(11), TxInterval(12), Uptime(13), Transitions(14). Colour enum 1-22
  (default, mpls, metro-ethernet, biz-internet, public-internet, lte, 3g, red…bronze, custom1-3,
  private1-6). UNVERIFIED: InetAddressIP index length-prefixing.
- **TLOC summary** — cheap, O(N) in aggregate. vEdge `.41916.6.1.6.1.N`; cEdge
  `.9.9.1002.1.1.6.1.N`. INDEX = IfName, Encap; SessionsTotal(3), SessionsUp(4), SessionsFlap(5).
- **Local identity** — vEdge `VIPTELA-SECURITY` `.41916.4.2.5.{1,8,12,19}` (DeviceType, SiteId,
  SystemIp, OrgName); cEdge `CISCO-SDWAN-SECURITY-MIB` `.9.9.1006.1.2.5.{…}`. Personality vEdge
  `.41916.11.1.1`, cEdge `.9.9.1004.1.1.1` (separates vedge from vsmart/vbond/vmanage).
- **gNMI** — no SD-WAN oper YANG found for IOS XE; discover live with `gnmic capabilities`. Go has no
  gNMI client (§6); any gNMI leg rides the `gnmic` sidecar emitting the same fact contract.

## Design

**Fact contract (source-agnostic):** `OverlayDeviceFacts{device_id, personality, system_ip, site_id,
tlocs[{if, encap, color?, total, up, flaps}], peers[{system_ip, site_id,
colorpairs[{local, remote, state, proto}]}], truncated, walked_at}`. Tenant is NEVER in the payload;
the reader stamps it from inventory.

**Classification — extend `ClassifyDeviceRole`, no new role values.** Add orthogonal `WANFlavor`
(`sdwan` | `routed` | `""`) and `Personality`, each with evidence. New facts: SD-WAN personality,
system-ip, site-id, SD-WAN ifName markers, enterprise 41916, overlay peer count / hub-ness, external
BGP peers public vs private, neighbour fabric roles, site kind, tunnel count.

| Class | Signals (SNMP/gNMI only) | Topology attachment |
|---|---|---|
| SD-WAN edge (`wan_edge` + `sdwan`) | strong: personality vedge, local SystemIp answers, BFD/TLOC tables present, sysObjectID 41916; medium: SD-WAN ifName markers. vsmart/vbond/vmanage ⇒ controller, not an edge | TLOC membership → per-(tenant, colour) transport node; observed overlay edges (bounded) |
| DC WAN edge (`dc_wan_edge`) | strong: site kind = dc; medium: adjacency to `dc_leaf`/`dc_spine` AND (external BGP OR SD-WAN); weak: overlay hub | fabric links + WAN handoff(s) + transport membership if SD-WAN headend |
| Plain branch/CE edge (`wan_edge` + `routed`) | router, ≥ 1 external BGP peer, no SD-WAN signals, no fabric adjacency; public peer ⇒ ISP (DIA), private ⇒ MPLS PE (DX); optional `bgpPeerRemoteAs`, `ipAdEntNetMask` | WAN port → per-tenant "ISP handoff (AS n)" / "MPLS handoff" node |

`nodeKind` uses the classified role (`wan_edge`/`dc_wan_edge` ⇒ `router`); `NodeRecord` carries role,
confidence and flavour.

**Overlay edges (observed).** Per-tenant `map[systemIP]deviceID` built once per cycle from local
SystemIp, then the `system`/`Sdwan-system-intf` interface IP; never `Lo65528`/`loopback6553x`; a
system-ip claimed twice is ambiguous ⇒ unresolved + metric. One edge per unordered device pair
(`sdwan|a|b`, colour-independent id), per-colour-pair state folded into the edge (up / degraded /
down). Unresolved peers become counts on the transport node, never `ext:` nodes.

**Transport nodes (inferred).** One `kind:"wan"` node per (tenant, colour), id
`wan:<hash(tenant)>:<color>`, label "WAN transport · biz-internet". The TLOC membership edge is
observed; the shared provider network behind a colour is INFERRED (a colour is the organisation's
label, not an ISP identity). Without BFD/TLOC data: attach only on positive evidence, else no edge
plus a `View.Degraded` note naming the edges whose SD-WAN MIBs do not answer.

**Provenance.** `EdgeRecord` gains `Provenance` (observed | inferred), `Relationship`, `Detail`;
inferred items always render with the inferred variant and confidence ≤ 0.6 — never presented as
observed.

**Staleness.** Overlay freshness = `walked_at` + 3× cadence; unreadable ⇒ carry forward (tracker 290
rule). Live BFD state is read-time enrichment, not persisted.

**Tenancy (§3a).** Tenant from inventory; per-tenant resolution maps; RLS on both tables;
tenant-namespaced node ids; isolation tests (two tenants with identical colours and system-ips ⇒
separate transport nodes, no cross edges, cross-tenant drill-down ⇒ 404).

**Observability.** `collector_sdwan_walk_{rows,truncated,duration_ms}{device}`;
`device_sdwan_tloc_sessions_{total,up}`, `device_sdwan_tloc_flaps`, `device_sdwan_bfd_peers{state}`;
NO per-session series (N² cardinality); `topology_overlay_systemip_{unresolved,ambiguous}_total`.

## Scale — hundreds to thousands of edges per tenant

1. **Polling.** Today's walker is GetNext-only. Per-device BFD rows ≈ (N−1) × colour pairs (N = 1,000,
   2 colours ⇒ ~2,000 rows/device, ~2M estate-wide). Three tiers: TLOC summary every 90 s (O(N));
   State-column walk only on change (SessionsUp < Total, flap counter rose, BFD trap); full detail walk
   every 6 h jittered or on unknown destination. GETBULK v2c/v3 with adaptive max-repetitions;
   per-device row cap with explicit `truncated` (missing ⇒ unknown, never down); one walk per device;
   sweep-wide PDU budget; streaming fold to per-peer aggregates (O(peers) memory).
2. **Graph size.** Never materialise N² pairs blindly. Per (tenant, colour): full/near-full mesh
   (density ≥ 0.9, ≥ 16 members) ⇒ domain node + EXCEPTIONS only (down/missing pairs); hub-and-spoke
   ⇒ spoke→hub edges O(N·H); otherwise up to a per-tenant cap, else domain + exceptions. Result ≈ N
   device + C transport nodes + N·C membership edges; > 1,000 nodes uses the existing
   aggregation/sigma path. Paged per-device peer drill-down.
3. **Resolution** is an O(1) per-tenant map rebuilt in O(N).
4. **Store writes.** Replace `pgStore.ReplaceAll` (delete-all + row-by-row reinsert) with a diff:
   upsert only structurally changed rows, batched (pgx `Batch`/`CopyFrom`); `last_seen` heartbeat
   coarsened to a bulk update; live state stays out of Postgres. Per-session rows never go to
   `netops.tunnels` (R4 would turn them into O(N²) seam suggestions).
5. **Correlation.** Overlay pairs stay OUT of `topology_links.json` (guard test). New seam rule R6:
   per tenant one `SDWAN` seam group whose members are per-colour underlay seams (DIA for
   internet/LTE colours, DX for mpls/private), endpoints are TLOC INTERFACE entities so a CPU alert on
   one branch never fuses with another. Shared cause via the existing seam-bridged fold plus a quorum
   hypothesis: ≥ k members of one underlay degraded ⇒ "transport <colour> degraded", owner `isp`.
   Seams ground only after owner activation (safe by default). Engine change in its own PR with a
   digital-twin storm test.
6. **Offline scale tests.** Generator for N edges × C colours × {mesh, hub-spoke, partial} + noise
   (NAT, ambiguous system-ips, truncation); fake MIB agent for cEdge/vEdge OIDs. Targets: inference
   N = 1,000 hub-spoke < 200 ms; N = 2,000 full mesh, C = 3 < 2 s and < 300 MB; 4,000-row GETBULK
   walk on loopback < 1 s; no-change reconcile writes 0 rows; 20k changed rows < 5 s.

## Defects found on the way (fix regardless)

1. SNMP column walks stop at 4,096 rows and return `nil` error — silent truncation
   (`collectors/tunnels.go`, `collectors/snmpv3.go`).
2. Seam rule R4 suggests VPN seams for cEdge TLOC tunnels (7 bogus suggestions on the lab).
3. `carrierOverlay.ts` hard-codes `status: "up"` on inferred uplinks and treats any `wan` node as an
   egress point.
4. `DeviceFact.TunnelCount` / `HasCloudTunnel` have no producer.
5. `port_inventory_current.role` / `seam` have no writer.

## Commit plan

| # | Commit | Area |
|---|---|---|
| 0a | Walk truncation explicit (`ErrWalkTruncated` + metric) | collectors |
| 0b | Carrier overlay: unknown status; skip backend `wan` nodes | frontend |
| 1 | Vendor profile: enterprise 41916 + SD-WAN hints | vendorprofile |
| 2 | Classifier: facts, `WANFlavor`, `dc_wan_edge` rules; `nodeKind` uses role; role on `NodeRecord` | topology |
| 3 | Gather classifier facts tenant-scoped (closes TunnelCount gap) + §3a test | backend |
| 4 | GETBULK v2c/v3, multi-varbind, adaptive max-repetitions | collectors |
| 5 | `sdwan_overlay` collector (3 tiers, caps, metrics), `ENABLE_SDWAN_OVERLAY` (+ GUI switch per tracker 348) | collectors |
| 6 | Pure inference: index, dedup, shapes, transport nodes, caps + generator + benchmarks | topology |
| 7 | Record/view extensions (`KindWAN`, relationship, provenance), freshness/carry-forward + §3a isolation | topology |
| 8 | Diff + batched store writes + `pgintegration` RLS leg | topology store |
| 9 | `/view` overlay + paged drill-down (cross-tenant 404) | backend |
| 10 | Seam R6; R4 skips SD-WAN; R2 types public peers as DIA | seam |
| 11 | UI: overlay relationship, sources, provenance wording, legend + vitest/Playwright | frontend |
| 12 | Engine: interface-scoped seam endpoints + quorum shared cause (owner review) | correlation |
| 13 | gNMI leg via `gnmic` (live-discovered paths) | deployment |

## Risks / needs a live walk

Classifier changes alter `kind`/role on existing estates (watch `corr_template_ungrounded_total`).
SD-WAN signals do not enter correlation today; new metric families need `rcaMetricFamilies`.
Cisco MIB files are not vendored (numeric OIDs fine; trap decode would need vendoring + licence
check). Live: IOS XE version ≥ 17.6.2; SNMP views / VPN 0 `allow-service snmp` expose the subtrees;
index encoding; scalar `.0`; vEdge sysDescr/sysObjectID; system-ip on `Sdwan-system-intf`;
`Lo65528` uniqueness; colour enum parity; NAT'd destinations; per-device walk time and CPU impact;
cEdge gNMI capability.
