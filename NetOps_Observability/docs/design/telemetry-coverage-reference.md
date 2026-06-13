<!--
  Multi-vendor telemetry COVERAGE reference (the foundation program, tracker #73).
  Status 2026-06-13: PARTIAL. Six deep-research passes ran; the session rate
  limit (reset 17:30 UTC) killed the synthesis step on all of them and most
  verification mid-vote. This doc captures ONLY the adversarially-VERIFIED
  primary-source claims (23 across P1-P4) as grounded seed, and honestly lists
  what still needs a re-run. It is NOT the finished master reference.
-->
# Multi-Vendor Telemetry Coverage Reference (Foundation — #73)

**Goal:** extend the source-agnostic single-contract (`device_*{device,vendor,…}`,
proven for `device_mem_percent` via the gnmic canonical lane, commit `8c5e776`)
to EVERY telemetry family across Enterprise + Service-Provider + Data-Center, so
the platform can detect "anything that happens in a network" — especially the
**control-plane / service-plane root-cause events** an RCA/correlation engine
depends on. Two planes: **metric plane** → canonical `device_*` names; **event
plane** → normalized syslog/firewall field schema (separate log pipeline).

Owner per family = SNMP vs gNMI-on-change vs controller-API. Mode = sample vs
**on-change** (preferred for protocol state that flaps).

---

## A. VERIFIED groundings (adversarially confirmed against primary sources)

### Routing control plane — BGP
- **BGP4-MIB (RFC 4273) is IPv4-only** — `bgp4PathAttrIpAddrPrefix` is a 32-bit
  IpAddress; **no IPv6 / VPNv4 / other AFI-SAFI**. Our current SNMP profile uses
  exactly this (`device_bgp_peer_state` = `bgpPeerState`, profiles.go:68) → it is
  **silently v4-only today**. [RFC 4273]
- `bgpPeerState` enumerates the 6 FSM states idle(1)…established(6) → canonical
  `device_bgp_peer_state`. `bgpPeerFsmEstablishedTransitions` = flap counter
  (`device_bgp_fsm_transitions`, already collected). [RFC 4273]
- **BGP4V2-MIB (draft-ietf-idr-bgp4-mibv2)** adds per-peer **per-AFI/SAFI**
  tracking incl. IPv6: `bgp4V2PeerState`, `bgp4V2PeerFsmEstablishedTransitions`,
  and prefix gauges `bgp4V2PrefixInPrefixes` / `…InPrefixesAccepted` /
  `…OutPrefixes` (`bgp4V2PrefixGaugesTable`). **This is the fix for our v4 blind
  spot** → `device_bgp_pfx_in/accepted/out{afi,safi}`. [draft-ietf-idr-bgp4-mibv2-15]

### Service plane — MPLS / LDP
- **MPLS-TE-STD-MIB (RFC 3812)**: `mplsTunnelOperStatus` = canonical LSP oper
  state, enum up(1)…lowerLayerDown(7) → `device_mpls_lsp_state` (same enum shape
  as ifOperStatus — reuse the status-enum mapping). 6 core tables incl.
  `mplsTunnelARHopTable` (actual signalled hops). [RFC 3812]
- **MPLS-LDP-STD-MIB (RFC 3815)**: `mplsLdpSessionTable` = per-peer LDP session →
  `device_ldp_session_state`. [RFC 3815]

### Tunneling / IPsec
- **CISCO-IPSEC-FLOW-MONITOR-MIB** (`1.3.6.1.4.1.9.9.171`): IKE phase-1
  (`cikeTunnelTable` .1.2.3, `cikeTunStatus`) + IPsec phase-2 (`cipSecTunnelTable`
  .1.3.2, `cipSecTunStatus`) → `device_ipsec_tunnel_state`. Discrete failure
  counters: anti-replay (`cipSecTunInReplayDropPkts`), decrypt/auth fails
  (`cipSecTunInDecryptFails`/`…InAuthFails`), encrypt fails. [Observium MIB ref]
- **OpenConfig `openconfig-if-tunnel.yang` is thin**: augments the interface tree,
  exposes only src/dst/ttl/gre-key — **NO tunnel oper-status, NO GRE keepalive
  leaf**. ⇒ GRE/IPsec state must come from vendor MIBs/YANG, not OpenConfig.

### QoS (highly vendor-specific — canonical layer does the most work here)
- **CISCO-CLASS-BASED-QOS-MIB**: per-class drop counters `cbQosCMDropPkt`/
  `cbQosCMDropByte` + pre/post-policy bytes → `device_qos_class_drops` /
  `device_qos_class_tx_bytes`. **Gotcha: two-part runtime index**
  `cbQosPolicyIndex`+`cbQosObjectsIndex` (RED adds `cbQosREDValue`); config vs
  stats keyed separately, hierarchy via `cbQosParentObjectsIndex` — per-class
  polling is index-complex and costly. [CISCO-CLASS-BASED-QOS-MIB]
- **openconfig-qos** organizes around classifiers / forwarding-groups / queues /
  scheduler-policies under `/qos/interfaces` → canonical `device_qos_queue_*`.
- **Nokia TIMETRA-QOS-MIB** exposes DSCP/FC/WRED named tables; the actual
  per-queue stat counters live in other conformance groups (verify on SR OS).

### SD-WAN (controller-API-sourced, NOT box SNMP/gNMI)
- **Cisco Catalyst SD-WAN (vManage) REST**, base `https://{vmanage}/dataservice/`:
  - BFD liveness → `GET /device/bfd/sessions|summary|tloc` → `device_sdwan_tunnel_state`, path loss.
  - Path SLA → `GET /device/app-route/sla-class|statistics` → `device_sdwan_path_{loss,latency,jitter}`.
  - Fabric → `GET /device/control/connections`, `GET /device/omp/peers` → `device_sdwan_control_conn_state`.

---

## B. PENDING — needs re-run (rate-limited; NOT yet verified)

These were searched but synthesis/verification died on the session limit. Do not
treat as final until re-run + verified:
- **P1 depth**: OSPF/IS-IS/BFD canonical mappings; Segment Routing (SR-MPLS/SRv6);
  L2VPN/EVPN/VXLAN; L1 optics-DDM/FCS/ENTITY inventory; L2 fabric (VLAN/STP/LACP/MAC);
  per-vendor gNMI/OpenConfig path tables (Cisco/Juniper/Arista/Nokia/Extreme).
- **P2 depth**: CDP (`cdpCacheTable`), BGP-LS (RFC 9552 AFI 16388), ENTITY-STATE-MIB
  (RFC 4268) FRU oper/alarm, per-vendor HW MIBs (jnxBoxAnatomy, CISCO-ENTITY-FRU-CONTROL,
  TIMETRA-CHASSIS), ASIC/NPU/ECC/PSU/fan/optics.
- **P3 depth**: per-vendor QoS OID/path tables, Arista LANZ, Juniper PFE queue stats.
- **P4 depth**: Versa (Director+Analytics), VeloCloud, Fortinet, Aruba, Prisma, SSR.
- **P5 firewall**: ENTIRELY inconclusive (0 verified) — FortiGate/PAN/ASA/SRX/CheckPoint/Versa
  metric OIDs + the per-vendor LOG-parse schemas (event plane). Re-run from scratch.
- **Cisco competitive studies**: study#1 (Networking Cloud / FSO / COP — FMM entity
  model leads only, unverified) and **Cisco Cloud Control / AI Canvas (0 sources —
  total failure)**. The AI-Canvas study is the owner-priority differentiator input;
  must re-run.

---

## C. Build order (by correlation value; validate each on the live clos lab)

1. **BGP all-AFI** — add BGP4V2-MIB (v6/VPNv4) to the SNMP profile + gNMI
   `…/bgp/neighbors/neighbor/state/session-state` **on-change**. Fixes today's
   silent v4-only blind spot. Highest RCA value (peer down = root cause).
2. **OSPF/IS-IS/BFD adjacency state** via gNMI on-change (SNMP fallback).
3. **MPLS LSP + LDP** (`device_mpls_lsp_state`, `device_ldp_session_state`).
4. **Hardware faults** (ENTITY-STATE FRU oper/alarm, optics DDM) — the
   "what hardware failed" layer.
5. **QoS drops** (`device_qos_class_drops`) — congestion RCA.
6. **IPsec/GRE/tunnel state**; then **SD-WAN** (Versa first, real net #70);
   then **firewall** (metric + event planes).

Each family flips under the existing ownership-gate discipline (one transport per
(device,family); prove parity vs raw lane before flipping). Extend
`audit_metric_contract.py` to cover gNMI emissions (critical-review HIGH finding).
