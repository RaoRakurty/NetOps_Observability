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

> ⚠ **The contract extends to `entity_id` (gap G2 — RE-AUDITED 2026-06-23, narrowed).**
> Canonical *metric names* aren't enough: correlation grounds signals by shared identity
> tokens, so the same element must carry the SAME `entity_id` across every producer.
> **Live data shows this is mostly already true:** syslog (`leaf1:Ethernet2`, `spine1`)
> and metric (`leaf1:Ethernet3`) ids are canonical by name and reconcile; no
> `ifIndex`-style ids exist in practice. The ONE non-canonical producer is **SNMP
> traps** → `sourceIP:binding` (e.g. `10.70.245.120:peer`; the lab NATs every device to
> a single gateway IP). The genuine G2 work is therefore narrow: resolve trap
> source-IP → device via the discovery mgmt-IP→device map — and **independence-aware**,
> because an un-resolved trap source currently counts as a distinct observer that can
> (legitimately or spuriously) anchor a `confirmed` verdict. See `correlation-engine.md`
> §4.2 (the re-audit block + the three-layer model).

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

### Firewall / NGFW (P5 — two planes; metric + event)
**Metric plane (canonical `device_fw_*`):**
- **FortiGate** (FORTINET-FORTIGATE-MIB, ent 12356.101) — best-grounded:
  - `device_fw_sessions` = `fgSysSesCount` (…101.4.1.8); `device_fw_session_rate` = setup rate `fgSysSesRate1` (**…101.4.1.11** — corrected 2026-06-15; `.9` is `fgSysLowMemUsage`); CPU `fgSysCpuUsage`, mem `fgSysMemUsage`. **Session-util % is DERIVED** (count vs platform max), not a single OID.
  - `device_fw_ha_state` = per-VDOM role `fgVdEntHaState` (…101.3.2.1.1.4: primary/master(1), secondary/backup(2), standalone(3)); mode `fgHaSystemMode`; sync `fgHaStatsSyncStatus` (**0/1**, not 1/2).
  - `device_fw_tunnel_state` = per-tunnel `fgVpnTunEntStatus` (…101.12.2.2.1.20: down1/up2) + aggregate `fgVpnTunnelUpCount`. FortiGate is the **one vendor with a real per-tunnel state enum** via SNMP.
  - `device_fw_ips_detected`/`_blocked` = `fgIps` (…101.9.2.1.1); `device_fw_av_detected`/`_blocked` = `fgAntivirus` (…101.8.2.1.1) — aggregate per-VDOM counters DO exist via SNMP (good for z-score baselining; per-event detail is syslog-only).
  - **`fgFwPolPktCount`/`ByteCount` (…fgFwPolStatsTable) are TOTAL pass-through counters, NOT denies** (corrected 2026-06-15). `device_fw_policy_denies` is **event-derived** (syslog `action=deny`), never an SNMP counter.
  - Authority: `docs/design/research/p5-firewall-telemetry.md` (2026-06-15, ~52 claims verified vs FORTINET-FORTIGATE-MIB).
- **Juniper SRX** — chassis-cluster failover delivered as an **SNMP TRAP** (not pollable) carrying prev/current state + reason → ideal `device_fw_ha_state` transition. SPU-Monitoring MIB for flow sessions. ⚠️ **REFUTED: `jnxJsFlowSofSummary` is NOT the session OID** — do not use.
- **Check Point** — HA `haState` (.1.3.6.1.4.1.2620.1.5.6, known defect: reads "Active" on all members); deny/drop via `fwDropPckts`/`fwReject*`. ⚠️ **REFUTED: `fwNumConn`/`fwConnsRate`/`haWorkMode`/`haClusterXLFailover`** — do not use as-cited.
- **OPEN (unverified):** Cisco ASA/FTD (CISCO-UNIFIED-FIREWALL-MIB/cfwConnectionStat), Palo Alto SNMP (PAN-COMMON-MIB panSession*), Versa, and the "device vs management-plane which-is-canonical" question.

**Event plane (normalized `fw_event` schema — syslog→Vector→OpenSearch, NOT metric store):**
- **Palo Alto PAN-OS** — comma-separated CSV by type (TRAFFIC/THREAT/URL/WILDFIRE/SYSTEM/CONFIG); positional field maps → action, src/dst ip+port, proto, app, rule, zones, user, bytes, session-id. Well-grounded.
- **FortiOS** — `key=value` (default) + CEF; Traffic/Event/UTM-Security split (AV/WebFilter/IPS/DLP/AppCtrl/WAF/DNS/anomaly). Well-grounded.
- Canonical fw-event fields: action(allow/deny/drop/reset), src/dst, proto, app-id, rule, zone, user, threat/signature/category, bytes, session-id, duration.

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

## D. SHIPPED 2026-06-14 — L1/inventory baseline-gap closures

Closing the documented SNMP baseline gaps (see netops-snmp-baseline-audit). All
additive to the generic profile; ownership-gate unchanged.

| Metric | OID / MIB | Status | Notes |
|--------|-----------|--------|-------|
| `device_if_fcs_errors` | dot3StatsFCSErrors, EtherLike-MIB RFC 3635 | correct, **not lab-exercised** | cEOS/SRL/FortiGate containers don't implement EtherLike-MIB; works on real gear. On the RCA bus (L1 fault discriminator). |
| `ifAlias` label | ifXTable .18, RFC 2863 | ✅ **live-validated** | operator circuit ID on every interface series + MetricEvent; 21 ifs (`to-dmz-fw`, `DCI-to-spine2`) flowing to correlation as a grounding token. |
| `device_if_last_change` | ifTable .9 | correct, not lab-exercised | flap timestamp; VM-only (step-on-flap, not a CUSUM level). |
| `device_entity_info` | ENTITY-MIB entPhysical* RFC 6933 | ✅ **live-validated** | FRU serial/model/class info series (VM-only metadata); 17 FRUs, real Cisco/Arista serials. Gotcha: entPhysicalClass is INTEGER (valueInt-decode, not raw byte). |

Audit CI greened: `device_bgp_pfx_in` + `device_isis_adj_state` documented as
GNMI_OWNED. Telegraf retired (legacy compose profile; Go collector owns SNMP).

---

## E. SHIPPED 2026-09-02 — A9 trap-parser coverage audit (the tracker-184 exercise, applied to SNMP traps)

The generated, always-current answer to "what does Correlix recognize?" now lives
in **`docs/design/telemetry-coverage-matrix.md`** (symptom × source × vendor ×
fidelity, derived from `telemetry-catalog/events.yaml` by
`telemetry-catalog/coverage_matrix.py`, drift-guarded in CI). This section
records only what the AUDIT established, which the matrix cannot: the verified
trap groundings, and the rule the audit followed.

### E.1 The anti-fabrication rule (adopted)

> A trap rule may match on an **OID only when that OID resolves in the vendored
> MIB index** — `src/backend/collectors/mibs/index/oididx.json`, regenerated by
> `make mib-index` (pysmi) from real MIB modules. An OID written from memory is
> an invented wire contract that fails **silently** on real hardware, which is
> exactly the failure mode this whole catalog exists to prevent.
>
> A symptom whose MIB is **not** vendored is matched on the MIB-decoded
> `event_type` envelope (#32) instead. Adding the module to `gen_index.py`'s
> `DEFAULT_MIBS` and re-running `make mib-index` then makes it classify **with no
> rule edit**.

Enforced by `telemetry-catalog/test_trap_rules_a9.py`
(`test_every_oid_a_promoted_guard_tests_resolves_in_the_vendored_mib_index`,
plus the same gate on every varbind column OID, plus an OID↔name-arm agreement
check so the two halves of a guard cannot classify different notifications).

### E.2 VERIFIED trap groundings (index-resolved, added to the audit's §A set)

| Symptom | Notification | OID | MIB | State varbind |
|---|---|---|---|---|
| OSPF adjacency | `ospfNbrStateChange`, `ospfVirtNbrStateChange` | `1.3.6.1.2.1.14.16.2.2`, `…2.3` | OSPF-TRAP-MIB | `ospfNbrState` `1.3.6.1.2.1.14.10.1.6` (enum 1 down … 8 full) |
| OSPF peer identity | `ospfNbrIpAddr` / `ospfNbrRtrId` | `1.3.6.1.2.1.14.10.1.1` / `…1.3` | OSPF-MIB | IpAddress → renders as the **same dotted quad** the syslog grammar extracts, so trap and syslog ground on one token |
| IS-IS adjacency | `isisAdjacencyChange` | `1.3.6.1.2.1.138.0.17` | ISIS-MIB (RFC 4444) | `isisAdjState` `1.3.6.1.2.1.138.1.10.1.12` (1 down, 2 init, 3 up, 4 failed) |
| STP topology | `topologyChange`, `newRoot` | `1.3.6.1.2.1.17.0.2`, `…0.1` | BRIDGE-MIB | **none** — SMIv1 `TRAP-TYPE` with no `VARIABLES`, so no port and no direction |
| Config change | `ciscoConfigManEvent`, `ccmCLIRunningConfigChanged`, `jnxCmCfgChange`, `entConfigChange` | `1.3.6.1.4.1.9.9.43.2.0.1/.2`, `1.3.6.1.4.1.2636.4.5.0.1`, `1.3.6.1.2.1.47.2.0.1` | CISCO-CONFIG-MAN-MIB, JUNIPER-CFGMGMT-MIB, ENTITY-MIB | n/a |
| Auth failure | `authenticationFailure` | `1.3.6.1.6.3.1.1.5.5` | SNMPv2-MIB | n/a |

**Enum rendering gotcha.** `resolveVarbind` (snmptrap.go) renders a decoded enum
as `label(raw)` — `down(1)`, `full(8)` — and an agent with the MIB unloaded sends
the bare integer. Every A9 state grammar classifies **both** spellings; a rule
that read only the label would silently produce `unknown` on half the fleet.

**MIBs NOT in the vendored index today** (so their OIDs are deliberately absent
from every guard): LLDP-MIB, CISCO-BGP4-MIB (compiles no notifications),
VRRP-MIB, CISCO-HSRP-MIB, CISCO-STP-EXTENSIONS-MIB, CISCO-MAC-NOTIFICATION-MIB.

### E.3 Two findings outside the parser — both CLOSED by A9b (2026-09-02)

1. **Config-change traps are invisible, not merely untyped.** `gen_index.py`'s
   `SEVERITY_HINT` seeded `ciscoConfigManEvent` at `notice`, which is *below*
   `producers.ALARM_SEVERITY_FLOOR` (4 = warning) — so a device config change
   did not even become a generic `device_alarm`.
   **CLOSED.** The config-change notifications (`ciscoConfigManEvent`,
   `ccmCLIRunningConfigChanged`, `jnxCmCfgChange`, `jnxCmRescueChange`,
   `entConfigChange`, `tmnxConfig*`) are seeded `warning`, and the symptom is
   now TYPED on both observers as `device_config_change`
   (`syslog.config.change`, `trap.config.change`) — with the five signature
   templates that consume it as an optional clause, so the kind is not inert.
   The SYSLOG row ships `shadow: true` (counted, emits nothing) and contributes
   nothing to the ingest screen: `%SYS-5-CONFIG_I` is 35 of the 100 noise slots
   of the ratified V1 workload profile, so emitting would re-classify a third of
   the V1 background — a profile version, which is the owner's call. The trap
   row emits (V1 injects syslog only).
   A merge bug was fixed in the same file: the generator preserved a node's
   *existing* hint over the table, so a hint CHANGE could never propagate to an
   OID the index already held. That is why this value had stayed at `notice`.
2. **Hardware/environment traps have the same problem**: `cefc*`,
   `ciscoEnvMon*`, `entStateOperDisabled`, `aristaEntSensorAlarm`,
   `jnxFanFailure`, `jnxPowerSupplyFailure`, `tmnxEq*` all carried **no**
   severity hint and defaulted to `notice`.
   **CLOSED.** The FAULTS are seeded `warning` and their recovery twins
   (`jnxFanOK`, `cefcFRUInserted`, `entStateOperEnabled`, …) `info` — the same
   split `linkDown`/`linkUp` has always had. They stay GENERIC `device_alarm`s:
   there is still no typed environmental kind to promote them to, and a sensor
   trap says a threshold moved, not which optic or which lane
   (see § E.4 / the coverage matrix).

### E.4 Audited and deliberately NOT promoted

The full verdict table with reasons is generated into
`docs/design/telemetry-coverage-matrix.md` (§ "Audited and NOT promoted").
The two that most often get asked for:

- **MAC move** (`cmnMacChangedNotification`, `aristaBridgeExtMacMove`) — the MAC
  and VLAN live in the FDB varbind's **OID index**, not its value, and the
  receiver renders a MAC as `AA:BB:…` while the syslog lane grounds on the Cisco
  dotted form. A MAC is a *global* grounding token (tracker 168), so emitting one
  in a second notation would split one moving MAC into two correlation objects —
  strictly worse than the generic alarm, which already carries the decoded
  vlan/mac in `fields` + `message_key`.
- **`linkDown` + `ifAdminStatus`/`ifOperStatus` enrichment** — audited, deferred.
  It would let the engine tell an administratively-shut port from a fault, but it
  changes the attrs and state of an already-shipping rule, re-identifying every
  link trap already stored. That is the same class of change as the declared
  `bgp_adjacency_change` divergence and needs its own corpus re-bake.
