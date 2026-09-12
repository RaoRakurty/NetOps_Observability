# Fault Coverage & Signature Matrix — Correlation Layer-3 Governance

> Status: **APPROVED (owner sign-off 2026-06-23).** All §7 decisions resolved;
> P1 (generic-alarm ingestion) cleared to build. Companion to `correlation-engine.md` (§4.4 three-layer
> model, §4.5 authoring) and `telemetry-coverage-reference.md` (#73, Layer-2
> collection). This doc owns the **Layer-3** question the others do not answer:
> *which faults must the engine name, how do we KNOW our coverage, and how does it
> grow without chasing an infinite list.*

---

## 0. Why this doc exists (the problem)

The failure-signature catalog (`catalog.py`, 15 templates) grew **ad-hoc** —
families were authored from a list in the design doc, not derived from a coverage
model. That raised two fair questions from the owner:

1. **Why these few?** — no principled selection criterion.
2. **How do we know we have all the required ones for enterprise + DC?** — no
   inspectable completeness story.

This doc answers both. It does **not** try to prove the catalog "complete" —
that is the wrong target (see §1). It establishes a governance model that makes
coverage *inspectable*, makes a gap *safe*, and makes growth *evidence-driven*,
and it ships the first **enterprise + DC + overlay fault matrix** as the living
artifact.

---

## 1. The governance model (the actual answer to "how do we know")

**Completeness is unprovable and the wrong target.** The fault space is
open-ended and vendor-specific; new gear and features add failure modes
continuously. The empirical record agrees: even the seminal DC-failure study
(Gill/Jain/Nagappan, *Understanding Network Failures in Data Centers*, SIGCOMM
2011) found redundancy masks only ~40% of failures and that a long tail of
short-lived, software/config faults dominates occurrence counts. Any vendor
claiming a "complete signature library" is marketing. Chasing completeness =
discovering missing families forever and never feeling done.

Replace "are we complete?" with **three inspectable properties:**

| Property | Mechanism | What it guarantees |
|---|---|---|
| **A gap is SAFE** | Generic-alarm ingestion (§4) + `undetermined`-with-evidence outcome | A fault with no signature still becomes a grounded, tiered incident — **never a blind spot**, only "named cause pending." |
| **Coverage is INSPECTABLE** | The layer × domain **fault matrix** (§3) — a bounded grid, not "every syslog" | You can review every *cell* and assert: covered / generic-ingest / N/A. The audit answer. |
| **Growth is EVIDENCE-DRIVEN** | The engine's own `undetermined` incidents, ranked by **frequency in THIS network** (§5) | You write the next signature for what *actually keeps breaking here*, not a theoretical list. Self-correcting; converges on what matters. |

This is a stronger answer to an auditor/customer than "we have N signatures": we
*observe* every fault (safety net), we can *show* the coverage grid, and we *grow*
from measured recurrence — which the AIOps literature confirms is the high-yield
path (~75% of production failures recur; recurring-incident matching beats
novel-anomaly inference as the core).

---

## 2. The decision rule — signature vs generic-ingest vs N/A

A **signature is not a log parser** (Layer 2 normalizes events into signals). A
signature is the Layer-3 rule that names a *root cause* with an owner, first
steps, and discriminators. It therefore earns its keep under exactly one test:

> **A signature is warranted only when correlation names a cause that no single
> alarm states** — i.e. it is multi-signal, cross-device, or cross-modality — OR
> it adds a *discriminator* (this-not-that), an *owner assignment*, or a
> *confirmation tier* the raw event lacks. Otherwise the event is **self-describing**
> and rides generic ingestion.

Per-cell disposition (the matrix §3 assigns one to every fault family):

- **`SIG`** — write a signature. The cause is emergent (e.g. *underlay BGP down →
  overlay VTEP blackhole → tenant probe loss = one incident*), or a high-value
  look-alike needs a discriminator, or the owner isn't obvious from one event.
- **`GEN`** — generic-ingest only. The device alarm is self-describing and
  already actionable (e.g. `%EVPN-3-BLACKLISTED_DUPLICATE_MAC` — the device
  diagnosed *and auto-mitigated*). It flows in as grounded evidence; it can still
  be *part of* a `SIG` incident, but needs no dedicated signature to restate it.
- **`N/A`** — not a correlation concern (pure inventory/info, or owned by another
  subsystem such as PromQL alerting).

**Implication for the existing C5 batch:** OSPF/IS-IS/STP/FHRP/MAC stay (each
adds a discriminator + owner + cross-modality confirm), but the rule means we do
**not** multiply signatures per protocol/mnemonic. Most of the VXLAN/EVPN events
the owner asked about are `GEN`, not `SIG`.

---

## 3. The fault matrix (enterprise + DC + overlay + SP/DIA)

Axes: **causal layer** (matches `layers.py`) × **domain**. Each fault family
carries: canonical signal `kind`, the disposition (§2), and current status.

Status legend — **collection** (is the telemetry ingested? cross-ref #73) /
**emit** (does a producer emit the signal `kind`?) / **disposition shipped?**:
✅ done · ◻ gap · ➖ N/A.

### Layer DEVICE — infra health
| Fault family | Signal kind | Disp. | Collect | Emit | Shipped |
|---|---|---|---|---|---|
| CPU/mem/process exhaustion | `device_resource_anomaly` | GEN (contributing) | ✅ | ✅ | ✅ |
| Environmental (PSU/fan/temp) | `device_sensor_anomaly` | GEN | ✅ | ◻ | ◻ |
| Device restart/reload | `device_restart` | GEN (contributing) | ✅ | ✅ | ✅ |

### Layer L1 — physical
| Fault family | Signal kind | Disp. | Collect | Emit | Shipped |
|---|---|---|---|---|---|
| Optics/DDM degradation (Rx low) | `optics_power_low` | SIG | ◻ partial | ◻ | ✅ `physical-degradation` |
| FCS/CRC line errors | `if_errors`/`fcs_error` | SIG (part of above) | ✅ | ✅ | ✅ |
| Cable/transceiver fault | (manifests as errors+flap) | SIG (part of above) | ✅ | ✅ | ✅ |

### Layer L2 — link / switching
| Fault family | Signal kind | Disp. | Collect | Emit | Shipped |
|---|---|---|---|---|---|
| Link down / flap | `link_state_change` | SIG | ✅ | ✅ | ✅ `local-link-fault` |
| STP topology change / loop | `stp_topology_change` | SIG | ✅ | ✅ | ✅ `stp-topology-change` (C5) |
| MAC flap / move (local) | `mac_flap` | SIG | ✅ | ✅ | ✅ `mac-flap` (C5) |
| VLAN / native-VLAN / trunk mismatch | `vlan_mismatch` | GEN | ◻ | ◻ | ◻ |
| LACP / port-channel member down | `lacp_state_change` | GEN + SIG (bundle-degraded) | ◻ | ◻ | ◻ |
| UDLD unidirectional link | `udld_error` | GEN | ◻ | ◻ | ◻ |
| LLDP/CDP neighbor change | `lldp_neighbor_change` | GEN (supporting) | ✅ | ✅ | ✅ |

### Layer L3 — control plane (routing)
| Fault family | Signal kind | Disp. | Collect | Emit | Shipped |
|---|---|---|---|---|---|
| BGP peer flap / down | `bgp_adjacency_change` | SIG | ✅ | ✅ | ✅ `bgp-peer-flap` |
| BGP route churn / withdrawal | `bgp_path_change` | SIG | ◻ partial | ◻ partial | ✅ `routing-instability` |
| OSPF adjacency flap | `ospf_adjacency_change` | SIG | ✅ | ✅ | ✅ `ospf-adjacency-flap` (C5) |
| IS-IS adjacency flap | `isis_adjacency_change` | SIG | ✅ | ✅ | ✅ `isis-adjacency-flap` (C5) |
| FHRP (HSRP/VRRP) failover | `fhrp_state_change` | SIG | ✅ | ✅ | ✅ `fhrp-failover` (C5) |
| ARP/ND / duplicate-IP | `dup_ip` | GEN | ◻ | ◻ | ◻ |

### Layer L3 — OVERLAY / TUNNELS (enterprise + DC)
> **Scope (owner, 2026-06-23):** "overlay" = the whole encapsulation family the
> enterprise + DC own — **VXLAN/EVPN** (DC fabric), **IPsec** (site-to-site /
> DMVPN / SD-WAN encryption), **GRE/mGRE**, and **generic tunnels**.
> **Service-provider overlay technologies — MPLS, L2VPN/L3VPN, segment routing,
> pseudowires, carrier-EVPN services — are OUT OF SCOPE for now** (a future column
> once enterprise/DC overlay is solid). All tunnels share two cross-cutting faults
> the engine treats once: **endpoint down/flap** and **MTU blackhole** (every encap
> adds header bytes); the per-tech rows below add the control-plane specifics.
>
> **Two lanes, don't conflate (competitive note, 2026-06-23):** this matrix is the
> **control-plane RCA** lane (the moat — *name the overlay root cause*). It is
> SEPARATE from **overlay data-plane *visibility*** (decapsulate VXLAN flows →
> attribute inner host-to-host traffic to VNI/tenant/app). The visibility lane is
> the **Kentik** benchmark — and we're below it today (flows = underlay 5-tuple only,
> no VNI/inner headers): tracked as **"Track A" = #82**. Cubro = hardware packet-broker
> decap (out of our lane). See memory `netops-exceed-market-bar`.

**VXLAN / EVPN (DC fabric overlay)**
| Fault family | Signal kind | Disp. | Collect | Emit | Shipped |
|---|---|---|---|---|---|
| EVPN BGP session (l2vpn-evpn AF) down | `bgp_adjacency_change` (+AF attr) | SIG (covered by bgp-peer-flap; enrich AF) | ✅ | ✅ partial | ◻ AF enrich |
| VTEP/NVE peer unreachable (underlay→VTEP) | `vtep_state_change` | **SIG (emergent: underlay→overlay)** | ◻ | ◻ | ◻ |
| VNI down / L2VNI-L3VNI not operational | `vni_state_change` | GEN | ◻ | ◻ | ◻ |
| EVPN MAC-mobility / dup-MAC freeze | `evpn_mac_move` | GEN (self-describing) | ◻ | ◻ | ◻ |
| **L2 loop across VTEPs** (dup-MAC + MAC-move-port-down + tenant loss) | *(cluster)* | **SIG (the high-value emergent one)** | ◻ | ◻ | ◻ |
| EVPN DF election / ESI multihoming | `evpn_df_change` | GEN (contributing) | ◻ | ◻ | ◻ |

**IPsec (site-to-site / DMVPN / SD-WAN encryption)**
| Fault family | Signal kind | Disp. | Collect | Emit | Shipped |
|---|---|---|---|---|---|
| IPsec tunnel / SA down (IKE phase-1 / SA phase-2) | `ipsec_tunnel_down` | **SIG (cross-site impact)** + GEN (IKE log) | ◻ | ◻ | ◻ |
| IKE negotiation failure (auth / proposal / DH mismatch) | `ipsec_ike_fail` | GEN (self-describing config) | ◻ | ◻ | ◻ |
| IPsec rekey / anti-replay drop | `ipsec_rekey_anomaly` | GEN | ◻ | ◻ | ◻ |

**GRE / mGRE & generic tunnels**
| Fault family | Signal kind | Disp. | Collect | Emit | Shipped |
|---|---|---|---|---|---|
| GRE/mGRE tunnel down / keepalive loss | `gre_tunnel_down` | GEN + SIG (impact) | ◻ | ◻ | ◻ |
| GRE recursive-routing shutdown | `gre_recursive` | GEN (self-describing) | ◻ | ◻ | ◻ |
| Generic tunnel flap / degraded | `tunnel_down` / `tunnel_degraded` | SIG | ◻ partial | ◻ partial | ◻ |
| **Tunnel MTU blackhole** (VXLAN/IPsec/GRE header bytes) | `tunnel_mtu` | SIG | ◻ partial | ◻ partial | ✅ `tunnel-mtu-blackhole` (generic; bind to encap) |

> Verified real shapes (2026-06-23 research). **VXLAN/EVPN:** NX-OS
> `%NVE-5-BFD_CC_STATE_CHANGE`, `%HMM-2-DUP_HOSTS`,
> `%L2FM-2-L2FM_VXLAN_MAC_MOVE_PORT_DOWN`; Arista `%EVPN-3-BLACKLISTED_DUPLICATE_MAC`,
> `%ETH-4-HOST_FLAPPING` (names `Vxlan1`); SR Linux `evpn`/`bfd` subsystem events
> (`…DfStatusChanged`). Corrected dead candidates: `%NVE-5-PEER_STATE_CHANGE` and a
> Nexus `%L2-L2RIB-` facility **do not exist** (the latter is IOS-XR). **IPsec/GRE
> shapes** (IOS `%CRYPTO-`, `%TUN-`, `%LINEPROTO` on TunnelN; vendor IKE logs) to be
> pinned in the P2-tunneling research before those rows ship.

### Layer L3/L4 — data plane (reachability / transport)
| Fault family | Signal kind | Disp. | Collect | Emit | Shipped |
|---|---|---|---|---|---|
| Reachability / packet loss | `probe_loss` | SIG | ✅ | ✅ | ✅ (dia/cloud sigs) |
| Latency departure | `probe_rtt_anomaly` | SIG | ✅ | ✅ | ✅ |
| MTU blackhole (PMTUD) | `tunnel_degraded` | SIG | ◻ partial | ◻ partial | ✅ `tunnel-mtu-blackhole` |
| QoS drops / congestion | `qos_drops`/`if_util_high` | SIG | ◻ partial | ◻ partial | ✅ `wan-congestion` |
| Volumetric / DDoS / top-talker | `flow_volume_anomaly` | SIG | ✅ | ✅ (C6) | ◻ signature |
| NAT/session-table/firewall exhaustion | `fw_resource_anomaly` | SIG | ◻ (P5) | ◻ | ◻ |
| Firewall policy-drop spike | `fw_policy_drop_rate` | SIG | ◻ (P5) | ◻ | ◻ |

### Layer L7 — service / application
| Fault family | Signal kind | Disp. | Collect | Emit | Shipped |
|---|---|---|---|---|---|
| DNS impairment | `dns_latency_high`/`dns_failure_rate` | SIG | ◻ partial | ◻ partial | ✅ `dns-impairment` |
| TLS handshake fail | `tls_handshake_fail` | SIG | ◻ | ◻ | ◻ |
| LB 5xx / app errors | `lb_5xx`/`http_error_rate` | SIG | ◻ partial | ◻ partial | ✅ partial `cloud-region` |

### Domain SEAMS — ownership-transition boundaries (cross-layer; owner attribution is the whole point)

Seams are first-class here because **the DC is a seam endpoint**: it talks to
cloud, to SP/DIA, and to remote sites across boundaries it does not own. A fault
*at* a seam must be **attributed** (enterprise edge vs carrier/DX provider vs
cloud provider) — the engine's differentiator. Each row binds to a canonical seam
type (`cloud-ingestion.md` §4: `DX`, `VPN`, `SDWAN`, `DIA`, `CLOUD_BACKBONE`),
which feeds the verdict's `owner` directly. Seam `visibility` (full/partial/blind)
caps the confidence claimable across it.

| Fault family | Seam type | Signal kind | Disp. | Shipped |
|---|---|---|---|---|
| DIA egress latency/loss | `DIA` | `probe_*` (+control corrobr.) | SIG | ✅ `dia-egress-latency`, `dia-egress-corroborated` |
| Carrier circuit degradation | `DIA`/`DX` | `if_errors`/`optics_power_low` | SIG (owner=carrier) | ✅ `physical-degradation` |
| Cloud region / backbone degradation | `CLOUD_BACKBONE` | `probe_*` + `cloud_health_event` | SIG (owner=cloud_provider) | ✅ `cloud-region-degradation` |
| **DC→cloud on-ramp (Direct Connect / ExpressRoute) down/degraded** | `DX` | `dx_circuit_anomaly`/`bgp_adjacency_change`+`probe_*` | **SIG (emergent: DC edge → DX → cloud)** | ◻ |
| **DC↔cloud site-to-cloud VPN tunnel down/flap** | `VPN` | `tunnel_down`/`tunnel_degraded`+`probe_*` | SIG | ◻ (tunnel sig exists, not seam-bound) |
| **DCI (DC-to-DC interconnect) degradation** | `DX`/`CLOUD_BACKBONE` | `if_errors`/`probe_*`/`bgp_*` | SIG | ◻ |
| Cloud gateway / NAT-GW / TGW health event | `CLOUD_BACKBONE` | `cloud_gw_anomaly` | GEN (self-describing API event) | ◻ |

**Reading the matrix:** the engine is strong on L1/L3-routing/L4-path/DIA/cloud
(the shipped 15 + C5). The clear **gap clusters** are: (1) **DC overlay** (VXLAN/
EVPN — collection + emit both missing), (2) **L2 access** (VLAN/LACP/UDLD), (3)
**firewall/security plane** (P5 collection exists as research, not wired), (4)
**volumetric/DDoS** signature, (5) **TLS / tunnel-down**. Most gaps are `GEN`
(safe via §4 the moment generic ingestion lands); only a handful are `SIG`.

---

## 4. The safety net — generic-alarm ingestion (the keystone deliverable)

Today `syslog_control_signal` is a **classifier** (explicit BGP/OSPF/IS-IS/LINK/
LLDP/STP branches) and traps are an **allowlist**; an *unrecognized* device alarm
becomes a searchable OpenSearch log but **not** an RCA signal. That is why a
catalog gap currently *can* be a blind spot — and why we keep asking "do we need
a signature for X."

**Proposal: a generic alarm producer.** Any device-generated alarm at
severity ≥ warning (severity-tagged syslog, or an SNMP *alarm-class* trap) whose
envelope (`facility`, `event_type`, `severity`, named entity) parses becomes a
canonical `device_alarm` signal — **no per-mnemonic branch**. It carries:
`kind="device_alarm"`, `entity_type`/`entity_id` from the named device/interface,
`modality=control_plane`, severity from the device, and `attrs` preserving
facility/mnemonic/text. It then grounds + correlates + tiers like any other
signal.

Consequences:
- The whole long tail (incl. most VXLAN/EVPN device alarms) enters the engine for
  free — gaps become *visible incidents*, not blind spots (property A, §1).
- Signatures shrink to the **emergent-cause** cells only (the §2 rule), permanently
  retiring most "do we need a signature for X?" questions.
- Anti-noise guardrail is preserved by the severity floor + the existing
  grounding gate (an ungrounded lone alarm never forms an object) + storm-mode.

Design questions to settle (see §7): the severity floor; SNMP alarm-trap
classification (ALARM-MIB / vendor alarm OIDs vs the current high-value
allowlist); and whether `device_alarm` is a distinct `kind` or a family prefix.

---

## 5. Evidence-driven growth — closing the loop

The engine already emits `undetermined` objects (grounded clusters with no
matching signature) and a **catalog coverage report** concept exists
(rca-market-research.md:263 — "signal kinds no signature consumes = rule-base
blind spots"). Formalize two feeds:

1. **Undetermined-frequency report** — top recurring `undetermined` signatures by
   (entity-pattern, kind-set, frequency). Each row is a *candidate signature*,
   pre-prioritized by real recurrence. This is the backlog generator.
2. **Unconsumed-kind report** — signal kinds that no signature `requires`
   (rule-base blind spots) and signatures whose required kinds are never emitted
   (dead templates — the early-catalog failure mode). A CI check.

These convert "how do we know what's missing" from a guess into a **measured,
ranked report** the engine produces about itself.

---

## 6. Reconciliation with existing docs

- `telemetry-coverage-reference.md` (#73) — **Layer 2 (collect)**. This doc's
  "Collect" column references it; a `◻` there is a *collection* task tracked under
  #73, not a signature task. The two stay in lock-step: a `SIG` cell can't ship
  until its `Collect`+`Emit` are ✅.
- `correlation-engine.md` §4.4/4.5 — **the model + authoring**. This doc is the
  *coverage instance* of that model; it does not change the engine.
- `p5-firewall-telemetry.md` — the firewall-plane research feeding the L3/L4
  firewall rows.

---

## 7. Open decisions for sign-off

1. ~~**Scope of the matrix**~~ — **RESOLVED (owner, 2026-06-23): seams are IN.** The
   DC is a seam endpoint (talks to cloud + SP/DIA + remote sites across boundaries
   it doesn't own), so SP/DIA + cloud + the DC↔cloud seam (DX/ExpressRoute, VPN,
   DCI, CLOUD_BACKBONE) are modeled as the **SEAMS** section, owner-attributed. Not
   split out — seam attribution is core to the differentiator.
2. ~~**Keystone first?**~~ — **RESOLVED (owner, 2026-06-23): YES.** Build
   **generic-alarm ingestion (§4) + the self-coverage reports (§5) BEFORE any more
   signatures**, so every gap is immediately safe and the signature count stays
   minimal. This is P1 in §8.
3. **SNMP alarm-trap policy** — **RESOLVED (owner, 2026-06-23): MIB-driven.** Already
   the architecture (`collectors/mibs/` + `gen_index.py` + `make mib-index` →
   embedded `oidindex.go`; no runtime SMI parse). Add an **operator MIB-upload knob
   under the SNMP section** → platform MIB store → bounded/sandboxed compile job →
   hot-reloadable index overlay. Platform-global (`requirePlatformAdmin`), public
   reference data, untrusted-input bounded. MIBs = *enrichment* (name + severity),
   not an ingestion gate — un-MIB'd traps still ingest. **Still open:** the
   generic-alarm severity floor (§4 — warning vs notice).
4. **Overlay disposition** — overlay = VXLAN/EVPN + IPsec + GRE + generic tunnels
   (**SP tech out of scope for now**). Confirm the `SIG`s are the *emergent/impact*
   ones only — VTEP-unreachable (underlay→overlay), L2-loop-across-VTEPs, IPsec/
   tunnel cross-site impact, tunnel-MTU blackhole — and everything self-describing
   (VNI down, dup-MAC freeze, IKE mismatch, GRE recursive) is `GEN`. Far less than a
   signature-per-mnemonic. **RESOLVED (owner, 2026-06-23): confirmed.**
5. **Backlog ordering** — i.e. *in what order do we close the matrix's `◻` gaps?*
   **Recommended: hybrid.** A one-time, bounded **pre-seed** of the few obvious
   emergent overlay `SIG`s (VTEP-unreachable, L2-loop-across-VTEPs) — since you've
   flagged overlay as important and a lab won't manufacture those faults to be
   observed — then **evidence-driven** (§5 undetermined-frequency feed) as the
   steady-state ranker for everything after. Pre-seed = bounded exception; evidence
   = the rule, so we don't reopen the ad-hoc door. **RESOLVED (owner, 2026-06-23):
   hybrid confirmed.**

---

## 8. Proposed phased plan (post-agreement)

- **P0 — this doc signed off.** The matrix becomes the living coverage artifact
  (+ a TRACKER item).
- **P1 — generic-alarm ingestion** (§4) + the §5 reports. The safety net + the
  backlog generator. *Highest leverage; retires most open questions.*
- **P2 — overlay collection + emit** (Layer 2 for the VXLAN/EVPN column, under
  #73) so the overlay `SIG` cells become buildable.
- **P3 — the 2 overlay emergent signatures** + close top undetermined-frequency
  gaps as they surface.
- **P4 — L2-access + firewall-plane gaps**, prioritized by §5 evidence.

Nothing in P1–P4 is built until this doc is agreed.
