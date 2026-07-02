# Port Intelligence / Physical-Layer Observability (owner design, 2026-07-02) — #94

Service-provider-grade physical-layer module for DC + carrier-handoff: classic
SFP/SFP+/SFP28 through QSFP+/QSFP28/QSFP56/QSFP-DD/OSFP, 100G–800G workflows.

## Core model & source rules (owner, binding)

- Layered port object: **PORT → TRANSCEIVER → LANE(S) → OPTICAL_CHANNEL →
  LOGICAL_CHANNEL → FIBER_PATH.**
- Source preference: **gNMI/OpenConfig streaming first**; SNMP IF-MIB /
  ENTITY-MIB / ENTITY-SENSOR-MIB as the universal fallback; vendor adapters
  (Juniper DOM MIB, Nokia DDM, Cisco/Arista enhanced DOM + coherent PMs);
  syslog/trap events; **CLI only as last-resort fallback (audited)**.
- Distinguish supported / third-party / unsupported transceivers.
- **Cardinality law:** serials/part numbers/panel IDs/circuit IDs/path
  components live in relational/event storage — NEVER default TSDB labels.
  Fast-changing numerics live in time-series.

## Normalized source families

1. **Interface identity/hierarchy:** ifIndex/ifName/ifDescr/ifAlias,
   admin+oper, ifHighSpeed, connector-present, lastChange; ifStack; LAG
   membership; breakout parent↔child.
2. **Inventory:** vendor/OUI/PN/serial/rev/firmware; form factor, media,
   optic type, connector, power class; supported status.
3. **DOM/DDM:** temp/voltage/TX-bias/TX-power/RX-power + module thresholds;
   per-lane TX/RX/bias; laser age where exposed.
4. **FEC/BER/PCS:** corrected + uncorrectable counters, pre-FEC BER, post-FEC
   BER; PCS deskew / local-fault / remote-fault / hi-BER.
5. **Coherent PM:** OSNR, ESNR, CD, DGD, PDL, carrier-frequency offset,
   optical frequency; mode descriptor metadata (min-rx-osnr, min/max input
   power, pre-FEC threshold).
6. **Fiber-path metadata (relational):** panel, cassette, jumper, polarity
   method, connector gender, circuit id, mux/demux id, amplifier id.

## Storage models

Relational: `port_inventory_current`, `transceiver_inventory_current`,
`port_lane_current`, `fiber_path_inventory`, `port_neighbor_current`,
`port_event_log`, `port_health_current` (all tenant-RLS per §3a).
TSDB families: port counters, optics, lane metrics, fec/ber, coherent PM.
Schema validation on: inventory payloads, lane payloads, coherent PM payloads,
physical path objects, events.

## Deterministic port-health scoring (owner weights)

link-state/flap 15 · inventory/config compat 8 · DOM absolute 12 · DOM margin
10 · lane symmetry/divergence 8 · **FEC/BER 18** · PCS/deskew/fault 10 ·
MAC/PHY corruption 8 · fiber-path consistency 6 · thermal/power envelope 5.

## Threshold policy objects (vendor-aware + fallback heuristics)

rx/tx_margin_low_warn_db, temperature_margin_high_warn_c,
voltage_margin_threshold_v, bias_growth_ratio,
pam4_prefec_ber_{watch,degraded,critical}, postfec_ber_{watch,degraded,critical},
corrected_fec_rate_vs_baseline, uc_words_policy, lane_divergence_ratio,
flap_rate_policy, coherent_osnr_margin_db, coherent_input_power_margin_db,
fiber_path_budget_headroom_db.

## Topics / API / UI (owner contract)

Topics: net.port.{inventory,metrics,lanes,optical,events,health} (map to
existing bus conventions). API: /api/port-intelligence/{summary, ports,
ports/{id}, ports/{id}/timeseries, ports/{id}/diagnose, transceivers,
transceivers/changes, fiber-paths/{path_id}, fiber-paths/validate (POST),
signatures/catalog}. UI: fleet heatmap (site/pod/rack/handoff), lane-aware
port explorer, port detail tabs (Overview/Counters/Optics/Lanes/FEC-BER-PCS/
Coherent/Fiber Path/Events/RCA Evidence), fiber-path workbench (MPO lane-map
viz, polarity/connector checks, fault domain), guided NOC playbook drawer
(operator vs manager voice).

## Security / RCA integration (binding)

Tenant-scoped RLS everywhere; no cross-tenant path joins; credentials by
secret reference only; CLI fallback audited; raw EEPROM suppressed from
standard APIs. Correlation attaches sig.spdc.* as supporting/discriminating
evidence; path resolution maps incident endpoints → port/lane/fiber-path.
**Root cause never confirmed without ≥2 independent modalities + path
grounding + no contradiction** — the 23 sig.spdc entries additionally carry
`allow_root_cause_confirmed:false` (physical-layer look-alikes: cap at
suspected/likely until a human or fiber-path validation corroborates).

## Phase plan (status)

| Phase | Scope | Status |
|---|---|---|
| **P1** | 23 sig.spdc.* catalog entries + new Template fields (score_impact, next_checks, allow_root_cause_confirmed w/ tier cap in scorer) + 20 fx_* fixtures + drill integration | ✅ shipped this session |
| **P2** | Storage: migration 0019 (7 RLS models) + `portintel` domain pkg (enums, validated payloads, module-detection resolver, topics) | ✅ shipped `8774005` |
| P3 | Collectors: SNMP universal (IF/ENTITY/ENTITY-SENSOR MIB) + gNMI/OpenConfig streaming + vendor DOM adapters + trap/syslog events + audited CLI fallback | queued |
| P4 | Threshold policy engine + deterministic port-health scorer (weights above) + port_health_current | queued |
| P5 | API endpoints + response models | queued |
| P6 | UI surfaces (heatmap, explorer, detail tabs, fiber workbench, playbook drawer) | queued |
| P7 | RCA path-resolution integration (incident endpoints → port/lane/fiber-path) | queued |

Known vendor gaps to research in P3: Nokia DDM exposure granularity; coherent
PM availability per platform (Cisco/Arista enhanced DOM vs OpenConfig
terminal-device); QSFP-DD per-lane DOM variance across optics vendors;
laser-age exposure is rare.

## UI design (owner, 2026-07-02) — P6, ENHANCE the existing page

**Binding navigation constraint (owner):** do NOT create a new
Monitor→Network→Interfaces&Ports path. Enhance the EXISTING
**Infrastructure → Devices → Interfaces** page (`InterfacePerformance.tsx` +
the device drill) into the workbench. Preserve the current Correlix nav model,
design tokens, and table components; persist user view prefs if the UI supports
it.

**Internal hierarchy:** Site → Rack/Row → Device → Slot/Linecard → Port Group →
Physical Port → Logical Interface → Transceiver → Lane(s) → Optical Channel →
Fiber Path → Neighbor. **Principle: separate logical interface state from
physical port/transceiver state, presented together.** A logical iface can be
up while the optic degrades; a physical port has many logical children /
breakout lanes / LAG / optical channels.

**Six column-preset views** (NOT one mega-table): NOC · Troubleshooting ·
Optics/DDM · 400G/800G Lane · Carrier Handoff · Inventory. Full per-view column
lists + the filter set (site/device/vendor/model/role/seam/status/speed/media/
form-factor/module-type/optic-pmd/connector/part/supported/dom-status +
boolean chips: low_rx_power, high_tx_bias, high_temperature, high_crc,
high_fec, fec_uncorrectable, flapping, carrier_handoff, cloud_interconnect,
lag_member, breakout_port, rca_attached) are captured in the owner spec
(chat 2026-07-02, mirror into components when P6 builds).

**Row → right-side detail drawer** with 10 sections: Interface State · Traffic
Counters · Ethernet Health · Transceiver Inventory · DDM/DOM · Lane
Diagnostics · FEC/PCS/BER · Neighbor/Physical Path · Events · RCA Evidence.
(RCA Evidence section binds directly to the sig.ent.spdc.* output shipped in
P1: matched_signature_id/name, confidence, operator_phrase, manager_phrase,
evidence supporting/missing/contradicting, next_check, correlation_id.)

**Module-detection enums** (normalize, do NOT trust description text — derive
from part number / EEPROM-CMIS / OpenConfig transceiver / ENTITY-MIB /
ENTITY-SENSOR / vendor OIDs / speed / connector / lane count / wavelength /
PMD app-code): module families (legacy GBIC..CDFP, SFP..SFP-DD, QSFP..
QSFP-DD1600, OSFP..OSFP-XD, coherent CFP2-DCO/ZR/800ZR/1600ZR, cables
DAC/AOC/AEC/ACC/copper), media type, optic PMD (SX..DWDM/BiDi/CR), connector
(RJ45/LC/MPO-8..24/MTP/CS/SN/MDC). These belong in a shared
`portTypes.ts`/`porttypes.go` enum + a detection resolver.

**API (P5, enhance existing Infra/Devices/Interfaces convention):**
`/api/infrastructure/{devices, devices/{id}, devices/{id}/interfaces,
interfaces, interfaces/{id}, interfaces/{id}/lanes, interfaces/{id}/ddm,
interfaces/{id}/events, transceivers, transceivers/changes, module-types,
filter-options}` — tenant-scoped, PBAC/RLS, server-side pagination, searchable.

**Acceptance criteria** (owner) recorded for P5/P6 sign-off: existing page
stays canonical; view switching; the full filter set; DDM in table + drawer;
module detection across all families incl. unknown; distinguish congestion vs
physical impairment; worst-lane health for 400/800G; neighbor + physical path;
RCA attaches iface/port/optic/DDM/FEC/lane evidence; tests for module
detection, DDM normalization, filters, tenant isolation, detail-response shape.
