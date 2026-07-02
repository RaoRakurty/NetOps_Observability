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
| P2 | Storage migrations (7 relational models, RLS) + schema validation + topics | queued |
| P3 | Collectors: SNMP universal (IF/ENTITY/ENTITY-SENSOR MIB) + gNMI/OpenConfig streaming + vendor DOM adapters + trap/syslog events + audited CLI fallback | queued |
| P4 | Threshold policy engine + deterministic port-health scorer (weights above) + port_health_current | queued |
| P5 | API endpoints + response models | queued |
| P6 | UI surfaces (heatmap, explorer, detail tabs, fiber workbench, playbook drawer) | queued |
| P7 | RCA path-resolution integration (incident endpoints → port/lane/fiber-path) | queued |

Known vendor gaps to research in P3: Nokia DDM exposure granularity; coherent
PM availability per platform (Cisco/Arista enhanced DOM vs OpenConfig
terminal-device); QSFP-DD per-lane DOM variance across optics vendors;
laser-age exposure is rare.
