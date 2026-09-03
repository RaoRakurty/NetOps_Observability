---
title: Inspect interfaces and optics
description: Read the fleet-wide interface table, switch column presets, open the detail drawer, and read the deterministic port-health score and its signature catalog.
page_type: task
sidebar_position: 3
---

# Inspect interfaces and optics

**Infrastructure → Interfaces & Optics** is the fleet-wide interface workbench, headed **Interfaces · Ports · Optics**. It separates the logical interface state from the physical transceiver state and presents both in one row, so a link that is administratively up while its optic is failing is visible without opening two tools.

## Before you begin

- `infrastructure:read` in your tenant. Every route below is filtered by the caller's tenant, and an interface id belonging to another tenant returns 404 rather than 403.
- Interfaces populate as the collectors poll devices over SNMP or gNMI.
- Transceiver diagnostics are opt-in. `FEATURE_PORT_DOM` defaults to `false`; where it is off, no optical power, temperature, voltage or bias series is collected at all.

## Steps

### Step 1 - Read the header and pick a preset

1. Read the header counters: total ports, degraded, critical, and RCA-attached.
2. Select one of the six column presets. Each preset is a fixed column list for one job:

| Preset | Columns it shows |
|---|---|
| **NOC** | Health, Device, Port, Description, Role, Seam, Admin, Oper, Speed, Dominant issue |
| **Troubleshooting** | Health, Device, Port, Admin, Oper, Speed, Dominant issue |
| **Optics / DDM** | Health, Device, Port, Form factor, Media, Vendor, Part #, Serial, Supported |
| **400G / 800G Lane** | Health, Device, Port, Form factor, Speed, Dominant issue |
| **Carrier Handoff** | Health, Device, Port, Seam, Role, Admin, Oper, Speed, Media, Dominant issue |
| **Inventory** | Device, Port, Form factor, Media, Vendor, Part #, Serial, Supported |

3. Narrow the table with the **Search device / port / vendor…** box, the **All seams** selector, or the **RCA attached** checkbox. The seam list is built from the rows you can see, so it never offers a filter that would return nothing.

### Step 2 - Read the port-health score

The **Health** column carries a score and a coloured state. The score is deterministic: the same evidence always yields the same number, so it is replay-stable and explainable. Every port starts at 100 and each dimension debits it by how far its evidence crosses the threshold policy. The dimension that took the largest debit becomes the row's **Dominant issue**.

| Dimension | Maximum debit |
|---|---|
| FEC and BER | 18 |
| Link state and flap | 15 |
| DOM absolute alarms | 12 |
| DOM margin | 10 |
| PCS, deskew and fault | 10 |
| Lane symmetry and divergence | 8 |
| Inventory and configuration | 8 |
| MAC/PHY corruption | 8 |
| Fiber-path consistency | 6 |
| Thermal and power | 5 |

The weights sum to 100, so a maximally broken port floors at 0. The score maps to four states: `ok` at 90 and above, `watch` at 70, `degraded` at 40, and `critical` below 40.

A dimension with no evidence takes no debit. A port that reports only link state therefore scores near 100, which is a statement about what was measured, not a clean bill of health for what was not.

### Step 3 - Open the detail drawer

Select a row. The drawer opens with four sections that keep the two planes apart:

- **Interface State**: admin, oper, speed, role, seam, LAG, breakout group, last change.
- **Transceiver Inventory**: form factor, media, vendor, part number, serial, supported status.
- **DDM / DOM**: optical power, temperature and bias, which stream from the metric plane once the collectors run against real optics hardware.
- **RCA Evidence**: the matched physical-layer signature and the dominant issue, or an explicit statement that no signature is attached along with the current score and state.

Every field that has no value renders as an em dash. A device that reports no transceiver data shows nothing in the transceiver and DDM sections. It never shows a zero, because zero optical power is a claim about the optic that nothing measured.

### Step 4 - Read the signature catalog

23 physical-layer signatures can attach to a port. They are served in a stable order by `/api/infrastructure/port-signatures`, each with an id, a name and the seams it applies to:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/infrastructure/port-signatures
```

```json
{"signatures":[{"id":"sig.ent.spdc.mpo-polarity-mismatch","name":"MPO polarity (Type A/B/C) mismatch","seams":"DC_FABRIC,CARRIER_INTERCONNECT"}, …]}
```

The catalog covers four families.

- **Multifiber and cabling**: MPO polarity, pinout and gender, row flip, missing fibers, dirty endface, broken strand, cassette mismatch.
- **Patch panel**: cross-connect error, label drift.
- **High-speed optics**: parallel-optic lane swap, PAM4 lane skew, per-lane BER divergence, QSFP-DD single-lane failure, OSFP incompatible part, high-power module thermal throttle, FEC masking a degrading link, PCS lane deskew failure.
- **Carrier and coherent**: DWDM mux and demux attenuation, channel frequency misalignment, ROADM filter-edge impairment, EDFA saturation or gain tilt, coherent OSNR degradation, CFP and OSFP vendor interoperability risk.

The catalog is the list of what *can* match. The wording of an actual match, its evidence and its confidence ride the live RCA object.

## What you see

The table lists your fleet's interfaces, and the header counters agree with `/api/infrastructure/port-summary`. On a lab with no optics collected, the honest answer is zero rather than a blank:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/infrastructure/port-summary
```

```json
{"by_state":{"critical":0,"degraded":0,"ok":0,"watch":0},"rca_attached":0,"total_ports":0}
```

With no rows, the table states why rather than going blank: `No interface/optics data yet. Ports populate as the collectors poll devices with SNMP/gNMI; optics (DDM) require transceivers that expose ENTITY-SENSOR-MIB or a vendor DOM MIB.`

The five routes behind the page:

| Route | What it returns |
|---|---|
| `GET /api/infrastructure/interfaces` | The paged table. Filters: `device`, `seam`, `role`, `media_type`, `form_factor`, `supported_status`, `oper_status`, `rca_attached`, `limit` (max 500), `offset`. |
| `GET /api/infrastructure/port-summary` | Fleet counts by health state plus the RCA-attached count. |
| `GET /api/infrastructure/module-types` | The closed taxonomies the filters and legends use: module families, media types, supported statuses, detection methods. |
| `GET /api/infrastructure/port-filter-options` | The distinct device, seam, role, media, form-factor and vendor values present in your own fleet. |
| `GET /api/infrastructure/port-signatures` | The 23-entry signature catalog. |

`GET /api/infrastructure/interfaces/{device}:{port}` returns one row for the drawer, and `/path` on that id resolves the port to its fiber path and far endpoint.

## Related

- [Work with the device inventory](/infrastructure/devices) for the devices these interfaces belong to.
- [Feature flags](/reference/feature-flags) for `FEATURE_PORT_DOM`.
- [Built-in dashboards](/dashboards-reports/built-in-dashboards) for the Interface Metrics board, which charts the same interfaces over time.
