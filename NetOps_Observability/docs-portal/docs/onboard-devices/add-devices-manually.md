---
title: Add devices manually
sidebar_label: Add devices manually
sidebar_position: 4
description: Add individual devices by name and management address when discovery isn't the right fit.
---

# Add devices manually

When you have a handful of devices, or devices outside a scanned range, add them individually.

## Steps

1. Go to <kbd>Infrastructure → Devices</kbd>.
2. Click **Add device**.
3. Fill in the fields:
   - **Name** — a friendly identifier (e.g. `core-rtr-1`, `leaf1`).
   - **IP or hostname** — the device's management address.
   - **Optional** — site, vendor, and other hints. Leave blank to let Correlix fill them from SNMP.
4. Save.

Correlix starts polling immediately using the matching [SNMP credential](/onboard-devices/snmp-profiles) (per‑device if set, otherwise the default).

## What Correlix fills in

You only provide name + address. From SNMP, Correlix enriches the record with:

- vendor, model, OS version, serial, uptime,
- the interface list and IP addresses,
- neighbor relationships for the topology.

## Editing and organizing devices

From <kbd>Infrastructure → Devices</kbd> you can:

- **filter** the fleet, and open a device for its details,
- assign a device to a **site** (used for scoping and maps),
- see live **status** (up/down) and per‑device coverage.

## Bulk alternative

Adding more than a few? Use one of these instead:

- **[SNMP discovery](/onboard-devices/snmp-discovery)** — scan subnets.
- **[Source of Truth import](/automation/overview)** — seed the inventory from CSV/JSON/GeoJSON or sync with NetBox.

## Next

- **[Verify the device is monitored](/onboard-devices/verify-monitoring)**.
