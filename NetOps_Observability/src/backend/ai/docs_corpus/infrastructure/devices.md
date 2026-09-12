---
title: Work with the device inventory
description: Read three-state device health, filter the fleet, open the per-device workspace, connect over SSH, and assign a device to a site.
page_type: task
sidebar_position: 2
---

# Work with the device inventory

**Infrastructure → Devices** is the fleet of record: every discovered and declared device with live reachability health, type and discovery source. The page is headed **Inventory & Devices** and refreshes itself every 30 seconds.

## Before you begin

- `infrastructure:read` in your tenant. Every list is filtered to your tenant before it is returned.
- `infrastructure:write` to add or delete a device, or to change site placement.
- At least one device onboarded. On a fresh install the grid reads `No devices yet — discovery hasn't returned anything.` See [SNMP discovery](/onboard-devices/snmp-discovery).

## Steps

### Step 1 - Read the page top to bottom

1. Read the KPI strip: **Inventory** (devices tracked), **Up**, **Degraded**, **Down**.
2. Read the four **Fleet composition** bars: **By type**, **By manufacturer**, **By discovery source**, and **Site placement**. Hover a segment for its exact count.
3. Read the grid. Health is three-state, computed from the last successful poll plus the device's active alerts.

| State | Dot | What it means |
|---|---|---|
| Up | green | Heartbeat fresher than 5 minutes and no active warning or critical alert. |
| Degraded | amber | Heartbeat 5 to 15 minutes stale, or reachable while carrying an active warning or critical alert. |
| Down | red | No heartbeat for more than 15 minutes. |

A reachable device that is alerting reads as *Degraded*, never as healthy. When the alert read itself fails, the **Degraded** tile says `stale heartbeat only` instead of `stale or alerting`, so a partial answer is never presented as a whole one.

### Step 2 - Filter and sort

1. Select a health chip above the grid: **All**, **Up**, **Degraded** or **Down**. Each chip carries its live count.
2. Type in the **Filter devices…** box. The filter matches device id, name, address, type, manufacturer, site, description and source.
3. Select a sortable column header to sort, and select it again to reverse.

The columns are **Device**, **Name**, **IP address**, **Type**, **Manufacturer**, **Site**, **Description**, **Source** and **Polled**. **Type** is inferred from SNMP. **Source** is how the device entered the inventory: SNMP discovery, static configuration, a manual entry, or a connector. Controllers and access points discovered by a wireless connector appear here too, with type `wlc` or `ap` and source `wireless`.

### Step 3 - Add a device by hand {#add-a-device-manually}

Discovery is the normal way in. To declare one directly:

1. Select **+ Add device**.
2. On the identity step, enter a **Device ID** and an **Address**. Both are required.
3. On the classification step, optionally set a display name and a vendor. Both can be changed later.
4. Select **Add device**. The row appears with source **Manual**.

To remove a device, use the row's **Delete** action and confirm.

### Step 4 - Open the device workspace {#open-the-device-workspace}

Select any row. The workspace opens with an identity header and three tabs:

- **Overview**: a KPI strip (reachability, interfaces up, interfaces down, BGP peers established, traffic in, traffic out) over live CPU, memory and traffic charts.
- **Interfaces**: the Interface Performance board pre-scoped to this device.
- **Routing & neighbors**: topology neighbors from discovered adjacencies, BGP peers with session state, and OSPF neighbors with adjacency state.

Select the close control or the dimmed backdrop to return to the grid.

### Step 5 - Connect over SSH

The device-login gateway is opt-in (`FEATURE_DEVICE_SSH`) and dormant by default. Where an administrator has enabled it, each row carries a **Connect** action:

1. Select **Connect** on the device's row.
2. Enter your own device credentials: a username plus either a password or a private key with an optional passphrase. Change the port if the device does not listen on 22.
3. Start the session. The credentials authenticate you to the device and are never stored by Correlix.
4. On the first connection the device's host-key fingerprint is recorded. Later sessions verify against it and warn when it changes.

### Step 6 - Assign a device to a site {#assign-a-device-to-a-site}

Site placement is declared intent. It drives the map and the per-site health rollup.

1. Declare the site first under **Infrastructure → Sites**. See [Declare sites](/infrastructure/geomap#declare-sites).
2. Back on the grid, open the picker in the **Site** column and choose a site, or `— Unassigned —` to clear it. The change saves immediately.

The picker is editable only while the internal source of truth supplies sites and at least one site exists. Where an external system is the placement authority, the column is read-only and placement is managed there. See [Automation and source of truth](/automation/overview).

## Result

The KPI strip totals match the fleet you expect, every device you operate carries a status dot that matches reality, and the **Site placement** bar shows no unplaced devices you care about. The same rows are served by `/api/devices`:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/devices
```

```json
[
  {
    "id": "spine1",
    "name": "spine1",
    "address": "172.40.40.11",
    "vendor": "nokia",
    "os": "SR Linux",
    "type": "switch",
    "tenant_id": "t_d3d501aa08e2395893b378a453b8af67",
    "source": "manual",
    "last_seen": "2026-09-03T02:58:15.80813818Z"
  },
  {
    "id": "spine2",
    "name": "spine2",
    "address": "172.40.40.12",
    "vendor": "nokia",
    "os": "SR Linux",
    "type": "switch",
    "tenant_id": "t_d3d501aa08e2395893b378a453b8af67",
    "source": "manual",
    "last_seen": "2026-09-03T02:58:15.839914873Z"
  }
]
```

Every response carries the true fleet total, so a page is never mistaken for the whole fleet. Add `?envelope=1` to read that total in the JSON body instead of the headers.

## Related

- [Inspect interfaces and optics](/infrastructure/interfaces-and-optics) for the per-interface view of the same fleet.
- [Place devices on the map](/infrastructure/geomap) for declaring the sites this page assigns.
- [Verify monitoring](/onboard-devices/verify-monitoring) when every device reads Down, which is usually a collection fault rather than a network one.
