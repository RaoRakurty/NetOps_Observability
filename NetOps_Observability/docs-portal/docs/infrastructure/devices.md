---
title: Devices
sidebar_label: Devices
sidebar_position: 2
description: Read the device inventory, filter by health, open the per-device workspace, connect over SSH, and assign devices to sites.
---

# Devices

<kbd>Infrastructure → Devices</kbd> is the inventory: every discovered and declared device, with live reachability health, type, and source. The page refreshes itself every 30 seconds, so status is always current — you never need to reload.

## Read the page top to bottom

1. **The KPI strip** — four counters: **Inventory** (devices tracked), **Up**, **Degraded**, **Down**.
2. **Fleet composition** — four distribution bars derived live from the inventory: **By type**, **By manufacturer**, **By discovery source**, and **Site placement** (placed at a site vs. unplaced). Hover any segment for its exact count. Unplaced devices won't roll up into any site view — this bar tells you how much placement work remains.
3. **Device inventory** — the grid itself.

## Understand the status states

Every row carries a status dot before the device ID (hover it for the label). Health is three-state, computed from the device's last successful poll plus its active alerts:

| State | Dot | Meaning |
| --- | --- | --- |
| **Up** | green | Heartbeat fresher than 5 minutes and no active warning/critical alert |
| **Degraded** | amber | Heartbeat 5–15 minutes stale, **or** reachable but carrying an active warning/critical alert |
| **Down** | red | No heartbeat for more than 15 minutes |

A reachable-but-alerting device deliberately reads as *Degraded*, not healthy. The **Polled** column shows the age of the last poll (for example `3m ago`) and tints amber/red as the heartbeat goes stale.

## Search and filter

1. Click a health chip above the grid — **All**, **Up**, **Degraded**, or **Down** — to filter by state. Each chip shows its live count.
2. Type in the **Filter devices…** box to narrow by text. The filter matches across device ID, name, IP address, type, manufacturer, site, description, and source.
3. Click any column header marked sortable (Device, Name, Type, Manufacturer, Site, Polled) to sort; click again to reverse. The default sort is by manufacturer.

### The columns

- **Device** — the device ID, with the status dot. Click it (or anywhere on the row) to open the device workspace.
- **Name / IP address / Description** — display name, management address, and model or operating system as reported by the device.
- **Type** — the functional role inferred from SNMP: Router, Switch, Firewall, Load balancer, Access point, WLC, Cloud GW, or Generic (unclassified).
- **Manufacturer** — the vendor, with a stable color chip per vendor family.
- **Site** — the device's declared site (see [Assign a device to a site](#assign-a-device-to-a-site)).
- **Source** — how the device entered the inventory: **SNMP** (discovered), **Static** (from configuration), **Manual** (added by hand here), or an external source-of-truth connector.
- **Polled** — age of the last successful poll.

## Add a device manually

Discovery is the normal way in ([SNMP discovery](/onboard-devices/snmp-discovery)), but you can declare a device directly:

1. Click **+ Add device** (top right of the grid).
2. **Identity** step: enter a **Device ID** and **Address** (IP or hostname). Both are required — marked with a red asterisk.
3. **Classification** step: optionally set a **Display name** and **Vendor** (both can be changed later).
4. Click **Add device**. The row appears with source **Manual**.

To remove a device, use the **Delete** row action and confirm.

## Open the device workspace

Click any row. The full-page workspace opens with a breadcrumb, an identity header (type, address, vendor, last seen, and an **Up**/**Down** badge), and three tabs:

- **Overview** — a KPI strip (Reachability, Interfaces up, Interfaces down, BGP peers established, Traffic in, Traffic out) over four live charts: CPU usage, memory usage, and traffic in/out for the last two hours.
- **Interfaces** — the full Interface Performance board pre-scoped to this device: throughput and utilization, flapping, errors & discards, packet mix, and operational status over time.
- **Routing & neighbors** — three live views: topology neighbors (from discovered adjacencies), BGP peers with session state (idle → established), and OSPF neighbors with adjacency state (down → full). Each entry carries a green/red state dot.

Click **×** (or the dimmed backdrop) to return to the grid.

## Connect over SSH

If device login has been enabled by your administrator, each row shows a **Connect** action that opens an in-browser terminal:

1. Click **Connect** on the device's row.
2. Enter *your own* device credentials — a username (required) plus either a password or a private key (with optional passphrase). Change the port if the device doesn't listen on 22.
3. Click connect. Your credentials are sent once over the encrypted session to authenticate you to the device — they are **never stored** by the platform.
4. On first connect, a banner records the device's host key fingerprint; later sessions verify against it and warn if it changes.

:::note
No **Connect** button? The device login gateway is an opt-in feature — ask your administrator to enable it.
:::

## Assign a device to a site

Site placement is *intent* data that powers the [Device Geomap](/infrastructure/geomap) and site rollups.

1. First declare sites under <kbd>Infrastructure → Device Geomap → Sites</kbd> (see [Device Geomap](/infrastructure/geomap#declare-sites)).
2. Back on the Devices grid, open the dropdown in the **Site** column and pick a site — or **— Unassigned —** to clear it. The change takes effect immediately.

If an external source-of-truth system is the placement authority, the Site column is read-only here and placement is managed in that system ([Automation & Source of Truth](/automation/overview)).

## Troubleshooting

- **A device you expect is missing** — discovery hasn't found it. Check [SNMP discovery](/onboard-devices/snmp-discovery) scope and credentials, or add it manually.
- **Everything shows Down** — usually a collection problem, not a network one. Check <kbd>Infrastructure → Troubleshooting</kbd> (collector reachability) and [Verify monitoring](/onboard-devices/verify-monitoring).
- **"No devices yet — discovery hasn't returned anything."** — the honest empty state on a fresh install; run through [onboarding](/onboard-devices/overview) first.
