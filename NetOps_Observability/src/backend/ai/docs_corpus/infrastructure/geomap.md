---
title: Device Geomap
sidebar_label: Device Geomap
sidebar_position: 4
description: See sites and devices on a world map, declare and import sites, and set device locations.
---

# Device Geomap

The **Device Geomap** (<kbd>Infrastructure → Device Geomap</kbd>) places your fleet on a world map so distributed networks are easy to reason about geographically. Placement is **intent data**: sites you declare with coordinates, and devices you assign to those sites. GeoIP is never used — private management addresses don't geolocate, so the map only ever shows what you've declared.

The page has three views, switched by the selector at the top: **Map**, **Sites**, and **Set locations**.

## Read the map

1. Open <kbd>Infrastructure → Device Geomap</kbd> (the **Map** view is the default).
2. Check the stat strip: **Sites**, **Sites on map** (those with coordinates), **Devices placed**, **Unplaced devices**, **Up**, **Down**. A non-zero *Unplaced devices* count is your to-do list — unplaced devices appear in no site rollup.
3. Read the bubbles. Each site with coordinates is one bubble:
   - **Size** — device count at the site.
   - **Color** — the health rollup: green when all devices are up, amber when some are down, red when *all* are down, grey when the site has no devices.
4. **Hover** a bubble for the rollup tooltip: site name, device count, up/down split. Drag to pan and scroll to zoom.
5. Below the map, the **Sites table** lists every site with Status, Coordinates, Devices, and Health (`N up · N down`) — including sites not yet on the map (coordinates "not set").

### Drill from a site to its devices

The map rolls health up; the device-level detail lives in the inventory:

1. Note the site name from the bubble or the Sites table.
2. Open <kbd>Infrastructure → Devices</kbd> and sort or filter the **Site** column by that name (the filter box matches site names too).
3. Click a device row to open its workspace — see [Devices](/infrastructure/devices#open-the-device-workspace).

## Declare sites

Sites are created in the **Sites** view — the platform's own source-of-truth site registry (badge: *Source of truth*).

1. Switch to **Sites**.
2. In the entry row at the bottom of the table, type a **Site name** (required — e.g. `Dallas Branch`), and optionally a **Status** (e.g. `active`), an **Owner** (e.g. `NetEng NOC`), and **Latitude** / **Longitude** as decimal WGS 84 (e.g. `32.78`, `-96.80`).
3. Click **Add site**. A URL-safe **slug** is generated automatically — devices can also be folded into a site by carrying a `site` label matching this slug.
4. Use **Edit** / **Delete** on any row to maintain it. Coordinates may be left blank to register a site that isn't on the map yet; it still works for rollups. Deleting a site returns its devices to *unplaced*.

Then assign devices to your sites from <kbd>Infrastructure → Devices</kbd> (the **Site** column) — see [Assign a device to a site](/infrastructure/devices#assign-a-device-to-a-site). Devices inherit their site's coordinates and fold into its bubble.

:::note
If an external source-of-truth system is the active authority, the Sites view is read-only here and site data is managed in that system — see [Automation & Source of Truth](/automation/overview).
:::

### Import sites in bulk

To seed sites (or device→site placements) from an existing system:

1. In the **Sites** view, click **Import…**.
2. Choose what to import — **Sites** or **Device → site placement** — and the format: **CSV**, **JSON**, or (for sites) **GeoJSON**.
   - Sites columns: `name`, `slug` (optional), `status`, `owner`, `latitude`, `longitude`. GeoJSON: a FeatureCollection of Point features (coordinates are `[lng, lat]`).
   - Placement columns: `device` (ID, hostname, management IP, or serial — matched against discovered devices) and `site` (slug).
3. Upload the file or paste its contents. Tick **Overwrite existing** only if the import should *change* existing rows, not just add new ones.
4. Click **Preview** — a dry run showing per-row actions (create / update / skip / conflict / error) with nothing written yet.
5. Review the plan, then click **Apply**.

The import is a one-way seed of intent: live discovery always stays authoritative for what actually exists.

## Set a location on a single device

The **Set locations** view lists every device with its placement provenance:

- Devices placed via a **declared site** are read-only here — their coordinates come from the site (edit the site instead).
- For anything else, type a free-form **Site label** plus decimal **Latitude** / **Longitude** and click **Save**. Devices sharing a label fold into one bubble. **Clear** removes a manual placement.

Unplaced devices are listed first, so the view doubles as a work queue.

## First run

On a fresh install the page explains itself instead of showing an empty map: it offers **Declare sites** and **Set device locations** buttons directly. Follow either path above and the map fills in from intent data.

## Troubleshooting

- **"No sites have coordinates yet."** — sites exist but lack latitude/longitude; edit them in the **Sites** view.
- **A device isn't on the map** — it's unplaced. Assign it a site (<kbd>Infrastructure → Devices</kbd> → Site column) or set a manual location.
- **A site bubble is grey** — the site has no devices assigned; the site exists but nothing rolls up into it yet.
