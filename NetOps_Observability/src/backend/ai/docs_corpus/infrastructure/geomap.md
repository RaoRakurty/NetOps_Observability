---
title: Place devices on the map
description: Create sites with coordinates, place devices on them, set a one-off location, and read the per-site health rollup.
page_type: task
sidebar_position: 5
---

# Place devices on the map

**Infrastructure → Sites** plots the fleet on a world map. Placement is declared intent: sites you create with coordinates, and devices you assign to them. GeoIP is never used, because a private management address does not geolocate. The map therefore shows exactly what you declared and nothing it guessed.

## Before you begin

- `infrastructure:write` in your tenant to create sites or place devices. Reading the map needs `infrastructure:read`.
- Decimal WGS 84 coordinates for each location, for example `32.78, -96.80`. A site without both values is registered but is not drawn.
- Devices onboarded, so there is something to place. See [Work with the device inventory](/infrastructure/devices).

The page has three tabs. The on-page control labels them **Map**, **Sites** and **Set locations**; the navigation flyout lists the same three as Map, Manage Sites and Set Locations, and each is deep-linkable.

## Steps

### Step 1 - Declare sites {#declare-sites}

1. Go to **Infrastructure → Sites** and select the **Sites** tab.
2. In the entry row at the bottom of the table, enter a **Site** name. This is the only required field.
3. Optionally set a **Status**, an **Owner**, and **Latitude** and **Longitude** as decimal WGS 84. Enter both coordinates or neither.
4. Select **Add site**. A URL-safe slug is generated from the name and shown read-only.
5. Use **Edit** and **Delete** on any row to maintain it. Deleting a site returns its devices to unplaced rather than deleting them.

The slug, not the display name, is the site's stable handle. Device-to-site assignments, file imports and the `site` device label all reference it.

Coordinates belong to the site, so correcting a wrong latitude moves every device assigned to it at once.

### Step 2 - Place devices on a site

1. Go to **Infrastructure → Devices**.
2. Open the picker in the **Site** column and choose the site. The assignment saves immediately and the device inherits the site's coordinates.
3. To unassign, choose `— Unassigned —` in the same picker.

Two alternatives to the picker: give the device a `site` label whose value matches the slug, or import a device-to-site placement file, described in [Import inventory from a source of truth](/automation/import-and-sync).

### Step 3 - Set a one-off location

For a device that belongs to no declared site:

1. Select the **Set locations** tab. Unplaced devices are listed first, so the tab doubles as a work queue.
2. Enter a free-form **Site label**, a decimal **Latitude** and a **Longitude** on the device's row, then select **Save**.
3. Devices sharing a label fold into one bubble. Select **Clear** to remove a manual placement.

A row whose placement came from a declared site is read-only here. Its coordinates come from the site definition and win by precedence, so edit the site instead.

### Step 4 - Read the map

1. Select the **Map** tab.
2. Read the stat strip: **Sites**, **Sites on map**, **Devices placed**, **Unplaced devices**, **Up**, **Down**. A non-zero **Unplaced devices** count is the remaining placement work, because an unplaced device rolls up into no site.
3. Read the bubbles. Size is the device count at the site. Colour is the health rollup: green when every device is up, amber when some are down, red when all are down, and grey when the site has no devices at all.
4. Hover a bubble for the site name and its up and down counts. Drag to pan, scroll to zoom.
5. Read the **Sites** table below the map. It lists Site, Status, Coordinates, Devices and Health, including sites whose coordinates read `not set`.

To go from a site to its devices, open **Infrastructure → Devices** and filter on the site name, then select a row to [open the device workspace](/infrastructure/devices#open-the-device-workspace).

## Result

Each site you declared with coordinates is a bubble in the right place, its tooltip shows the device count you expect, and **Unplaced devices** is zero for the devices you care about.

Before any site exists, the page states why instead of drawing an empty world, and `/api/geomap` says the same thing:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/geomap
```

```json
{"geo_enabled":false,"reason":"sot"}
```

The page then offers **Declare sites** and **Set device locations** directly. Two other honest states are worth recognising: a site with no coordinates is listed but not drawn, and a grey bubble means the site exists with no devices assigned, not that its devices are down.

## Related

- [Work with the device inventory](/infrastructure/devices) for the **Site** column that does the placing.
- [Import inventory from a source of truth](/automation/import-and-sync) for seeding sites and placements from a file.
- [Keep sites and inventory in sync](/automation/sites-and-inventory) for when an external system owns the record.
