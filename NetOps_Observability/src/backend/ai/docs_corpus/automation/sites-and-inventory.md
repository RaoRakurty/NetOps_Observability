---
title: Sites & inventory
sidebar_label: Sites & inventory
sidebar_position: 2
description: Create sites, assign devices to them, and drive the geographic map from declared intent.
---

# Sites & inventory

Sites are the unit of *declared* network geography: a name, an optional status and owner, and WGS 84 coordinates. Devices assigned to a site inherit its location, fold into one bubble on the [Device Geomap](/infrastructure/geomap), and roll their health up to the site.

## Before you begin

- You need **infrastructure write** permission in your tenant.
- Devices should already be onboarded (see [Onboard devices](/onboard-devices/overview)) — you can declare sites first, but placement only shows once devices exist.
- Have decimal latitude/longitude for each location (e.g. `32.78, -96.80`). Correlix never uses GeoIP; if you don't declare coordinates, the site won't appear on the map.

## Create a site

1. Go to <kbd>Infrastructure → Device Geomap</kbd>.
2. Select the **Sites** view (the segmented control at the top; if no sites exist yet, click **Declare sites** on the empty state instead).
3. In the last table row, fill in the new-site fields:

   | Field | Required | Notes |
   |---|---|---|
   | **Site** | Yes | Display name, up to 120 characters (e.g. `Dallas Branch`). A URL-safe **slug** is generated automatically (`dallas-branch`) and shown read-only. |
   | **Status** | No | Free text, e.g. `active`. |
   | **Owner** | No | Team or business unit responsible, up to 120 characters (e.g. `NetEng NOC`). |
   | **Latitude** / **Longitude** | No | Decimal WGS 84. Enter **both or neither** — latitude −90…90, longitude −180…180. Leave both blank to register a site that isn't on the map yet. |

4. Click **Add site**. The site appears in the table with its generated slug.

::::info The slug is the site's stable handle
Device → site assignments, file imports, and the `site` device label all reference the **slug**, not the display name. It is derived from the name at creation and shown in the Sites table.
::::

## Edit or delete a site

1. In <kbd>Infrastructure → Device Geomap → Sites</kbd>, find the site's row.
2. Click **Edit**, change the name, status, owner, or coordinates, then click **Save** (or **Cancel**).
3. To remove a site, click **Delete** and confirm. Devices assigned to that site fall back to *unplaced* — they aren't deleted, they just leave the map until reassigned.

Coordinates are attached to the **site**, so moving a site (fixing a wrong latitude, say) instantly moves every device assigned to it.

## Assign devices to sites

1. Go to <kbd>Infrastructure → Devices</kbd>.
2. Find the device row and open the **Site** column — it's an inline picker listing your declared sites.
3. Pick the site. The assignment saves immediately; the device inherits the site's coordinates and rolls into its map bubble.
4. To unassign, select **— Unassigned —** in the same picker.

Alternatives to the picker:

- **Bulk**: import a *Device → site placement* file — see [Import & external sync](/automation/import-and-sync).
- **Label**: give the device a `site` label whose value matches the site's slug; it folds into that site the same way.

::::info When the Site column is read-only
The picker is editable only while the internal Source of Truth is the active provider and at least one site is declared. If an external provider currently supplies sites, they are managed in that system.
::::

## Set a location for a device without a site

For one-off devices that don't belong to a declared site:

1. Go to <kbd>Infrastructure → Device Geomap</kbd> and select **Set locations**.
2. Unplaced devices are listed first. For a device, enter a free-form **Site label**, decimal **Latitude**, and **Longitude** (all in the row), then click **Save**.
3. Devices sharing the same label fold into one map bubble. Click **Clear** to remove a manual placement.

Rows whose placement reads **Source of Truth · &lt;site&gt;** are read-only here — their coordinates come from the site definition and win by precedence. Edit the site instead.

## How sites drive the geographic map

On the **Map** view of the [Device Geomap](/infrastructure/geomap):

- Each site with coordinates renders as a bubble; **size** reflects device count.
- **Color** reflects health: green when all devices are up, amber when some are down, red when all are down, grey when the site has no devices.
- Hovering a bubble shows the site name plus its up/down device counts.

## Verify

1. Open <kbd>Infrastructure → Device Geomap</kbd> (Map view).
2. Check the stat strip: **Sites**, **Sites on map**, **Devices placed**, and **Unplaced devices** should match what you declared. Unplaced devices are highlighted when any remain.
3. Confirm each site bubble sits where you expect and its tooltip shows the right device count.
4. In the **Sites** table below the map, confirm **Coordinates** is set (not `not set`) for every site you want plotted.

## Troubleshooting

- **A site doesn't appear on the map** — it has no coordinates. Edit the site and add both latitude and longitude (decimal WGS 84).
- **"Enter both latitude and longitude as decimals (WGS 84), or leave both blank."** — you filled only one coordinate, or used a non-numeric value (e.g. `32°46'N`). Convert to decimal degrees.
- **A device shows as unplaced** — it has no site assignment and no manual location, or it's assigned to a site that no longer exists. Reassign it in <kbd>Infrastructure → Devices</kbd>.
- **A device sits in the wrong place** — its site's coordinates are wrong (fix the site), or a stale manual location overrides expectations (**Set locations** → **Clear**).
- **The empty map says "No sites have coordinates yet."** — you have sites but none carries coordinates; the map fills in only from declared intent.
