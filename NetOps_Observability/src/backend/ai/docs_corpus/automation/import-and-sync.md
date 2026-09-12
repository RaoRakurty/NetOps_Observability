---
title: Import inventory from a source of truth
description: Import sites and device-to-site placement from a CSV, JSON or GeoJSON file, read the dry-run reconcile plan, and apply it.
page_type: task
sidebar_position: 3
---

# Import inventory from a source of truth

The import panel takes a file that already holds your site list or your device placement and seeds the internal record with it, in one pass, with a mandatory dry run first. It is a one-way seed of declared intent. Live discovery stays authoritative for what actually exists.

For the ongoing connector instead of a file, see [Keep sites and inventory in sync](/automation/sites-and-inventory).

## Before you begin

- `infrastructure:write` in your tenant. Records are stamped from the authenticated principal, never from the payload, and an import can never write into another tenant.
- For a placement file, the sites must already exist. A binding to an unknown slug is rejected per row.
- A file of at most 1 MiB of text, which is thousands of rows.

### Site file columns

Accepted as CSV, JSON or GeoJSON.

| Column or key | Required | Header aliases | Notes |
|---|---|---|---|
| `name` | Yes | `site`, `site_name` | The display name. |
| `slug` | No | none | The stable handle. Generated from the name when omitted. |
| `status` | No | none | Free text, for example `active`. |
| `owner` | No | `team`, `owner_team` | The responsible team. |
| `lat` / `lng` | No | `latitude` / `lon`, `longitude` | Decimal WGS 84. Both or neither, per row. |

CSV takes the header row first and ignores column order. JSON is an array of site objects. GeoJSON is a `FeatureCollection` of `Point` features whose `name`, `slug`, `status` and `owner` are read from each feature's properties, and whose coordinates are `[longitude, latitude]`, longitude first, per the standard.

### Placement file columns

Accepted as CSV or JSON.

| Column or key | Required | Header aliases | Notes |
|---|---|---|---|
| `device` | Yes | `device_id`, `host`, `hostname`, `name`, `ip`, `address`, `serial` | Any stable identifier. |
| `site` | Yes | `site_slug`, `slug` | The target site's slug. |

A device row is matched against the inventory you can see, in this order: exact id, then serial, then management address, then hostname. Serial comes before address because an address is not a stable identity. A device in another tenant does not match, which is how a cross-tenant write is made structurally impossible rather than merely refused.

## Steps

1. Go to **Infrastructure → Sites** and select the **Sites** tab.
2. Select **Import…** in the Sites card header.
3. Choose the kind: **Sites** or **Device → site placement**.
4. Choose the format, then choose the file or paste its contents. Choosing a `.csv`, `.json` or `.geojson` file sets the format for you.
5. Leave **Overwrite existing** unchecked for a first pass. The import is then non-clobbering: it creates new records only.
6. Select **Preview**. This is a dry run. The plan is computed and nothing is written.
7. Read the plan, described below. Any edit to the file or the overwrite box clears the plan, so you always apply exactly what you last previewed.
8. Select **Apply**. Apply stays disabled until you have previewed, because the dry run is mandatory.

### Reading the reconcile plan

The plan shows per-action counters and a per-row table of the source line, the key matched, the action and a detail.

| Action | What it means | Written on Apply |
|---|---|---|
| `create` | Nothing matched. A new record will be created. | Yes |
| `unchanged` | An existing record matched and is already identical. | Nothing to do |
| `conflict` | An existing record matched and the row would change it. The detail names what, for example `exists; would change coordinates (enable overwrite to apply)`. | No, unless overwrite is on |
| `update` | Overwrite is on. The detail lists the changed fields, or a rebind from the old site to the new one for a placement. | Yes |
| `error` | The row is invalid and is never applied. Fix the row. | No |

An import preserves an existing value where the row is blank, and never reassigns a record's owning tenant.

Two error details are worth recognising:

- `no visible device matches "…"` means the identifier matched nothing in your tenant by id, serial, management address or hostname. Confirm the device is onboarded and the identifier is exact.
- `no site "…" visible in this tenant` means the target slug does not exist yet. Import the sites file before the placement file.

Both strings are produced by the importer itself and appear in the plan's **Detail** column.

## Result

The panel reads **Applied** with final per-action counts, and the Sites table refreshes underneath. Switch to the **Map** tab: imported sites with coordinates appear as bubbles, and **Devices placed** rises by the number of applied bindings. Spot-check one device under **Infrastructure → Devices** and confirm its **Site** column shows the imported site.

The same operation is available at `POST /api/sot/import` with a body of `kind` (`sites` or `device_sites`), `format` (`csv`, `json` or `geojson`), the raw file text in `data`, `dry_run`, and `overwrite`. `dry_run` defaults to true, so an API caller that omits it gets the plan rather than a write.

Two failures that look alike but are not: a plan that is entirely `conflict` means the records already exist with different values, and a plan that is entirely `error` means the file did not match your inventory at all. Re-run with **Overwrite existing** only where the file should win over what is in the console.

## Related

- [Place devices on the map](/infrastructure/geomap) for creating sites by hand.
- [Keep sites and inventory in sync](/automation/sites-and-inventory) for the ongoing connector.
- [Work with the device inventory](/infrastructure/devices) for confirming a placement landed.
