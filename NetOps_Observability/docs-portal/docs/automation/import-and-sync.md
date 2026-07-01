---
title: Import & external sync
sidebar_label: Import & external sync
sidebar_position: 3
description: Bulk-seed sites and device placement from a file, and connect an external source-of-truth system.
---

# Import & external sync

Two ways to bring an existing system of record into Correlix:

- **File import** — a one-way seed of sites and device → site placement from CSV, JSON, or GeoJSON. One-off, dry-run first, tenant-scoped.
- **External sync** — connect the bundled inventory service or your external source-of-truth system under <kbd>Automation → Source Of Truth</kbd> and exchange device records on a schedule. Platform administrators only.

Either way, live discovery stays authoritative — imports and sync add *intent*, never observed state.

## Import from a file

### Before you begin

- You need **infrastructure write** permission.
- For device → site placement, import (or create) the **sites first** — a binding to an unknown site slug is rejected per row.
- Files are read as text, up to **1 MiB** (thousands of rows).

### File formats

**Sites** (`CSV`, `JSON`, or `GeoJSON`):

| Column / key | Required | Accepted header aliases | Notes |
|---|---|---|---|
| `name` | Yes | `site`, `site_name` | Display name (max 120 chars). |
| `slug` | No | — | Stable handle; generated from the name when omitted. |
| `status` | No | — | Free text, e.g. `active`. |
| `owner` | No | `team`, `owner_team` | Responsible team (max 120 chars). |
| `lat` / `lng` | No | `latitude` / `lon`, `longitude` | Decimal WGS 84; both or neither per row. |

- **CSV** — first row is the header; column order doesn't matter.
- **JSON** — an array of site objects: `[{"name": "Dallas Branch", "lat": 32.78, "lng": -96.80}]`.
- **GeoJSON** — a `FeatureCollection` of `Point` features; `name`, `slug`, `status`, `owner` are read from each feature's `properties`. Coordinates are `[longitude, latitude]` — **longitude first**, per the GeoJSON standard.

**Device → site placement** (`CSV` or `JSON`):

| Column / key | Required | Accepted header aliases | Notes |
|---|---|---|---|
| `device` | Yes | `device_id`, `host`, `hostname`, `name`, `ip`, `address`, `serial` | Any stable identifier; matched against your visible inventory as **id → serial → management IP → hostname**. |
| `site` | Yes | `site_slug`, `slug` | The target site's slug (a name is slugified). |

### Run the import

1. Go to <kbd>Infrastructure → Device Geomap</kbd> and select the **Sites** view.
2. Click **Import…** in the Sites card header. The **Import from a file** panel opens.
3. Pick the kind: **Sites** or **Device → site placement**.
4. Pick the format (**CSV**, **JSON**, or — for sites only — **GEOJSON**), then choose the file, or paste its contents into the text box. Picking a `.csv`/`.json`/`.geojson` file sets the format automatically.
5. Leave **Overwrite existing (apply changes, not just new rows)** unchecked for a first pass — the import is then non-clobbering: it only creates new records.
6. Click **Preview**. This is a **dry run** — the plan is computed and nothing is written.
7. Read the plan (next section). Adjust the file or the overwrite checkbox and **Preview** again — any edit clears the plan, so you always apply exactly what you last previewed.
8. Click **Apply**. Apply stays disabled until you've previewed — the dry run is mandatory.

### Reading the reconcile results

The plan shows per-action counters and a per-row table (**Line** in the source file, **Key** matched, **Action**, **Detail**):

| Action | Meaning | Written on Apply? |
|---|---|---|
| `create` | No existing record matched; a new one will be created. | Yes |
| `unchanged` | An existing record matched and is already identical. | No (nothing to do) |
| `conflict` | An existing record matched but the row would change it (the Detail says what — e.g. `would change coordinates`). Skipped unless **Overwrite existing** is checked. | No |
| `update` | Overwrite is on: the existing record will be updated (Detail lists the changed fields, or `rebind old → new` for placements). | Yes |
| `error` | The row is invalid — bad coordinates, missing site, or `no visible device matches "…"`. Never applied; fix the row. | No |

Existing values are preserved where the import row is blank, and a record's owner tenant is never reassigned by an import.

### Verify

1. After **Apply**, the panel shows **Applied** with final per-action counts; the Sites table refreshes underneath.
2. Switch to the **Map** view: imported sites with coordinates appear as bubbles, and the **Devices placed** stat rises by the number of applied bindings.
3. Spot-check a device in <kbd>Infrastructure → Devices</kbd> — its **Site** column should show the imported site.

### Troubleshooting

- **Apply is greyed out** — you haven't previewed this exact input yet. Click **Preview** first.
- **Everything is `conflict`** — the records already exist with different values. Re-run with **Overwrite existing** checked *only* if the file should win over what's in the console.
- **`no visible device matches "…"`** — the identifier doesn't match any device in your tenant by id, serial, management IP, or hostname. Check the device is onboarded and the identifier is exact.
- **`no site "…" visible in this tenant`** — import the sites file before the placement file.
- **Sites land in the ocean** — a GeoJSON with `[lat, lng]` order. GeoJSON is `[lng, lat]`; swap the pair.

## Connect an external system

<kbd>Automation → Source Of Truth</kbd> manages the inventory connector. The status badge reads **Connected**, **Bundled · off**, **Disabled**, or **Not set up**.

1. Open <kbd>Automation → Source Of Truth</kbd> (platform administrator).
2. Click **Set up** (or **Manage** if already configured). The wizard opens with the **bundled inventory** preselected — it ships with the platform, already wired, no URL or token. To use your own system, click **Connect an external inventory instead →** and complete two extra steps:
   - **Connect** — the inventory URL (`https://…`).
   - **Authenticate** — an API token with read access to the device inventory; stored encrypted, never shown again.
3. Tick **Enable inventory discovery** and set the **Poll interval (seconds)** — minimum 15, default 60.
4. Choose the **Sync direction** (default **Off** — nothing moves until you opt in):
   - **Devices → Source of Truth** — discovered devices are written into the inventory.
   - **Source of Truth → Devices** — inventory-declared devices are pulled into <kbd>Infrastructure → Devices</kbd> as additional records.
   - **Bidirectional** — both, de-duplicated by IP / serial / name.
5. Click **Save**. The collector picks the change up on its next poll.

With the bundled inventory enabled, its console is embedded right on the page (**Reload** and **Full screen** controls included). An external instance is managed in its own console; Correlix only exchanges records with it.

**On-demand controls:** **Sync devices** polls the inventory into Devices now; **Push to inventory** (shown when the direction includes writing) pushes discovered devices up now — it also runs automatically every 5 minutes.

### Verify

- The status badge reads **Connected**.
- The poll line under the toolbar shows a recent timestamp and a device count: `Inventory → Devices (poll): … · N device(s)`; after a push, a second line shows `created` / `already present` counts. Any poll or push error appears inline on the same lines.
- With a pull direction set, pulled devices appear in <kbd>Infrastructure → Devices</kbd>, and drift checks in <kbd>Security → Compliance Monitoring</kbd> activate against the declared records.
