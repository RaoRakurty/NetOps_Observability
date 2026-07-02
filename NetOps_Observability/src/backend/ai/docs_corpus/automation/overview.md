---
title: Automation & Source of Truth overview
sidebar_label: Overview
sidebar_position: 1
description: How Correlix separates intent from observed state, and how the Source of Truth provider model works.
---

# Automation & Source of Truth

Your **Source of Truth (SoT)** is the authoritative record of what *should* exist on the network — sites, device placement, and ownership. Correlix keeps that record itself, built from two things it already has:

- **Discovered inventory** — the devices Correlix found and monitors (<kbd>Infrastructure → Devices</kbd>). This is *observed state*: what is actually on the wire.
- **Sites** — locations you declare, with coordinates and ownership (<kbd>Infrastructure → Device Geomap → Sites</kbd>). This is *intent*: what you say the network looks like.

The Automation section adds an optional connector on top: <kbd>Automation → Source Of Truth</kbd> lets you run a bundled inventory console, or connect your external source-of-truth system, and exchange device records with it.

## Intent vs. observed state

Correlix deliberately keeps the two planes separate:

| Plane | Where it comes from | Examples |
|---|---|---|
| **Observed** | Discovery and live telemetry | Device up/down, interfaces, serial, management IP, running OS |
| **Intent** | You (declared in the console or imported) | Sites and their coordinates, device → site placement, site owner |

Observed state is never overwritten by intent, and intent is never inferred from the wire. The map is a good example: the [Device Geomap](/infrastructure/geomap) places devices using **site coordinates you declared** — never GeoIP, because private management addresses don't geolocate. Health (up/down) then rolls up onto those intended locations.

Where the two planes disagree, that disagreement is surfaced rather than hidden: <kbd>Security → Compliance Monitoring</kbd> runs **drift checks** that compare declared records against observed ones (device registered in the Source of Truth, name / management IP / serial / platform match) whenever declared device records are being pulled in.

## The provider model in plain language

The Source of Truth is a **role**, not a product. Three rules govern it:

1. **The internal Source of Truth is always the observability authority.** What Correlix discovered and monitors, plus the sites you declare in the console, decide what is monitored, where it sits on the map, and who owns it. This record is always editable in the app.
2. **An external system is an automation connector, never a replacement.** Under <kbd>Automation → Source Of Truth</kbd> you can enable the bundled inventory service or point at an external inventory instance. It exchanges *device records* — you choose the direction — but it never supersedes discovery, never drives map placement, and never locks the in-app Sites editor.
3. **Nothing syncs until you opt in.** The sync direction defaults to **Off**. A fresh install never auto-populates an inventory from discovery, and never pulls declared devices in, until an operator picks a direction.

The available sync directions, in the UI's own words:

- **Off** — no automatic sync (the default).
- **Devices → Source of Truth** — discovered devices are written into the inventory; build a system of record from scratch, seeded by discovery.
- **Source of Truth → Devices** — inventory-declared devices are pulled in and appear under <kbd>Infrastructure → Devices</kbd> alongside discovered ones, as additional records — not as the authority over them.
- **Bidirectional** — both, with records de-duplicated by management IP, serial, and name.

Step-by-step setup is in [Import & external sync](/automation/import-and-sync).

## Seeding from a file

If your site list and device placement already live somewhere — a spreadsheet, a DCIM export, a GeoJSON file — you don't have to retype them. The **Import** panel (<kbd>Infrastructure → Device Geomap → Sites → Import…</kbd>) takes CSV, JSON, or GeoJSON and seeds the internal Source of Truth in one pass:

1. Rows are **identified** against existing records (sites by slug; devices by serial → management IP → hostname).
2. Changes are **reconciled** conservatively: new records are created, existing records that would change are reported as conflicts and skipped unless you explicitly enable overwrite.
3. A **dry-run preview is always first** — nothing is written until you click **Apply**.

The full procedure, file formats, and how to read the reconcile plan are in [Import & external sync](/automation/import-and-sync).

## What lives where

| Task | Where |
|---|---|
| Create / edit / delete sites | <kbd>Infrastructure → Device Geomap → Sites</kbd> |
| Assign a device to a site | <kbd>Infrastructure → Devices</kbd> — the **Site** column |
| Set a one-off device location (no site) | <kbd>Infrastructure → Device Geomap → Set locations</kbd> |
| Import sites / placements from a file | <kbd>Infrastructure → Device Geomap → Sites → Import…</kbd> |
| Enable the bundled inventory or connect an external one | <kbd>Automation → Source Of Truth</kbd> |
| See intent-vs-observed drift | <kbd>Security → Compliance Monitoring</kbd> |

::::info Permissions
Sites, device placement, and file import are tenant-scoped and need **infrastructure write** permission. The Source of Truth connector under <kbd>Automation → Source Of Truth</kbd> is platform-wide plumbing and is reserved for **platform administrators**.
::::

## Next steps

- [Sites & inventory](/automation/sites-and-inventory) — create sites, assign devices, and light up the geographic map.
- [Import & external sync](/automation/import-and-sync) — bulk-seed from a file and connect an external system.
