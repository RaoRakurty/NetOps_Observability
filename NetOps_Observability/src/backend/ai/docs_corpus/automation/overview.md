---
title: Automation and source of truth
description: How Correlix separates declared intent from observed state, what the source-of-truth connector does and does not do, and where each task lives.
page_type: index
sidebar_position: 1
---

# Automation and source of truth

Correlix keeps two planes apart on purpose. **Observed state** is what discovery and live telemetry found on the wire. **Declared intent** is what you say the network should look like. Neither overwrites the other, and where they disagree the disagreement is surfaced rather than averaged away.

| Plane | Where it comes from | Examples |
|---|---|---|
| Observed | Discovery and live telemetry | Device up or down, interfaces, serial, management address, running OS |
| Intent | Declared in the console or imported from a file | Sites and their coordinates, device-to-site placement, site owner |

The map is the clearest case. It places devices from site coordinates you declared, never from GeoIP, because a private management address does not geolocate. Health then rolls up onto those declared locations.

| Page | What it covers |
|---|---|
| [Keep sites and inventory in sync](/automation/sites-and-inventory) | The inventory connector: choosing a sync direction, running a sync or a push, and reading the drift it exposes. |
| [Import inventory from a source of truth](/automation/import-and-sync) | The one-way file import that seeds sites and device-to-site placement, dry-run first. |

Placing devices and declaring sites in the console is a separate task, covered in [Place devices on the map](/infrastructure/geomap).

## Three rules that govern the source-of-truth role

The source of truth is a role, not a product.

1. **The internal record is always the observability authority.** What Correlix discovered and monitors, plus the sites you declare, decide what is monitored, where it sits and who owns it. That record stays editable in the console.
2. **An external system is a connector, never a replacement.** It exchanges device records in a direction you choose. It never supersedes discovery, never drives map placement, and never locks the in-console sites editor.
3. **Nothing syncs until you opt in.** The sync direction defaults to **Off**. A fresh install neither populates an external inventory from discovery nor pulls declared devices in until an operator picks a direction.

## What lives where

| Task | Console path |
|---|---|
| Create, edit or delete a site | **Infrastructure → Sites → Sites** |
| Assign a device to a site | **Infrastructure → Devices**, the **Site** column |
| Set a one-off device location | **Infrastructure → Sites → Set locations** |
| Import sites or placements from a file | **Infrastructure → Sites → Sites**, then **Import…** |
| Enable the bundled inventory or connect an external one | **Infrastructure → Source of Truth** |
| See intent-versus-observed drift | **Security → Compliance** |

:::note Permissions
Sites, device placement and file import are tenant-scoped and need `infrastructure:write`. The source-of-truth connector under **Infrastructure → Source of Truth** is platform plumbing, and the leaf is shown to the platform owner only.
:::

## Related

- [Place devices on the map](/infrastructure/geomap) for declaring the sites this section keeps in sync.
- [Work with the device inventory](/infrastructure/devices) for the observed half of the picture.
- [Configuration drift](/security/config-drift) for drift in device configuration rather than in inventory records.
