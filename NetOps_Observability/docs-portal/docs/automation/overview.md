---
title: Automation & Source of Truth overview
sidebar_label: Overview
sidebar_position: 1
description: Keep your inventory of record accurate — internal Source of Truth or NetBox.
---

# Automation & Source of Truth

Your **Source of Truth (SoT)** is the authoritative inventory of what *should* exist on the network. Correlix maintains its own internal SoT (from discovery + a sites store) and can connect to **NetBox** as an automation system of record.

Open it at <kbd>Automation → Source Of Truth</kbd> (platform‑owner scope).

## The model

- **Internal SoT is always the observability authority** — what Correlix discovered and monitors.
- **NetBox** connects as an *automation* system of record; you can sync discovered devices into it.
- **Sites** capture location/intent and are editable in the console.

## Import an existing inventory

You can seed the internal SoT from a file:

1. Open the **Sites / Import** area under Source of Truth.
2. Upload a **CSV / JSON / GeoJSON** inventory.
3. Review the **dry‑run** (identify → reconcile) before committing — nothing is changed until you confirm.

This is an "identify then reconcile" import, so existing devices are matched (by management IP → serial → name) rather than duplicated.
