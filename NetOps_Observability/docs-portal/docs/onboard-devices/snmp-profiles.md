---
title: SNMP profiles & credentials
sidebar_label: SNMP profiles & credentials
sidebar_position: 2
description: Manage the SNMP v2c community strings and SNMPv3 USM users Correlix uses to read your devices, and the vendor OID/metric library.
---

# SNMP profiles & credentials

Correlix reads devices over SNMP. This page covers the two things the **SNMP Profile Manager** manages:

- **Credentials** — the v2c community strings and SNMPv3 users used to authenticate.
- **Profiles** — the vendor OID & metric library that tells Correlix *what* to read from each vendor.

Open it at <kbd>Administration → Data Collection → SNMP Profile Manager</kbd>.

## Add an SNMP credential

1. Open the **Credentials** tab (*"Per‑device community / SNMPv3 USM secrets"*).
2. Choose the SNMP version and fill in the fields:

   **SNMP v2c**
   - **Community string** — your read‑only community.

   **SNMP v3 (recommended)**
   - **Username** (security name)
   - **Auth protocol** — SHA or MD5 — and the **auth passphrase**
   - **Privacy protocol** — AES or DES — and the **privacy passphrase**
   - **Security level** — noAuthNoPriv / authNoPriv / authPriv (authPriv is recommended)

3. Save.

:::info Secrets are write‑only
Credentials are encrypted at rest and **never displayed again** after saving. A stored secret shows as `••••••`. Saving with the field left blank keeps the existing secret.
:::

### Scope: default vs per‑device

- A **default credential** is tried against devices that don't have a specific one — handy when most of your fleet shares a community/user.
- A **per‑device credential** overrides the default for that device — use it for exceptions (a different community, a v3‑only box).

Correlix picks the most specific credential that authenticates.

## Vendor profiles (OID & metric library)

The **Profiles** tab (*"Vendor OID & metric library"*) is the catalog of what Correlix reads per vendor — interface counters, CPU/memory, environment sensors, protocol state, and so on.

- Out‑of‑the‑box profiles cover the common enterprise and data‑center vendors, so most devices work with **no profile configuration** — just a credential.
- You generally only touch this tab to **extend coverage** (add an OID/metric for a platform that exposes something extra).

:::tip You usually don't need to edit profiles
For a standard onboarding, add a credential and add the device — the built‑in profiles handle the rest. Come back to Profiles only when a specific metric you want isn't being collected.
:::

## Verify a credential works

After attaching a credential and adding a device:

1. Go to <kbd>Administration → Data Collection → Data Sources</kbd>.
2. The device's **SNMP metrics** cell should turn green within a poll cycle (~1 minute).
3. If it stays "No data", the credential or reachability is the usual cause — see [Troubleshooting](/reference/troubleshooting).

## Next

- **[Discover devices](/onboard-devices/snmp-discovery)** in bulk, or **[add one manually](/onboard-devices/add-devices-manually)**.
- Then **[verify monitoring](/onboard-devices/verify-monitoring)**.
