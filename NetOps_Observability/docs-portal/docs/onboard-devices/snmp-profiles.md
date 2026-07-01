---
title: SNMP profiles & credentials
sidebar_label: SNMP profiles & credentials
sidebar_position: 2
description: Manage the SNMP v1/v2c community strings and SNMPv3 USM users Correlix uses to read your devices, and the vendor OID/metric library.
---

# SNMP profiles & credentials

Correlix reads devices over SNMP. The **SNMP Profile Manager** is where you manage both halves of that:

- **Credentials** — the v1/v2c community strings and SNMPv3 users used to authenticate to devices.
- **Profiles** — the vendor OID and metric library that tells Correlix *what* to read from each vendor.

Open it at <kbd>Administration → Data Collection → SNMP Profile Manager</kbd>. A segmented control at the top switches between the **Credentials** pane (*"Per-device community / SNMPv3 USM secrets"*) and the **Profiles** pane (*"Vendor OID & metric library"*).

## Create an SNMP credential

1. Open <kbd>Administration → Data Collection → SNMP Profile Manager</kbd> and select the **Credentials** pane.
2. Click **+ New profile**.
3. Fill in the common fields:

   | Field | Required | Notes |
   | --- | --- | --- |
   | **Name** | yes | A handle you'll reference from devices, e.g. `Core Switches`. |
   | **Version** | yes | `v1`, `v2c`, or `v3`. Prefer v3 where the device supports it. |
   | **Port** | yes | Defaults to `161`. Change only if the device answers SNMP on a non-standard port. |
   | **Timeout (ms)** | yes | Defaults to `2000`. Raise for slow WAN-attached devices. |
   | **Retries** | yes | Defaults to `1`. |

4. Fill in the version-specific fields.

   **For v1 / v2c:**

   | Field | Notes |
   | --- | --- |
   | **Community string** | Your read-only community. Entered as a secret; never displayed again. |

   **For v3 (USM):**

   | Field | Options | Notes |
   | --- | --- | --- |
   | **Security name** | — | The USM username configured on the device. |
   | **Security level** | `noAuthNoPriv` · `authNoPriv` · `authPriv` | `authPriv` (the default) is recommended. The auth and privacy fields below appear only when the level requires them. |
   | **Auth protocol** | `MD5` · `SHA` · `SHA224` · `SHA256` · `SHA384` · `SHA512` | Shown for `authNoPriv` and `authPriv`. |
   | **Auth key** | — | The authentication passphrase (secret). |
   | **Privacy protocol** | `DES` · `3DES` · `AES128` · `AES192` · `AES256` | Shown for `authPriv` only. |
   | **Privacy key** | — | The privacy (encryption) passphrase (secret). |
   | **Context** | — | Optional SNMPv3 context name; leave blank unless your device requires one. |

5. Click **Save profile**. The credential appears in the profiles table with its version, port, auth and privacy summary, and a **Secrets** column confirming which secrets are stored (`community ✓`, `auth ✓`, `priv ✓`).

:::info Secrets are write-only
Credentials are stored encrypted and **never displayed again** after saving. When you edit a profile, secret fields show `•••••• (unchanged)` — leaving them blank keeps the existing secret; typing a new value replaces it.
:::

### Edit or delete a credential

1. In the **Credentials** pane, find the profile row and click **Edit** or **Delete**.
2. When editing, only fill secret fields if you're rotating them — blank means "keep what's stored".
3. Deleting a profile does not delete devices; devices that referenced it fall back to the instance-wide default community (see below).

### Assign a credential to a device

Each device record carries a **credential reference** — the name (or id) of the SNMP profile the poller should use for it. Matching is by profile id first, then by name (case-insensitive).

- Devices **with a reference** are polled with that profile — v3 profiles thread the full USM parameters; v1/v2c profiles thread the community.
- Devices **without a reference** fall back to the instance-wide default community configured at deployment.

Today the reference is set on the device record itself — through the device API, an inventory import, or the seeded device file — rather than a picker in the add-device dialog. Group your fleet into a few shared profiles (e.g. `campus-v2c`, `dc-v3`) and reference those.

## Vendor profiles (OID & metric library)

The **Profiles** pane is the catalog of what Correlix reads per platform: interface counters, CPU/memory, temperature, protocol state, and so on. It ships with built-in profiles — **Universal** profiles that apply standard MIBs to every device, plus vendor packs (Cisco IOS/IOS-XE, Juniper JUNOS, Arista EOS, Fortinet FortiGate, Palo Alto PAN-OS, and more — see [Supported devices](/onboard-devices/supported-devices)). Vendor profiles are matched to devices automatically by the device's SNMP identity fingerprint.

For a standard onboarding **you don't need to touch this pane** — add a credential, add the device, and the built-ins handle the rest. Come here to extend coverage:

### Add a metric to a profile

1. In the **Profiles** pane, use the search box on the left to find the profile, grouped by category (Universal, Routers/Switches, Firewalls, Servers/Hosts, …). Select it.
2. In the metric table on the right, enter the new metric's **name**, **OID**, **type**, and **unit**, then add it.

### Bulk-load metrics

1. Select the target profile.
2. Open the upload panel and paste (or choose a file containing) a JSON array of metrics:

```json
[
  { "name": "psu_status", "oid": "1.3.6.1.4.1.9.9.13.1.5.1.3", "type": "gauge", "unit": "" }
]
```

3. Confirm the upload; the metrics are appended to the profile.

### Create a custom vendor profile

1. In the profile list, type the vendor name into **New vendor profile…** and click **+**.
2. The profile is created under the **Custom** category with an empty metric table — add metrics as above.

## Verify

1. Attach the credential and add a device ([manually](/onboard-devices/add-devices-manually) or via [discovery](/onboard-devices/snmp-discovery)).
2. Go to <kbd>Administration → Data Collection → Data Sources</kbd>.
3. The device's **SNMP metrics** cell should turn green within a poll cycle (about a minute).

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| SNMP metrics stays "no data" | Wrong community/passphrase, or device is v3-only | Re-save the credential secrets; confirm the version matches the device |
| Works from your laptop, not from Correlix | ACL restricts SNMP by source address | Permit the Correlix address in the device's SNMP ACL |
| Timeouts on remote devices | Default 2000 ms timeout too tight over WAN | Raise **Timeout (ms)** and **Retries** on the profile |
| A vendor metric you expect is missing | Not in the built-in profile for that platform | Extend the vendor profile with the OID (above) |

See [Troubleshooting](/reference/troubleshooting) for the full flow.

## Next

- **[Discover devices](/onboard-devices/snmp-discovery)** in bulk, or **[add one manually](/onboard-devices/add-devices-manually)**.
- Then **[verify monitoring](/onboard-devices/verify-monitoring)**.
