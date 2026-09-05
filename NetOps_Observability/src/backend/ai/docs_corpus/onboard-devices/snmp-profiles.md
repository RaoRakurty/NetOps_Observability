---
title: Add an SNMP credential
sidebar_label: Add an SNMP credential
description: Store a v1/v2c community or an SNMPv3 USM user in the SNMP Profile Manager, and bind it to the devices it should poll.
page_type: task
sidebar_position: 3
---

# Add an SNMP credential

A credential is what lets the SNMP collectors read a device. This procedure
creates one and explains how a device selects it. Secrets are write-only: they
are stored encrypted and are never returned by the API or shown in the console
again.

Do this before adding devices. Polling starts on the next cycle after a device
appears, and a device with no working credential produces no metrics at all.

## Before you begin

- A role with `infrastructure` write permission.
- The community string or the SNMPv3 user, authentication passphrase and
  privacy passphrase already configured on the device. To have Correlix mint
  both sides for you, use
  [SNMP configuration by vendor](/onboard-devices/vendor-snmp-configs) instead.
- UDP 161 open from Correlix to the device. See
  [Connectivity requirements](/reference/connectivity-requirements).
- `ENABLE_SNMP_COLLECTION` and `ENABLE_SNMP_METRICS` set to `true`. Both default
  to `true`. The first runs the reachability pollers, the second runs the metric
  collector; metrics need both.

## Steps

1. Go to **Administration → Data sources → SNMP Profiles**.
2. Select the **Credentials** pane.
3. Select **+ New profile**.
4. Enter a **Name**. It becomes the profile id after slug conversion, and it is
   what a device record references.
5. Choose a **Version**: `v1`, `v2c` or `v3`.
6. Set **Port**, **Timeout (ms)** and **Retries**, or accept the defaults of
   `161`, `2000` and `1`. Raise the timeout for devices reached over a WAN.
7. For `v1` or `v2c`, enter the **Community string**.
8. For `v3`, enter the **Security name** and choose a **Security level** of
   `noAuthNoPriv`, `authNoPriv` or `authPriv`. The default is `authPriv`.
9. For `authNoPriv` or `authPriv`, choose an **Auth protocol** and enter the
   **Auth key**.
10. For `authPriv`, choose a **Privacy protocol** and enter the **Privacy key**.
11. Enter a **Context** only if the device requires an SNMPv3 context name.
12. Select **Save profile**.

## Result

The profile appears in the table with its version, port, authentication and
privacy summary, and a **Secrets** column that ticks each secret the store
holds: the community, the authentication key and the privacy key. The values
themselves are gone. When you reopen the profile, each secret field reads
`•••••• (unchanged)`; leaving it blank keeps the stored secret, and typing a new
value replaces it.

The allowed values are served by `GET /api/snmp/options`. Captured from the lab
stack:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/snmp/options
```

```json
{
  "auth_protocols": ["MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"],
  "priv_protocols": ["DES", "AES128"],
  "security_levels": ["noAuthNoPriv", "authNoPriv", "authPriv"],
  "versions": ["v1", "v2c", "v3"]
}
```

:::caution The privacy list is exactly two values
`DES` and `AES128` are the only privacy protocols the USM engine implements.
`3DES`, `AES192` and `AES256` were offered in an earlier release and removed:
the engine ran AES-192 and AES-256 as AES-128 with a truncated key, so a correct
credential was rejected by the device as `decryptionError`, and `3DES` matched no
branch and failed every poll. A save that names any of them is now refused.
:::

## Bind the credential to devices

A device record carries a `credential_ref`. The collector resolves it against
the profile id first, then against the profile name, case-insensitively. Set it
through the device API or an inventory import:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"id":"spine1","address":"172.40.40.11","credential_ref":"core-switches"}' \
  http://localhost:8000/api/devices
```

A device with no `credential_ref` falls back to the deployment-wide
`SNMP_COMMUNITY`, which defaults to `public`.

Which collector polls a device follows from the resolved credential. A v1 or
v2c profile puts the device on the `snmpv2c` collector; a v3 profile puts it on
`snmpv3`. Both poll UDP 161 every 30 seconds. The metric collector polls every
60 seconds.

## What happens when a credential stops working

The credential sentinel re-verifies each device's active credential every two
minutes. When the bound profile stops answering, it probes the other profiles
stored for the same tenant and adopts the first that answers, with a ten-minute
per-device cooldown between sweeps. The device API then reports
`credential_active` alongside `credential_ref`, so the console can show that
polling is running on a profile other than the one bound. When the bound profile
answers again the override is cleared.

The sentinel selects among credentials you have already stored. It never guesses
one, and it never crosses a tenant boundary.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| The device stays unreachable on `snmpv2c` or `snmpv3` | The stored secret or version does not match the device | Re-save the secret; confirm the profile version matches what the device runs |
| A v3 poll fails with a decryption error | The device is configured for a privacy protocol Correlix does not speak | Reconfigure the device for AES-128 or DES |
| Reachable from a shell but not from Correlix | An SNMP ACL on the device excludes the Correlix address | Permit the Correlix address in the device SNMP configuration |
| Timeouts on WAN-attached devices | The 2000 ms default is too tight | Raise **Timeout (ms)** and **Retries** |
| A vendor metric is missing | The OID is not in that platform's profile | Add it in the **Profiles** pane, or supply `SNMP_PROFILES_FILE` |

## Related

- [SNMP configuration by vendor](/onboard-devices/vendor-snmp-configs)
- [Configure SNMP discovery](/onboard-devices/snmp-discovery)
- [Add a device by hand](/onboard-devices/add-devices-manually)
- [Verify a device is being monitored](/onboard-devices/verify-monitoring)
