---
title: Back up a device configuration
description: Capture a device's running configuration over the SSH gateway, read a stored version, compare two versions, and promote one to the golden baseline.
page_type: task
sidebar_position: 12
---

# Back up a device configuration

A capture stores one device's running configuration as a versioned, sealed
document. From there you can read it, diff two versions, promote one as the
golden baseline, and let the drift evaluator measure every later capture
against it.

## Before you begin

- `FEATURE_CONFIG_BACKUP` must be `true` on the backend. It defaults to off,
  and with it off no configuration route is registered: the paths answer `404`
  and the console shows `Config backup is not enabled on this deployment`.
- `SEAL_PROVIDER` must be configured. Correlix refuses to start the module
  rather than store device configurations in cleartext.
- Capture credentials: `CONFIG_BACKUP_SSH_USER` plus either
  `CONFIG_BACKUP_SSH_PASSWORD` or `CONFIG_BACKUP_SSH_KEY`. Use a read-only
  account. Without them the module refuses to construct and names what is
  missing.
- A role with `infrastructure:write` to trigger a capture or set a golden
  baseline. `infrastructure:read` is enough to read versions and diffs.
- A device whose platform resolves to a supported vendor. See the table below.

## Steps

1. Go to **Infrastructure → Devices** and select the device.
2. Select the **Configuration** tab.
3. Select **Back up now**.
4. Wait for the versions table to gain a row. The capture is bounded at
   60 seconds end to end.
5. Select **View** on a version to read its text.
6. Select **Diff previous** to compare it with the capture before it.
7. Select **Set golden**, then **Confirm**, to promote a version as the
   baseline every future capture is measured against.

## Result

The summary line at the top of the panel carries a state badge, the last
capture time, the golden baseline, and the next scheduled capture:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/devices/spine1/config/status
```

```json
{
  "device_id": "spine1",
  "golden_sha": "22fe79d239bf21dd23ddb665b1d80a833f943df913a13c2c488908b1ba0d68bb",
  "last_capture_at": "2026-09-03T04:04:07.53312562Z",
  "last_sha": "22fe79d239bf21dd23ddb665b1d80a833f943df913a13c2c488908b1ba0d68bb",
  "next_scheduled_at": "2026-09-04T04:04:07.53312562Z",
  "state": "in_sync"
}
```

The versions list carries one row per capture:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/devices/spine1/config/versions
```

```json
{
  "device_id": "spine1",
  "golden_sha": "22fe79d239bf21dd23ddb665b1d80a833f943df913a13c2c488908b1ba0d68bb",
  "items": [
    {
      "sha": "22fe79d239bf21dd23ddb665b1d80a833f943df913a13c2c488908b1ba0d68bb",
      "captured_at": "2026-09-03T04:04:07.53312562Z",
      "size_bytes": 59733,
      "status": "ok",
      "golden": true,
      "drift": "in_sync"
    }
  ],
  "next_cursor": null
}
```

An empty history says what it means: nothing was collected, not that the
configuration is unchanged.

## How the capture runs

The capture goes over the SSH gateway, and each of these properties is a
deliberate constraint rather than an implementation detail:

- **Host-key pinning on first use.** The first capture from a device records
  its host-key fingerprint. Every later capture compares against the recorded
  one and fails the connection on a mismatch. With no host-key verifier
  configured the module refuses to connect at all; it never ignores host keys.
- **No PTY and no stdin.** The session is a single non-interactive `exec` of
  one command. It cannot be typed into.
- **One command, from a closed per-vendor table.** The command comes from the
  vendor profile registry, never from a caller-supplied string, and the
  registry validates at load that every command is a read-only show or display
  verb with no chaining metacharacter.
- **A 4 MiB cap.** A configuration larger than that is refused with
  `configuration exceeded the capture size cap`, never truncated into something
  that looks like a valid short capture.
- **Device chatter is discarded.** Standard error is not configuration.

| Vendor | Command |
|---|---|
| Arista EOS | `show running-config` |
| Cisco IOS-XE, IOS-XR, NX-OS | `show running-config` |
| Juniper Junos | `show configuration \| display set \| no-more` |
| Huawei VRP | `display current-configuration` |
| Nokia SR Linux | `info from running flat` |
| Nokia SR OS | `admin display-config` |

A device whose platform matches no profile is refused with
`no configuration-capture command is bound for this device's platform`.
Correlix never probes a device to guess a command.

A device that answers with a diagnostic rather than a configuration, such as a
line beginning `%` or `syntax error`, is recorded as a failed capture with the
reason, never as a stored version.

## Secrets are redacted on every read

A named redaction rule list runs over every API response and every diff. The
mask is a fixed `****`, so it does not leak the length of the secret it hides.

| Rule family | What is masked |
|---|---|
| Vendor-independent | `pre-shared-key`, `key-string`, `shared-secret`, and the token after an SNMPv3 `auth` or `priv` algorithm |
| Cisco and Arista | Enable secret, username secret, SNMP community, AAA server key, keychain key, ISAKMP key, line password, BGP neighbor password, OSPF MD5 key, PPP password, WPA pre-shared key, FTP password |
| Juniper Junos | Encrypted and plain-text passwords, authentication keys, secrets, SSH public keys, SNMP communities |
| Huawei VRP | `cipher` and `irreversible-cipher` values, simple passwords, SNMP communities |
| Nokia SR OS | Hashed values, passwords, communities, authentication keys |
| Nokia SR Linux | Any `$scheme$` crypt value, passwords, communities, secret keys, SSH keys |
| PEM blocks | Everything between a `BEGIN` and `END` marker line, with the marker lines kept |
| Hex blobs | Any line that is nothing but 32 or more hex characters, such as a certificate chain body |

The sealed copy keeps the original byte for byte, because that is the restore
artifact. The drift verdict is also computed on the unredacted text, so
rotating a secret counts as a real change rather than disappearing behind
identical masks.

Both configuration reads are recorded in the audit trail with a `sensitive`
tag: `config_backup_version_read` and `config_backup_diff_read`. A
configuration read is sensitive even when redacted, because it is the device's
operational blueprint.

## The golden baseline

A golden baseline is optional and is never created automatically. Inventing one
from the first capture would silently declare whatever state the device
happened to be in as correct.

- `golden_sha: null` means no baseline is set, so drift cannot be measured.
- Only a version whose status is `ok` can be promoted.
- The golden version is never removed by retention.
- Promoting a version is recorded as `config_backup_set_golden`.

## Schedule and retention

| Setting | Environment variable | Default |
|---|---|---|
| Capture interval | `CONFIG_BACKUP_INTERVAL` | 24 hours, with ±10 % jitter |
| Versions kept per device | `CONFIG_BACKUP_KEEP_VERSIONS` | 30, bounded between 2 and 500 |
| Sealed blob directory | `CONFIG_BACKUP_DIR` | `/data/config-backups` |
| Device SSH port | `CONFIG_BACKUP_SSH_PORT` | 22, overridden by the device's own port |

A device already capturing answers `429` on a second trigger.

## Related

- [Review configuration drift](/security/config-drift)
- [Capture packets on a device](/security/packet-capture)
- [Check compliance against a framework](/security/compliance)
- [Optional modules](/deploy/optional-modules)
- [Feature flags reference](/reference/feature-flags)
