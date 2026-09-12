---
title: Collect diagnostics from a device
description: Turn on the read-only capture transport, provision a least-privilege account, and understand the honest 503 when it is off.
page_type: task
sidebar_position: 7
---

# Collect diagnostics from a device

Protocol diagnostics can run an issue's read-only command bundle against one of
your own devices over SSH. The transport is dormant by default. This page turns
it on, and describes the paste path that works when it is off.

## Before you begin

- Host access to `deployment/docker/.env` to set the flag and the credential.
- A least-privilege, read-only account on the devices. The feature runs `show`
  commands only, enforced by a read-only guard and a closed per-vendor command
  table, so the identity it authenticates with should not be able to do anything
  else on the device either.
- `infrastructure:write` for the operator who presses **Collect**. The catalog,
  the analysis and the export need only `infrastructure:read`.
- The device must be in the caller's own inventory. A device from another
  tenant and a device that does not exist return the identical 404, so no id is
  ever revealed.

## Steps

### Step 1 - Decide whether you need it

With the transport off, the panel still does everything except talk to the
device: pick the issue, paste output from your own terminal session, analyze it,
and export the redacted bundle. Turn the transport on when operators should not
have to leave the console to capture.

### Step 2 - Enable the flag

1. Open `deployment/docker/.env`.
2. Set the flag. It defaults to `false` in the compose file:

   ```bash
   FEATURE_PROTOCOL_DIAG_COLLECT=true
   ```

### Step 3 - Provision the diagnostics identity

Set a dedicated read-only account and either a password or a private key:

```bash
PROTOCOL_DIAG_SSH_USER=correlix-diag
PROTOCOL_DIAG_SSH_PASSWORD=<sealed value>
# or
PROTOCOL_DIAG_SSH_KEY=<sealed value>
PROTOCOL_DIAG_SSH_PORT=22
```

The secret is sealed at rest and is resolved per session. It never reaches a
log, a response or an audit record.

:::caution
A partially configured identity is a hard error, never a silent fallback. If
`PROTOCOL_DIAG_SSH_USER` is set with no password and no key, the collect fails
and says so. Only when none of the three variables is set does Correlix fall
back to the configuration-backup capture identity (`CONFIG_BACKUP_SSH_*`), which
is already a least-privilege read-only account on the same devices.
:::

### Step 4 - Restart the API and capture

1. Restart the API so it picks up the flag and the credential.
2. Open **Investigate → Troubleshooting → Protocol diagnostics**.
3. Select the issue, select the device, and select **Collect**.

The first capture from a device pins that device's SSH host key. The store is
the same one the operator terminal, configuration capture and packet capture
use, so a device whose key changed is refused identically everywhere. A
deployment with no host-key store refuses to wire the transport at all rather
than connecting without a host-key policy.

## Result

The panel reports the number of commands captured, the host they came from, and
the dialect they rendered in. The output shown on screen is already redacted: the redaction pass runs
at capture, before the collection is serialised, so neighbour passwords,
authentication keys and SNMP communities are masked in the browser and in
anything you copy out of it. The raw capture never leaves the server process.

Each capture is written to the immutable audit trail as
`protocol_diagnostics.collect`, tagged sensitive, with the device, the issue and
the command count. It is the same treatment a stored-configuration read gets.

### When the transport is off

`POST /api/troubleshoot/protocol-diagnostics/collect` answers **503** with
`protocol-diagnostics collector is not configured on this deployment`, and the
panel says:

```text
Collection is not wired on this deployment yet — paste the command output below and analyze that instead.
```

That is a product state, not an error, and no capture is ever fabricated to fill
the screen.

### Other honest refusals

| What you see | What it means |
|---|---|
| `That device is not visible to you — pick one from your own inventory.` | 404. The device belongs to another tenant or does not exist. Correlix never says which. |
| `You do not have permission to do that — collecting from a device needs infrastructure write access.` | 403 on the write gate. The paste path still works. |
| The server's own reason | 400. The request was refused, for example an unknown issue id. |

## Related

- [Diagnose a BGP, OSPF or IS-IS issue](/investigate/protocol-diagnostics)
- [Export a redacted bundle for vendor support](/investigate/send-to-tac)
- [Feature flags](/reference/feature-flags)
- [Security overview](/security/overview)
