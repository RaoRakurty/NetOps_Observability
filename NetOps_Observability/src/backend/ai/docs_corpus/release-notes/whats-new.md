---
title: What's new
description: What changed in Correlix, by month, with the flag and the surface for every entry.
page_type: index
sidebar_position: 1
---

# What's new

Correlix ships continuously. Each month below lists what an operator can see and
do that they could not before, the surface it appears on, and the feature flag
that controls it where one exists.

| Month | Headline |
|---|---|
| [September 2026](/release-notes/2026-09) | The Security section, BGP depth and the BMP receiver, the symptom-first Investigation surface, protocol diagnostics with live collect, IGP depth, Iris skills and chaining, configuration backup and drift, packet capture. |
| [August 2026](/release-notes/2026-08) | TLS and mTLS on every internal hop, the Transport Security page, the eight-section navigation, the graphical installer, GUI-configurable identity providers, the BGP Operations page. |
| [July 2026](/release-notes/2026-07) | The canonical incident report, seam ownership on every case, alert episodes and maintenance windows, real SNMP discovery, cloud observability, the appliance installer, Iris. |

## How to read an entry

Every entry names three things.

- **What it does**, in the terms an operator uses.
- **Where it appears**: a console path, an API route, or both.
- **The flag**, when the capability is optional. An optional module whose flag
  is off registers no routes at all, so its paths answer `404` and the feature
  is not enumerable from outside. Other flags gate a collector or a worker while
  their read routes stay registered and answer honestly that the capability is
  off. See [Feature flags](/reference/feature-flags).

An entry that describes a coverage or honesty behaviour is describing shipped
behaviour, not a limitation. Correlix reports an absent measurement as absent.
See [What an empty result means](/reference/honest-states).

## Check which build is running

A container is recreated from whatever image already exists, so restarting a
service can quietly redeploy older code. The running process states its own
revision on an unauthenticated route, so a deploy script or a person with `curl`
can check it without a credential:

```bash
curl -s http://localhost:8000/admin/version
```

```json
{
  "version": "0.1.0-scaffold",
  "sha": "d32f0c0f00ac2cdc2b59475a8ffd347e37a3e1cb",
  "built_at": "2026-09-03T03:55:50Z",
  "started_at": "2026-09-03T04:08:06Z",
  "uptime": "29s",
  "identified": true
}
```

`identified` is `false` when the binary was not told its revision at build time.
Treat that as a failed check, not a passed one: an artifact that cannot name
itself is the situation this route exists to catch.

## Related

- [Feature flags](/reference/feature-flags)
- [REST API reference](/reference/api)
- [Upgrade a deployment](/deploy/upgrade)
