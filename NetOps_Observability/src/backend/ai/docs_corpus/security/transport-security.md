---
title: Review transport security posture
description: Read the declared, target and observed transport of every Correlix path, spot the three kinds of drift, and export the report.
page_type: task
sidebar_position: 15
---

# Review transport security posture

Transport Security is a read-only inventory of every transport path inside the
deployment. Each row states what the path is declared to use, what it is meant
to use, and what a live probe actually saw on the wire. It is where you check
that the deployment's encryption posture is what you think it is.

## Before you begin

- A role with `administration:admin`. The page is gated on that, and the scope
  you get is decided by who you are:
  - **Platform owner**: every path, the peer identities, and the boot
    validator's findings.
  - **Tenant administrator**: only the device trust-domain lanes your fleet
    rides, plus your own device count. Platform-internal hops are absent
    because listing them enumerates platform attack surface.
- The transport inventory loaded at boot. When it did not, the route answers
  `503` rather than an empty table pretending to be posture.

## Steps

1. Go to **Administration → Platform Security → Transport Security**.
2. Read the summary strip: **Paths**, **Drifting**, **Exceptions**, **Critical
   problems**, **Warnings**.
3. Read the table, one row per path.
4. Check the **Observed** column against the **Declared** column.
5. Read the **Drift / Exception** column for any row that disagrees.
6. Select **Export report (HTML)** to download the report. The export is
   platform-administrator only.

## Result

The table carries **Edge**, **Channel**, **Declared**, **Target**, **Peer
identity**, **Observed** and **Drift / Exception**. This is a row from the lab
stack:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/security/transport-posture
```

```json
{
  "edge": "api-opensearch",
  "source": "api",
  "destination": "opensearch",
  "channel": "store",
  "protocol": "http",
  "port": 9200,
  "trust_domain": "workload",
  "owning_epic": "SEC-008",
  "current_tier": "plaintext",
  "declared_tier": "tls",
  "target_tier": "tls",
  "identity": "spiffe://netops/ns/default/sa/opensearch",
  "observed": {
    "probe_ok": true,
    "cert_not_after": "2026-09-08T19:28:32Z",
    "last_checked": "2026-09-03T04:03:31.300756961Z"
  }
}
```

The platform response also carries `scope`, `generated` and a `validator`
object with the boot profile and its findings by severity.

## Unprobed paths say so

The **Observed** column has three states, and only one of them is a claim:

| Observed text | What it means |
|---|---|
| `cert ok, expires <date>` | A probe reached the endpoint and read the served certificate |
| `No certificate presented` | A probe reached the endpoint and nothing was served |
| `not probed` | No probe watches this endpoint. Correlix makes no claim about it |

`not probed` is never rendered as either good or bad. Drift is computed only
where an observation exists.

## The three kinds of drift

| Drift | What it says |
|---|---|
| `declared <tier> but no certificate observed on the wire` | The path claims TLS and serves none. This is the one to fix |
| `served certificate is EXPIRED` | The path serves a certificate whose validity has passed |
| `certificate observed on an edge declared <tier>` | Enforcement is ahead of the declaration. Surfaced so the inventory gets updated |

A row with an accepted exception shows the owner, the acceptance date, the age
in days and the reason, rather than hiding a plaintext hop behind a check mark.

## What the page does not do

- It is read-only. Nothing on it changes a deployment's transport
  configuration.
- It makes no cryptographic authenticity claim for any device lane. A device
  lane carries whatever transport the device protocol supports, and a lane with
  a declared exception is plaintext by an explicit, owner-accepted decision.
- The export separates Correlix-owned paths from device lanes for exactly that
  reason, and carries the note on the device-lane section verbatim.

## Related

- [Security section overview](/security/overview)
- [Administration overview](/administration/overview)
- [Check compliance against a framework](/security/compliance)
- [API reference](/reference/api)
