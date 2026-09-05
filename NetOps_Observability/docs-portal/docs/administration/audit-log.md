---
title: Read the audit log
sidebar_label: Audit log
description: Find who changed what, who was refused, and prove that a permission change took effect.
page_type: task
sidebar_position: 7
---

# Read the audit log {#the-audit-log}

The audit log is the scoped, append-only trail of every mutating request and every denial. It answers three questions: who changed this, who tried and was refused, and did the change I made actually take effect.

## Before you begin

- **Permission:** `administration:admin`. The trail is per-tenant data. A tenant administrator sees only their own tenant's events, an organization administrator sees every tenant in the organizations they administer, and the platform administrator sees everything.
- The `auditor` role is built for this page: `read` on every module including `administration`, and write on nothing.
- Console path: **Administration → Access & Audit → Audit Log**.

## Steps

### Read the trail in the console

1. Open **Administration → Access & Audit → Audit Log**.
2. Read the columns:

   | Column | What it holds |
   | --- | --- |
   | **Time** | When the request completed. |
   | **Actor** | The username, or `apikey:<id>` for a machine client. Blank for an unauthenticated request. |
   | **Tenant** | The actor's tenant, or `platform` when the actor was acting cross-tenant. |
   | **Action** | The method and the API path, for example `POST /api/devices`. |
   | **Status** | The HTTP status the request returned. |
   | **Decision** | `allow`, `deny` or `error`. |
   | **From** | The source address. |

3. Select a column header to sort. Denied rows carry a red accent, and errors an amber one.

The view loads the newest 300 events and refreshes every 20 seconds.

### Query the trail from the API

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/audit?limit=3&envelope=1"
```

```json
{
  "audit": [
    {
      "id": "da6d889eb2908612",
      "time": "2026-09-03T04:29:40.775401288Z",
      "actor": "",
      "method": "POST",
      "path": "/api/internal/vmalert/api/v2/alerts",
      "status": 200,
      "decision": "allow",
      "remote": "172.18.0.19"
    }
  ],
  "complete": false,
  "limit": 3,
  "offset": 0,
  "returned": 3,
  "total": 5000
}
```

Four parameters are accepted, and any other query parameter is refused with `400` naming it.

| Parameter | Meaning |
| --- | --- |
| `limit` | Page size. Defaults to 200, capped at 1000. |
| `offset` | Rows to skip. |
| `before` | An RFC 3339 timestamp, exclusive upper bound. Pass the time of the last row you saw to walk older pages. |
| `since` | An RFC 3339 timestamp, inclusive lower bound. |

Without `envelope=1` the body is a bare array and the same numbers arrive as headers: `X-Total-Count`, `X-Page-Limit`, `X-Page-Offset`, `X-Page-Max-Limit` and `X-Page-Complete`. A malformed `limit`, `before` or `since` is refused by name rather than silently replaced with a default, because a mistyped window that quietly returns the newest page is read as the window.

## What is recorded

Capture happens at one chokepoint in the request path, after authentication, so a new endpoint is audited without anyone remembering to instrument it.

- **Every mutating request.** Anything that is not `GET`, `HEAD` or `OPTIONS`.
- **Every denial**, including denied `GET` requests, because probing is what a denial trail is for.
- **Not successful reads.** A `GET` that succeeds is not recorded. The volume would bury the events that matter.
- **Not reads of the trail itself**, so the log does not record its own paging.

`decision` is derived from the status: `401`, `403` and `404` are `deny`, any other status at or above 400 is `error`, and everything else is `allow`.

A path that carries a capability token is masked before it is stored. A denied request on such a route still carries the token in its path, and a forged or expired token is exactly what an attacker probes with.

### Sensitive reads are tagged

Some reads are recorded even though they succeed, because the read itself is the sensitive act. Those events carry `detail.sensitive: true` and are written by the module rather than by the middleware:

- Protocol diagnostics collection and export.
- Packet capture start, fetch and download.
- Configuration backup fetch and diff, which also set `redacted: true`.

The unseal path adds its own record with a fuller detail block. See [Review sensitive-data access](/administration/sensitive-data-access).

## Honest states

The audit trail is the one surface where silence is itself a claim. A page reading "no events" would be read as "no privileged actions occurred", so the code refuses to let a failure look like that.

- **An unreadable trail answers `503`, not an empty list.** The message is `audit trail is temporarily unreadable; this is NOT an empty trail — retry`. The status is `503` rather than `500` on purpose: the trail exists, it could not be read right now, and the caller should retry instead of recording a clean bill of health.
- **The total is `-1` when the count failed.** On the Postgres backend, a count that errors returns `-1` for unknown, never `0`. A `-1` in `total` or in `X-Total-Count` means the number is unknown, not that the trail is empty.
- **An organization-scoped read fails loudly rather than short.** The trail for an organization administrator is merged from each administered tenant. If one tenant's read fails, the whole request fails rather than contributing zero rows, because a partial audit answer is a wrong audit answer.
- **Past the merge ceiling you are told to page differently.** Beyond an offset plus limit of 5000, an organization-scoped read is refused with `400` telling you to walk with `before=`. A short page there would be indistinguishable from the end of the trail.
- **Past the end of the trail is an empty page**, never a clamped last page that re-serves rows you already walked.

On the default `STORE_BACKEND=postgres` backend each event is its own row under row-level security, and the trail is bounded only by retention. On the `file` compatibility backend the trail is a bounded ring of the newest 5000 events, and older events fall off it.

## Result

A change you just made appears within one refresh, with your username in **Actor** and the matching method and path in **Action**. A request you expected to be refused appears with decision **deny** and the status the caller received, which is how you confirm a permission change took effect without asking the person to try again.

## Related

- [Add users and grant access](/administration/identity-access) for the `auditor` role.
- [Review sensitive-data access](/administration/sensitive-data-access) for the reveal trail specifically.
- [Honest states](/reference/honest-states) for the same distinction on other surfaces.
- [Troubleshooting](/reference/troubleshooting) for the symptom index.
