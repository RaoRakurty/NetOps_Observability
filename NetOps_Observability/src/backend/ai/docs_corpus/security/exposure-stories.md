---
title: Exposure stories
description: What turns a set of security findings into one correlated case with a causality path and a named owner, and what an empty list means.
page_type: concept
sidebar_position: 6
---

# Exposure stories

An exposure story is a correlation case whose evidence set includes the
security lane. It is the object that makes security the fourth evidence class
rather than a second product: one narrative covering several observations
across several entities, with a causality path, a verdict tier and a seam
owner.

## How it works

The correlation engine groups observations that land on the same entities and
seams inside one window. A security finding grounds on a device, an interface
and a seam exactly as a metric, a log line or a flow record does, so no
security-specific correlation code exists. When a finding lands beside other
telemetry on the same entity, the resulting case becomes an exposure story.

The detail view is the RCA workspace, reused unchanged. An exposure story is an
RCA case, so it reads like one: the same causality path with broken links
rendered in red, the same ownership panel, the same export.

Go to **Security → Exposure Stories** for the list, or read it over the API:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/security/exposure-stories
```

On the lab stack the list is currently empty:

```json
[]
```

## What each story carries

| Field | What it states |
|---|---|
| `top_hypothesis` | The narrative headline, or "Correlated exposure" when none is stated |
| `owner` | The seam owner, or "unattributed" when the seam resolved to nobody |
| `verdict_tier` | `confirmed`, `suspected`, or "undetermined" |
| `confidence` | A percentage, or "not stated" when the engine did not state one |
| `signal_count` | How many observations folded into the story |
| `node_count` | How many entities the story spans |
| `grounding` | What the story is grounded on |

Correlix names the seam and the party that owns it. It does not name a generic
operations team as the owner of a fault, and it phrases a verdict as what the
evidence supports.

## An empty list is a legitimate answer

`GET /api/security/exposure-stories` answers `[]`, never an error, when nothing
correlated. "No stories" and "the query failed" must not look the same to the
page, so a failure is reported as a failure and an empty result is reported as
an empty result.

The console states the same thing in words: a story appears when security
evidence lands on the same entity and seam as other telemetry inside one
correlation window, and an empty list means nothing correlated, not that
nothing is wrong.

## The limits

- A story exists only where correlation happened. A finding on an entity
  nothing else touched stays a finding and appears only under
  [Exposures](/security/exposures).
- Disabling a detection rule silences its evidence everywhere, including the
  exposure stories that rule grounds. See
  [Enable a detection rule](/security/detection-rules).
- A story id belonging to another tenant answers `404` and renders as "not
  found". It never renders as a blank workspace, which would imply the story
  exists but is empty.

## Related

- [Review exposures](/security/exposures)
- [Investigate a security finding](/security/investigate-a-finding)
- [Root-cause analysis explained](/investigate/rca-explained)
- [Continuous threat and exposure management](/security/ctem)
