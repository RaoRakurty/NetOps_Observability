---
title: Security
description: "Continuous threat and exposure management for the network estate: findings, exposures, compliance, configuration backup and drift, packet capture."
page_type: index
sidebar_position: 1
---

# Security

This section is for the operator who has to answer "what is exposed on this
network, who owns it, and what did nobody look at". Correlix assesses the
devices in your inventory, files each verdict as a security **finding**, and
folds those findings into the same RCA cases the rest of the product produces.

## What Correlix is, and is not

Correlix is **network-first**. Security is the fourth evidence class in
correlation, beside metrics, logs and flows. It is not a separate product and
it is not a SIEM. Server, endpoint and cloud-workload detection is routed out
to a partner SIEM; Correlix does not ingest it and does not claim to.

What that means in practice:

- A security finding grounds on a device, an interface and a [seam](/reference/glossary), the same
  entities every other observation grounds on.
- A correlated security finding opens in the RCA workspace as an **Exposure
  Story**, with the same causality path and ownership panel as a network case.
- There is no log-retention product, no UEBA, and no host agent.

## Pages

| Page | What it answers |
|---|---|
| [Continuous threat and exposure management](/security/ctem) | What the CTEM funnel measures, and why `validate` is always 0 |
| [Run a security scan](/security/run-a-scan) | How to make the producer lane assess this tenant now |
| [Investigate a security finding](/security/investigate-a-finding) | How to read one verdict and decide what to do |
| [Review exposures](/security/exposures) | The findings workbench: facets, current verdicts, full history |
| [Exposure stories](/security/exposure-stories) | What turns findings into a correlated case |
| [Check compliance against a framework](/security/compliance) | Framework selection, scorecards, and unassessed controls |
| [Enable a detection rule](/security/detection-rules) | The detection catalog and per-tenant enablement |
| [Review threat detections](/security/threat-detection) | Device-log detections and flow-derived network behaviour |
| [Review vendor advisories](/security/vulnerabilities) | The advisory feed, CVE matching and coverage gaps |
| [Create a saved findings view](/security/saved-views) | Named filter sets over the Exposures workbench |
| [Back up a device configuration](/security/config-backup) | Capture, versioning, redaction and the golden baseline |
| [Review configuration drift](/security/config-drift) | Fleet configuration state and what each state means |
| [Capture packets on a device](/security/packet-capture) | Bounded on-device capture, its guardrails and its audit trail |
| [Review transport security posture](/security/transport-security) | Declared against observed transport on every internal path |

## Tenant isolation

Every security surface is scoped to the caller's tenant, and the scoping is in
the storage layer rather than in the page. State it once and rely on it
everywhere on the Security pages:

- A list, facet, trend or scorecard returns only the caller's tenant's rows.
- A finding id, exposure-story id or saved-view id belonging to another tenant
  returns `404`, the identical answer an id that does not exist returns. The
  existence of another tenant's data is never revealed.
- A write stamps the owner from the authenticated token. A tenant named in a
  request body is rejected, not honoured.
- The cross-tenant (platform) view is refused for writes that need one
  unambiguous owner, such as detection-rule enablement and framework selection.

## An empty list means not evaluated, not clean

Every Security page distinguishes "nothing was found" from "nothing was
looked at", and says which one applies:

| State | What Correlix reports |
|---|---|
| A device with no finding in the window | Counted in `unassessed`, never in a pass |
| A control that could not be evaluated | Verdict `Unknown`, never `Pass` |
| An advisory feed that is not provisioned | Unassessed, never "no CVEs apply" |
| An advisory feed that is provisioned and matches nothing | Genuinely clear, and says so with the assessed count |
| A framework with nothing assessed | `score_percent` is `null`, never `0 %` |
| A transport hop with no probe watching it | "not probed", never "secure" |
| A device never captured | Configuration state `unknown`, never `in_sync` |

## Optional modules

Three parts of this section ship behind feature flags that default to off.
A module whose flag is off registers no routes at all: its paths answer `404`,
so the feature is not enumerable by probing.

| Flag | Default | What it turns on |
|---|---|---|
| `FEATURE_SECURITY_LANE` | off | The producer lane that runs scans and emits findings, plus `/api/security/lane/status` and `/api/security/scan` |
| `FEATURE_CONFIG_BACKUP` | off | Configuration capture, versioning, diff, golden baseline and drift |
| `FEATURE_PACKET_CAPTURE` | off | Bounded on-device packet capture |

The findings read API is not behind a flag. `/api/security/findings`,
`/api/security/posture`, `/api/security/rules` and the rest answer on every
deployment. With `FEATURE_SECURITY_LANE` off they answer with an empty result
set, because no producer has written anything.

## Related

- [Optional modules](/deploy/optional-modules)
- [Feature flags reference](/reference/feature-flags)
- [API reference](/reference/api)
- [Glossary](/reference/glossary)
