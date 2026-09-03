---
title: Investigate a security finding
description: "Read one security verdict end to end: its status, the asset and seam it grounds on, the standards it maps to, and what to do next."
page_type: task
sidebar_position: 4
---

# Investigate a security finding

A finding is one verdict about one control on one asset. This procedure takes
you from a row in the Exposures table to a decision: fix it, accept it, or
close the coverage gap that stopped Correlix assessing it at all.

## Before you begin

- A role with `infrastructure:read`. Every findings route is read-gated at that
  level and then filtered to your tenant.
- At least one completed scan. With no scan, the list is empty because nothing
  was assessed. See [Run a security scan](/security/run-a-scan).

## Steps

### Step 1 — Open the finding

Go to **Security → Exposures** and select a row. The finding detail opens in
the inspector, or in a **Finding detail** panel when the workspace inspector is
off.

To fetch the same object over the API, use the finding id:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/security/findings?limit=2"
```

```json
{
  "items": [
    {
      "source": "correlix-netrule",
      "scan_uid": "scan-t_d3d501aa08e2395893b378a453b8af67-20260903T040523.613Z",
      "time": "2026-09-03T04:05:23.614Z",
      "evidence_class": "exposure",
      "status": "Unknown",
      "status_id": 0,
      "standards": ["AC-17", "AC-4", "SC-7"],
      "control": "AC-4",
      "control_title": "Web management reachable from an untrusted seam with no ACL",
      "category_name": "access-control",
      "severity": "high",
      "resource": {"uid": "spine1", "hostname": "spine1"},
      "raw_rule_id": "exposure-http",
      "id": "a47da10d334064755833b13ed99ceb67ffb6b515793cae4f9089c4cac8d8119b",
      "scan_id": "scan-t_d3d501aa08e2395893b378a453b8af67-20260903T040523.613Z",
      "native_id": "security|security_exposure|exposure|AC-4|spine1|scan-t_d3d501aa08e2395893b378a453b8af67-20260903T040523.613Z|exposure-http"
    }
  ],
  "next_cursor": null,
  "total": 322
}
```

`GET /api/security/findings/{id}` returns one finding. A finding id belonging
to another tenant answers `404`, the same answer an id that does not exist
returns.

### Step 2 — Read the status before the severity

The status is the verdict. Six values exist, and only three of them are
verdicts:

| Status | `status_id` | What it means |
|---|---|---|
| `Pass` | 1 | The control was evaluated and satisfied |
| `Warning` | 2 | Evaluated, and something is off |
| `Fail` | 3 | Evaluated, and the control is violated |
| `NotApplicable` | 4 | The platform genuinely cannot express the insecure state |
| `Error` | 5 | The check ran and could not reach an answer |
| `Unknown` | 0 | No verdict was reached. Never read this as clear |

`Unknown` is the one to act on first. It usually means the input the rule needs
was missing. A hardening rule with no captured running configuration reports
`running-config unavailable — control not assessed (fail-closed)`; an advisory
check with no feed reports `Vendor advisory exposure not assessed`.

### Step 3 — Identify the asset and the seam

`resource.uid` and `resource.hostname` name the device. The **Seam** column
names the ownership transition the finding sits on, and an unassessed seam
renders as a dash rather than a zero.

A finding with a resolvable seam is the one you can hand to an owner. That is
exactly what the CTEM funnel's `mobilize` stage counts.

### Step 4 — Read the standards it maps to

`standards` carries the control ids the finding satisfies evidence for, such as
`AC-17`, `AC-4` and `SC-7`. `control` is the canonical NIST 800-53 control the
compliance scorecards project from. A framework is never a tag on a finding;
enabling a framework changes what is reported, never what is collected.

### Step 5 — Act on it

| What you see | What to do |
|---|---|
| `Fail` on a hardening rule | Apply the remediation the finding carries, then re-scan |
| `Fail` on an exposure probe | Restrict the management service at the seam, or turn it off |
| `Fail` on an advisory match | Read the CVE and plan the upgrade. See [Review vendor advisories](/security/vulnerabilities) |
| `Unknown` from a missing configuration | Turn on `FEATURE_CONFIG_BACKUP` and capture the device. See [Back up a device configuration](/security/config-backup) |
| `Unknown` from an unresolved platform | Fix the device's vendor and OS on its inventory row |
| `Unknown` from an unprovisioned feed | Provision the advisory feed |

### Step 6 — Check whether it correlated

If the finding grounded on the same entity and seam as other telemetry inside
one correlation window, it appears in **Security → Exposure Stories** as part
of a single case, with a causality path and an owner. See
[Exposure stories](/security/exposure-stories).

## Result

You can state, for one asset, which control was evaluated, what the verdict
was, what evidence produced it, and either the remediation or the reason
nothing could be assessed. A finding you cannot state that for is a coverage
gap, and the gap is the work.

## Current verdict against full history

The **Current verdicts** and **Full history** toggle above the table changes
what the query returns:

- **Current verdicts** collapses to the latest verdict per finding identity.
  This is what the Overview, the funnel and the compliance scorecards use.
- **Full history** returns every recorded verdict, including superseded ones.
  Use it to see when a control started failing.

Current-state paging is bounded at 10000 findings, and walking past that bound
is refused rather than served short. A short page with an empty cursor while
the total says thousands more would read as "that is all the data there is".

## Related

- [Review exposures](/security/exposures)
- [Exposure stories](/security/exposure-stories)
- [Continuous threat and exposure management](/security/ctem)
- [Check compliance against a framework](/security/compliance)
