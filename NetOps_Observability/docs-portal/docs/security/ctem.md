---
title: Continuous threat and exposure management
description: What the CTEM funnel counts at each stage, how assessment coverage is measured, and why the validate stage is always zero.
page_type: concept
sidebar_position: 2
---

# Continuous threat and exposure management

Continuous threat and exposure management (CTEM) is the loop Correlix runs over
the network estate: scope the assets, discover what is wrong with them,
prioritise, validate, mobilise an owner. Correlix implements the loop for
network infrastructure only. Server, endpoint and cloud-workload detection
routes out to a partner SIEM, and Correlix does not claim to cover it.

Security is the fourth evidence class in correlation, not a separate product.
A finding grounds on the same device, interface and seam every other observation
grounds on, which is what allows a security verdict and a network symptom to land in
one RCA case.

## How it works

A scan produces **findings**. Each finding is one verdict about one control on
one asset, filed with a severity, a status, an evidence class and the standards
it maps to. Three evidence classes exist:

| Evidence class | What produces it |
|---|---|
| `posture` | Hardening rules read against a device's captured running configuration |
| `exposure` | Seam-aware probes for reachable management services, and vendor advisory matches |
| `signal` | Device-log detections and flow-derived behaviour, tagged with MITRE ATT&CK techniques |

`GET /api/security/posture` reports the funnel and the assessment coverage
behind it. This is a real response from the lab stack:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/security/posture
```

```json
{
  "coverage": {
    "assessed_assets": 3,
    "total_assets": 3,
    "unassessed": 0
  },
  "funnel": {
    "discover": 192,
    "mobilize": 0,
    "prioritize": 84,
    "scope": 3,
    "validate": 0
  },
  "last_scan": {
    "scan_id": "scan-t_d3d501aa08e2395893b378a453b8af67-20260903T034325.938Z",
    "time": "2026-09-03T03:43:25Z"
  },
  "notes": {
    "coverage": "assessed_assets counts DISTINCT devices with at least one finding in the window; unassessed is the remainder of the tenant's device registry and is NOT a pass — nobody looked at those assets.",
    "scope": "cross-tenant (platform) view: the funnel spans every tenant's findings.",
    "validate": "always 0: the finding model carries no validation marker (secfindings.Finding has no such field and the bus event carries none), so a non-zero value here would be invented rather than measured."
  }
}
```

## What each stage counts

| Stage | Definition |
|---|---|
| `scope` | Devices in the caller's tenant registry, not devices that happen to carry findings |
| `discover` | Distinct current findings, one per finding identity after the latest verdict is folded |
| `prioritize` | Current findings at severity `critical` or `high` |
| `validate` | Always `0`. See below |
| `mobilize` | Current findings whose seam is resolvable, so there is an owner to hand the work to |

The funnel always describes current state, whatever window the caller asked
for. A funnel computed over every historical verdict would count one control
that failed in thirty scans as thirty exposures.

## Validate is always zero, on purpose

The finding model carries no validation marker. There is no such field on the
finding and none on the bus event, so any number other than `0` would be
invented rather than measured. The response says so in `notes.validate`, in the
product's own words, rather than leaving the reader to guess.

Read `validate: 0` as "Correlix does not measure this", not as "nothing was
validated".

## Coverage is not a pass

`coverage.assessed_assets` counts distinct devices with at least one finding in
the window. `coverage.unassessed` is the remainder of the tenant's device
registry. Those assets are not clean; nobody looked at them.

When a device carries findings but has aged out of inventory, `total_assets`
grows to hold it rather than the assessed count being clipped. Reporting more
assessed assets than exist would be nonsense.

## Hardening over a missing configuration

Hardening rules read a device's captured running configuration. When no
configuration is on file, whether because `FEATURE_CONFIG_BACKUP` is off or
because that device has never been captured, every rule reports
`running-config unavailable — control not assessed (fail-closed)` with the
status `Unknown`. It is never a `Pass`.

The same rule holds one level up. A device whose platform label matches no
vendor profile yields exactly one finding, `platform-unresolved`, saying that
no hardening control was evaluated for it.

## Truncation is reported

The current-state fold is bounded at 5000 distinct findings. Past that bound
the response carries a `funnel` note saying the count is truncated and how many
it covers. A partial count is never presented as the whole picture.

## Related

- [Run a security scan](/security/run-a-scan)
- [Review exposures](/security/exposures)
- [Exposure stories](/security/exposure-stories)
- [Security section overview](/security/overview)
