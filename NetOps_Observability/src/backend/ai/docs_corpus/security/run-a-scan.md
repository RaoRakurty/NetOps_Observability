---
title: Run a security scan
description: Run the security producer lane for your tenant, then read the lane status to confirm what it assessed and emitted.
page_type: task
sidebar_position: 3
---

# Run a security scan

A scan makes the security producer lane assess every device in your tenant now,
instead of waiting for its next scheduled pass. Use it after you onboard
devices, after you enable or disable a detection rule, or after you provision
the advisory feed, so the Security pages reflect the change immediately.

## Before you begin

- `FEATURE_SECURITY_LANE` must be `true` on the backend. It defaults to off,
  and with it off the two lane routes are not registered at all: they answer
  `404`, so the feature is not enumerable. See
  [feature flags](/reference/feature-flags).
- A role with `administration:write`. The scan gate is the per-tenant
  administration gate, the same one detection-rule enablement uses.
- A tenant selected. There is no "scan everything" button. A scan writes
  tenant-attributed evidence, so the cross-tenant platform view is refused with
  a `400` telling you to scope into a tenant first.
- At least one device in the inventory. The lane assesses the device registry;
  an empty registry produces an empty scan.

## Steps

### Step 1 — Queue the scan

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/security/scan
```

The route accepts no request body. The tenant comes from the token.

A successful call answers `202 Accepted`:

```json
{"queued": true, "tenant_seg": "t_d3d501aa08e2395893b378a453b8af67"}
```

If a scan is already queued or running for your tenant, the call answers `429`.
The trigger queue is bounded at eight entries; a scan is not started twice for
the same tenant concurrently.

### Step 2 — Read the lane status

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/security/lane/status
```

```json
{
  "enabled": true,
  "interval_seconds": 900,
  "max_findings_per_tenant": 5000,
  "metrics": {
    "dead_lettered_total": 0,
    "emit_failures_total": 0,
    "emitted_exposure": 10,
    "emitted_posture": 54,
    "emitted_signal": 2,
    "findings_truncated_total": 0,
    "lost_total": 0,
    "scan_runs_total": 1,
    "ungroundable_total": 0
  },
  "tenants": [
    {
      "tenant_id": "t_d3d501aa08e2395893b378a453b8af67",
      "tenant_seg": "t_d3d501aa08e2395893b378a453b8af67",
      "last_scan_id": "scan-t_d3d501aa08e2395893b378a453b8af67-20260903T040523.613Z",
      "last_scan_at": "2026-09-03T04:05:23.613399992Z",
      "outcome": "ok",
      "trigger": "manual",
      "duration_ms": 433,
      "findings_emitted": 66,
      "findings_truncated": 0,
      "devices_assessed": 2
    }
  ],
  "topic": "netops.security"
}
```

A tenant administrator sees only its own row. The platform administrator sees
one row per tenant.

### Step 3 — Confirm the funnel moved

Go to **Security → Security Overview**. The **Exposure pipeline** group shows
assessment coverage and the CTEM funnel, with the scan id and time underneath.

## Result

`outcome` on your tenant's row reads `ok` and `last_scan_at` is the time you
triggered the scan. Four outcomes exist:

| Outcome | What it means |
|---|---|
| `ok` | Every lane assessed and everything was emitted |
| `partial` | Findings reached the bus, but a lane, a batch or the per-tenant cap degraded the run |
| `error` | Nothing could be emitted |
| `skipped` | A run was already in flight for this tenant |

Read `findings_emitted: 0` carefully. It means no producer had anything to
report, not that the estate is clear. Check `devices_assessed` on the same row:
a scan that assessed zero devices assessed nothing.

## Scan cadence and bounds

| Setting | Environment variable | Default |
|---|---|---|
| Scan interval | `SECURITY_SCAN_INTERVAL` | 15 minutes, with ±10 % jitter so replicas never scan in lockstep |
| Findings per tenant per run | `SECURITY_MAX_FINDINGS_PER_TENANT` | 5000, with the excess counted in `findings_truncated` |
| Local dead-letter spool | `SECURITY_DEADLETTER_FILE` | `/data/security_deadletter.jsonl`, bounded at 64 MiB |

A batch that exhausts its retries is dead-lettered onto `netops.deadletter` and
then to the local spool. `lost_total` moves only when both of those also fail,
so it counts evidence with no durable copy anywhere.

## Related

- [Continuous threat and exposure management](/security/ctem)
- [Enable a detection rule](/security/detection-rules)
- [Review exposures](/security/exposures)
- [Optional modules](/deploy/optional-modules)
- [Feature flags reference](/reference/feature-flags)
