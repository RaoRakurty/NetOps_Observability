---
title: Review configuration drift
description: Read the fleet configuration state list, tell the four drift states apart, and separate never captured from capture failed.
page_type: task
sidebar_position: 13
---

# Review configuration drift

Config Drift is one row per device: its configuration state, when it was last
captured, the version that capture produced, the golden baseline it is measured
against, and the reason when a capture failed.

## Before you begin

- `FEATURE_CONFIG_BACKUP` must be `true` on the backend. It defaults to off,
  and with it off `/api/config/drift` is not registered: it answers `404` and
  the page renders `Config backup is not enabled on this deployment`.
- A role with `infrastructure:read`.
- At least one capture attempt. A device is listed only once a capture has been
  attempted against it.

## Steps

1. Go to **Infrastructure → Config Drift**.
2. Select a state chip to narrow the list: **All**, **In sync**, **Changed**,
   **Drifted** or **Unknown**.
3. Read the **Detail** column for the failure reason or the next scheduled
   capture.
4. Select a device name to open its **Configuration** panel.
5. Select **Load more** for the next page. Rows are appended and the order never
   changes.

## Result

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/config/drift
```

```json
{
  "items": [
    {
      "device_id": "spine1",
      "device_name": "",
      "state": "changed",
      "last_sha": "22fe79d239bf21dd23ddb665b1d80a833f943df913a13c2c488908b1ba0d68bb",
      "golden_sha": null,
      "last_capture_at": "2026-09-03T02:58:45.343338807Z",
      "added": 728
    },
    {
      "device_id": "spine2",
      "device_name": "",
      "state": "changed",
      "last_sha": "498ee27da618918406f65137ff99c8052176aca7c6bd8ab086ad091b9ddcb27d",
      "golden_sha": null,
      "last_capture_at": "2026-09-03T02:58:45.403157342Z",
      "added": 731
    }
  ],
  "next_cursor": null,
  "total": 2
}
```

Both devices above read `changed` with `golden_sha: null`: they have been
captured once, and with no baseline set there is nothing for them to be in sync
with.

## The four states

| State | What it means |
|---|---|
| `in_sync` | This capture matches the previous one, and either no golden is set or the golden matches too |
| `changed` | This capture differs from the capture before it |
| `drifted` | A golden baseline is set and this capture differs from it |
| `unknown` | Not assessed. Nothing has been captured, or the last capture failed |

`drifted` outranks `changed` and is checked first: a device that walked away
from its known-good state is the louder fact. A device with no golden baseline
can never be `drifted`.

The first capture of a device is `changed`, not `in_sync`. There is nothing yet
for it to be in sync with.

`unknown` is never rendered green. It is an absence of assessment, not a clean
result.

## Never captured against capture failed

Both surface as `unknown`, and they are different facts. Tell them apart by the
fields that come with the state:

| Case | What the response carries |
|---|---|
| Never captured | No drift row at all. `last_sha`, `golden_sha` and `last_capture_at` are `null`, and there is no `last_error` |
| Capture failed | `last_error` carrying the reason, plus the previous `last_sha` and `last_capture_at`, which are real but stale |

The device panel says the same thing in words. **Never captured** carries "No
configuration has been captured from this device yet, so drift cannot be
assessed". **Capture failed** carries the reason the device gave and warns that
the state below it is stale.

A device missing from this list has not been assessed. It is not thereby in
sync.

## Query parameters

`GET /api/config/drift` accepts exactly four parameters and rejects anything
else with a `400`:

| Parameter | Values |
|---|---|
| `state` | `in_sync`, `changed`, `drifted` or `unknown` |
| `limit` | A positive integer; 100 by default, capped at 500 |
| `cursor` | The `next_cursor` from the previous page |
| `as_tenant` | Narrows into one tenant; it can only narrow |

`device_name` is empty for a cross-tenant caller. Fleet enumeration is not
built into this route.

## What a drift finding carries

A `changed` or `drifted` capture emits one security finding, control id
`CFG-DRIFT-001`, category `drift`, onto the security evidence topic. `in_sync`
emits nothing.

The finding carries **a diff summary only**. Its title reads
`Device configuration drift (+728/-0 lines)`, its observed and intended fields
describe the change in the same terms, and its evidence reference points at the
stored version by locator and digest. The configuration text never leaves the
sealed store.

That is enforced rather than intended. A test serialises the whole wire event
and fails if the JSON contains any configuration line from its fixture,
including the canary hostname, interface, address and enable secret it plants
for the purpose.

| State | Finding status | Severity |
|---|---|---|
| `changed` | `Warning` | medium |
| `drifted` | `Fail` | high |

The remediation the finding carries is to review the configuration diff and
either restore the baseline or promote the current version to golden.

## Related

- [Back up a device configuration](/security/config-backup)
- [Investigate a security finding](/security/investigate-a-finding)
- [Check compliance against a framework](/security/compliance)
- [Optional modules](/deploy/optional-modules)
- [Feature flags reference](/reference/feature-flags)
