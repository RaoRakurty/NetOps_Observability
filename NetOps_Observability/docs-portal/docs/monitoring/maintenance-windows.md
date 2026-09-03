---
title: Schedule a maintenance window
sidebar_label: Schedule a maintenance window
description: Schedule planned work so alert notifications pause for the scope you name and the incident stays out of reliability statistics.
page_type: task
sidebar_position: 4
---

# Schedule a maintenance window

A maintenance window is a declared period of planned work. While a window covers
an alert, Correlix pauses its notifications and stamps any incident that starts
inside it as planned maintenance, so the reliability rollups separate planned
work from unplanned downtime.

A window suppresses notifications only. Alerts still fire, episodes still fold,
and every alert stays visible in the queue. Correlix does not hide evidence to
keep a phone quiet.

Windows are tenant-scoped. A window you create covers your tenant's alerts and
is invisible to every other tenant.

## Before you begin

- `alerts:read` to list windows and `alerts:write` to create, edit or delete
  one. See [identity and access](/administration/identity-access).
- The device ids, site slugs or rule names the work affects. An empty scope list
  means every device, every site or every rule.
- The change window: start and end for one-time work, or the weekday, wall-clock
  start, duration and timezone for recurring work.

## Steps

### Step 1: open the list

1. Go to **Operations → Monitors → Maintenance Windows**.
2. Select **New window**.

An empty list reads **No maintenance windows declared. Planned work currently
pages like an outage.**

### Step 2: name the work

1. Enter a **Name**. It is capped at 128 printable characters on one line.
2. Enter a **Description** if the next engineer needs the context. It is capped
   at 1,024 characters.

### Step 3: scope it

1. In **Devices**, enter comma-separated device ids. Leave it blank for all.
2. In **Sites**, enter comma-separated site slugs. Leave it blank for all.
3. In **Monitor rules**, enter comma-separated rule names. Leave it blank for
   all.

The three lists are combined with AND across dimensions and OR inside one. A
window scoped to two devices and one rule covers only that rule on those two
devices.

A non-empty list never matches an unknown value. A site-scoped window does not
cover an alert whose site Correlix has not resolved. The matching is deliberately
conservative, because over-suppressing is how a real outage goes unnoticed.

### Step 4: set the schedule

For one-time work:

1. Select **One-time**.
2. Set **Starts** and **Ends**. The end must be after the start, and the span is
   capped at 90 days.

For recurring work:

1. Select **Recurring**.
2. Tick the weekdays the occurrence may start on: `mon` through `sun`. The form
   states `no day selected = every day`.
3. Set **Start time** as a wall-clock time.
4. Set **Duration (minutes)**, between 1 and 10,080 (7 days). An occurrence may
   run past midnight into the next day.
5. Set **Timezone** to an IANA location such as `America/Chicago`. Blank means
   UTC.

To bound a recurring series with a first and last instant, set `starts_at` and
`until` through the API. The console form does not expose those two fields.

### Step 5: save

1. Leave **Enabled** ticked. A window created with it cleared is stored but
   suppresses nothing.
2. Select **Create window**. On an existing window the button reads **Save
   changes**.

## Result

The window appears in the table with columns **Window**, **Status**, **Scope**,
**When** and **Updated**, and per-row **Edit** and **Delete** controls.

The **Status** column carries one chip:

| Chip | Meaning |
|---|---|
| **Suppressing now** | An occurrence is active at this instant. |
| **Enabled** | The window is live but no occurrence is running now. |
| **Disabled** | The window is stored and inert. |

While an occurrence covers an alert:

- Notifications for that alert are not delivered.
- The alert still appears on **Operations → Active Alerts** with its episode
  count rising.
- Any incident whose onset falls inside the window is stamped as maintenance and
  is excluded from the MTBF and chronic-offender rollups on **Analytics →
  Recovery Scorecard**.
- Devices inside the window render in the calm maintenance state on the topology
  views instead of as faults.

### Suppression fails open

If the window store cannot be read, Correlix treats the alert as **not**
covered and delivers the notification anyway. The failure is logged. Noisy is the
safe direction: a broken store must never hide a real alert.

An invalid stored timezone also fails toward noisy. The window covers nothing
until it is corrected.

## The maintenance-window API

| Route | Permission | What it does |
|---|---|---|
| `GET /api/alerts/maintenance-windows` | `alerts:read` | List this tenant's windows. Returns `{"windows": [...], "count": N}`. |
| `POST /api/alerts/maintenance-windows` | `alerts:write` | Create one. Returns `201` with the stored window. |
| `GET /api/alerts/maintenance-windows/{id}` | `alerts:read` | Read one. |
| `PUT /api/alerts/maintenance-windows/{id}` | `alerts:write` | Replace the mutable fields. |
| `DELETE /api/alerts/maintenance-windows/{id}` | `alerts:write` | Remove it. |

The window object carries `id`, `tenant_id`, `name`, `description`,
`device_ids`, `sites`, `rules`, `starts_at`, `ends_at`, `schedule`, `until`,
`enabled`, `created_by`, `created_at` and `updated_at`. The `schedule` object
carries `tz`, `weekdays`, `start_hour`, `start_minute` and `duration_minutes`.

Rules the API enforces:

- A one-time window uses `starts_at` and `ends_at`. Sending `until` is refused.
- A recurring window uses `schedule` with optional `starts_at` and `until`.
  Sending `ends_at` is refused.
- `enabled` defaults to `true` when the field is omitted, so a freshly declared
  window never silently does nothing.
- The owner is stamped from the authenticated token. A `tenant_id` in the
  request body is ignored.
- An id belonging to another tenant returns `404` on read, update and delete.
  The existence of another tenant's window is never revealed.
- A tenant is capped at 200 windows. Exceeding it returns `400`.
- Each scope list is capped at 200 entries of 128 characters.

## Related

- [Work the alert queue](/monitoring/manage-alerts)
- [Incident timing and recovery](/incident-response/rca-time-intelligence)
- [Sites and inventory](/automation/sites-and-inventory)
- [Configure a notification channel](/incident-response/notifications)
