---
title: Work the alert queue
sidebar_label: Work the alert queue
description: "Work the Active Alerts episode queue: acknowledge, assign, mute, snooze and annotate a repeated firing once."
page_type: task
sidebar_position: 3
---

# Work the alert queue

**Operations → Active Alerts** renders episodes, not a flat firing dump. Every
firing of the same rule against the same resource folds into one row with an
occurrence count, so a link that flaps 40 times is one line to triage rather
than 40.

Use this page to take ownership of a firing condition, pause its notifications
while you work it, and leave a record for whoever picks it up next.

## Before you begin

- `alerts:read` to see the queue. Every action on an episode needs
  `alerts:write`. Check yours on **Administration → Identity & Access**, or
  read `GET /api/auth/permissions`.
- A rule that is firing. An empty queue is a state in its own right, and the
  Result section below says how to read it.

## Steps

### Step 1: pick the filter

1. Go to **Operations → Active Alerts**.
2. Use the **Episode filter** control to choose **Open**, **Closed** or **All**.
   **Open** is the default and covers active and recently-cleared episodes.
   **Closed** shows episodes that stayed quiet past the close window.

The strip above the table counts **Active episodes**, **Critical**, **Flapping**
and **Notifications paused**.

### Step 2: read the row

The table columns are **Monitor**, **Severity**, **Resource**, **Occurrences**,
**Status**, **First seen** and **Last seen**. Occurrences renders as `×N`.

Status carries the lifecycle state and any chips that apply to the row.

| State | Meaning |
|---|---|
| Active | The condition is holding now. |
| Cleared | The condition stopped, and the close window has not yet elapsed. |
| Closed | The episode stayed quiet past the close window. A new firing opens a new episode. |

| Chip | Meaning |
|---|---|
| **Flapping** | The episode flipped state at least 6 times inside the flap window. |
| **Notifications paused** | Someone muted the episode. |
| **Snoozed until** *time* | Notifications are paused until that instant. |
| **Ack ·** *user* | Acknowledged, and by whom. |
| **→** *assignee* | Assigned, and to whom. |

The close window defaults to 15 minutes and the flap detector to 6 flips in 15
minutes. Both are set at deployment time with `ALERT_EPISODE_CLOSE_WINDOW`,
`ALERT_EPISODE_FLAP_FLIPS` and `ALERT_EPISODE_FLAP_WINDOW`.

### Step 3: open the triage panel

1. Select the row. The panel lists **Resource**, **First seen**, **Last seen**,
   **Occurrences**, **Acknowledged** and **Assigned to**.

### Step 4: take the episode

1. Select **Acknowledge** to record that a human has seen it. The control becomes
   **Undo acknowledge**.
2. Enter a username in the **Assignee** field and select **Assign**. Usernames
   accept letters, digits, and `. _ @ + -`, up to 64 characters. With the field
   empty, the control reads **Clear assignee**.

### Step 5: pause the noise, not the evidence

1. Select **Mute notifications** to stop delivery for this episode alone. The
   control becomes **Resume notifications**.
2. To pause for a fixed period instead, choose a duration from **Snooze duration**
   and select **Snooze**. The presets are **30 minutes**, **2 hours**, **8 hours**
   and **24 hours**. **2 hours** is preselected. While snoozed, **Clear snooze**
   ends it early.

Mute and snooze suppress notifications only. The episode stays in the queue, the
occurrence count keeps rising, and the alert stays visible to everyone else. To
pause a whole scope for planned work instead of one episode, use a
[maintenance window](/monitoring/maintenance-windows).

### Step 6: leave a record

1. Type into **New note** and select **Add note**. Notes are capped at 2,000
   characters, 50 per episode, and each one records who wrote it and when.
2. Where the episode names a device, select **View logs** to open the log drawer
   filtered to that host over the last 60 minutes.

## Result

The row shows the state you set, and the notification channels stop delivering
for the episodes you muted or snoozed.

The queue itself is a live read. This capture is from a lab stack whose SNMP
collectors could not reach either spine:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/alerts
```

```json
[
  {
    "id": "CollectorAllTargetsUnreachable|collector=snmpv2c",
    "rule": "CollectorAllTargetsUnreachable",
    "severity": "critical",
    "summary": "Collector snmpv2c cannot reach any target",
    "labels": { "collector": "snmpv2c", "severity": "critical" },
    "fired_at": "2026-09-03T03:32:59.379985203Z"
  },
  {
    "id": "NoSamplesIngested|collector=snmpmetrics",
    "rule": "NoSamplesIngested",
    "severity": "warning",
    "summary": "Collector snmpmetrics produced 0 samples",
    "labels": { "collector": "snmpmetrics", "severity": "warning" },
    "fired_at": "2026-09-03T03:37:29.381596952Z"
  }
]
```

An empty response means no rule is firing right now. It does not mean every rule
was evaluated: a rules file that failed to load leaves its rules blind, and the
alert list cannot tell you that. [Honest states](/reference/honest-states) sets
out how Correlix separates the two.

## The episode API

Every console action has a route. The list read needs `alerts:read`; all five
actions need `alerts:write` and are audited.

| Route | What it does |
|---|---|
| `GET /api/alerts/episodes` | List episodes. Accepts `status` (`open`, `active`, `cleared`, `closed`, `all`) and `limit`. |
| `POST /api/alerts/episodes/{id}/ack` | Body `{"acknowledged": true}`. `false` undoes it. |
| `POST /api/alerts/episodes/{id}/assign` | Body `{"assignee": "name"}`. An empty string clears the assignee. |
| `POST /api/alerts/episodes/{id}/mute` | Body `{"muted": true}`. `false` resumes. |
| `POST /api/alerts/episodes/{id}/snooze` | Body `{"until": "<RFC3339>"}`, capped at 7 days and required to be in the future. An empty string clears it. |
| `POST /api/alerts/episodes/{id}/notes` | Body `{"text": "…"}`. |

The list returns at most 200 episodes by default and 500 at the hard cap. When
it truncates, the response sets `"truncated": true` and `total` still carries the
true count, so a truncated page never reads as a smaller queue. Episodes are
ordered by `last_seen`, newest first. An episode id belonging to another tenant
returns `404`, the same answer as an id that does not exist.

## Related

- [Create a monitor](/monitoring/create-a-monitor)
- [Schedule a maintenance window](/monitoring/maintenance-windows)
- [Read an incident](/incidents/reading-an-incident)
- [Search logs](/explore/logs)
