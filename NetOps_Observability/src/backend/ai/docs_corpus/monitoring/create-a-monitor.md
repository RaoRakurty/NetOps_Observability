---
title: Create a monitor
sidebar_label: Create a monitor
description: Create a monitor threshold from a template, scope it to devices, set the hold time, and check the live preview before it goes live.
page_type: task
sidebar_position: 2
---

# Create a monitor

A monitor is an alert rule you define yourself. It watches one metric
expression, holds for a period you choose, and raises an alert with the severity
you set. Correlix stores it beside the 130 built-in rules and evaluates it on the
same 30-second loop, so a monitor you create behaves exactly like a shipped rule.

Use this when the condition you care about is not already covered by the
[built-in rule set](/reference/alert-rules).

## Before you begin

- Platform-owner access. Monitor rules are platform-global configuration, so
  `/api/rules` is gated by the cross-tenant check. An organization or tenant
  admin receives `403`. See [identity and access](/administration/identity-access).
- Telemetry for the metric the monitor watches. A monitor over
  `device_cpu_percent` never fires if no collector is producing that series.
  Confirm collection first on [verify monitoring](/onboard-devices/verify-monitoring).
- The device names or a name pattern you want to scope to, if the monitor should
  not watch the whole fleet.

## Steps

### Step 1: open the wizard

1. Go to **Operations → Monitors → Create Monitor**.

### Step 2: choose what to watch

1. Pick a template from one of the six categories: **Availability**,
   **Resources**, **Interfaces**, **Routing**, **Path SLA**, or **Custom**.
2. Select **Next**.

Each template is backed by a metric the stack already collects. The template
carries a default threshold, hold time and severity, all of which you change in
the next step.

| Category | Templates |
|---|---|
| Availability | Device unreachable, Interface down, Interface flapping |
| Resources | High CPU, High memory |
| Interfaces | Interface errors, Interface discards, Interface utilization |
| Routing | BGP peer down, OSPF neighbor down |
| Path SLA | Path RTT, Path loss |
| Custom | Custom query |

**Custom query** takes a raw metric expression with no guardrails. The other
eleven compose the expression for you.

### Step 3: set the condition

1. In **Device scope**, enter a device name or a pattern. Leave it blank to watch
   every device.
2. In **Threshold**, enter the value the metric must cross. The unit for the
   template is shown beside the field. State-match templates such as **Device
   unreachable** have no threshold field.
3. In **Must hold for**, enter the number of seconds the condition must hold
   before the alert fires. `0` fires on the first matching evaluation. The
   maximum is 24 hours.
4. In **Severity**, choose `info`, `warning` or `critical`.
5. Select **Next**.

### Step 4: review and create

1. Read **Final expression**. This is the metric query Correlix stores and
   evaluates. Correlix does not parse it locally, so the review step
   instant-evaluates it and shows which series would fire right now.
2. Enter a **Monitor name**. Names accept letters, digits, `_` and `-`, must
   start with a letter or digit, and are capped at 128 characters. A name that
   already exists is refused with `409`.
3. Select **Create monitor**.

## Result

The wizard shows **Monitor created**, naming the rule and stating that the
engine evaluates it every 30 seconds and fires after the condition holds for the
number of seconds you set. From there, **View monitors →** opens the rule list
and **Create another** restarts the wizard.

The new rule is stamped with the label `origin: ui`, which is how the rule list
separates a monitor you created from a built-in one and is what makes it
deletable. It is persisted to `USER_RULES_FILE` (default `/data/user_rules.json`)
and reloaded into the engine on restart.

From then on the monitor behaves like any shipped rule:

- Its firings appear on **Operations → Active Alerts** and fold into episodes.
- Episode mute and snooze, and any covering
  [maintenance window](/monitoring/maintenance-windows), pause its notifications
  while leaving the alert visible.
- It dispatches to every configured
  [notification channel](/incident-response/notifications) on the firing edge,
  and sends a resolution to the channels that accept one.

To confirm from the API:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/rules
```

The response merges the built-in rules with the ones you created. To remove a
monitor, either use the rule list or call
`DELETE /api/rules?name=<name>`. Deleting a built-in rule returns `404` with
`no operator-created rule with that name`.

:::note
**Operations → Monitors → Monitor Rules** carries a second creation path, an
**Add rule** modal whose finish button is **Save rule**. It writes the same
object as the wizard, without the template list or the live preview.
:::

:::note
Cloud monitors are a separate object with a separate lane. They live on
**Operations → Cloud → Settings** under **Cloud monitors**, run on the cloud
metric catalog, evaluate once a minute, and emit at `warning` severity. They do
not appear in Active Alerts, do not fold into episodes, and are not suppressed by
episode mute or maintenance windows.
:::

## Related

- [Work the alert queue](/monitoring/manage-alerts)
- [Alert rules reference](/reference/alert-rules)
- [Configure a notification channel](/incident-response/notifications)
- [Query metrics](/explore/metrics)
