---
title: Review and manage monitor rules
sidebar_label: Monitor Rules
description: Review every alert rule the engine evaluates, tell built-in rules from the monitors you created, add a rule by expression and delete a custom monitor.
page_type: task
sidebar_position: 2
---

# Review and manage monitor rules

**Operations → Monitors → Monitor Rules** lists every alert rule the engine
evaluates: the built-in rules that ship with Correlix and the custom monitors
created in the console. Use it to check what is being watched, to add a rule
when you already know the expression, and to delete a custom monitor you no
longer need.

## Before you begin

- A platform administrator account. Alert rules are platform-global: they fire
  across every tenant, so reading and changing them is limited to the platform
  owner. For any other account the page shows **The monitor list could not be
  loaded.**
- For a guided rule with templates and a live preview, use
  [Create a monitor](/monitoring/create-a-monitor) instead.

## Steps

To review the rules:

1. Go to **Operations → Monitors → Monitor Rules**.
2. Read the header: one chip counts the rules, and **Live · live evaluation**
   shows the list loaded.
3. Sort the table by **Name**, **Source**, **Severity** or **For**.

To add a rule:

1. Select **Add rule**.
2. On **Define**, enter a **Name** and choose a **Severity**: `info`,
   `warning` or `critical`. The name takes letters, digits, `-` and `_`, starts
   with a letter or digit, and must not match an existing rule.
3. On **Condition**, enter the **Expression**, for example
   `device_cpu_percent > 90`, and how many seconds it **Must hold for**.
   `0` fires on the first matching evaluation.
4. Select **Save rule**. The page confirms **Saved monitor** with the rule's
   name.

To delete a custom monitor:

1. Find the row. Only rows whose **Source** is **custom** carry **Delete**.
2. Select **Delete** and confirm. Its active alerts resolve on the next
   evaluation.

## What you see

| Column | What it shows |
|---|---|
| **Name** | The rule's unique name. |
| **Source** | **built-in** for a rule that ships with Correlix, **custom** for a monitor created in the console. |
| **Severity** | `info`, `warning` or `critical`. |
| **Expression** | The metric condition the engine evaluates every 30 seconds. |
| **For** | How long, in seconds, the condition must hold before the rule fires. |

## Common questions

**Why can I not delete a built-in rule?** Built-in rules ship in the rules file
with the platform. Only custom monitors are deletable, from this page or with
`DELETE /api/rules?name=<name>`.

**The page says the monitor list could not be loaded. Is nothing being
monitored?** No. The rule list did not answer, which says nothing about
evaluation. Rules keep evaluating, and the page states that under the message.

**Where do the alerts from these rules appear?** On **Operations → Active
Alerts**. See [Work the alert queue](/monitoring/manage-alerts).

## Related

- [Create a monitor](/monitoring/create-a-monitor)
- [Built-in alert rules](/reference/alert-rules)
- [Work the alert queue](/monitoring/manage-alerts)
- [Schedule a maintenance window](/monitoring/maintenance-windows)
