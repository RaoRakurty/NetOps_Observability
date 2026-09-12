---
title: Monitoring and alerting
sidebar_label: Overview
description: What Correlix watches, how a rule becomes an alert, and where each part of the alerting chain is configured.
page_type: index
sidebar_position: 1
---

# Monitoring and alerting

Correlix decides when something is wrong with alert rules, presents the firings
as a queue an operator works, pauses notifications during planned work, and
reports on its own health through a separate route. The operator who owns the
alert queue works all four.

| Page | What it covers |
|---|---|
| [Create a monitor](/monitoring/create-a-monitor) | Build a threshold rule from a template, scope it to devices, and set the hold time. |
| [Work the alert queue](/monitoring/manage-alerts) | Triage alert episodes: acknowledge, assign, mute, snooze, annotate. |
| [Schedule a maintenance window](/monitoring/maintenance-windows) | Pause notifications for planned work and keep the incident out of reliability statistics. |
| [Track link quality](/monitoring/link-quality) | Read error and discard ratios, saturation risk, and overlay tunnel health. |
| [Monitor Correlix itself](/monitoring/host-monitoring) | Route platform self-health alerts to a phone and run the external watchdog. |

## The alerting chain

Correlix ships 154 alert rules and evaluates them continuously.

| Rule file | Rules | What it covers | Evaluated by |
|---|---|---|---|
| `src/config/rules.yaml` | 130 | Device, interface, routing and collector conditions. | The in-API engine and vmalert. |
| `src/config/rules-scale-slo.yaml` | 24 | Platform self-health and engine liveness. | vmalert only. |

The full rule list, with every expression and threshold, is generated from those
two files onto the [alert rules reference](/reference/alert-rules).

The split is deliberate. The second file is read by vmalert alone, so its rules
keep firing when the api is the component that is down, wedged or drowning.

The in-API engine re-evaluates its rules every 30 seconds. Each vmalert rule
group carries its own interval of 30 or 60 seconds.

A rule that starts holding raises an **alert**. Repeated firings of the same rule
against the same resource fold into one **episode**, which is what
[Operations → Active Alerts](/monitoring/manage-alerts) renders. An alert clears
itself on the first evaluation where the condition stops holding.

## Delivery tiers

A rule's `tier` label, not its severity, decides who is woken on the platform
self-health route. There are three values. Product and tenant alerts take a
different path, described under
[configure a notification channel](/incident-response/notifications).

| Tier | Rules | Delivery |
|---|---|---|
| `page` | 9 rules in the `engine-liveness` group | Pushed to the operator's phone immediately, at high priority. |
| `heartbeat` | `AlertingHeartbeat` only | Never routed to a person. It stamps a metric that proves the delivery path works. |
| default (warning) | Everything else, including every rule in `rules.yaml` | Folded into a periodic digest on the platform self-health route. |

The nine `tier: page` rules are:

| Rule | The condition it pages for |
|---|---|
| `CorrelationConsumerDead` | The correlation consumer group has no members. |
| `CorrelationLagGrowing` | The correlation consumer is in the group but its lag keeps climbing. |
| `CorrConsumerNotRunning` | The engine reports its consumer is not running. |
| `CorrConsumerRestartLoop` | The engine consumer is restarting repeatedly. |
| `RouterConsumerDead` | A `netops-router-*` consumer group has no members. |
| `RouterConsumerLagGrowing` | A router lane is in the group and falling behind. |
| `IngestPipelineSilent` | Ingest produced nothing when it should not be silent. |
| `ClickHouseWritesRejected` | Storage is refusing writes. |
| `AlertDeliveryBroken` | The alerting heartbeat stopped arriving. |

Those nine cover four page-worthy conditions: an engine consumer is not
consuming, ingest is silent when it should not be, storage is refusing writes,
and the alerting heartbeat itself stopped. Everything else that proves an engine
is working is already covered by the warning and critical rules in
`rules.yaml`, which is why nothing else is allowed to page.

Reproduce the list against the checked-in source at any time:

```bash
awk '/- alert: /{a=$3} /tier: page/{print a}' src/config/rules-scale-slo.yaml
```

The command also prints `OpenSearchClusterRed`, because a comment block that
documents the tiers sits between that rule and the next `- alert:` line. Nine
rules carry the label.

## What an empty alert list means

An empty alert list means no rule is firing right now. It does not mean every
rule was evaluated. A rules file that fails to load leaves the engine running
with the rules it already had, and every alert defined in that file is blind
until the file is fixed. Read [honest states](/reference/honest-states) for how
Correlix separates *not measured* from *measured as zero* across every surface.

## Related

- [Alert rules reference](/reference/alert-rules)
- [Configure a notification channel](/incident-response/notifications)
- [Incidents](/incidents/overview)
- [Verify a deployment](/deploy/verify-deployment)
