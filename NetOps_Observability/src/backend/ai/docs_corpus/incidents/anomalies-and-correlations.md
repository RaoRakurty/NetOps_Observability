---
title: Anomalies & Correlations
sidebar_label: Anomalies & Correlations
sidebar_position: 4
description: How anomaly detection and failure-signature correlation work, and how to use the Anomalies and Correlations console pages.
---

# Anomalies & Correlations

Two engines sit between raw telemetry and an actionable incident: **anomaly detection** (is this metric behaving abnormally?) and **correlation** (do these abnormal signals share a cause?). This page explains both at the operator level, and walks their console pages.

## How anomaly detection works

Correlix baselines every **device + metric pair** independently, with no thresholds to configure:

- It keeps a **rolling window** of that pair's most recent samples (up to 200) and continuously computes the window's mean and spread.
- After a short warm-up (about 20 samples), each new value is scored against the baseline: how many standard deviations away it is (a **rolling z-score**).
- A value **3 or more standard deviations** from baseline is flagged as a finding — severity **warning**, escalating to **critical** at extreme deviations (5σ and beyond). The deviation is the **Score** column you see in the console.

What this means in practice:

- **The baseline is per-pair and adaptive.** A CPU that always runs at 90% won't alert at 90% — but a jump *out of its own normal* will. A newly monitored device needs a short warm-up before it can produce findings.
- **Anomalies complement monitors, they don't replace them.** Use [monitors](/monitoring/create-a-monitor) for hard conditions you must be paged on; anomaly detection covers the long tail you'd never write rules for.
- **A finding is a signal, not a verdict.** Findings feed the correlation engine, which decides whether they add up to something real.

## Use the Anomalies page

1. Go to <kbd>Monitoring → Anomalies</kbd>. The **Detected Findings** board shows KPIs for the window — **Findings**, **Critical**, **Warning**, **Informational** — and refreshes automatically, most recent first.
2. Read the queue columns: **Time**, **Severity**, **Kind** (what class of deviation — e.g. an anomaly or an event cluster), **Device**, **Component**, **Summary**, and **Score** (the deviation strength — higher is further from baseline).
3. Filter by severity with the dropdown (**Info / Warning / Critical**).
4. Click a row to open the finding's context: full description, timestamps, device, component, and id.
5. If the finding names a device, click **View logs** to pivot straight into that device's syslog around the event ([Logs](/explore/logs)).

**Verify:** with devices reporting, an induced deviation (e.g. a sustained traffic spike on a normally quiet interface) appears here within a few polling cycles once the metric's baseline has warmed up.

:::note Findings are deliberately noisy-tolerant
Expect informational and warning findings during normal operation — that's the detector being sensitive so correlation has raw material. Don't triage findings one by one; let the Correlations page tell you which ones cluster into something actionable.
:::

## How correlation works

The correlation engine turns findings and events into **RCA candidates** in three moves:

1. **Group by time and place.** Signals from four evidence planes — device health, routing/link events, traffic flow, and active checks — are grouped when they align in a time window *and* share a network relationship. The **Linked by** column names that relationship: *Same path* (the signals sit on one forwarding path), *Boundary* (they straddle a responsibility handoff — your ISP edge, a cloud gateway), or both. Signals merely coincident in time, with no such link, are not grouped.
2. **Match against failure signatures.** Each group is ranked against a catalog of known fault patterns — *BGP peer flap*, *Local link fault*, *WAN edge congestion*, *Routing instability*, *Circuit / optics degradation*, *ISP / DIA egress latency*, *DNS resolution impairment*, *Cloud region degradation*, *Tunnel MTU blackhole*, and more. The best match becomes the **Likely cause**, and brings the signature's recommended owner and first-steps playbook with it.
3. **Issue an honest verdict.** The candidate is tiered **Confirmed** (independent evidence agrees across at least two signal classes), **Suspected**, or **Not confirmed** — and the detail view accounts for every signal: used, ignored, or missing. See [Reading an incident](/incidents/reading-an-incident) for the full anatomy, and [Working incidents](/incidents/working-incidents#when-to-trust-confirmed-vs-suspected) for how to act on each tier.

## Use the Correlations page

1. Go to <kbd>Monitoring → Correlations</kbd>. Each row in the **Candidate queue** is one correlation group; the list refreshes automatically.
2. Triage by **Status** and **Quality** first, then read **Likely cause**, **Owner**, and **Linked by** to understand each candidate's shape (column meanings in [Working incidents](/incidents/working-incidents#triage-the-rca-queue)).
3. Watch the **Evidence source** column: *trusted* means the verdict rests on production telemetry; *weak* means low-authority sources; *test check* marks synthetic/debug signals that must never drive action.
4. Click a row for the full RCA workspace — evidence matrix, timeline, causal topology, ticket card.

### Signature coverage gaps

Below the queue, the **Signature coverage gaps** panel turns "we couldn't tell" into a work list. Each row is a recurring evidence shape the engine *almost* matched but couldn't confirm — showing how often it recurred, the nearest signature, and exactly which evidence clause was missing. Ranked by recurrence, it's your prioritized list of what telemetry to add next: if the same gap says "Missing: active-probe evidence" week after week, deploying a probe on that path will convert those recurring *Not confirmed* rows into verdicts.

## Troubleshooting

- **No findings at all** — confirm metrics are flowing ([Verify monitoring](/onboard-devices/verify-monitoring)). Newly added devices need baseline warm-up before findings can fire.
- **Findings but no correlations** — single-plane deployments produce findings that rarely group. Add an independent plane ([syslog](/send-data/syslog), [traps](/send-data/traps), [flows](/send-data/flows)) so signals can corroborate each other.
- **Everything reads "Not confirmed"** — check the Signature coverage gaps panel; it names the missing evidence per recurring pattern. Confirmation needs two *independent* signal classes, not two signals of the same class.
- **A candidate you were watching disappeared** — resolved candidates age out of the default window; switch the state filter to **Resolved**.
