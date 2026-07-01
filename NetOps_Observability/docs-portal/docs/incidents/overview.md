---
title: Events & Incidents overview
sidebar_label: Overview
sidebar_position: 1
description: The event timeline, incidents, root-cause correlation, and recovery metrics.
---

# Events & Incidents

This is where Correlix earns its keep: instead of a flood of alerts, it groups related signals into **incidents** and names the **root cause** with evidence.

## What's in it

| Feature | Console path | What it's for |
| --- | --- | --- |
| **Events** | <kbd>Monitoring → Events</kbd> | Unified timeline (syslog, traps, alerts, anomalies, changes) |
| **Incidents** | <kbd>Monitoring → Incidents</kbd> | Grouped, prioritized incidents |
| **Correlations** | <kbd>Monitoring → Correlations</kbd> | The RCA view — fault domain, evidence, owner |
| **Recovery Scorecard** | <kbd>Monitoring → Recovery Scorecard</kbd> | Per‑phase incident timing (MTTI/MTTC/MTTR) |
| **Service View** | <kbd>Monitoring → Service View</kbd> | Application‑centric health & attribution |

## How correlation reads (operator view)

Each incident carries a **verdict** (Confirmed / Suspected / Undetermined), the **evidence** that supports it (clickable back to the source), a **recommended owner**, and **next actions**. A **confirmed** verdict means independent planes agreed — see [Key concepts](/getting-started/concepts#root-cause).

The **Recovery Scorecard** then measures *where time went* in each incident — detect → correlate → isolate → own → mitigate → resolve — so you improve the process, not just react.

Feed correlation more planes ([syslog](/send-data/syslog), [traps](/send-data/traps), [flows](/send-data/flows)) for higher‑confidence verdicts.
