---
title: Read the Operations Overview
sidebar_label: Operations Overview
description: Read what is broken, who it hurts, what changed and what to do first from the Operations Overview, one screen built on the RCA cases and the health score.
page_type: task
sidebar_position: 2
---

# Read the Operations Overview

**Overview → Operations Overview** answers four questions on one screen: is
anything broken, who does it hurt, what changed, and what do I do first. It is
built on the open RCA cases and the health score, and each panel links to the
page that has the detail.

## Before you begin

- A signed-in account. The panels are per tenant: they count your own tenant's
  devices, sites and cases only.

## Steps

1. Go to **Overview → Operations Overview**.
2. Read the KPI strip across the top: **Health score**, **Active incidents**
   (confirmed RCA), **Suspected RCA**, **Impacted sites**, **Impacted devices**
   and **Telemetry**, the number of telemetry classes that are live out of four.
   Each tile carries a sparkline of its recent values and opens the page behind
   it.
3. Read the spotlight under the strip. It names the top confirmed or suspected
   issue in one sentence, built from the evidence, for example an interface
   down or a BGP peer down.
4. Work down the panels:

   | Panel | What it answers |
   |---|---|
   | **RCA coverage** | Open RCA candidates, confirmed, suspected, and how many matched a known signature. |
   | **Top health contributors** | What pulls the health score down. |
   | **Top active issues** | The open correlated issues, most important first. |
   | **Hot paths** | Path health for the top five measured paths: whether each is bad, compared to what, and who likely owns the fix. |
   | **Recommended action** | The one next step for the top issue. |
   | **RCA path view** | Where on the path the top issue sits, and the likely fault location. |
   | **Site / region health** | Not available yet. It needs site-tagged telemetry, and the panel says so. |
   | **Capacity outlook** | The interfaces closest to saturation. |
   | **What changed** | Topology, inventory and alert-state changes in the last 24 hours. |
   | **Impact** | Devices affected, sites and open issues tied to an active case. |
   | **Telemetry coverage** | Which telemetry classes are live. |
   | **Platform health (internal)** and **Internal monitoring checks** | Correlix's own stack. Platform health reads the stack status, which only a platform administrator can see. |

## What you see

A panel with nothing to show reads as a deliberate state with a short note, for
example **No active correlated issues.** or **No changes in the last 24h.**. A
panel whose source did not answer reads as degraded, for example **Correlation
is not answering right now.**. Neither is ever a blank that looks healthy.
**Health score** reads `—` with **insufficient** when there is not enough
telemetry to compute it.

The sparklines are built from the values this browser has seen, kept per
tenant, so switching tenant never shows another tenant's history.

## Related

- [Dashboards and reports](/dashboards-reports/overview)
- [Read My Dashboard](/dashboards-reports/my-dashboard)
- [Read an RCA case](/investigate/read-an-rca-case)
