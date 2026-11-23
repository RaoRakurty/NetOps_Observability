---
title: Read the Overview page
sidebar_label: Overview
description: What the Overview page shows — the Operations Overview — what is broken, who it hurts, what changed and what to do first, built on the RCA cases and the health score.
page_type: task
sidebar_position: 2
---

# Read the Overview page

The **Overview** page (**Overview → Overview**) shows the **Operations
Overview**, the default screen for the whole network. It answers four
questions on one screen: is anything broken, who does it hurt, what changed,
and what do I do first. It is built on the open RCA cases and the health score,
and each panel links to the page that has the detail.

## Before you begin

- A signed-in account. The panels are per tenant: they count your own tenant's
  devices, sites and cases only.

## Steps

1. Go to **Overview → Overview**.
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
   | **Health by site** | Devices up and down per site, worst site first. With no sites declared it says so and links to **Add sites**. |
   | **Capacity outlook** | The interfaces closest to saturation. |
   | **What changed** | Topology, inventory and alert-state changes in the last 24 hours. |
   | **Impact** | Devices affected, sites and open issues tied to an active case. |
   | **Telemetry coverage** | Which telemetry classes are live. |
   | **Platform health (internal)** and **Internal monitoring checks** | Correlix's own stack. Only a platform administrator sees these two panels. |

## What you see

A panel with nothing to show reads as a deliberate state with a short note, for
example **No active correlated issues.** or **No changes in the last 24h.**. A
panel whose source did not answer reads as degraded, for example **Correlation
is not answering right now.**. Neither is ever a blank that looks healthy.
**Health score** reads `—` with **insufficient** when there is not enough
telemetry to compute it.

The sparklines are built from the values this browser has seen, kept per
tenant, so switching tenant never shows another tenant's history.

## Other layouts

- **Standard layout** (`#/overview/operations/standard`) groups the same
  answers under headings — What needs attention, Open problems, What is broken
  now, Health by site, What changed, Is data arriving, and a closed Traffic and
  resources group — with a **Dashboard** picker in its header.
- When a tenant administrator makes a dashboard the team default, **Overview**
  opens that dashboard instead, and the Operations Overview stays at
  `#/overview/operations/builtin`. See [My dashboards](/dashboards-reports/my-dashboards).

## Related

- [Dashboards and reports](/dashboards-reports/overview)
- [My dashboards](/dashboards-reports/my-dashboards)
- [Read an RCA case](/investigate/read-an-rca-case)
