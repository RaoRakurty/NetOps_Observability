---
title: Read the Overview
sidebar_label: Overview
description: Read what needs attention, the open problems, what is broken now, health by site, what changed and whether data is arriving, from the one default Overview page.
page_type: task
sidebar_position: 2
---

# Read the Overview

**Overview → Overview** is the one default screen for the whole network. It
answers, top to bottom: what needs attention, what is broken and where, what
changed, and whether the data behind all of it is arriving. Each panel links to
the page that has the detail.

## Before you begin

- A signed-in account. The panels are per tenant: they count your own tenant's
  devices, sites and cases only.

## Steps

1. Go to **Overview → Overview**.
2. Read **What needs attention** at the top. It names the top confirmed or
   suspected problem in one sentence, built from the evidence (for example an
   interface down or a BGP peer down), with the **Recommended action** beside
   it. When nothing is open and health is good it says **Nothing needs
   attention right now.** It never says that while the health score is
   degraded: it then tells you to start with the health contributors.
3. Read the KPI strip: **Health score**, **Active incidents** (confirmed RCA),
   **Suspected RCA**, **Impacted sites**, **Impacted devices** and **Telemetry**,
   the number of telemetry classes that are live out of four. Each tile carries
   a sparkline of its recent values and opens the page behind it.
4. Work down the groups:

   | Group | What it answers |
   |---|---|
   | **Open problems** | The top open cases, where the fault is on the path, the devices and sites affected, and RCA coverage. |
   | **What is broken now** | Active alerts, what pulls the health score down, BGP peers and OSPF / IS-IS adjacencies, and the hot measured paths. |
   | **Health by site** | Devices up and down per site, worst site first. With no sites declared it says so and links to **Add sites**. |
   | **What changed** | Topology, inventory and alert-state changes in the last 24 hours, and the interfaces closest to saturation. |
   | **Is data arriving** | Which telemetry classes are live, and how many devices answer. A platform administrator also sees the platform's own health. |
   | **Traffic and resources** | Closed by default. Traffic in and out, tunnels, interface utilization, CPU and memory. Open it when you need it. |

5. To build a view of your own, use **My dashboards**.

## What you see

The header says **Live** with the time of the last data, **Connecting** before
the first answer, or **Disconnected** with how many feeds are failing. It is
driven by real answers, never a clock.

A panel with nothing to show reads as a deliberate state with a short note, for
example **No active correlated issues.** or **No changes in the last 24h.**. A
panel whose source did not answer reads as degraded, for example **Correlation
is not answering right now.**. Neither is ever a blank that looks healthy.
**Health score** reads `—` with **insufficient** when there is not enough
telemetry to compute it.

The sparklines are built from the values this browser has seen, kept per
tenant, so switching tenant never shows another tenant's history.
