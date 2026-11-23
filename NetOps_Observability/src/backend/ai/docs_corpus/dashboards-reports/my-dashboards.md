---
title: Build your own dashboards
sidebar_label: My dashboards
description: Make a copy of the default Overview, start from Network telemetry or start empty, arrange live panels on a 12-column grid, and open each dashboard by its own address.
page_type: task
sidebar_position: 3
---

# Build your own dashboards

**Overview → My dashboards** holds your tenant's own views. Each one is built
from the same live panels as the default Overview — open problems, the next
step, alerts, health by site, traffic, interfaces, routing — and each has its
own address, so you can bookmark it, share it or open it from the **Dashboard**
picker at the top of Overview.

## Before you begin

- A signed-in account with write permission in at least one area, for example
  an operator. A read-only or auditor account can open dashboards but not
  create, change or delete them.
- Dashboards are shared with your tenant: everyone in it sees the same list.
  Another tenant never sees them, and opening another tenant's dashboard
  address reads **This dashboard does not exist**.

## Steps

1. Go to **Overview → My dashboards**.
2. Pick a starting point:
   - **Make a copy of the default** starts from the Overview itself.
   - **Start from Network telemetry** starts from resources, traffic,
     interfaces, routing, path quality, alerts and topology.
   - **Start empty** lets you pick every panel yourself.
3. Select **+ Add panel** to add more. The **Problems and RCA** group holds the
   Overview's own panels: what needs attention, the KPI strip, top active
   issues, where the fault is, impact, RCA coverage, health contributors,
   health by site, what changed, capacity outlook, telemetry coverage and hot
   paths.
4. Set each panel's width from the width control (3, 4, 6, 8 or 12 columns),
   move it earlier or later, or remove it.
5. Name the dashboard and select **Save**. It opens at its own address,
   `#/overview/dashboards/<id>`.
6. To change it later, open it and select **Edit**. To remove it, select
   **Delete** in the list and confirm.

## What you see

The header of an open dashboard says **Live** with the time of the last data,
**Connecting**, or **Disconnected** with how many feeds are failing. The
Problems and RCA panels on one dashboard share a single read, so adding several
of them does not multiply the load.

A dashboard holds at most 40 panels. A tenant keeps at most 500 dashboards. A
panel saved by a newer version that this version does not know is kept in the
saved layout untouched, and the dashboard says how many such panels it holds.

A save that fails says the dashboard could not be saved, and why. A list that
fails to load says so rather than showing no dashboards.

## Make a dashboard your team's default

A tenant administrator can make one dashboard the Overview that everyone in the
tenant opens.

1. Go to **Overview → My dashboards**.
2. Next to the dashboard, select **Make this the team default**. The list marks
   it **Team default**.
3. To go back to the Operations Overview, select **Reset to built-in**.

Everyone in the tenant now opens that dashboard from **Overview**. The
**Dashboard** picker reads **Overview (team default)** and still offers
**Operations Overview**, which opens at `#/overview/operations/builtin`. Each
person's own dashboards stay in the list as before.

Only a dashboard of your own tenant can be the team default, and another tenant
never sees it. If the team default is deleted, or someone may not read
dashboards, Overview shows the Operations Overview with a short note saying the team
default is not available. Only a tenant administrator sees the two buttons.
