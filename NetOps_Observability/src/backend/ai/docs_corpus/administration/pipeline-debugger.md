---
title: Follow a record through the pipeline
sidebar_label: Pipeline Debugger
description: Send one marked record into Correlix from the Pipeline Debugger page and see the last hop that had it, raise module log detail for a bounded window, and trace a parser decision.
page_type: task
sidebar_position: 24
---

# Follow a record through the pipeline

**Platform → Tools → Pipeline Debugger** answers "my telemetry is not showing
up, where did it stop?". It sends one record through the stack's own ingress
with a marker on it, then follows the marker hop by hop: the event bus, the
three stores, correlation and the product API. Each hop gets a verdict and the
delay since the previous hop that saw it.

The page drives the same routes as the `correlix-debug` command on the host.
Each section shows the equivalent command. For what each hop proves, read
[Debug the pipeline](/send-data/debug-the-pipeline).

## Before you begin

- A platform administrator account. A trace reads telemetry back out of the
  shared stores, and raising a log level changes the service for every tenant,
  so every route behind this page is platform-only and audited. A tenant or
  organization administrator cannot reach it.
- The device the record will claim to come from. No device is contacted,
  written to or reconfigured.

## Steps

### Step 1 - Follow one record

1. Go to **Platform → Tools → Pipeline Debugger**.
2. Under **Follow one record**, choose the **Telemetry**: **Syslog**, **SNMP
   trap**, **Flow**, or **gNMI (follow only)**.
3. Choose the **Device**, and optionally the **Tenant**. The default is every
   tenant you can read.
4. For syslog, traps and flows, set **Wait (seconds)**. For gNMI, set **Look
   back (minutes)** and, optionally, the **Path**.
5. Select **Send one record and follow it**. For gNMI the button reads
   **Follow real traffic**: gNMI is followed passively and nothing is
   injected.

The page shows the **Marker** it used and a row per hop.

### Step 2 - Read the hops

A hop has one of four states: seen, not seen, not observable with the reason,
or still being waited on. **Not observable** is not a miss. Two hops are only
visible from the host, and the page says so instead of reporting them as
losses. The first hop that did not see the record is where to look.

### Step 3 - Reopen a saved run

**Saved runs** lists earlier runs. Select **Open** to read a run's hops again,
or **Download** to keep it or hand it to support.

### Step 4 - Raise log detail, if the hops are not enough

1. Under **Log detail**, choose the modules.
2. Select **Raise to full detail**. The level is raised for 30 minutes at most.
3. Select **Return to normal now** when you are done.

### Step 5 - Trace a parser decision

1. Under **Parser decision trail**, enter the **Text to match** and a **Filter
   window (minutes)**, 30 at most.
2. Select **Arm**. The next records containing that text log each parser
   decision. What you arm is never shown back in full.
3. Select **Turn off** when you have what you need.

## What you see

A per-hop table with the verdict, the evidence or reason, and the time **From
previous hop**. A run you started from the page is saved when it ends, and
**Saved runs** names it.

## Related

- [Debug the pipeline](/send-data/debug-the-pipeline)
- [Debug the pipeline from the CLI](/administration/debug-the-pipeline-cli)
- [Check the health of the Correlix stack](/administration/stack-health)
