---
title: Review applications and business services
description: Find the applications Correlix identified, see how they depend on each other, and maintain the service catalog, application registry and business services you author yourself.
page_type: task
sidebar_position: 2
---

# Review applications and business services

**Infrastructure → Applications** answers what runs and who owns it. It has four
tabs: **Catalog**, **Application map**, **Registries** and **Business services**.
The application names come from the identity engine and from the catalogues you
author. The cloud inventory underneath them is under **Operations → Cloud**. See
[Monitor cloud accounts](/monitoring/cloud).

## Before you begin

- `infrastructure:read` to view the tabs, and `infrastructure:write` to create,
  edit or archive a catalogue entry. Every list is per tenant, and another
  tenant's entry is never shown.
- The service catalog and business services need the relational store. A
  deployment without it shows the server's reason, for example **Service
  catalog unavailable**, instead of an empty list.

## Steps

### Step 1 - Find an application in the Catalog

1. Go to **Infrastructure → Applications**. **Catalog** opens first.
2. Filter by **Provider**, **Env**, **Confidence** or **Mapped by**. **Mapped
   by** says how the name was found: a cloud tag, the resource graph, an
   operator entry or the firewall application ID.
3. Read the row: health, criticality, owner, environment, confidence, cloud,
   account, region, resource count, traffic, error rate and p95 latency. A
   value that is not measured shows `—`.
4. Select the row to open the application. The detail shows its incident
   timeline, the identity evidence behind the name, the mapped resources, cloud
   metrics, traffic, gateway 5xx events and its RCA state, and lists what is not
   measured for it.

### Step 2 - Read the Application map

**Application map** has two views:

- **Observed dependencies** draws only the service-to-service traffic seen in
  cloud flow records: AWS VPC Flow Logs, Azure NSG flow logs and GCP VPC flows.
  Edges are weighted by volume. Rejected traffic is drawn as blocked. An
  address no inventory claims is drawn as an unattributed endpoint, never as a
  service. The caption states the window, the number of flow pairs and when the
  map was generated. Without cloud flow telemetry the map is empty and says so.
- **Structure** groups each application's resources by category, live from the
  inventory. It shows structure, not traffic.

The scope filters do not narrow the observed map yet. It is drawn for the whole
tenant over the selected window, and a note on the map says so.

### Step 3 - Maintain the registries

**Registries** holds the two lists operators author, side by side:

| Registry | What it does |
|---|---|
| **Service catalog** | Groups traffic. Each service has a grouping rule that matches on ports, destination prefixes or protocols, and attachments that record what watches it. |
| **Application registry** | Names ownership. |

The two lists are separate. Nothing joins a catalog service to an application
today, and the page says so.

To add a service to the catalog:

1. Select **New service** under **Service catalog** and name it.
2. Open **Grouping & attachments** on the row.
3. Enter the grouping rule. Until a rule matches on ports, destination prefixes
   or protocols, nothing is attributed to the service, and the editor tells you
   so before you save.

**Archive** removes an entry from the list. It is an archive, not a delete, and
the confirmation says so.

### Step 4 - Set criticality on Business services

**Business services** is the catalog of the services your teams run, with the
criticality and owner that drive the impact view on **Operations → Cloud →
Overview**.

1. Select **New service**.
2. Enter the **Service name**. It is the only required field.
3. Set **Criticality**: **Business-critical**, **High**, **Normal** or **Low**.
4. Enter the **Owner**, a **Runbook URL** and a **Description**.
5. Save.

Deleting a business service returns its resource mappings to inference, and
the confirmation says so.

## Result

When a service you marked **Business-critical** degrades, the **Services
Degraded** card on the Cloud **Overview** counts it and its note reads, for
example, `1 business-critical`. The **Degraded services** table shows the
criticality and the owner you entered.

## Related

- [Monitor cloud accounts](/monitoring/cloud)
- [Attribute traffic to applications and services](/explore/application-attribution)
- [Analyse flows](/explore/flows) for on-premises flow records.
