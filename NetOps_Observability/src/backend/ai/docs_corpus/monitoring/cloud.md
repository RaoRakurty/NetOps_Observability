---
title: Monitor cloud accounts
description: Read what your connected AWS, Azure and GCP accounts report, from service health and resources to data delivery, security lanes and cloud investigations.
page_type: task
sidebar_position: 6
---

# Monitor cloud accounts

**Operations → Cloud** shows what your connected cloud accounts report, and
only that. It has six tabs: **Overview**, **Resources**, **Data sources**,
**Security**, **Investigations** and **Settings**. Every number comes from the
accounts you connected. A tab with nothing ingested shows an empty state that
names what is missing, and a value Correlix does not measure shows `—`.

The application layer that sits on top of this inventory, meaning the
application list, the application map and the registries, is under
**Infrastructure → Applications**. See
[Review applications and business services](/infrastructure/applications).

## Before you begin

- `infrastructure:read` to view the tabs, and `infrastructure:write` to connect
  an account or change a setting. The data is per tenant: you see your own
  tenant's accounts and resources only.
- At least one connected cloud account. Until one is connected, every tab reads
  **No cloud inventory yet**.
- Outbound access from Correlix to the provider's identity and resource
  endpoints. See [Connectivity requirements](/reference/connectivity-requirements).

## Steps

### Step 1 - Connect a cloud account

1. Go to **Operations → Cloud** and select **Data sources**.
2. On **Accounts**, select **Connect a cloud account**.
3. Work through the wizard: **Provider**, **Account**, **Authentication**,
   **Trust setup**, **Scope**, **Validate** and **Activate**. The trust step
   gives you the provider-side setup for least-privilege, read-only access.
4. Select **Validate**. The check runs against the provider. An account is
   activated only after validation passes.

### Step 2 - Confirm data is arriving

On **Data sources** there are three views:

| View | What it answers |
|---|---|
| **Accounts** | One row per account, subscription or project. **Connection health** and **Data delivery** are judged separately, so a connection that authenticates but delivers nothing reads **No data arriving**. |
| **Sources** | A matrix of source types per region: inventory, flow logs, load balancer logs, metrics, cloud health, provider incidents, change and audit, DNS, firewall, NAT gateway logs and network seam data. |
| **Ingestion Status** | Whether each source is **Flowing**, **Stale**, **Not configured**, **Permission denied**, **Misconfigured**, **Nothing has arrived yet** or **Not collected here**. |

A source that is not configured reads as not configured. It never reads as
healthy.

### Step 3 - Narrow the view

The scope bar under the page title filters every tab by provider, account,
region and environment, and sets the time range. The range applies to alerts,
changes and findings. The inventory views state **current inventory · not a
time-range view**, because they always show the current state.

When data exists but the scope matches none of it, the tab says **No …
in this scope** and offers **Clear filters**. That is a different state from
nothing ingested.

## What you see

### Overview

**Data readiness** comes first, so you can see which sources are connected
before you read any verdict. Below it, three card groups:

- **Impact**: **Services Degraded** and **Open Investigations**.
- **Coverage**: **Services Observed**, **Resources Mapped** and
  **Untagged Resources** as a percentage of the inventory.
- **Change**: **Recent Cloud Changes** from the provider audit log.

The **Degraded services** table lists each degraded service with its health,
criticality, duration, blast radius and owner. **Duration unknown** means the
provider status says degraded but no timestamped observation fell in the window.
The **Open investigations** table lists the cloud cases the correlation engine
formed, with the probable cause, confidence and state.

### Resources

Three sub-views:

- **Resources**: every discovered resource with its type, state, cloud,
  account, region, service, owner, how it was mapped, confidence, health,
  traffic and missing tags. Select rows and choose **Assign to service** to map
  them to a service yourself.
- **Service mapping**: how each resource was identified, and **Coverage by
  scope**, the share of attributed resources per provider and region.
- **Untagged**: resources that no rule maps to a service, with a
  recommendation for each. **Assign to a service** fixes one directly.

### Security

**Security lane coverage** shows whether the WAF, load balancer and DNS log
lanes are delivering. **Security findings** lists what those lanes reported in
the window. When no lane is delivering, the tab says so instead of showing an
empty findings table.

### Investigations

Five sub-views over the selected window:

| Sub-view | What it lists |
|---|---|
| **Timeline** | Health changes and cloud changes on one time axis. |
| **Alerts** | Provider health reports, with the metric, current value, baseline, reason and severity. |
| **Changes** | Management-plane changes from CloudTrail or the Azure Activity Log, with the actor, change type and related symptoms. |
| **Findings** | The evidence ledger: each finding with its category, service, resource, source, confidence and reason, and the investigation it belongs to. **Grounded** reads **gap** when the finding is not yet tied to evidence. |
| **Network connectivity** | The Direct Connect, VPN and ExpressRoute connections a service rides. It needs connection telemetry and shows real connections only. |

Selecting an investigation opens it in a drawer on the same page. Its id is
kept in the address, so a refresh or a shared link reopens it.

### Settings

- **Catalog Sources**: the managed AWS, Azure, GCP and Microsoft 365 address
  feeds used for attribution, refreshed every six hours.
- **Cloud Connectors**: a shortcut to **Connect a cloud account**.
- **Attribution Precedence**: which identification source wins when sources
  disagree. Reordering changes the winner only. A weak source never becomes
  confirmed by being ranked higher.
- **Identification Coverage** and **Identification Overrides**: what each
  attribution layer holds, and the names your tenant declares for itself.
- **Required Tags**: the tags every resource must carry. They drive the
  missing-tags columns.
- **RCA Window**: the default read window for the cloud views. The server
  bounds every read to seven days.
- **Seam Owners**: the real party that owns each seam for your tenant, so RCA
  ownership names that party instead of the generic class.
- **Cloud monitors**: threshold and anomaly monitors on one cloud metric. See
  [Create a monitor](/monitoring/create-a-monitor).
- **Recent Governance Changes**: who changed which setting above, and when.

## Related

- [Review applications and business services](/infrastructure/applications)
- [Attribute traffic to applications and services](/explore/application-attribution)
- [Search logs](/explore/logs) for **Cloud Logs**, which opens the log plane.
- [Create a monitor](/monitoring/create-a-monitor)
