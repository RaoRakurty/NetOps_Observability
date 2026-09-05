---
title: Configure application attribution
description: Read the identification coverage behind an application name, declare an override the vendor feeds get wrong, and keep the service catalog and the application registry.
page_type: task
sidebar_position: 5
---

# Configure application attribution

A flow record carries addresses, ports and counters. It does not carry a name. Correlix supplies the name from an ordered set of sources, and it groups traffic into services from a rule you write. Both are configured on **Operations → Services**: the identification order and its coverage, the overrides you declare on top of it, and the two registries that name what the traffic belongs to.

## Before you begin

- **Permission:** `infrastructure:read` to read every surface on this page, `infrastructure:write` to declare an override or to keep either registry.
- Flow records arriving. See [Analyse flows](/explore/flows).
- The service catalog and the application registry are Postgres-backed. On a deployment without the database, the registry panels state that reason instead of showing an empty list.

## Steps

### Read the identification coverage

**Operations → Services → Settings** carries **Identification Coverage**. It reports the order the engine trusts its sources in and how much each layer holds.

1. Read the numbered order. Your own overrides sit at the top of it.
2. Read the four shared counts: **Vendor prefixes**, **Vendor domains**, **Firewall attributions** and **Cloud attributions**. Those four layers are platform-wide.
3. Read the three tenant counts: **Your overrides** and the prefix and domain split beneath it.

The order itself is set in **Attribution Precedence** on the same tab. The coverage card reports the order rather than setting it, so the two never disagree.

Where the override store does not answer, the count reads as unknown with the reason, never as zero. A tenant with no overrides and a tenant whose override store is unreadable are different facts, and identification behaves differently in each.

Where no vendor feeds are configured, the card says so. Identification then falls to the firewall, the cloud inventory and your own overrides.

### Declare an override

**Identification Overrides**, on the same tab, is the tenant's own naming. It outranks every other source, so an entry here wins outright.

1. Select **New override**.
2. Choose what to match on: an IP prefix, a domain suffix, an AS number or a port.
3. Enter the match value. A prefix takes an IPv4 CIDR or address, and a port takes 0 to 65535.
4. Enter the **Application name** to report.
5. Leave **confidence** empty to take the engine's default, or enter a value between 0 and 1.
6. Select **Add override**.

Rows belong to this tenant. They are stamped from your sign-in, and no other tenant reads or removes them. Creating and removing an override is recorded in the platform audit log. The row itself carries no separate history, which is why the panel says so rather than offering a per-row trail that does not exist.

### Keep the two registries

**Operations → Services → Registries** holds the two operator-authored registries, with a panel at the top naming which registry drives what.

| Registry | What it is for |
| --- | --- |
| **Service catalog** | An operable unit of traffic. Its selector is what makes per-service flow totals add up. |
| **Application registry** | The business application and the team accountable for it. It names ownership and does not group traffic. |
| **Cloud business services** | The cloud-side registry behind resource assignment and the criticality-aware impact view. It lives on the **Catalog** view. |

The service catalog and the application registry are separate lists today. A service cannot be attached to an application in the product, so treat a shared name as a convention you keep rather than a link the platform enforces.

#### Add a service and give it a selector

A service with no usable selector is carried with nothing attributed to it. That is what the **Not measured** rows in the flow **Services** section mean.

1. Open **Operations → Services → Registries**.
2. Under **Service catalog**, add the service with its name and criticality.
3. Open the service and add a grouping rule. A rule matches on destination ports, destination prefixes, protocols, or a combination.
4. A rule that matches on none of those attributes attributes nothing. The panel says so before you save it.

Each saved rule is a new version. Rules are append-only, so the history of how a service was measured stays readable.

Deleting a service archives it. Attribution history is kept rather than rewritten.

#### Register an application

Under **Application registry**, add the application with its name, its owner team and its criticality. The owner team is what carries application ownership into root-cause attribution. Deleting an application archives it.

## What you see

The coverage card names every layer the engine can draw on, with a count for each and an honest unknown where a layer did not answer. An override you declare appears at the top of that order and names its traffic from the next resolution onwards. A service with a saved selector stops reading **Not measured** in the flow **Services** section and starts carrying bytes and flows.

## Related

- [Analyse flows](/explore/flows) for the **Applications** and **Services** sections these settings drive.
- [Read an RCA case](/investigate/read-an-rca-case) for where application ownership appears during an incident.
- [Honest states](/reference/honest-states) for the difference between unknown and zero.
