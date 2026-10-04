---
title: Search raw documents in Search Dashboards
sidebar_label: Search Dashboards
description: Open OpenSearch Dashboards inside the console for ad-hoc search across the log indices and for index management.
page_type: task
sidebar_position: 22
---

# Search raw documents in Search Dashboards

**Platform → Tools → Search Dashboards** embeds OpenSearch Dashboards in the
console. It is the power-user view over the search tier: ad-hoc queries across
the indices, saved visualisations, and index management. For everyday log
search, use **Explore → Logs**, which is tenant-scoped and needs no knowledge of
the index layout.

## Before you begin

- A platform administrator account. Search Dashboards reads the shared search
  tier directly, so it is platform-global and never offered to a tenant or
  organization administrator.

## Steps

1. Go to **Platform → Tools → Search Dashboards**.
2. Use OpenSearch Dashboards in the frame as you would on its own: **Discover**
   for queries, **Dashboards** and **Visualize** for saved views, and the
   management pages for indices.

## What you see

The OpenSearch Dashboards interface, served from `/search/` behind the same
sign-in as the console.

:::caution
Search Dashboards is not tenant-scoped. Every tenant's documents are visible
here. Share what you find with the same care as any cross-tenant data.
:::

## Related

- [Search logs](/explore/logs) for tenant-scoped log search.
- [Review quarantined telemetry](/administration/review-quarantined-telemetry)
- [Check the health of the Correlix stack](/administration/stack-health)
