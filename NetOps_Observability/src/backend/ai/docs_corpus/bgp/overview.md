---
title: BGP operations
sidebar_label: Overview
sidebar_position: 1
description: The routing observatory - watchlist, RPKI, AS paths, geofeeds, alerting, bogons, and a BMP receiver for your own routers.
page_type: index
---

# BGP operations

This section is for the operator who has to answer one question during a routing
incident: is this prefix still announced the way you expect, and if not, what
changed. The console page is **Analytics → Metric Dashboards → BGP Operations**.
Every section of that page renders on load, so the outage call does not start
with a hunt through tabs.

Two kinds of data reach the page. Public routing facts come from RIPE NCC RIS /
RIPEstat and from RDAP, behind a bounded per-resource cache. Your own routing
state comes from your own routers over BMP, once you enable the receiver and a
network engineer points a router at it.

## The pages

| Page | What it gives you |
|---|---|
| [Watch a prefix or an ASN](/bgp/watchlist) | Pin the resources this tenant cares about. The watchlist drives the RPKI sweep, the near-live feed and the alert evaluator. |
| [Investigate a BGP prefix](/bgp/investigate-a-prefix) | Routing status, visibility, the RPKI verdict, collector paths, update churn and registry ownership for one resource. |
| [Check RPKI origin validation](/bgp/rpki) | The ROA verdict for one prefix or for the whole watchlist, with "could not check" kept separate from "no ROA". |
| [View AS paths for a prefix](/bgp/as-paths) | The collector-to-origin graph, deduplicated and capped, with dropped paths counted. |
| [Find a published geofeed](/bgp/geofeed) | The RFC 8805 geolocation feed a holder published for its own address space. |
| [Configure BGP alerting](/bgp/alerting) | The incident classes, the corroboration floor, and the policy that declares your expected origins and upstreams. |
| [Review bogon sightings](/bgp/bogons) | The reserved-address set in force and any bogon seen on this tenant's own feeds. |
| [Point a router at the BMP receiver](/bgp/bmp) | Receive a router's Adj-RIB-In over TCP and read it back, bounded and per-tenant. |

## What this section does not do

- **Correlix configures no device.** Turning on BMP is an environment change on
  the platform plus a configuration change a network engineer makes on the
  router. The receiver is read-only toward the network.
- **Four modules are off by default**: `FEATURE_BGP_ALERTS`,
  `FEATURE_BGP_LIVE_FEED`, `FEATURE_BGP_BOGON_FEED` and `FEATURE_BMP`. See
  [the feature flag reference](/reference/feature-flags).
- **No IRR mirror is built**, so route-object consistency, on-demand
  looking-glass verification and third-party corroboration are absent from the
  page rather than shown as empty panels. The page footer names those gaps.
- **Every panel fails on its own and says so.** A dead registry lookup does not
  blank the routing verdict, and no panel renders a failure as a clean result.

## Honesty on this page

Correlix separates *not measured* from *measured as zero* everywhere in this
section:

- With `FEATURE_BGP_ALERTS` off, the watchlist carries the note "No incident
  here means NOT EVALUATED, not healthy." An empty incident list is never
  rendered as all clear.
- An RPKI verdict of `unavailable` means the validator could not be reached. It
  is not counted as `valid`, and it is never merged with `unknown`, which means
  no ROA covers the prefix.
- A BMP response with no sessions says that no router is exporting. It is an
  empty feed, not an empty routing table.

The full table is at [what an empty result means](/reference/honest-states).

## Related

- [The API reference for every `/api/bgp` route](/reference/api)
- [Feature flags and their defaults](/reference/feature-flags)
- [Ports and outbound reachability](/reference/connectivity-requirements)
