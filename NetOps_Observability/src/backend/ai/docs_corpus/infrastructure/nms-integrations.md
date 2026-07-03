---
title: NMS Integrations
sidebar_label: NMS Integrations
sidebar_position: 7
description: Connect third-party NMS and controller platforms (Meraki, Catalyst Center, Catalyst SD-WAN Manager, Nexus Dashboard, Versa, Prime) so their computed state, SLA metrics, and alarms become correlated RCA evidence.
---

# NMS Integrations

<kbd>Infrastructure → NMS Integrations</kbd> connects third-party NMS and controller platforms — Meraki Dashboard, Catalyst Center, Catalyst SD-WAN Manager (vManage), Nexus Dashboard / NDFC, Versa Director / Concerto, Prime Infrastructure, or any generic controller — and ingests what each platform has already computed about its own domain: health state, SLA metrics, and alarms.

This is **controller intelligence ingestion, not log collection**. A controller is treated as a domain expert whose view is harvested, normalized, and reconciled against the direct telemetry Correlix collects itself. Everything is **read-only**: no connector ever writes to, or changes configuration on, a controller.

## What gets ingested

Each connector normalizes vendor data into three signal classes, each routed to the store built for its shape:

| Class | What it is | Where it lands |
|---|---|---|
| **Metrics** | SLA / performance series the controller computed (e.g. per-tunnel latency, jitter, loss, quality score) | Time-series store, as `controller_metric_*` series |
| **State** | Current health the controller asserts (tunnel up/down, device reachable, BFD session state) | State table with first-seen / last-seen / flap tracking |
| **Events** | Alarms and discrete changes (BFD down, control-connection loss, policy change) | The correlation engine, as management-plane evidence |

## How controller evidence is weighed

A controller is **one witness, not the truth**. Its signals carry the `management_plane` evidence class, and the engine's independence gate applies:

- **Controller-only evidence caps at *suspected*.** A controller alarm alone never confirms a fault — confirmation requires a corroborating witness from an independent evidence stream (active probes, control-plane events from the devices themselves, flows, or device telemetry).
- **Agreement upgrades confidence.** When the controller and direct telemetry both witness the same fault, corroborated signatures (for example an SD-WAN tunnel failure seen by both the controller and path probes) can reach *confirmed*.
- **Disagreement is surfaced, never averaged.** If the controller says healthy while probes say down, the contradiction is shown explicitly in the RCA evidence — the controller's optimism never masks a real fault, and its alarm alone never declares one.

### Ask the AI assistant

Because controller signals are cited evidence on the correlation object, the assistant can answer questions like:

- *"What did the controller report for this incident?"*
- *"Is this confirmed by direct telemetry, or controller-only?"*
- *"Which evidence streams agree, and is anything contradicting?"*

The answers come from the persisted evidence set of the incident — the assistant narrates what the engine already concluded; it never re-scores.

## Connect a controller

1. Enable the feature: set `FEATURE_NMS_INTEGRATIONS=true` in the deployment environment and restart the API service. Until then the page shows setup instructions and no connector runs.
2. Open <kbd>Infrastructure → NMS Integrations</kbd> and pick the vendor card.
3. Walk the wizard: **Connection** (base URL, poll interval, which streams to poll) → **Credentials** → **Review**, which runs a live authentication test and a first poll.

| Vendor | Authentication | Notes |
|---|---|---|
| Meraki Dashboard | API key, or OAuth | Needs the organization ID; also accepts webhooks |
| Catalyst Center | Username / password | Token refreshed automatically |
| Catalyst SD-WAN Manager (vManage) | Username / password | Includes app-route SLA metrics and BFD/tunnel state |
| Nexus Dashboard / NDFC | Username / password | Optional login domain |
| Versa Director / Concerto | OAuth client credentials, or Basic | |
| Prime Infrastructure | Username / password | |
| Generic controller | Bearer / API key / Basic | Polls an events endpoint; also accepts HMAC-signed webhooks |

Controllers with self-signed certificates: enable **Accept self-signed certificate** on that integration (per-integration opt-in; the default is strict TLS verification).

### Credential security

Credentials are encrypted at rest with a per-tenant key and are **write-only**: after saving, the UI and API only ever show *which* fields are set, never their values. Every integration belongs to the tenant that created it — no other tenant can see or reach it. Grant the controller account **read-only** privileges; the connector never needs more.

## Operate an integration

Each integration row shows a health dot, last successful poll, event volume, and error rate. From the row you can:

- **Poll now** — run an immediate cycle (works even while paused; useful during setup).
- **Test** — re-run the live authentication check.
- **Pause / resume** — stop polling without losing configuration or history.
- **States / Runs** — inspect the current controller-asserted states and recent poll history.

Polling is polite by design: each integration polls on its own interval, requests are rate-limited and retried with backoff (honoring vendor `429` / `Retry-After` responses), and pollers checkpoint so a restart never re-ingests history. Duplicate events are deduplicated before they reach the correlation engine.
