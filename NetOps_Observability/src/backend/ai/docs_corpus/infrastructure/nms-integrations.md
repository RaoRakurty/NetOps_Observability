---
title: Connect a vendor controller
description: Connect a third-party NMS or controller and ingest the state, SLA metrics and alarms it already computed as management-plane evidence.
page_type: task
sidebar_position: 9
---

# Connect a vendor controller

**Infrastructure → Discovery & NMS → NMS Integrations** connects a third-party controller and ingests what that platform has already computed about its own domain: health state, SLA metrics and alarms. This is controller-intelligence ingestion, not log collection. A controller is treated as a domain expert whose view is harvested, normalized and reconciled against the telemetry Correlix collects directly.

Every connector is read-only. None of them writes to a controller or changes its configuration.

## Before you begin

- `FEATURE_NMS_INTEGRATIONS=true` on the API service, then a restart. The flag defaults to off, and until it is set the page shows setup instructions and no connector runs.
- A controller account with read-only privileges. The connector never needs more.
- `infrastructure:write` in your tenant. An integration belongs to the tenant that created it, and no other tenant can see or reach it.

## Steps

### Step 1 - Pick the vendor

Open **Infrastructure → Discovery & NMS**, select the **NMS Integrations** tab, and select the vendor tile. Nine connectors ship:

| Connector | Authentication it supports |
|---|---|
| Cisco Meraki Dashboard | API key or OAuth. OAuth is preferred. |
| Cisco Catalyst Center | Basic, exchanged for a token. |
| Cisco Catalyst 9800 WLC | Basic over RESTCONF. IOS-XE offers no OAuth. |
| Cisco Catalyst SD-WAN Manager | Basic, token or session. Token is preferred. |
| Cisco Nexus Dashboard and NDFC | Basic, token or API key. |
| Cisco Prime Infrastructure | Basic only. |
| Versa Director | Basic or OAuth. OAuth is preferred. |
| Versa Concerto | Basic or OAuth. OAuth is preferred. |
| Generic REST and webhook | Basic, API key, token or OAuth. |

### Step 2 - Walk the wizard

1. **Connection**: the controller base URL, the poll interval in seconds, and which streams to poll. The interval is floored at 30 seconds and each connector carries its own vendor default.
2. **Credentials**: the fields that vendor's auth flow requires.
3. **Review & connect**: a live authentication test and a first poll.

For a controller with a self-signed certificate, enable **Accept self-signed certificate** on that integration. It is a per-integration opt-in and strict TLS verification is the default.

Credentials are encrypted at rest with a per-tenant key and are write-only. After saving, the console and the API report only which fields are set, never their values.

### Step 3 - Operate the integration

Each integration row shows a health dot, the last successful poll, event volume and error rate. From the row:

- **Poll now** runs an immediate cycle, which works while paused and is useful during setup.
- **Test** re-runs the live authentication check.
- **Pause** and **resume** stop polling without losing configuration or history.
- **States** and **Runs** show the states the controller currently asserts and the recent poll history.

Polling is deliberate about load. Each integration polls on its own interval, requests are rate-limited and retried with backoff that honours a vendor `429` and `Retry-After`, and pollers checkpoint so a restart never re-ingests history. Duplicate events are removed before they reach the correlation engine.

### Step 4 - Read what a connector declares it can observe

A connector declares each capability it supports along with a fidelity, and fidelity is earned upward rather than assumed:

| Fidelity | What it means |
|---|---|
| `none` | The vendor cannot report it. An honest hole, not a gap in Correlix. |
| `doc_claimed` | Authored from the vendor's own documentation and unproven against a live system. |
| `lab_validated` | A captured fixture replays through the transformer to the right canonical output. |
| `live_validated` | Confirmed flowing end to end from a real system. |

A capability at `none` renders as an explicit "not observable here". It never renders as a healthy tile, because an unsupported capability is not a passing one.

## Result

The integration row shows a recent successful poll, and its observations appear on correlation objects as management-plane evidence. Each connector normalizes vendor data into three classes:

| Class | What it is | Where it lands |
|---|---|---|
| Metrics | SLA and performance series the controller computed, such as per-tunnel latency, jitter, loss and quality score | The time-series store, as `controller_metric_*` series |
| State | Health the controller asserts, such as tunnel up or down, device reachable, BFD session state | A state table with first-seen, last-seen and flap tracking |
| Events | Alarms and discrete changes, such as BFD down, control-connection loss, policy change | The correlation engine, as management-plane evidence |

### How controller evidence is weighed

A controller is one witness, not the truth. Its observations carry the `management_plane` modality, and the independence gate applies:

- **Controller-only evidence is held at suspected.** Where the modality coverage is management-plane and nothing else, the verdict wording says so: `controller-only evidence; held at suspected until direct telemetry corroborates`.
- **Agreement raises confidence.** Where any direct modality also witnesses the fault, the wording reads `corroborated by direct telemetry (independent evidence streams agree)`.
- **Disagreement is shown, not averaged.** Where the controller says healthy while probes say down, the contradiction appears in the RCA evidence. The controller's optimism never masks a fault, and its alarm alone never declares one.

Because controller observations are cited evidence on the correlation object, [Iris](/iris-ai/overview) can answer what the controller reported for a case, whether the case is corroborated or controller-only, and which evidence streams disagree. Iris narrates the persisted evidence set; it never re-scores it.

## Related

- [Monitor wireless](/infrastructure/wireless) for the inventory the Catalyst 9800 connector fills.
- [Ask Iris](/iris-ai/ask-iris) for questioning the evidence a controller contributed.
- [Feature flags](/reference/feature-flags) for `FEATURE_NMS_INTEGRATIONS`.
