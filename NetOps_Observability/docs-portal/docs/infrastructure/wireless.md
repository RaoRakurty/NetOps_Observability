---
title: Monitor wireless
description: Read the vendor-neutral wireless inventory - controllers, access points with uplinks, slot-keyed radios, and WLANs - and understand the guarded action framework.
page_type: task
sidebar_position: 8
---

# Monitor wireless

**Infrastructure → Wireless** is the RF-side lens on one LAN. Wired and wireless are a single domain in Correlix, so a controller or an access point is a device row in the same inventory as a switch, and this page adds what only the wireless model knows: radios, WLANs and the AP-to-switch-port join.

The inventory is read-only. It is written by a vendor controller connector, and nothing on this page mutates a controller.

## Before you begin

- `infrastructure:read` in your tenant. Every list is scoped to the caller's tenant, and a controller or AP id from another tenant returns 404 rather than 403.
- A vendor controller connected. The Cisco Catalyst 9800 WLC connector supplies the inventory today, over read-only RESTCONF credentials. See [Connect a vendor controller](/infrastructure/nms-integrations).

## Steps

### Step 1 - Read the stat strip

Open **Infrastructure → Wireless**. Four counters head the page: **Controllers**, **Access points**, **APs with a radio down**, and **Stale (not seen last poll)**. Stale is its own counter on purpose. A record that the last poll did not re-confirm is not the same fact as a record the controller reported as down.

With nothing connected the page states how to fill it rather than showing an empty table: add a Cisco Catalyst 9800 integration under NMS Integrations, and the controllers, APs, radios and WLANs discovered there appear here.

### Step 2 - Read the controllers table

| Column | What it shows |
|---|---|
| **Name** | The controller name, or its id when the vendor reports none. |
| **Vendor** | The vendor that supplied the record. |
| **Cluster** | The cluster role: `standalone`, `ha_pair`, `n_plus_1`, `cloud_managed` or `controllerless`. |
| **Members** | The number of physical members in the logical control domain. |
| **Visibility** | How much of the controller is observable. A cloud-managed estate stays `partial`, because full visibility is earned rather than assumed. |
| **Last seen** | When the record was last confirmed. |

A controller is the logical control domain that access points join. Members are the physical boxes. A member failover changes member state and never an AP's controller binding.

### Step 3 - Read the access points table

| Column | What it shows |
|---|---|
| **Name**, **Model**, **Serial** | Identity as the controller reports it. An unreported field renders as a dash. |
| **Radios** | One chip per radio, keyed by slot and labelled with its band, tinted by operational state. An AP with no radios reported reads `no radios reported`. |
| **LAN uplink** | The AP's switch and port, which is the wireless-to-wired join. Where the controller does not report it, the cell reads `unknown`. |
| **Mgmt address** | The AP's management address. |
| **Forwarding** | Where client data goes. An unreported value reads `not reported`, never a guessed default. |
| **Last seen** | When the record was last confirmed. |

Radio identity is the pair of access point and slot, not band. Dual-5 GHz and tri-band access points make band ambiguous as an identity axis, so band is display and query only.

### Step 4 - Read the WLANs table and keep three identities apart

The WLANs table lists **Profile**, **SSID**, **Security**, **Auth**, **Forwarding** and **Enabled**. Unreported security and auth read `not reported`; unreported forwarding reads `unknown`.

The model refuses to conflate three things:

| Identity | What it is |
|---|---|
| **SSID** | The broadcast name. Not unique, not owned, estate-wide. |
| **WLAN** | The configuration profile on one controller: SSID plus security, auth, VLAN and forwarding. Controller-scoped. |
| **BSSID** | The MAC one radio broadcasts for one WLAN. The only precise answer to "where was this client". |

A WLAN's mobility domain is populated only when the controller exposes one, and is never inferred from two WLANs sharing an SSID. A null mobility domain means roam analysis abstains, which is the honest answer.

### Step 5 - Find the same devices in the fleet

Open **Infrastructure → Devices**. Controllers appear with type `wlc` and access points with type `ap`, both with source `wireless`. The projection is read-time only: the wireless store stays the single source of truth, and a controller that SNMP discovery already found keeps its discovery row, because the projection de-duplicates by management address.

## What you see

The tables list what the connector last reported. With no connector, the lists are honestly empty rather than absent:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/wireless/controllers
```

```json
null
```

The read-only routes:

| Route | What it returns |
|---|---|
| `GET /api/wireless/controllers` | Every visible controller. Append `/{id}` for one. |
| `GET /api/wireless/aps` | Every visible access point, with its radios overlaid. Append `/{id}` for one. |
| `GET /api/wireless/wlans` | Every visible WLAN profile. |
| `GET /api/wireless/bssids` | Every visible BSSID, with its radio, WLAN and AP references. |
| `GET /api/wireless/actions` | The guarded action register. It returns 404 while `FEATURE_WIRELESS_ACTIONS` is off. |

### Guarded actions, and why version 1 refuses to run one

`FEATURE_WIRELESS_ACTIONS` defaults to `false`, and while it is off the action routes return 404. Where it is on, three low-risk action kinds exist: `rrm_channel_change` on one radio, `ap_radio_reset` on one AP, and `client_deauth` on one client session. Each proposal passes five gates in order, and every gate fails closed:

| Gate | What it requires |
|---|---|
| 1 Proposal | The action's evidence family must have participated in the correlation object it claims to remediate. An action is never proposed from a title. |
| 2 Eligibility | The kind must be in the tenant allowlist, which is empty by default; the verdict must be `confirmed`, so a suspected or undetermined verdict never remediates; and the target must be exactly one entity of the action's type. |
| 3 Approval | A named human approver. Per-type auto-approve is opt-in, off by default, and audited as itself. |
| 4 Execution | Idempotent and timeout-bounded, through the vendor connector only, never over raw SSH. |
| 5 Verification | After execution the originating observation is re-measured in a settle window. Not recovered means rollback where possible and the action records as failed. |

Version 1 registers **no executor**. An approved action that reaches gate 4 therefore records the state `failed` with the reason `gate 4: no executor registered — the vendor write RPC has not earned live validation (Phase 9)`. The framework reports a refusal rather than pretending to have acted. Every transition is an audit event.

### Client data and retention

Per-client wireless events are stored in ClickHouse with a TTL set by `CH_WIRELESS_RETENTION_DAYS`, which defaults to 30 days because those events are personal data. The knob is clamped up to a 7-day floor and never down.

No per-client series reaches the metric store, and that is enforced by the schema rather than by convention. A client MAC is a ClickHouse column, never a metric label: aggregate series in the metric store are per-AP and per-radio only. Per-client RF is sampled at event boundaries such as associate, roam, disassociate and onboarding phase transitions, and on demand during an open episode, never continuously.

## Related

- [Connect a vendor controller](/infrastructure/nms-integrations) for connecting the Catalyst 9800 that fills these tables.
- [Work with the device inventory](/infrastructure/devices) for the fleet rows the controllers and access points project into.
- [Feature flags](/reference/feature-flags) for `FEATURE_WIRELESS_ACTIONS`.
