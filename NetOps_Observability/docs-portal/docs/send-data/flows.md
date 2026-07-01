---
title: Flow records (NetFlow / sFlow / IPFIX)
sidebar_label: Flow records
sidebar_position: 5
description: Enable flow export on your devices to unlock traffic analytics, top talkers, and application attribution.
---

# Flow records (NetFlow / sFlow / IPFIX)

Flow records tell you **who is talking to whom, over what, and how much** — the basis of traffic analytics, top‑talker analysis, and application attribution. Correlix ingests the standard flow protocols.

## Supported protocols

- **NetFlow** v5 and v9
- **IPFIX**
- **sFlow**

## Configure flow export on a device

On each exporting device (typically your routers, switches, and firewalls), set Correlix as the flow collector:

- **Collector / destination** — your Correlix flow endpoint (host/IP).
- **Port** — commonly **2055** (NetFlow), **4739** (IPFIX), or **6343** (sFlow); use whichever your instance is configured to listen on.
- **Sampling rate** — sFlow and high‑volume links use sampling (e.g. 1‑in‑1000). Note the rate; Correlix accounts for it.

```bash
# Cisco IOS-XE (NetFlow v9 / IPFIX via Flexible NetFlow) — illustrative
flow exporter CORRELIX
 destination <correlix-flow-ip>
 transport udp 2055
```

:::warning Watch volume on unsampled flows
Full (unsampled) flow export on busy links can be very high volume. Prefer **sampled** export (sFlow, or NetFlow sampling) on high‑throughput interfaces.
:::

## Verify

1. <kbd>Administration → Data Collection → Data Sources</kbd> — the **Flows** column turns green.
2. <kbd>Flows</kbd> — top talkers, conversations, and service breakdowns populate.

## What it unlocks

- **Top talkers** and busiest services/ports.
- **Application attribution** — flows resolved to real applications (cloud/SaaS ranges, DNS correlation, and on‑box firewall App‑ID). See [Service View](/incidents/overview).
- Traffic context for **correlation** (e.g. a spike aligning with an incident).

## Next

- **[Explore flows](/explore/flows)**.
- **[Verify coverage](/onboard-devices/data-sources)**.
