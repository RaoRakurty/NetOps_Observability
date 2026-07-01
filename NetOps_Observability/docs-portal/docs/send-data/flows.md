---
title: Flow records (NetFlow / sFlow / IPFIX)
sidebar_label: Flow records
sidebar_position: 5
description: Enable flow export on your devices to unlock traffic analytics, top talkers, and application attribution.
---

# Flow records (NetFlow / sFlow / IPFIX)

Flow records tell you **who is talking to whom, over what, and how much** — the basis of top-talker analysis, conversation views, and application attribution. Correlix's flow collector ingests the standard flow protocols; you enable export on each device where traffic visibility matters (WAN edges, cores, internet borders, firewalls).

## Step 1 — Choose a protocol

The collector supports four protocols, each on its own UDP port:

| Protocol | Port | Best for | Notes |
| --- | --- | --- | --- |
| **NetFlow v9** | UDP **2055** | Routers and firewalls | Template-based; flexible fields |
| **NetFlow v5** | UDP **2055** | Legacy platforms | Fixed format, IPv4 only — use v9/IPFIX where available |
| **IPFIX** | UDP **4739** | Modern routers, Junos, SD-WAN | The IETF standard (a.k.a. NetFlow v10) |
| **sFlow** | UDP **6343** | High-throughput switches | Packet-sampled by design — low device overhead |

Rules of thumb:

- **Routers / firewalls** → NetFlow v9 or IPFIX (whichever the platform exports natively).
- **Data-center / campus switches at high rates** → sFlow.
- Pick **one** protocol per device; there's no benefit to exporting the same traffic twice.

## Step 2 — Configure the exporter

Point the device at Correlix on the port matching your protocol (`CORRELIX_IP` is your Correlix instance):

```text
! Cisco IOS / IOS-XE — NetFlow v9 (Flexible NetFlow)
flow exporter CORRELIX
  destination CORRELIX_IP
  source Loopback0
  transport udp 2055
  template data timeout 60
  export-protocol netflow-v9

flow monitor CORRELIX-FM
  exporter CORRELIX
  record netflow ipv4 original-input

interface GigabitEthernet0/0
  ip flow monitor CORRELIX-FM input
  ip flow monitor CORRELIX-FM output
```

```text
# Juniper Junos — IPFIX
set services flow-monitoring version-ipfix template IPFIX-T template-refresh-rate 30
set forwarding-options sampling instance CORRELIX family inet output flow-server CORRELIX_IP port 4739 version-ipfix
set forwarding-options sampling instance CORRELIX input rate 50
# then apply the sampling instance to the interfaces you want measured
```

```text
! Arista EOS — sFlow
sflow source-interface Loopback0
sflow destination CORRELIX_IP 6343
sflow sample 1000
sflow run
```

Apply the monitor/sampling to **both directions** of the interfaces you care about where the platform requires it (as in the Cisco example) — otherwise you'll only see half of each conversation.

## Step 3 — Set a sampling rate

Sampling is a trade-off you should make deliberately:

- **sFlow is always sampled** (e.g. `1-in-1000` on 10G+ links is typical). That's the point of the protocol — near-zero device overhead.
- **NetFlow/IPFIX can be unsampled**, but full flow export on busy links generates very high record volume on both the device and the collector. Prefer sampled export (e.g. `1-in-50` to `1-in-1000` depending on link speed) on high-throughput interfaces; unsampled is fine on low-rate WAN links where per-flow completeness matters.

:::warning Sampled volumes are estimates
Correlix reads the sampling rate carried in the flow stream and **scales volumes accordingly** — a 1-in-1000 sample of a 1 GB transfer displays as ~1 GB, not 1 MB. Scaled numbers are statistically solid for top talkers and trends, but they are estimates: small, short flows may be missed entirely at aggressive sampling rates. Don't treat sampled byte counts as billing-grade.
:::

## Step 4 — Verify

1. Wait a couple of minutes. NetFlow v9 and IPFIX are **template-based**: the device must send its templates before data records can be decoded, so the first records can lag the config change by a template cycle (set `template data timeout 60` as in the example to keep this short).
2. <kbd>Administration → Data Collection → Data Sources</kbd> — the device's **Flows** column turns green.
3. <kbd>Flows</kbd> — top talkers, conversations, and service breakdowns populate. See [Flow analytics](/explore/flows).
4. Sanity-check a known conversation (e.g. a file transfer you start yourself) appears with plausible volume.

## Troubleshooting

**Nothing arriving**

1. Protocol/port mismatch is the most common cause — NetFlow to **2055**, IPFIX to **4739**, sFlow to **6343**. Sending IPFIX to 2055 or sFlow to 2055 won't decode.
2. Confirm UDP is open on the path for the port you chose ([Connectivity requirements](/reference/connectivity-requirements)).
3. Confirm the monitor/sampler is actually **applied to interfaces** — a configured exporter with no interface attachment exports nothing (check platform counters, e.g. Cisco `show flow exporter statistics`).
4. Check the exporter's source address is one Correlix can associate with the device.

**Flows arrive late or in bursts**

- Normal: devices export a flow when it ends or when an active timeout expires (often 60–120 s by default). Long-lived flows appear as periodic updates, not a live stream.

**Volumes look wrong**

- Too low by a large constant factor → the sampling rate isn't being applied/announced as expected; verify the sampler config on the device.
- Only one direction of conversations visible → the monitor is applied `input`-only (or `output`-only); apply both.

**Lots of "unknown" applications**

- Expected and honest: Correlix labels an application only when it has real evidence (well-known services, cloud/SaaS ranges, DNS correlation, or a firewall's on-box application ID carried in [syslog](/send-data/syslog)). Onboarding your firewalls' logs materially improves attribution.

## What it unlocks

- **Top talkers**, conversations, and busiest services in [Flow analytics](/explore/flows).
- **Application attribution** across the traffic your exporters see.
- Traffic context for **correlation** — a spike that aligns with an incident is corroborating evidence.

## Next

- **[Explore flows](/explore/flows)**.
- **[Verify coverage](/onboard-devices/data-sources)**.
