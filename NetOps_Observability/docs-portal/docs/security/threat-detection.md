---
title: Threat Detection
sidebar_label: Threat Detection
sidebar_position: 3
description: Flow-derived threat signals — horizontal/vertical scan detection and traffic to high-risk service ports.
---

# Threat Detection

Threat Detection surfaces **network threat signals computed from your flow records** (NetFlow / IPFIX / sFlow). It requires no new collection and no security appliances: every panel is derived from the same flows you already export for traffic analytics.

The board answers two questions for the selected time window:

- **Is anything scanning the network?** A single source talking to unusually many distinct hosts, or unusually many distinct ports, is the classic scan signature.
- **Is traffic reaching high‑risk service ports?** Legacy management and lateral‑movement services (Telnet, SMB, RDP, exposed databases, …) that should rarely cross your network unnoticed.

:::note Heuristic, not a verdict
These signals are a **triage starting point**, not a conviction. A backup server legitimately touches many hosts; a monitoring poller touches many ports. Use the board to find candidates, then confirm in [flow exploration](/explore/flows).
:::

## Before you begin

- **Flow export enabled** on your routers, switches, or firewalls — see [flow records](/send-data/flows). Verify flows are arriving under <kbd>Administration → Data Collection → Data Sources</kbd> before expecting anything here.
- **A role with read access to Infrastructure** to view the board.

The wider your flow export coverage (especially at choke points: core, distribution, firewall), the more of the network these signals can see. A scan that never crosses a flow‑exporting device is invisible to this board.

## Set the analysis window

The board is driven by the **global time‑range picker** in the top bar (Last 15 min · Last 1 hour · Last 6 hours · Last 24 hours · Last 7 days). All panels recompute for the selected window, and the board auto‑refreshes every 30 seconds.

- Use **Last 15 min / Last 1 hour** while actively watching for a scan in progress.
- Use **Last 24 hours / Last 7 days** for a periodic review — slow scans spread over hours only stand out in longer windows.

## Read the board

### Scan detection (flow fan‑out)

Two ranked bar panels, each listing the top source addresses by fan‑out in the window:

| Panel | Signal |
| --- | --- |
| **Horizontal scan suspects — distinct destination hosts per source** | One source touching many different *hosts* — network sweep behavior (host discovery, worm propagation) |
| **Vertical scan suspects — distinct destination ports per source** | One source touching many different *ports* — port‑scan behavior against one or few targets |

Bars turn **red at 25 or more** distinct hosts/ports. That threshold is a starting default — tune your reading of it to your environment (a management station or vulnerability scanner will legitimately exceed it; note such sources and treat *new* entrants to the list as the signal).

### High‑risk service exposure

The **"Traffic to high‑risk destination ports (bytes)"** panel shows how much traffic reached ports associated with lateral movement, remote access, and legacy management:

| Port | Service | Port | Service |
| --- | --- | --- | --- |
| 21 | FTP | 3389 | RDP |
| 23 | Telnet | 5900 | VNC |
| 135 | MS‑RPC | 3306 | MySQL |
| 139 | NetBIOS | 6379 | Redis |
| 445 | SMB | 11211 | memcached |
| 1433 | MSSQL | 2049 | NFS |
| 512/513/514 | rexec / rlogin / rsh | | |

If none of these ports saw traffic in the window, the panel states *"No traffic to known high‑risk ports (FTP/Telnet/SMB/RDP/VNC/DB/…) in this window."*

### All top destination ports

Below it, the **"All top destination ports"** panel shows the busiest destination ports in the window as badges — high‑risk ports render red with their service name (e.g. `445 (SMB)`), everything else in the accent color. Hover a badge to see its flow count. This is your quick "what does the network actually talk on" profile; an unfamiliar port appearing near the top is worth a look even if it isn't on the high‑risk list.

## Investigate a scan suspect

1. Go to <kbd>Security → Threat Detection</kbd> and set the time range that showed the suspect.
2. Note the source address at the top of the **Horizontal** or **Vertical scan suspects** panel and its fan‑out count (e.g. *"87 hosts"*).
3. Cross‑check both panels: a source high on *both* (many hosts **and** many ports) is much more likely to be hostile reconnaissance than a single‑dimension talker.
4. Decide whether the source is expected:
   - Known infrastructure — monitoring pollers, vulnerability scanners, backup servers, domain controllers — routinely produces high fan‑out. Keep a mental (or documented) allowlist.
   - An **end‑user subnet address, a DMZ host, or an unknown address** with high fan‑out is the real signal.
5. Pivot to <kbd>Explore → Flows</kbd> and filter to that source address to see the full conversation detail — which hosts/ports it touched, when, and how much data moved. See [exploring flows](/explore/flows).
6. Check the **High‑risk service exposure** panel for the same window: a scanner that found an open SMB/RDP/Telnet port and then moved real bytes over it has progressed from reconnaissance to access — escalate accordingly.
7. Contain per your incident process (isolate the source, block at the firewall). Correlix is observability, not enforcement — it will show you the traffic stopping once your control is in place.

## Verify it worked

1. With flow export confirmed under <kbd>Administration → Data Collection → Data Sources</kbd>, open <kbd>Security → Threat Detection</kbd> with the range at **Last 1 hour**.
2. The **All top destination ports** panel shows badges (your normal service mix — expect 443, DNS, etc. near the top).
3. The scan panels list sources — on a healthy quiet network these are low‑count and dominated by infrastructure addresses.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| *"No flow data in this window."* | No flows in the selected range. Widen the time range; if still empty, flow export isn't reaching the platform — re‑verify with [flow records](/send-data/flows) and the Data Sources page. |
| Panels show an error message | The flow analytics store couldn't be queried — check overall stack health, then retry. |
| Scan panels look empty but ports panel has data | Normal on quiet networks — fan‑out panels only rank sources that exist in the window; nothing may exceed noise levels. |
| Byte counts look too low | Sampled flow export (e.g. 1‑in‑1000 sFlow) is scaled up automatically using the reported sampling rate; verify the sampling rate configured on the exporter matches what it reports. |

## Related

- [Send flow records](/send-data/flows) — enable and verify flow export.
- [Explore flows](/explore/flows) — the pivot target for investigations.
- [Vulnerability Management](/security/vulnerability-management) — whether a scanned target is actually exploitable.
