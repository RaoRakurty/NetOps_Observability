---
title: Turn Correlix features on and off
sidebar_label: Features
description: Switch Correlix features on or off from the console, see which apply at once and which after a restart, and restart Correlix to apply them.
page_type: task
sidebar_position: 22
---

# Turn Correlix features on and off

**Platform → Configuration → Features** is where the platform administrator
switches Correlix features on and off. You never edit configuration files: the
values set at install are only the starting point, and what you save here wins.

Only the platform administrator sees this page. Organisation and tenant
administrators do not.

## 1. Choose a feature

Features are grouped: **Collection**, **Discovery**, **Routing**,
**Active measurement**, **Configuration and device access**,
**Integrations and automation**, **Analytics** and **Iris AI**. Each line says what the feature does, and where its current value
came from:

- **Set at install** — the value the installer chose.
- **Changed here** — saved on this page, with who saved it and when.
- **Not set at install** — the built-in default applies.

## 2. Turn it on or off

Use the switch. The change is saved at once and written to the audit log.

Features that reach into your network or out of Correlix — SSH to devices,
configuration backup, diagnostic commands, packet capture, wireless actions,
ticket updates from your ITSM tool, the UniFi controller, the two **Active
measurement** switches, and every **Iris AI** switch — ask you to confirm
before they turn **on**. Turning any feature
**off** never asks.

### The Active measurement switches

| Switch | What it does |
|---|---|
| **Path discovery** | The Correlix prober traces the hop-by-hop path to each path target every minute, so **Measured paths** and root-cause analysis can see where a path breaks. |
| **Active path probes (STAMP)** | The prober sends standard STAMP test packets to each probe target to measure latency, jitter and loss. |

Both send test packets from this Correlix server into your network, so they
start **off**. They run in the separate prober service, which picks up a
change within about 15 seconds; no restart is needed. If the prober cannot
read the switch from Correlix — for example while Correlix itself is
restarting — it stops measuring rather than guess, and resumes on its own.
Targets that are never probed (the server itself, link-local and cloud
metadata addresses, multicast) are refused whoever listed them.

The prober only obeys switch settings that Correlix has signed with a key
that just the two of them hold, so no other service can turn measurement on.
Each measured path belongs to the workspace whose target it traced, and only
that workspace sees it.

### The Iris AI switches

| Switch | What it allows | Needs |
|---|---|---|
| **Iris AI models** | Iris sends questions and the evidence it gathered to your configured AI provider for written answers and chat. Off, Iris answers from Correlix data alone. | the Iris AI add-on |
| **AI investigations** | The AI model runs read-only lookups across your network data. Each workspace still opts in. | the add-on, Iris AI models |
| **Iris active probes** | Iris's methods may send a short test (3 pings, one traceroute, one DNS lookup or one web request) from this Correlix server to a workspace's own devices or declared probes — never from a customer device. Each workspace opts in. | the add-on, AI investigations |
| **Iris actions (approval needed)** | Iris may propose a note for an incident's ITSM ticket or save its finding to investigation memory; nothing happens until someone other than the person Iris answered approves it. Never a device change. | the add-on, AI investigations |
| **Iris over MCP (read-only)** | An external AI assistant may use Iris's read-only lookups with a workspace API key. Data leaves Correlix for that assistant. | — |
| **Iris in Slack and Teams** | People may ask Iris from Slack or Microsoft Teams; each linked chat account is approved by an administrator. | — |

These switches are set **on this page only** — no install setting or
configuration file can turn them on — and they start off. A switch that needs
the Iris AI add-on cannot be turned on without it; the page says why.

## 3. Restart if asked

Each feature says when a change takes effect:

- **Applies at once** — in force as soon as you save.
- **Applies after restart** — the feature is started when Correlix starts.
  Until the restart, the line shows what is running now and what will run
  after it, for example *Running on now; off after restart.*

When a restart is needed, a banner offers **Restart now**. Correlix restarts
cleanly and the page updates when it is back, usually within a minute or two.
If your installation cannot restart itself, the banner tells you to restart the
Correlix service from the host instead.

## What is not on this page

- Settings that have their own page — notification channels, ITSM connections,
  SNMP discovery ranges — are changed there.
- Security controls such as encryption and TLS are set at install. A switch on
  this page can never stop Correlix from starting.
