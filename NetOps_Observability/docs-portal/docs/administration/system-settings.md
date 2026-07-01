---
title: System settings (DNS & NTP)
sidebar_label: System (DNS & NTP)
sidebar_position: 7
description: Configure the DNS resolvers Correlix uses for outbound URLs and the NTP servers it tracks its clock against.
---

# System settings (DNS & NTP)

These are Correlix's own **system** network settings — the DNS resolvers the platform uses to resolve outbound URLs, and the NTP servers it tracks its clock against. Configure them in the **System · DNS & NTP** box on <kbd>Administration → Settings</kbd>. Platform‑owner only.

## DNS servers

The DNS servers Correlix uses to **resolve outbound URLs** — integrations (ServiceNow, Jira), webhooks, notification providers, and any host Correlix connects to by name.

1. Go to <kbd>Administration → Settings</kbd>.
2. Enter one or more **DNS server IPs** (one per line).
3. (Optional) add **search domains**.
4. **Save** — Correlix immediately starts resolving names through these servers.

:::info Takes effect immediately
On save, the configured resolvers become the platform's resolver — every URL Correlix looks up goes through them. Use **Test connectivity** to confirm a name resolves.
:::

## NTP servers

The NTP time sources Correlix tracks its clock against. Accurate time matters — timestamps drive event ordering and correlation.

1. Enter one or more **NTP servers** (host or IP), one per line.
2. **Save**, then **Test connectivity**.

The test reports, per server: **reachable**, **stratum**, the measured **clock offset** (how far Correlix's clock is from the source), and **round‑trip time**. An offset near zero means Correlix's clock is in sync; a large offset is flagged.

:::note Host clock
In a containerized deployment Correlix **measures and reports** its clock offset against your NTP servers so you can confirm sync. Keeping the host OS clock disciplined to these servers is the deployment's responsibility; Correlix surfaces the health.
:::

## Test connectivity

Click **Test connectivity** to:

- resolve a well‑known name through the configured **DNS** servers (confirms outbound resolution works), and
- query each **NTP** server for reachability, stratum, and offset.

Use it right after saving to verify the platform can resolve URLs and reach its time sources.
