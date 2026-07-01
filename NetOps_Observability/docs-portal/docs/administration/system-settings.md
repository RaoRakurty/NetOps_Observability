---
title: System settings (DNS & NTP)
sidebar_label: System (DNS & NTP)
sidebar_position: 7
description: Configure the DNS resolvers Correlix uses for outbound URLs and the NTP servers it tracks its clock against.
---

# System settings

<kbd>Administration → Settings</kbd> holds the platform's general configuration. Integration credentials are *not* here — they live with their connectors under [Incident Response → Integrations](/incident-response/integrations). The page is a stack of cards:

| Card | What it sets | Who sees it |
| --- | --- | --- |
| **Default landing page** | The page everyone lands on after sign‑in | All admins |
| **DNS** | The resolvers Correlix uses for outbound URLs | **Platform operators only** |
| **NTP** | The time sources Correlix tracks its clock against | **Platform operators only** |
| **Log export limits** | Anti‑exfiltration guardrails on log exports | Visible to admins; only the platform operator can save |

## Default landing page

1. Go to <kbd>Administration → Settings</kbd>.
2. In **Default landing page**, pick a page from the dropdown — **Built-in (Dashboards · Home)** or any of the listed views.
3. The choice applies platform‑wide at the next sign‑in.

## DNS resolvers

The DNS servers Correlix uses to **resolve outbound URLs** — ticketing integrations, webhooks, notification providers, and any host the platform connects to by name.

1. Go to <kbd>Administration → Settings</kbd> and find the **DNS** card (it shows how many resolvers are configured).
2. Click **Configure**. In the popup:

   | Field | Format |
   | --- | --- |
   | **DNS servers** | One per line — IP addresses, e.g. `1.1.1.1` |
   | **Search domains** *(optional)* | One per line, e.g. `corp.example.com` |

3. Click **Save** — the resolvers take effect immediately for every name the platform looks up.
4. Click **Test connectivity**. The result table shows, per test: **Query** (the name resolved), **Result** (*resolved* / *failed*), and **Answer** (the first resolved IP, or the error).
5. Click **Close**.

:::info Saves merge
DNS and NTP are stored together but edited separately — saving one never clears the other.
:::

## NTP time sources {#ntp-time-sources}

Accurate time matters: timestamps drive event ordering and correlation. This card sets the NTP sources Correlix *measures its clock against*.

1. On the same Settings page, find the **NTP** card and click **Configure**.
2. **NTP servers** — one per line, host or IP, e.g. `pool.ntp.org`, `time.cloudflare.com`.
3. Click **Save**, then **Test connectivity**. The result table shows per server:

   | Column | Meaning |
   | --- | --- |
   | **Server** | The configured source |
   | **Reachable** | *yes* / *no* (with the error when unreachable) |
   | **Stratum** | The server's NTP stratum |
   | **Offset** | How far Correlix's clock is from that source, in ms — flagged when beyond ±1000 ms |
   | **RTT** | Round‑trip time to the source, in ms |

An offset near zero means the platform's clock is in sync.

:::note Host clock
In a containerized deployment Correlix **measures and reports** its offset so you can confirm sync; keeping the host OS clock disciplined to these servers is the deployment's responsibility. Correlix surfaces the health.
:::

## Log export limits

Guardrails on log exports (anti‑exfiltration and abuse protection). They apply live — no restart — and while the card renders for admins, **only the platform operator can save changes** (a tenant must not be able to raise its own caps).

1. On the Settings page, find **Log export limits** and click **Configure**.
2. Adjust the limits (all required):

   | Field | Governs |
   | --- | --- |
   | **Rate limit (exports / min / tenant)** | How many exports a tenant may start per minute |
   | **Max rows per export** | Row cap per export job |
   | **Max size (MB)** | Byte cap per export |
   | **Max runtime (minutes)** | How long one export may run |
   | **Max time window (hours)** | The widest time range one export may cover |
   | **Download link TTL (minutes)** | How long a download link stays valid (clamped 5–15 min) |
   | **Sync → async threshold (rows)** | Above this, an export becomes a background job |

3. Click **Save limits**. The confirmation reads *"Saved. New limits apply to all exports immediately."*

## Verify

- **DNS**: after saving, run **Test connectivity** — the query should show *resolved* with an answer IP. A webhook or integration that previously failed on name resolution should now connect.
- **NTP**: each server shows **Reachable: yes** with a small offset. Recheck after any host‑clock maintenance.
- **Export limits**: from a tenant account, start a log export in [Explore → Logs](/explore/logs) that exceeds a limit — it should be clamped or refused.

## Troubleshooting

- **The DNS/NTP cards aren't on my Settings page.** They're platform‑operator‑only; a tenant admin sees only the cards their scope allows.
- **DNS test says *failed*.** Confirm the resolver IPs are reachable from the deployment host and answer queries from it (firewalls between the platform and your resolvers are the usual culprit).
- **NTP shows a large offset.** Correlix reports the drift; fix it by disciplining the *host* clock to the same servers, then re‑test — the offset should collapse toward zero.
- **Export limit save is refused.** Only the platform operator can change export limits; the attempt is recorded in the [Audit Log](/administration/overview#the-audit-log) as a deny.

## Related

- **[Incident Response → Notifications](/incident-response/notifications)** — the outbound senders that depend on DNS resolution.
- **[Explore → Logs](/explore/logs)** — where log exports are run.
