---
title: Configure system settings
sidebar_label: System settings
description: Set the post-sign-in landing page, the timestamp zone, the platform's DNS and NTP sources, and the log-export limits.
page_type: task
sidebar_position: 9
---

# Configure system settings

**Administration → Settings** holds the platform's general configuration: where people land after signing in, how timestamps render, the resolvers and time sources the platform itself uses, and the guardrails on log exports. Integration credentials are not here. They live with their connectors under **Administration → Incident Response**.

## Before you begin

- **Permission:** `administration:admin` opens the page. The landing page and the time display are per-tenant settings.
- **Permission:** platform administrator for DNS and NTP. `GET` and `PUT` on `/api/system/network` and the probe at `/api/system/network/test` all call `requirePlatformAdmin`, and the two cards are hidden from a tenant administrator. This is platform-global configuration.
- **Permission:** log-export limits render for any administrator and `GET /api/exports/policy` answers for them, but `PUT` is refused for anyone who is not the platform owner. A tenant must not be able to raise its own caps.
- For DNS, have the resolver addresses reachable from the deployment host. For NTP, have the server names or addresses your organization uses.

## The cards

| Card | What it sets | Who can save |
| --- | --- | --- |
| **Default landing page** | The page everyone lands on after signing in | All administrators |
| **Time display** | Whether timestamps render in the local zone or UTC, for the whole tenant | All administrators |
| **DNS** | The resolvers Correlix uses for outbound names | Platform administrator only |
| **NTP** | The time sources Correlix measures its clock against | Platform administrator only |
| **Log export limits** | Anti-exfiltration guardrails on log exports | Platform administrator only |

## Steps

### Set the default landing page

1. Open **Administration → Settings**.
2. In **Default landing page**, pick from the list. **Built-in (Dashboards · Home)** is the shipped choice.
3. The choice saves as you make it and applies at the next sign-in. A tenant can override it in Identity & Access.

### Set the time display

1. In **Time display**, pick **Local** or **UTC**.
2. The change applies immediately, and every rendered timestamp re-labels without a reload.

Storage is always UTC. Only the display changes. The setting is per tenant, administrator-set, and applies to all of the tenant's users.

### Configure DNS resolvers

These are the resolvers Correlix uses to resolve outbound names: ticketing integrations, webhooks, notification providers, and any host it connects to by name.

1. Find the **DNS** card. It shows how many resolvers are configured.
2. Select **Configure**.
3. Enter the **DNS servers**, one per line, as IP addresses.
4. Optionally enter **Search domains**, one per line.
5. Select **Save**. The resolvers become the process resolver immediately, for every name the platform looks up.
6. Select **Test connectivity**. The probe resolves a name through the configured resolvers and reports the name it queried, whether it resolved, and the addresses it got back or the error.

The probe resolves `cloudflare.com` unless you name another host, and it queries each configured resolver on UDP 53.

DNS and NTP are stored as one record and edited separately. Saving one never clears the other.

### Configure NTP time sources {#ntp-time-sources}

Timestamps drive event ordering and correlation, so clock accuracy is not cosmetic. This card sets the sources Correlix measures its clock against.

1. Find the **NTP** card and select **Configure**.
2. Enter the **NTP servers**, one per line, as hostnames or addresses.
3. Select **Save**, then **Test connectivity**. The result table reports, per server:

   | Column | Meaning |
   | --- | --- |
   | **Server** | The configured source |
   | **Reachable** | Whether it answered, with the error when it did not |
   | **Stratum** | The server's NTP stratum |
   | **Offset** | How far the platform's clock is from that source, in milliseconds |
   | **RTT** | Round-trip time to the source, in milliseconds |

The probe speaks SNTP to each server on UDP 123 and reports the reachable server with the smallest absolute offset as the platform offset. An offset near zero means the clock is in sync.

:::note Correlix reports the offset, the host keeps the clock
In a containerised deployment Correlix measures and reports its offset so you can confirm sync. Disciplining the host operating system's clock to these servers is the deployment's job. Correlix surfaces the health rather than setting the time.
:::

### Set the log-export limits

The limits apply live, with no restart.

1. Find **Log export limits** and select **Configure**.
2. Adjust the fields. The shipped defaults are below.

   | Field | Governs | Default |
   | --- | --- | --- |
   | Rate limit, exports per minute per tenant | How many exports a tenant may start per minute | 10 |
   | Max rows per export | Row cap per export job | 500000 |
   | Max size | Byte cap per export | 268435456 bytes, which is 256 MiB |
   | Max runtime | How long one export may run | 300 seconds |
   | Max time window | The widest range one export may cover | 168 hours, which is 7 days |
   | Download link TTL | How long a download link stays valid | 600 seconds, clamped to between 5 and 15 minutes on read |
   | Sync to async threshold | Above this row count an export becomes a background job | 5000 rows |

3. Select **Save limits**.

If the stored limits cannot be read, the looser environment defaults are in force and the failure is logged loudly rather than shaped like a missing setting.

## Result

The DNS test reports the query as resolved with an answer address, and an integration that previously failed on name resolution connects. Each NTP server reports **Reachable: yes** with a small offset. `GET /api/exports/policy` returns the limits you saved, and an export from a tenant account that exceeds one is clamped or refused.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/exports/policy
```

```json
{
  "rate_per_min": 10,
  "max_rows": 500000,
  "max_bytes": 268435456,
  "max_runtime_seconds": 300,
  "max_range_hours": 168,
  "link_ttl_seconds": 600,
  "sync_max_rows": 5000
}
```

## Related

- [Notifications](/incident-response/notifications) for the outbound senders that depend on DNS resolution.
- [Explore logs](/explore/logs) for where exports are run.
- [Read the audit log](/administration/audit-log) to see a refused save recorded as a deny.
- [Connectivity requirements](/reference/connectivity-requirements) for the outbound ports these probes use.
