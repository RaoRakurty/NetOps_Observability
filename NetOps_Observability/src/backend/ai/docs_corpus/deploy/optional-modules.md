---
title: Turn on an optional module
description: Set the flag, supply what the module additionally needs, recreate the service, and confirm the module is live rather than dormant.
page_type: task
sidebar_position: 8
---

# Turn on an optional module

Most Correlix capabilities are dormant until a flag turns them on. With the flag off, nothing is constructed, scheduled or routed: no worker, no route, no metric series, and the module's API paths answer `404`. A handful of modules need more than the flag, because turning them on without a credential or without key custody would either fail at the first use or write sensitive data in the clear.

The modules below need more than the flag. The full switch list lives in [Feature flags](/reference/feature-flags).

## Before you begin

- Shell access to the host and the ability to edit `deployment/docker/.env`.
- The extra input the module needs, from the table below. A module with a missing input fails loudly at start; it never guesses.
- A window to recreate the affected service. Most modules live in the `api` service.
- For the sealed modules, an active sealing provider: add `seal` to `COMPOSE_PROFILES` and set `SEAL_PROVIDER=swtpm`. Enabling TLS does both. See [Enable TLS and mTLS](/deploy/enable-tls).

## Steps

1. Open `deployment/docker/.env`.

2. Set the module's flag to the exact string `true`. Any other value, including `TRUE` and `1`, leaves the module off.

   ```
   FEATURE_CONFIG_BACKUP=true
   ```

3. Set everything in the module's **Also needs** column. A partially configured module is a hard error at start, not a silent fallback.

   ```
   CONFIG_BACKUP_SSH_USER=correlix-ro
   CONFIG_BACKUP_SSH_KEY=/data/keys/correlix-ro.pem
   ```

4. Recreate the service that hosts the module.

   ```bash
   cd deployment/docker && docker compose up -d api
   ```

   Modules in the `prober` service need `docker compose up -d prober`, and the `prober` compose profile must be active.

5. Read the service log for the module's own startup line. A refusal is loud and names what is missing.

   ```bash
   docker compose logs --tail=50 api
   ```

## Result

The module's routes stop answering `404` and start answering. A dormant module and a broken one are distinguishable: dormant means the route does not exist, and broken means the service refused to start and said why.

## Modules that need more than a flag

| Module | Flag | Also needs |
|---|---|---|
| Security evidence lane | `FEATURE_SECURITY_LANE` | Nothing beyond the flag. Bounded by `SECURITY_SCAN_INTERVAL` (default `15m`) and `SECURITY_MAX_FINDINGS_PER_TENANT` (default `5000`). |
| Configuration backup and drift | `FEATURE_CONFIG_BACKUP` | An active sealing provider, plus `CONFIG_BACKUP_SSH_USER` and one of `CONFIG_BACKUP_SSH_PASSWORD` or `CONFIG_BACKUP_SSH_KEY`. `CONFIG_BACKUP_SSH_PORT` defaults to `22`. Disk for the sealed blobs in `data/config-backups`. |
| Packet capture | `FEATURE_PACKET_CAPTURE` | The same sealing provider, plus `PCAP_SSH_USER` and one of `PCAP_SSH_PASSWORD` or `PCAP_SSH_KEY`. `PCAP_SSH_PORT` defaults to `22`. Disk for the sealed captures in `data/pcap`. |
| Protocol diagnostics collect | `FEATURE_PROTOCOL_DIAG_COLLECT` | `PROTOCOL_DIAG_SSH_USER` plus one of `PROTOCOL_DIAG_SSH_PASSWORD` or `PROTOCOL_DIAG_SSH_KEY`. `PROTOCOL_DIAG_SSH_PORT` defaults to `22`. |
| BMP receiver | `FEATURE_BMP` | `BMP_LISTEN` if the default `:11019` is wrong for this host, and the matching host port published. Every router that pushes must already exist in the inventory. |
| BGP alerting | `FEATURE_BGP_ALERTS` | A populated BGP watchlist. The flag turns on the watchlist evaluator that raises transition alerts and emits evidence. |
| BGP live feed | `FEATURE_BGP_LIVE_FEED` | Egress to the upstream routing-data source. The feed is a bounded per-tenant ring of recent updates. |
| Device SSH terminal | `FEATURE_DEVICE_SSH` | Nothing stored. Each operator supplies their own credentials per session, and every session is authenticated and audited. |
| Traceroute collector | `FEATURE_TRACEROUTE` | The `prober` compose profile, `TRACEROUTE_TARGETS`, and the `NET_RAW` capability, which the shipped `prober` service already declares. `TRACEROUTE_METHOD` is `icmp` or `tcp`; `TRACEROUTE_TCP_PORT` defaults to `443`. |
| Sealed fields | `FEATURE_SEALED_FIELDS` | Real key material. Set `SEAL_PROVIDER=swtpm` and bring up the sealing sidecar. |

## Four behaviours to expect

**A partially configured identity is a hard error.** Protocol diagnostics falls back to the configuration-backup capture account when none of its own three variables is set, because that account is already a least-privilege read-only login on the same devices. A user with no secret beside it is refused at start rather than silently authenticating as a different account.

**A dormant vault refuses construction.** `FEATURE_SEALED_FIELDS=true` with no key custody stops the API at boot with the reason, instead of accepting seal rules that would not encrypt. The check runs at start, not at the first sealed event hours later in the ingest path where nobody is watching.

**Sealed modules refuse cleartext.** Configuration backup and packet capture will not start without an active sealing provider. Neither module writes a device configuration or a capture to disk unencrypted.

**Some limits are not knobs.** Packet capture's duration and size ceilings are hard caps in code and have no environment variable, because a setting that could raise "maximum capture duration" to an hour would be the unbounded capture the design forbids, wearing a configuration file. Only retention (`PCAP_KEEP`, default `20` per device) and the capture identity are tunable. The BMP receiver's message size, connection count, per-session update depth and read deadlines are hard caps for the same reason.

## Disk to budget

| Module | Directory | Rough size |
|---|---|---|
| Configuration backup | `data/config-backups` | running-config size, times `CONFIG_BACKUP_KEEP_VERSIONS` (default `30`), times device count. About 3 GB for 200 KB configurations across 500 devices, before compression. |
| Packet capture | `data/pcap` | Up to 25 MiB per capture, times `PCAP_KEEP`, times device count, in the worst case. |

Both directories are created `0700` and owned by the API's runtime user. `data/config-backups` is the only copy of a captured configuration, so include it in the backup rotation. A capture can contain payload bytes; treat `data/pcap` as sensitive.

## Related

- [Feature flags](/reference/feature-flags) - every switch, with the default the shipped compose file sets.
- [REST API reference](/reference/api) - the routes each module registers.
- [Enable TLS and mTLS](/deploy/enable-tls) - the shortest path to an active sealing provider.
