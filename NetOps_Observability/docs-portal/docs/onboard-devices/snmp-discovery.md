---
title: Discover devices (SNMP)
sidebar_label: Discover devices
sidebar_position: 3
description: Point Correlix at your management subnets and let it find and inventory devices automatically over SNMP.
---

# Discover devices (SNMP)

Instead of adding devices one by one, you can have Correlix **scan your management subnets** and onboard everything that answers SNMP. This is the fastest way to bring a fleet in. Discovery runs continuously once configured and is **idempotent** — re-runs update existing devices and add new ones without creating duplicates.

## Step 1 — Enable SNMP on the devices

Discovery can only find devices that answer SNMP. Enable a **read-only** credential on each device. The snippets below are **generic examples** for the common CLI families — adapt names, ACLs, and addresses to your platform and security policy. `CORRELIX_IP` is your Correlix instance's address.

```text
! Cisco IOS / IOS-XE style — v2c read-only, restricted by ACL
access-list 10 permit host CORRELIX_IP
snmp-server community MyR0Community RO 10

! ...or SNMPv3 (recommended)
snmp-server group CORRELIX-GRP v3 priv
snmp-server user correlix CORRELIX-GRP v3 auth sha AUTH-PASSPHRASE priv aes 128 PRIV-PASSPHRASE
```

```text
! Arista EOS style
snmp-server community MyR0Community ro
! ...or SNMPv3
snmp-server user correlix CORRELIX-GRP v3 auth sha AUTH-PASSPHRASE priv aes PRIV-PASSPHRASE
```

```text
# Juniper JunOS style
set snmp community MyR0Community authorization read-only
set snmp community MyR0Community clients CORRELIX_IP/32
```

## Step 2 — Add the matching credential in Correlix

Discovery authenticates with the credentials you've stored:

1. Go to <kbd>Administration → Data Collection → SNMP Profile Manager</kbd> → **Credentials**.
2. Create a profile matching what you configured on the devices (community or v3 user). See [SNMP profiles & credentials](/onboard-devices/snmp-profiles) for every field.

If most of the fleet shares one community, one profile is enough; add per-group profiles for exceptions.

## Step 3 — Set the discovery range

Discovery is scoped by **network ranges in CIDR notation**, configured per instance in the deployment settings (`.env` on a self-hosted install):

```bash
# deployment/docker/.env
ENABLE_SNMP_DISCOVERY=true          # on by default
SNMP_CIDR_RANGES=10.20.0.0/24,10.30.5.0/26   # comma-separated, YOUR management subnets
```

Apply the change by recreating the service:

```bash
docker compose up -d
```

:::warning Narrow the range before scanning
The shipped default range is `10.0.0.0/8` — an entire private class A. **Replace it with your actual management subnets** before pointing discovery at a real network. Scanning too-wide ranges wastes poll capacity, trips IDS/ACL alarms, and can sweep hosts you don't own.
:::

## Step 4 — Watch devices arrive

1. Go to <kbd>Infrastructure → Devices</kbd>. Discovered devices appear with a **Source** badge of **SNMP** and a status dot as their first heartbeats land.
2. For every responding device, Correlix reads its **system identity** over SNMP — the device **Type** column (Router/Switch/Firewall/…) and **Manufacturer** are inferred from the device's SNMP identity fingerprint, not guessed. Recognized vendors include Cisco, Juniper, Arista, Fortinet, Palo Alto, Nokia, Huawei, MikroTik, Extreme, F5, Dell, HP, and Check Point; Linux/host agents are recognized too.
3. Interface inventory and metrics start on the normal poll cycle (about a minute). The [Data Sources coverage matrix](/onboard-devices/data-sources) shows each device turning green for **SNMP metrics**.

The inventory merges discovery with your other sources (manual adds, [Source of Truth import](/automation/overview)) — the same device reported by two sources is de-duplicated into one record, and the first-registered source wins on conflicting facts.

## Neighbor-based topology

As devices are polled, Correlix learns neighbor relationships and draws them on the **[Topology Canvas](/infrastructure/topology-canvas)** automatically — you don't wire the topology by hand. Layer-2 neighbor discovery (LLDP/CDP) is enabled per instance; ask your platform administrator if links you expect aren't appearing.

## Verify

- Every expected device is listed at <kbd>Infrastructure → Devices</kbd> with an **Up** dot.
- <kbd>Administration → Data Collection → Data Sources</kbd> shows **SNMP metrics** green for each.
- Spot-check one device: open it from the inventory and confirm interfaces and uptime are populated.

## Troubleshooting — a device didn't appear

Work down this table in order; the causes are listed by how often they're the culprit.

| # | Symptom | Likely cause | How to confirm / fix |
| --- | --- | --- | --- |
| 1 | Device absent from inventory | Not reachable on **UDP 161** from Correlix | Firewall/ACL in the path — check [Connectivity requirements](/reference/connectivity-requirements); test with `snmpwalk` from a host beside Correlix (below) |
| 2 | Device absent | **Credential mismatch** — community/user doesn't match, or the device is v3-only and you stored v2c | Re-check the stored profile against the device config; version must match |
| 3 | Device absent | **Outside the scanned range** | Add its subnet to `SNMP_CIDR_RANGES` and re-apply |
| 4 | Device absent | **SNMP not enabled** on the device | Configure it (Step 1) |
| 5 | Device present but **Down** | Answered once, now unreachable or credential rotated | Check the device's SNMP ACL and the profile's secrets |
| 6 | Present but vendor/type = Unknown | Device answered but its identity isn't in the recognition table | Cosmetic only — metrics still collect via the Universal profiles; set the vendor manually on the device record if you want |

Quick reachability test from a machine on the same network segment as Correlix (generic example using standard SNMP tools):

```bash
snmpwalk -v2c -c MyR0Community -t 2 10.20.0.5 1.3.6.1.2.1.1
# system description, uptime, name should print — if it times out, fix reachability/ACL first
```

See [Troubleshooting](/reference/troubleshooting) for the full no-data flowchart.

## Next

- **[Add richer telemetry](/send-data/overview)** — syslog, traps, flows.
- **[Verify a device is monitored](/onboard-devices/verify-monitoring)**.
