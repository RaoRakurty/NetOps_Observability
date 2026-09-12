---
title: Onboard your first device
sidebar_label: Onboard your first device
description: Store an SNMP credential, add one device, confirm collection on the coverage matrix, and read its first metrics.
page_type: task
sidebar_position: 3
---

# Onboard your first device

This procedure takes one router or switch from an empty inventory to live
metrics on a dashboard. Each step ends with a checkpoint that tells you whether
to continue or fix something first. Use it for the first device on a new
deployment; for a whole management range, use
[Discover devices](/onboard-devices/snmp-discovery) instead.

## Before you begin

- **An administrator account on the console.** Credentials, devices and data
  sources are administrative objects.
- **The console address.** The console is served on TCP port 8000 of its host
  unless the installer was given another port.
- **One device management address that Correlix can reach on UDP 161.**
- **That device's read-only SNMP credential**, either a v2c community string or
  an SNMPv3 user with its auth and privacy settings.
- **The firewall openings on the path.** See
  [Connectivity requirements](/reference/connectivity-requirements).
- **The tenant the device belongs to.** Correlix stamps the owning tenant from
  the account that creates the device, so sign in as an account in the tenant
  that should own it.

## Steps

### Step 1 — Sign in

1. Open the console address in a browser.
2. Choose a sign-in method. **Local account** is always present; a directory
   method (LDAP or TACACS+) and single sign-on buttons appear only when an
   administrator has enabled them.
3. Enter your username and password.
4. If the account has MFA enabled, enter the 6-digit code from your
   authenticator app.

**Checkpoint:** you land on **Overview → Home**, the Command Center, with the
icon rail on the left. If sign-in fails or the account reports as locked, see
[Troubleshooting](/reference/troubleshooting).

### Step 2 — Store the SNMP credential

Correlix needs a credential before it can read anything from the device.

1. Go to **Administration → Data sources → SNMP Profiles**.
2. Select the **Credentials** pane. Its hint line reads *Per-device community /
   SNMPv3 USM secrets*.
3. Enter the credential. For **v2c**, enter the read-only community string. For
   **v3**, enter the username, the auth protocol and passphrase, and the privacy
   protocol and passphrase.
4. Select **Save**.

**Checkpoint:** the credential appears in the list with its secret masked. The
secret is encrypted at rest and never displayed again; saving later with the
field left blank keeps the stored value. Scoping a credential to one device
rather than the fleet is covered in
[SNMP profiles and credentials](/onboard-devices/snmp-profiles).

:::tip
The **Profiles** pane is the vendor OID and metric library. Built-in profiles
cover the common vendors, so a first onboarding needs only a credential.
:::

### Step 3 — Add the device

1. Go to **Infrastructure → Devices**.
2. Select **+ Add device**.
3. Enter a name, for example `spine1`.
4. Enter the management address, for example `172.40.40.11`.
5. Leave site and vendor blank. Correlix fills them from SNMP.
6. Select **Add device**.

Polling starts immediately, using the matching credential from Step 2.

The device is stamped with the tenant of the account that created it. Correlix
takes the owning tenant from your token and ignores any tenant in the request
body, so a device cannot be filed into a tenant you do not hold. Every later
read of that device is filtered by the same tenant.

**Checkpoint:** the device is a new row in the Devices table. The API agrees:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/devices
```

```json
[
  {
    "id": "spine1",
    "name": "spine1",
    "address": "172.40.40.11",
    "vendor": "nokia",
    "os": "SR Linux",
    "type": "switch",
    "tenant_id": "t_d3d501aa08e2395893b378a453b8af67",
    "source": "manual",
    "last_seen": "2026-09-03T02:58:15.80813818Z"
  }
]
```

### Step 4 — Confirm the device is being read

Two surfaces answer this, and they answer different questions.

1. Stay on **Infrastructure → Devices**. Within about one poll cycle the status
   dot turns green and the row fills with facts read over SNMP: vendor, model,
   uptime.
2. Go to **Administration → Data sources → Data Sources**. Find the device's
   row in the coverage matrix: one row per device, one column per source (SNMP
   metrics, Flows, Syslog, Traps) and a Coverage count out of four.
3. Hover the **SNMP metrics** cell. It reads *receiving* when the source
   answered with data, *no data* when the source answered and had nothing, and
   *coverage unknown* when the query itself could not run.

**Checkpoint:** a green dot on Devices and a *receiving* SNMP metrics cell on
Data Sources. The status dot states heartbeat freshness and nothing else:

| Status | What it means |
|---|---|
| **Up** | A heartbeat within the last 5 minutes. |
| **Degraded** | The heartbeat is older than 5 minutes, or the device has active alerts. |
| **Down** | Nothing heard for over 15 minutes. |

The Coverage column counts how many of the four sources answered with data, out
of four. A new device that has only SNMP configured reads 1/4, and that is the
correct reading rather than a fault.

If the dot stays amber or red, or the cell stays *no data* after a few minutes,
the cause is reachability or a credential mismatch. Ask the collectors
themselves, because a collector reports its own state and names its own error:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/collectors
```

```json
{
  "name": "snmpv2c",
  "kind": "protocol",
  "enabled": true,
  "healthy": false,
  "last_tick": "2026-09-03T03:47:29.378961516Z",
  "last_error": "2/2 targets did not answer (last error: read udp 172.18.0.9:51458->172.40.40.12:161: i/o timeout)",
  "targets": 2,
  "reachable": 0,
  "last_poll_ms": 6001
}
```

A collector that is `enabled` but not `healthy`, with `reachable` at zero, has
tried and failed. That is a different fact from a collector that is disabled and
has never run, and Correlix raises it as an alert against the collector rather
than reporting the devices as healthy:

```json
[
  {
    "id": "CollectorAllTargetsUnreachable|collector=snmpv2c",
    "rule": "CollectorAllTargetsUnreachable",
    "severity": "critical",
    "summary": "Collector snmpv2c cannot reach any target",
    "fired_at": "2026-09-03T03:32:59.379985203Z"
  },
  {
    "id": "DeviceUnreachable|collector=snmpv2c,device=spine1",
    "rule": "DeviceUnreachable",
    "severity": "critical",
    "device_id": "spine1",
    "summary": "spine1 unreachable from snmpv2c",
    "fired_at": "2026-09-03T03:29:59.379975793Z"
  }
]
```

Read the `last_error` first. A timeout on UDP 161 points at a filter or an ACL
on the path. An authentication failure points at the credential from Step 2. The
full decision table is in [Troubleshooting](/reference/troubleshooting).

### Step 5 — Read the first metrics

1. Go to **Analytics → Metric Dashboards → Device Monitoring** and select the
   device.
2. Read the CPU, memory and interface panels as polls arrive.
3. Go to **Analytics → Metric Dashboards → Interface Performance** for
   per-interface throughput, utilization and errors across the fleet.

The Device Monitoring board opens on an inventory and reachability panel, then
groups the fleet's device resources (CPU and memory), the busiest interfaces by
inbound and outbound bits per second, and the fleet packet mix. Panels that need
a source you have not configured yet, such as the flow insights and the tunnel
state panels, state that they have nothing rather than drawing an empty chart.

**Checkpoint:** real numbers for the device. A panel showing `—` means the
metric is not collected for that device. It does not mean the value is zero.
That distinction holds everywhere in the product: a counter Correlix never read
is reported as absent, because reporting it as `0` would be a claim about the
device that nothing measured. See [Honest states](/reference/honest-states).

Utilization updates once per poll cycle. To see a value move, push traffic
across a link and watch the interface panels on the next cycle.

### Step 6 — Point syslog at Correlix

Metrics report how the device is doing. Syslog reports what the device says
happened, and it is the highest-value source to add next.

1. On the device, set the syslog destination to the Correlix address on UDP port
   514, at severity `informational` and above. Vendor commands are in
   [Send syslog](/send-data/syslog).
2. Cause a loggable event, such as bouncing a lab interface or leaving
   configuration mode.
3. In the console, go to **Administration → Data sources → Data Sources** and
   check that the device's **Syslog** cell reads *receiving*.
4. Go to **Explore → Logs**, set the source selector to **Syslog (devices)**,
   set the range to **Last 1h**, and search for the device:

   ```
   host:"spine1"
   ```

**Checkpoint:** the device's own messages appear in the results table under
Time, Source, Level, Application and Message.

Adding syslog changes what correlation can conclude about this device, not just
what you can read. Metrics and syslog are two different measurement classes, so
a fault that shows in both can be corroborated. A fault visible in only one
stays at a lower verdict tier no matter how loud that stream is. The same
applies to each further source you add, which is why
[Send flow records](/send-data/flows) and [Send SNMP traps](/send-data/traps)
are the recommended next steps rather than optional extras.

## Result

The device is in the inventory, reading **Up**, and reporting at least SNMP
metrics and syslog on the coverage matrix. From one credential and one address,
Correlix has built the inventory record over SNMP, started time series for CPU,
memory and every interface, begun learning neighbors for the
[topology canvas](/infrastructure/topology-canvas), and made the device eligible
for monitors, anomaly detection and correlation. No further wiring is required.

Three checks confirm the outcome without opening a dashboard. The device is in
`GET /api/devices` with a `last_seen` timestamp inside the last five minutes.
The collector that reads it reports `healthy` with a non-zero `reachable` count
in `GET /api/collectors`. The device's row on the coverage matrix reads
*receiving* for every source you configured, and *no data* only for sources you
have not configured yet.

Repeat Steps 3 to 5 for each further device, or move to
[Discover devices](/onboard-devices/snmp-discovery) to sweep a management range
and onboard everything that answers.

## Related

- [Send flow records](/send-data/flows) and [Send SNMP traps](/send-data/traps),
  the sources that raise correlation confidence next
- [Create a monitor](/monitoring/create-a-monitor)
- [Onboard devices](/onboard-devices/overview) for discovery, bulk import and
  credential scoping
- [Verify monitoring](/onboard-devices/verify-monitoring)
- [Start a shift](/noc-guide/where-to-start)
