---
title: Check the data-source coverage matrix
sidebar_label: Check the coverage matrix
description: Read the per-device coverage matrix, understand what each of its three cell states claims, and find the device where a configuration change did not take.
page_type: task
sidebar_position: 8
---

# Check the data-source coverage matrix

The coverage matrix shows, per device, which of the four telemetry planes
delivered data in the last 15 minutes. It reports what arrived, not what is
configured, which makes it the fastest way to find the device where a change did
not take effect.

Read it after every onboarding change and after every device-side configuration
push.

## Before you begin

- A role with `infrastructure` read permission.
- At least one device in the inventory. With none, the page reads
  *No devices discovered yet. Add devices under Infrastructure → Devices to
  begin.*

## Steps

1. Go to **Administration → Data sources → Data Sources**.
2. Read the header counters: **Devices**, **SNMP metrics**, **Flows**,
   **Syslog**, **Nothing arriving**, and **Unknown** when it is non-zero.
3. Work down the table. It sorts by **Coverage** ascending, so the least covered
   devices are at the top.
4. For each row that is short, open the page for the plane that is missing and
   check the device-side configuration.
5. Leave the page open while you make a change. It reloads every 30 seconds.

## What you see

One row per device and one column per plane.

| Column | What turns it on | What the page checks |
|---|---|---|
| **Device**, **Address** | Nothing | The inventory record |
| **SNMP metrics** | A credential that answers, plus UDP 161 | A `device_sysuptime` series in the last 15 minutes whose `device` label equals the device id or name |
| **Flows** | The device exporting NetFlow, IPFIX or sFlow | The device's address appearing as a flow exporter in the last 15 minutes |
| **Syslog** | The device sending syslog | A recent syslog document whose host, hostname, device, agent or source field equals the device name or address |
| **Traps** | The device sending traps, with `FEATURE_SNMP_TRAPS` on | The same field match against recent trap documents |
| **Coverage** | Nothing | A badge counting the planes that answered yes, out of four |

## Three cell states, not two

| Cell | Meaning |
|---|---|
| A green dot and `yes` | Data for this device arrived on this plane inside the window |
| A grey dot and `—` | The store answered, and this device was not in the answer |
| An amber dot and `?` | The query for this plane failed. Coverage for it is **unknown** |

The third state exists because collapsing it into `—` once reported a metric
store outage as "no telemetry from any device", which is a definitive claim
about the whole fleet that nothing supported. When a plane query fails, a banner
names it and says the devices may well be sending data.

The **Coverage** badge shows `?` after the count when any cell is unknown, and
the count is then a floor rather than a verdict.

**Nothing arriving** counts only devices where all four planes answered and all
four said nothing. A device with an unknown cell is never counted there.

## What "no data" means

`—` means nothing arrived on that lane for that device in the last 15 minutes.
It is not a statement about the device's health.

- A quiet device legitimately shows `—` for syslog. A healthy switch that logged
  nothing in 15 minutes has nothing to send.
- A device shows `—` for traps whenever the trap receiver is off, whatever the
  device is doing.
- A device shows `—` for flows when it exports from an address the inventory
  does not hold, even while its flow records are arriving and being stored.

Conversely, a green cell is proof that the whole path worked end to end for that
device: device configuration, network path, ingest, storage and query.

## Two attribution rules that produce a confusing `—`

Both of these come from the lab stack, where flow records are arriving and the
matrix still shows `—` on the flows column for every inventory device.

Flows are attributed by the exporter address:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/flows/topn?by=device&since=900s&limit=5"
```

```json
{
  "data": [
    { "k": "172.40.40.52", "bytes_total": "24220", "packets_total": "273", "flows": "39" },
    { "k": "172.40.40.51", "bytes_total": "18144", "packets_total": "189", "flows": "27" }
  ],
  "rows": 2
}
```

The inventory holds `spine1` at `172.40.40.11` and `spine2` at `172.40.40.12`.
Neither exporter address matches, so both rows show `—` for flows while flow
records are demonstrably arriving. A device exporting from a loopback that the
inventory does not know will do exactly this.

SNMP is attributed by the `device` label on the `device_sysuptime` series. On
the same stack that query returns nothing:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/metrics/query_range?query=device_sysuptime&start=1788409339&end=1788410239&step=300"
```

```json
{"status":"success","data":{"resultType":"matrix","result":[]},"stats":{"seriesFetched": "0","executionTimeMsec":0}}
```

An empty matrix is the reason both rows show `—` for SNMP metrics. The cause is
visible one page over: the SNMP collectors report
`2/2 targets did not answer`. See
[Verify a device is being monitored](/onboard-devices/verify-monitoring).

## Reading a row

| Coverage | What the device gives you |
|---|---|
| `0/4` | Nothing arrived on any plane. Start with SNMP metrics |
| `1/4` with SNMP green | Health, interfaces, CPU and protocol state on the poll cycle |
| `2/4` with SNMP and syslog green | The above plus events at the moment the device emits them |
| `3/4` or `4/4` | Independent evidence on several planes, which is what raises root-cause confidence |
| Any count with `?` | A floor. At least one plane could not be queried |

## Troubleshooting a cell stuck on `—`

| Cell | What to check |
|---|---|
| **SNMP metrics** | Credential version and secret, UDP 161 on the path, and any SNMP ACL on the device. See [Add an SNMP credential](/onboard-devices/snmp-profiles) |
| **Flows** | That the exporter's source address matches the inventory address, and that the protocol matches the port: NetFlow 2055, IPFIX 4739, sFlow 6343. See [Send flow records](/send-data/flows) |
| **Syslog** | That the device's configured hostname matches its inventory name, and that UDP or TCP 514 is open. See [Send syslog](/send-data/syslog) |
| **Traps** | That `FEATURE_SNMP_TRAPS` is on, and that the device's trap destination is UDP 162. See [Send SNMP traps](/send-data/traps) |
| The whole row | The device's status on **Infrastructure → Devices** first |

For the collector side of the same question, platform administrators can read
**Administration → Data sources → Sensors**, which shows the collection
engines with target counts, reachability and poll timings. That separates "this
device is not answering" from "this collector is not running".

## Related

- [Verify a device is being monitored](/onboard-devices/verify-monitoring)
- [Send data to Correlix](/send-data/overview)
- [What an empty result means](/reference/honest-states)
