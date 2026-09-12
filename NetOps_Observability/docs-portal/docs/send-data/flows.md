---
title: Send flow records
sidebar_label: Send flow records
description: Choose NetFlow, IPFIX or sFlow, configure the exporter to the right port, set a sampling rate, and confirm the records are landing.
page_type: task
sidebar_position: 5
---

# Send flow records

Flow records tell you who is talking to whom, over what, and how much. They are
the basis of top-talker analysis, conversation views and application
attribution. Enable export on the devices where traffic visibility matters:
WAN edges, data-centre cores, internet borders and firewalls.

The collector accepts NetFlow v5 and v9, IPFIX and sFlow, each on its own UDP
port. Sending the wrong protocol to a port does not decode.

## Before you begin

- The device is [in the inventory](/onboard-devices/add-devices-manually), with
  the management address it will export from.
- The UDP port for your protocol open from the device to Correlix. See
  [Connectivity requirements](/reference/connectivity-requirements).
- A decision about sampling. See the section below before configuring a busy
  interface.

## Steps

1. Choose one protocol for the device. Exporting the same traffic twice gains
   nothing.

   | Protocol | Port | Suited to |
   |---|---|---|
   | NetFlow v9 | UDP 2055 | Routers and firewalls. Template-based, flexible fields |
   | NetFlow v5 | UDP 2055 | Legacy platforms. Fixed format, IPv4 only |
   | IPFIX | UDP 4739 | Modern routers and SD-WAN. The IETF standard |
   | sFlow | UDP 6343 | High-throughput switches. Packet-sampled by design |

2. Configure the exporter with Correlix as the destination on that port.
3. Set the source interface to the address the inventory holds for the device.
4. Apply the monitor or sampler to the interfaces you want measured, in both
   directions where the platform requires it. An input-only monitor shows one
   half of every conversation.
5. Set a sampling rate.
6. Wait a few minutes, then confirm records are arriving.

### Device configuration

These blocks are the platform's own documented examples, from
`docs/INGESTION.md`. Replace `MONITOR_HOST` with the address of the Correlix
host.

Cisco IOS and IOS-XE, NetFlow v9:

```text
flow exporter NETOPS
  destination MONITOR_HOST
  source Loopback0
  transport udp 2055
  template data timeout 60
  export-protocol netflow-v9

flow monitor NETOPS-FM
  exporter NETOPS
  record netflow ipv4 original-input

interface GigabitEthernet0/0
  ip flow monitor NETOPS-FM input
  ip flow monitor NETOPS-FM output
```

Juniper Junos, IPFIX:

```text
set services flow-monitoring version-ipfix template IPFIX-T template-refresh-rate 30
set forwarding-options sampling instance NETOPS family inet output
  flow-server MONITOR_HOST port 4739 version-ipfix
```

Apply the sampling instance to the interfaces you want measured.

Arista EOS, sFlow:

```text
sflow source-interface Loopback0
sflow destination MONITOR_HOST 6343
sflow run
```

### Sampling

sFlow is always sampled; that is the point of the protocol and it is why device
overhead is near zero. NetFlow and IPFIX can be unsampled, but full flow export
on a busy link produces a very high record rate on both the device and the
collector. Sample high-throughput interfaces and keep unsampled export for
low-rate links where per-flow completeness matters.

Correlix reads the sampling rate carried in the record and multiplies byte and
packet counts by it at query time. A rate of zero is treated as one. Scaled
totals are sound for top talkers and trends and are estimates, not measurements:
short flows can be missed entirely at an aggressive rate. Do not treat sampled
byte counts as billing-grade.

## Result

Records reach the flow analytics within a few minutes. NetFlow v9 and IPFIX are
template-based, so the device must send its templates before any data record can
be decoded; the first records lag the configuration change by one template
cycle.

Confirm with the top-talkers query. Captured from the lab stack:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/flows/top?limit=3"
```

```json
{
  "data": [
    { "src": "172.16.13.2", "dst": "224.0.0.5", "bytes_total": "38532", "packets_total": "387", "flows": "54" },
    { "src": "172.16.15.2", "dst": "224.0.0.5", "bytes_total": "36288", "packets_total": "378", "flows": "54" },
    { "src": "172.16.14.2", "dst": "224.0.0.5", "bytes_total": "36288", "packets_total": "378", "flows": "54" }
  ],
  "rows": 3,
  "rows_before_limit_at_least": 5
}
```

Check that your device is one of the exporters:

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

The **Flows** column for the device turns green on
[the coverage matrix](/onboard-devices/data-sources) once the exporter address
in that list matches the device's inventory address.

## Attribution is by exporter address

Flows are tied to a device by the exporter address in the record, and to a
tenant by the same value. Nothing in the flow payload sets tenancy.

In the capture above, the exporters are `172.40.40.51` and `172.40.40.52`. The
inventory holds `spine1` at `172.40.40.11` and `spine2` at `172.40.40.12`.
Neither matches, so both devices show no flows on the coverage matrix while
records are demonstrably arriving and queryable. A device exporting from a
loopback the inventory does not know behaves exactly this way. Fix it by setting
the exporter source address to the inventory address, or by recording the
exporting address on the device.

## Two stores, two answers

Flow records land in two places and the numbers differ on purpose.

| Store | What it holds | What it is for |
|---|---|---|
| The analytics store | Every record, unsampled by Correlix | Top talkers, conversations, volumes. The canonical answer |
| The log store | A 1-in-50 sample of the records | Free-text flow search alongside logs |

Search, retention and export responses from the log store carry a disclosure
naming the rate and saying counts there are estimates that need multiplying.
When two flow numbers in the console disagree, check which store answered.

## Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| Nothing arrives | Protocol and port mismatch | NetFlow to 2055, IPFIX to 4739, sFlow to 6343. IPFIX sent to 2055 does not decode |
| Nothing arrives | UDP blocked on the path | Confirm the port you chose is open end to end |
| Nothing arrives | The monitor or sampler is not applied to any interface | A configured exporter with no interface attachment exports nothing. Check the device's exporter statistics |
| Records arrive but the device shows no flows | The exporter address does not match the inventory address | Set the exporter source to the management address |
| Records arrive late or in bursts | Normal. A device exports a flow when it ends or when its active timeout expires | Long-lived flows appear as periodic updates, not a live stream |
| Volumes are low by a constant factor | The sampling rate is not being announced as expected | Verify the sampler configuration on the device |
| Only one direction of each conversation | The monitor is applied in one direction | Apply it to both |
| Many unknown applications | Correlix labels an application only on evidence | Onboarding your firewalls' [syslog](/send-data/syslog) improves this, because FortiOS traffic logs carry the firewall's own application identification |

## Related

- [Explore flows](/explore/flows)
- [Check the data-source coverage matrix](/onboard-devices/data-sources)
- [Send syslog](/send-data/syslog)
- [Connectivity requirements](/reference/connectivity-requirements)
