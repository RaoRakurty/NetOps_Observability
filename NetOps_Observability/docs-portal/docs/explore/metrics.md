---
title: Metrics Explorer
sidebar_label: Metrics Explorer
sidebar_position: 4
description: Chart any collected metric — quick-picks for common signals, a browsable metric catalog, and full query syntax for precise filtering.
---

# Metrics Explorer

The **Metric Workbench** at <kbd>Metrics</kbd> turns any collected metric into a chart: pick a curated signal with one click, browse the raw metric catalog, or write a query yourself. It's the surface for "how is this value trending?" questions — device CPU, interface throughput, error rates, temperature.

## Chart a metric (quick-picks)

The fastest path is the categorized quick-pick rows at the top of the page:

1. Go to <kbd>Metrics</kbd>.
2. Click a chip. The chart below renders immediately, one line per device. Groups you'll see (each chip only appears if that metric actually exists in your data — a missing chip means nothing collects it yet):

   | Group | Quick-picks |
   | --- | --- |
   | **Device health (SNMP)** | CPU utilization · Memory % · Memory used (KB) · Memory used (bytes) · Temperature |
   | **Interfaces (SNMP)** | Ingress bit/s · Egress bit/s · In errors/s · In discards/s |
   | **gNMI streaming** | gNMI ingress bit/s · gNMI egress bit/s · SR Linux CPU |
   | **Collector health** | Reachable targets · Samples / poll · Collector up |

3. Set the window with the global **time-range picker** in the top bar. The chart re-queries automatically when the range changes.

Quick-picks are pre-aggregated **per device** — "Ingress bit/s" sums a device's interfaces into one clean line per device, so a fleet reads as a readable comparison rather than dozens of raw series. Hover the chip to see the exact query it runs; it also lands in the query box, ready to edit.

## Browse the full catalog

For anything not covered by a quick-pick:

1. Click **Browse metrics (N)** — N is how many distinct metric names your platform currently holds.
2. Type in the filter box to narrow the list (e.g. `errors`).
3. Click a name. It's charted as-is, with a display unit guessed from the name.

This is the raw catalog: every metric the collectors are writing, including per-interface series and streaming (gNMI) paths.

## Write a query

The query box accepts full **PromQL syntax** (the industry-standard metrics query language). Type a query and click **Run** (or press Enter).

The essentials, all verified against the metrics the platform collects:

| Goal | Query |
| --- | --- |
| Raw series, all devices | `device_cpu_percent` |
| One device only | `device_cpu_percent{device="core-sw1"}` |
| One interface's inbound bit/s | `rate(device_if_in_octets{device="core-sw1",ifName="Ethernet1"}[5m]) * 8` |
| Fleet average | `avg(device_cpu_percent)` |
| One line per device | `avg by (device) (device_cpu_percent)` |
| Errors per second, per device | `sum by (device) (rate(device_if_in_errors[5m]))` |
| Hottest sensor per device | `max by (device) (device_temp_celsius)` |

**Filtering by device and interface** is done with label matchers in braces. SNMP interface metrics carry these labels:

- `device` — the device name (also on CPU/memory/temperature metrics),
- `ifName` — the interface name as the device reports it (e.g. `Ethernet1`),
- `ifAlias` — the interface description, when configured,
- `index` — the raw interface index,
- `vendor` — the device vendor.

Regex matchers work too: `{device=~"edge-.*"}` matches every device whose name starts with `edge-`.

:::note Counters need `rate()`
Octet, packet, error, and discard metrics are ever-increasing counters. Chart them through `rate(...[5m])` to get a per-second value; multiply octets by 8 for bits per second — exactly what the interface quick-picks do.
:::

## Read the chart

- **One line per series**; the legend names each as *device · interface* where those labels exist (scrollable when there are many).
- **Y-axis and tooltip** auto-format to the metric's unit — `%`, bit/s (`Kbps`/`Mbps`/`Gbps`), bytes (`KB`/`MB`/`GB`), `°C`.
- **Hover** anywhere for a synced tooltip across all series at that instant.
- The resolution adapts to the window (roughly 240 points), so a 24-hour chart stays readable.

### Live mode

Click **○ Live** next to Run to stream the chart — it re-queries every 5 seconds until you toggle it off. Use it while making a change ("did traffic move when I shifted that route?") instead of mashing refresh.

## Typical explorations

- **Is one device an outlier?** Quick-pick **CPU utilization**, widen to **Last 24 hours** — the odd line stands out immediately.
- **Is this link saturating?** `rate(device_if_out_octets{device="wan-rtr1",ifName="GigabitEthernet0/0/1"}[5m]) * 8`, compared against the circuit's capacity.
- **Where are the errors?** Quick-pick **In errors/s** — a healthy fleet is a flat zero; any lift names the device. Then narrow with `{device="…"}` and drop the `sum by` to see which interface.
- **Is collection itself healthy?** Quick-pick **Reachable targets** or **Collector up** — a dip here explains gaps in every other chart.

When an exploration earns a permanent home, recreate it as a [dashboard or report](/dashboards-reports/overview), or wrap a threshold around it as a [monitor](/monitoring/create-a-monitor).

## Troubleshooting

**"No data for this query / range":**

- **Nothing collected yet** — telemetry arrives every ~30–60 seconds once collectors poll a device. Fresh install: onboard devices first ([Onboard devices](/onboard-devices/overview)) and give it a minute.
- **Misspelled metric or label** — use **Browse metrics** to confirm the exact metric name, and a bare query (no matchers) to see which label values exist before filtering.
- **Label value mismatch** — matchers are exact by default; `{device="Core-SW1"}` won't match `core-sw1`. Use `=~` with a regex if unsure.
- **Range vs. data age** — a metric that started flowing an hour ago has nothing to show at **Last 7 days** resolution edges; try a shorter window.

**A quick-pick chip is missing** — the underlying metric doesn't exist in your data (chips self-hide), usually because no onboarded device exposes it (e.g. no gNMI-streaming devices → no gNMI group).

**Query error under the bar** — the query didn't parse or exceeded limits; the message includes the reason from the query engine.

Metric queries are **tenant-scoped** like everything else in the Data zone — you only ever chart your own devices.
