---
title: Query metrics
description: Query a metric from the curated catalog or write your own, stream the chart live, and read the honest empty state.
page_type: task
sidebar_position: 2
---

# Query metrics

**Explore → Metrics** is the **Metric Workbench**: pick a metric from a curated catalog, or write a query, and get a chart. The catalog leads with the network telemetry the stack actually collects rather than with the store's own internal metrics.

## Before you begin

- An authenticated session. Correlix injects a server-side tenant filter into every metric query, so a scoped principal can only read its own devices' series.
- Devices onboarded and polling. Telemetry arrives roughly every 30 to 60 seconds once a collector polls.
- A time window chosen in the top-bar range picker. The workbench charts that window.

## Steps

### Step 1 - Pick from the catalog

The quick picks are grouped, and a pick that has no series in the store hides itself, so the catalog never offers a dead chart.

| Group | Quick picks |
|---|---|
| Device health (SNMP) | CPU utilization, Memory %, Memory used (KB), Memory used (bytes), Temperature |
| Interfaces (SNMP) | Ingress bit/s, Egress bit/s, In errors/s, In discards/s |
| gNMI streaming | gNMI ingress bit/s, gNMI egress bit/s, SR Linux CPU |
| Collector health | Reachable targets, Samples / poll, Collector up |

Select a pick. Its query is loaded into the query box and the chart redraws. Each pick aggregates per device or per source, so the chart shows one clean line per device rather than dozens of per-core or per-interface series.

Memory used appears twice on purpose. Vendor profiles emit it in different units, kilobytes on Nokia SR OS and bytes on Cisco, and two different units cannot be summed into one series.

### Step 2 - Write your own query

1. Select the metric picker to browse every metric name in the store, and filter as you type.
2. Or type into the query box. The placeholder shows the shape: `query, e.g. rate(device_if_in_octets[5m]) * 8`.
3. Select **Run**.

The chart title is the query itself, so what you are looking at is always stated.

### Step 3 - Stream it live

Use the live toggle beside **Run** to re-run the query every 5 seconds. The chart advances without a page reload. Turn it off when you are reading a fixed window.

## What you see

A chart of the window you selected, one series per device or source, with the axis and tooltip formatted for the metric's unit: bit/s, bytes, kilobytes, per cent, degrees Celsius, or a plain count.

Where the query returns nothing, the panel says why rather than drawing an empty axis: no data for this query or range, and telemetry arrives every 30 to 60 seconds once collectors poll. That is a statement about this query in this window, not a claim that the device is idle.

Two routes serve the page, and both accept a query:

| Route | What it returns |
|---|---|
| `GET /api/metrics/query` | The instant value of a query. |
| `GET /api/metrics/query_range` | A series over a start, end and step, which is what the chart draws. |

An instant query against the live lab:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/metrics/query?query=collector_up"
```

```json
{"status":"success","data":{"resultType":"vector","result":[
  {"metric":{"__name__":"collector_up","collector":"snmpmetrics"},"value":[1788409625,"0"]},
  {"metric":{"__name__":"collector_up","collector":"snmpv2c"},"value":[1788409625,"0"]},
  {"metric":{"__name__":"collector_up","collector":"snmpv3"},"value":[1788409625,"1"]},
  {"metric":{"__name__":"collector_up","collector":"tunnels"},"value":[1788409625,"0"]}
],"stats":{"seriesFetched":"4","executionTimeMsec":0}}}
```

Read that carefully: a collector absent from the result never polled, and a collector present with the value `0` polled and reached nothing. The two are different facts.

## Related

- [Create a monitor](/monitoring/create-a-monitor) to turn a query you trust into an alert rule.
- [Metrics reference](/reference/metrics) for the metric names and their labels.
- [Built-in dashboards](/dashboards-reports/built-in-dashboards) for the boards that chart these metrics without a query.
