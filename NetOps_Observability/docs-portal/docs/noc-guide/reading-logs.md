---
title: Read device logs during an incident
sidebar_label: Read device logs
description: Scope a log search to one device and window, read the level honestly, recognise the three shapes that matter, and pivot from a line to the case that contains it.
page_type: task
sidebar_position: 3
---

# Read device logs during an incident

Logs are the network describing itself in its own words. Correlix reads that
stream continuously and turns parts of it into correlation input, and an
operator still needs to open it directly when the correlated view has no answer
yet. This procedure covers scoping a search, reading it, and getting back out
to the case. For the search syntax and export options, see
[Search logs](/explore/logs).

## Before you begin

- **The device name as Correlix knows it.** The name in the inventory on
  **Infrastructure → Devices** is the value the `host` field carries.
- **A time to search around.** A reported symptom time, an alert's fired-at
  time, or an RCA case's window.
- **Syslog arriving from that device.** Check the device's **Syslog** cell on
  **Administration → Data sources → Data Sources**. If it does not read
  *receiving*, the absence of log lines says nothing about the device. See
  [Send syslog](/send-data/syslog).

## Steps

### Step 1 — Scope the search

1. Go to **Explore → Logs**.
2. Set the signal selector to **Syslog (devices)**. This narrows the search to
   what network devices said about themselves, and excludes the traps, flow
   records and application logs that share the surface.
3. Set the range. Start at **Last 1h**. Widen to **Last 6h** or **Last 24h**
   only when the hour is quiet.
4. Enter a field query. The box takes Lucene `query_string` syntax, and the hint
   under it gives the pattern:

   ```
   host:"spine1"
   ```

5. Select **Search**.

The results table shows **Time**, **Source**, **Level**, **Application** and
**Message**, newest first, each row tinted by its level.

The signal selector decides which record type you are reading, and the choice
changes the meaning of every result. **Syslog (devices)** is what the devices
said. **SNMP traps** is what they pushed. **Flows** is a sampled copy of the
traffic records, held for search; the unsampled store is behind **Explore →
Flows**. **Firewall logs** narrows syslog to records a firewall vendor parser
produced. **App logs** covers Correlix's own services and is visible only to the
platform owner. Leaving the selector on **All** searches across them, which is
useful for a first sweep and misleading for a count.

If you run the same scope every shift, select **Save** and name it. It is then
waiting under **Explore → Saved Searches**. Selected rows export with the same
five columns the table shows.

### Step 2 — Read the level, then distrust it

The **Level** column shows the level the device itself sent. That is a statement
about how loudly the device spoke, not about how much the message matters. On
the lab spines, every line below arrives at `notice`, and two of them are the
device reporting a real degradation:

```text
2026-09-03T04:21:47Z  spine2  notice  sr_license_mgr  - - -  debug|4279|4279|08488|TR||E: licensemgr license_mgr.cc:581     CheckLicenseExpiration  no default license file nor configured license instances, posting license expiry
2026-09-03T04:21:47Z  spine2  notice  sr_xdp_cpm      - - -  debug|4599|4956|08558|TR||W: csim_pd   csim_platform.cc:2623   UpdateLicenseValidity  No valid license, limiting packet rate to 10000pps
```

Two habits follow.

1. **Narrow to what hurts when the stream is loud.** Add `level:error`, or
   combine it: `host:"spine1" AND level:error`.
2. **Read the record, not just the column.** Select a row and the complete
   document opens. Correlix records the parser's own reading in
   `normalized_severity` alongside the device's `severity`, so the two lines
   above carry `error` and `warning` even though both arrived as `notice`.
   Routing and adjacency messages in particular are often emitted at notice
   level on real platforms.

### Step 3 — Recognise the three shapes

Individual lines matter less than the shape the stream makes.

**A repeat is one condition, not many events.** The same line arriving over and
over is a device restating a condition it is stuck in. On the lab stack, one
subsystem on `spine1` restates the same warning every second:

```text
2026-09-03T04:15:55Z  spine1  notice  sr_grpc_server  - - -  debug|5290|5290|2536838|TR||W: common    grpc_server_instance.cc:1965 BuildAndStartServer  Unable to retrieve TLS profile 'EDA'
2026-09-03T04:15:56Z  spine1  notice  sr_grpc_server  - - -  debug|5290|5290|2536839|TR||W: common    grpc_server_instance.cc:1965 BuildAndStartServer  Unable to retrieve TLS profile 'EDA'
2026-09-03T04:15:57Z  spine1  notice  sr_grpc_server  - - -  debug|5290|5290|2536840|TR||W: common    grpc_server_instance.cc:1965 BuildAndStartServer  Unable to retrieve TLS profile 'EDA'
```

Count the occurrences and find the first one. The first line is closest to the
cause; the rest are the same fact repeated.

**A burst marks a state change.** Many lines from one device in a few seconds,
after relative quiet, means something transitioned and every subsystem that
noticed said so. Read the head of the burst. The lines at the end describe
consequences the earlier lines caused, and they are the ones most likely to
send you after a symptom instead of a cause.

**An echo across devices is one event, not several.** When neighbouring devices
report the same condition within seconds, that is one topology-wide fact. Both
lab spines report the same licensing condition one second apart, each from two
subsystems:

```text
2026-09-03T04:21:47Z  spine2  notice  sr_license_mgr  - - -  debug|4279|4279|08488|TR||E: licensemgr license_mgr.cc:581     CheckLicenseExpiration  no default license file nor configured license instances, posting license expiry
2026-09-03T04:21:47Z  spine2  notice  sr_xdp_lc_1     - - -  debug|4599|4957|08586|TR||W: csim_pd   csim_platform.cc:2623   UpdateLicenseValidity  No valid license, limiting packet rate to 10000pps
2026-09-03T04:21:48Z  spine1  notice  sr_license_mgr  - - -  debug|4353|4353|08488|TR||E: licensemgr license_mgr.cc:581     CheckLicenseExpiration  no default license file nor configured license instances, posting license expiry
2026-09-03T04:21:48Z  spine1  notice  sr_xdp_lc_1     - - -  debug|4666|5039|08590|TR||W: csim_pd   csim_platform.cc:2623   UpdateLicenseValidity  No valid license, limiting packet rate to 10000pps
```

Four lines, two devices, one condition. Treated as four problems it is noise;
read as one condition with a blast radius of two devices it is a finding.

### Step 4 — Read an empty result as a fact, not an all-clear

Zero hits is an answer, and it has two possible meanings. Search a device that
never sent a line and the response is explicit about how much was searched:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8000/api/logs/search?signal=syslog&from=now-6h&to=now&query=host:"leaf1"'
```

```json
{
  "took": 421,
  "timed_out": false,
  "_shards": {"total": 15, "successful": 15, "skipped": 14, "failed": 0},
  "hits": {"total": {"value": 0, "relation": "eq"}, "max_score": null, "hits": []}
}
```

Every shard answered and none held a matching record. That separates
*queried and empty* from *could not be queried*, which is a different fact. It still does not distinguish a healthy quiet device from a device
whose logging path is broken, and neither does the console. Resolve it on
**Administration → Data sources → Data Sources**: a device whose Syslog cell
reads *no data* is not sending, and silence from a device that normally reports
steadily is itself worth investigating.

### Step 5 — Pivot out of the stream

1. Select a row. The complete underlying record opens, with every field the
   collector wrote. Two of them tell you how much Correlix understood of the
   line: `parser_id` names the rule that read it, and `parser_status` says
   whether it parsed. A line the parser did not recognise is still stored and
   still searchable, and it contributes less to correlation, because the fields
   that grounding depends on were never extracted. The shapes arriving from your
   tenant that no rule recognises are listed on **Administration → Data
   sources → Telemetry Coverage**, which is where a recurring blind spot gets
   fixed rather than worked around.
2. Note the device and the timestamp, then go outward:
   - **Investigate → Findings** for a baseline deviation on that device around
     that time. Each finding carries a severity, a kind, a component, a summary
     and a score, and its detail view offers **View logs** back to where you
     came from.
   - **Investigate → RCA** for a candidate whose window covers the timestamp.
   - **Overview → Home** if it correlated and matters. It is in the Action Queue
     with an owner and a next action.
3. Going the other way, from an alert or a finding to the logs, use the **View
   logs** button on the detail view. It opens that device's syslog pre-scoped.

## Vendor message shapes

The lab stack runs Nokia SR Linux, so the captures above are SR Linux. The
shapes below are the Cisco-style forms Correlix parses on other platforms. They
are constructed illustrations of the message grammar, not captures from a
running device, and the exact wording differs by platform and release.

| What happened | Constructed example |
|---|---|
| Interface transition | `%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down` |
| Line protocol follows it | `%LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to down` |
| BGP session drops on the hold timer | `%BGP-5-ADJCHANGE: neighbor 10.50.0.1 Down Hold timer expired` |
| BGP session drops after a notification | `%BGP-5-ADJCHANGE: peer 10.0.0.1 (AS 65001) old state Established event RecvNotify new state Idle` |
| OSPF adjacency drops | `%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Ethernet1 from FULL to DOWN` |

An interface transition followed within seconds by a protocol adjacency change
on the same device is one fault with two witnesses on one plane. The same
adjacency change reported by the neighbour at the far end is a second observer,
and that is the difference the confirmation bar measures.

## Result

You can scope the stream to one device and window, tell a repeat from a burst
from an echo, read an empty result without mistaking it for health, and move
from a single line to the finding or RCA case that already contains it.

## Related

- [Search logs](/explore/logs)
- [Start a shift](/noc-guide/where-to-start)
- [From observation to ticket](/noc-guide/from-signal-to-ticket)
- [Send syslog](/send-data/syslog)
- [Honest states](/reference/honest-states)
