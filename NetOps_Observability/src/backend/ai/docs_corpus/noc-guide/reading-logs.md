---
title: Reading logs like an operator
sidebar_label: Reading logs
sidebar_position: 3
description: Scope Log Search to a device and time window, read severity, spot bursts and flaps, pivot from a log line to the incident — and understand how logs feed correlation.
---

# Reading logs like an operator

Logs are the network narrating itself, one line at a time. Correlix reads that narration continuously — extracting events from it and feeding them to the correlation engine — but there is no substitute for an operator who can open the stream and read it directly. This page is the technique.

For the full search syntax and export options, see the [Log Search reference](/explore/logs); this page is about *reading*.

## Step 1 — Open and scope the search

1. Go to <kbd>Logs → Log Search</kbd>.
2. In the signal dropdown, choose **Syslog (devices)**. This scopes to what network devices themselves said, excluding other record types (traps, flow records) that share the search surface.
3. Pick a time range — start with **Last 1h**; widen to **Last 6h** or **Last 24h** only if the hour is quiet.
4. Scope to the device under suspicion. Type a field query in the search box:

   ```
   host:"edge-router-01"
   ```

   The search box accepts field-level query syntax — the hint line under the title shows the pattern (e.g. `level:error`, `src_addr:10.0.0.5 AND dst_port:22`).
5. Click **Search**.

You should now see a results table with **Time**, **Source**, **Level**, **Application**, and **Message** columns, newest activity on top, with each row tinted by its severity.

:::tip
Running the same scope every shift? Click **★ Save** and give it a name — it will be waiting under <kbd>Logs → Saved Searches</kbd>.
:::

## Step 2 — Read severity first

Severity is the fastest filter your eyes have. Device syslog arrives with a level (`error`, `warning`, `notice`, `info`, and vendor variants), and the Level column colors it. Two habits:

1. **Narrow to what hurts**: add `level:error` (or combine: `host:"edge-router-01" AND level:error`) to strip the routine chatter.
2. **Don't ignore notices near an incident**: routing protocols often announce topology changes at *notice* level. Severity says how loudly the device spoke, not how important it was.

## Step 3 — Spot the patterns

Individual lines matter less than shapes in the stream. Three shapes cover most incidents:

**Bursts.** Dozens of lines from one device in seconds, after relative silence. A burst marks a state change — something transitioned, and every subsystem that noticed said so. Read the *first* lines of the burst; they are usually closest to the cause.

**Flaps.** The same pair of messages alternating — up, down, up, down. A flapping interface or protocol session is often worse than a clean failure, because everything downstream keeps re-converging. If you see the same line at 14:02, 14:07, and 14:11, you have a flap, not three problems.

**Protocol messages.** Adjacency and session changes (BGP, OSPF, spanning tree, tunnel state) are the network describing its own topology reshaping. One adjacency change on one device is noise; the same change echoed by neighbors within seconds is a real event with a real blast radius.

## Step 4 — Pivot from a log line

1. Click any row. The full underlying record opens — the headline fields plus the complete document, so you can see every field the collector recorded.
2. Note the device and timestamp, then pivot outward:
   - <kbd>Monitoring → Anomalies</kbd> — did this deviate from baseline? Findings for the device carry a severity and score, and their detail view offers **View logs** straight back to where you came from.
   - <kbd>Monitoring → Correlations</kbd> — has this already been grouped? Check the **RCA Candidates** queue for a group whose window covers your timestamp.
   - <kbd>Dashboards → Home</kbd> — if it correlated and matters, it is in the Action Queue with an owner and a next action.
3. Working the other direction — from an alert or finding to logs — use the **View logs** button on the detail view: it opens the device's own syslog for the last hour, pre-scoped.

## How logs feed the correlation engine

You don't have to read logs for Correlix to use them. Every collected log line flows into the same pipeline you triage with:

1. Device syslog and traps are ingested continuously and appear raw under <kbd>Monitoring → Events</kbd> — one time-sorted stream to correlate against metrics and flows.
2. The correlation engine consumes this stream alongside metric anomalies. Meaningful events — protocol changes, link transitions, error bursts — become correlation input.
3. When events from the stream group with anomalies (by time and by network relationship), they become the **Signals** counted on an RCA candidate, and appear as markers on the incident's evidence timeline.

This is why log evidence shows up *inside* an RCA: the engine attaches the relevant lines to the case, and the RCA's evidence view tells you what each contributed. A log stream is one signal class — remember the confirmation bar: a root cause is **confirmed** only when independent evidence agrees across at least two signal classes, so logs alone typically yield a *Suspected* verdict until metrics, probes, or flows corroborate.

## Worked mini-scenarios

The log lines below are **illustrative examples** in common vendor formats — your devices' exact wording will differ.

### Scenario A — the link flap

Search: `host:"dist-sw-02" AND level:error`, Last 1h. You see:

```
14:02:11  %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
14:02:14  %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down
14:07:03  %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up
14:11:40  %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
```

**Reading:** the same interface cycling within minutes — a flap, likely physical (optic, cable, far-end device). **Next:** check <kbd>Monitoring → Anomalies</kbd> for interface-error findings on `dist-sw-02`, and expect a correlation candidate whose *Linked by* is **Same path** if downstream devices reacted.

### Scenario B — the routing ripple

Search: `level:notice OR level:error`, Last 1h, no host filter. You see, across *two* sources within seconds:

```
09:31:22  core-r1   %BGP-5-ADJCHANGE: neighbor 10.0.12.2 Down — hold time expired
09:31:24  core-r2   %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.1 on TenGigE0/0/0 from FULL to DOWN
```

**Reading:** two independent devices reporting adjacency loss toward the same neighborhood at the same moment — not two problems, one topology event. **Next:** this is exactly the shape the engine groups; go to <kbd>Monitoring → Correlations</kbd> and look for a fresh candidate naming a routing cause. Verify the blast radius on <kbd>Infrastructure → Topology Canvas</kbd>.

### Scenario C — the silent device

A user reports a site down. Search: `host:"branch-fw-07"`, Last 6h — **zero results**, when the device normally logs steadily.

**Reading:** silence from a talkative device is evidence. Either the device is down, or its logging path is broken. **Next:** check the device's live status via <kbd>Infrastructure → Devices</kbd>, then [verify its monitoring](/onboard-devices/verify-monitoring). Don't mistake "no logs" for "no problem."

## Where to go next

Once you can read the stream, follow it downstream: [From signal to ticket](/noc-guide/from-signal-to-ticket) walks one incident from the first anomaly to the filed ticket, including how the log evidence you just learned to read appears inside the RCA.
