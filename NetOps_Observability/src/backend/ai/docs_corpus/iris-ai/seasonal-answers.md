---
title: Seasonal answers
description: How Iris answers "is this normal for this time of week?" by comparing a value with the same hour in earlier weeks or days.
page_type: concept
sidebar_position: 7
---

# Seasonal answers

Most network numbers have a rhythm: busy at 9:00 on weekdays, quiet at night and
at weekends. A single average gets both ends wrong — it calls every Monday
morning "high" and misses a link that is unusually busy at 3:00. When you ask
whether something is normal, Iris compares it with **the same hour in earlier
weeks** instead.

## Ask it

- `is traffic on edge-1 normal for this time of week?`
- `which interfaces are unusually busy for this time of day?`

## How it works

Say you ask at 10:00 on a Tuesday and the value is 300 Mb/s.

1. Iris reads the same metric at 10:00 on each of the last four Tuesdays — say
   180, 200, 190 and 210 Mb/s.
2. It takes the **typical value** (the middle of those, 195 Mb/s) and **how
   much it normally varies**.
3. It says how far today is from typical, for example: *usually about 195 Mb/s
   for this time of week (4 of 4 weeks used); 300 Mb/s is well above its normal
   range.*

It uses the middle value, not the average, so one unusual week (an outage, a
backup run) does not distort the baseline. An hour that fell inside a
maintenance window is left out, and the answer says how many weeks it used.

## How much history it needs

| History | What Iris compares with | How it says it |
|---|---|---|
| 3 or more earlier weeks | the same hour on the same weekday | "for this time of week" |
| 5 or more earlier days | the same hour on earlier days | "for this time of day" — never "for a Tuesday" |
| less | the flat level of the last 7 days | "not enough history" |

## Keep four weeks of history

Metric storage keeps 30 days, so a comparison reaching back four weeks can run
short as old data ages out. Turn on **Seasonal baselines history** under
**Platform → Configuration → Features** (`FEATURE_SEASONAL_ROLLUP`) to keep one
hourly summary per metric for nine weeks. It applies after a restart, and it is
off by default.

## What it does not change

Seasonal answers change what Iris tells you; they do not change how the
correlation engine opens incidents. The engine can still raise an incident for a
routine peak, and Iris, when asked, can explain that the peak is normal for that
time. An installation may also run a counted-only comparison inside the engine
to measure how often the two would disagree; it never changes an incident.

## Related

- [Investigate an incident with Iris](/iris-ai/ask-iris)
- [Turn Correlix features on and off](/administration/features)
