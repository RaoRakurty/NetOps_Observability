---
title: What an empty result means
sidebar_label: What an empty result means
sidebar_position: 51
description: A lookup table for every Correlix surface that can return nothing, saying which of the two reasons applies and what the blank does not claim.
page_type: reference
---

# What an empty result means

Correlix separates *not measured* from *measured as zero*. A screen that shows
nothing is therefore two different facts, and this table says which one you are
looking at. Every row is drawn from a shipped behaviour, and the quoted strings
are the ones the product emits.

## The table

| Surface | What you see | What it means | What it does not mean |
|---|---|---|---|
| `GET /api/bgp/alerts` with `FEATURE_BGP_ALERTS` off | `alerts: []`, `incidents: []`, `status.enabled: false`, and the note `BGP alerting is off. Set FEATURE_BGP_ALERTS=true to run the watchlist evaluator. An empty list here means the evaluator has not run — NOT that nothing is wrong.` | The evaluator was never constructed, so no prefix was classified. | Not that your prefixes are healthy. Nothing looked. |
| The watchlist with the evaluator off | `incidents_note: "Incident classification is off. Set FEATURE_BGP_ALERTS=true to run the watchlist evaluator. No incident here means NOT EVALUATED, not healthy."` instead of an `incidents` map | Classification is off, so the list carries no verdicts. | Not an all-clear per prefix. |
| RPKI verdict `unavailable` | The chip **UNAVAILABLE**, and `error` naming the failure | The validator could not be reached, or the origin AS was not determinable. | Not `valid`, and not the same as `unknown`. Collapsing the two would overstate ROA coverage. |
| RPKI verdict `unknown` | The chip **NO ROA** | No ROA covers this prefix. | Not a failed lookup, and not a pass. |
| `GET /api/bgp/aspa` with no provider configured | `status.configured: false` with a reason and a `how_to` | No ASPA source is configured, and no public per-ASN ASPA API exists to fall back on. | Not that the AS authorizes nobody. That is a different claim, and it is never made. |
| `GET /api/bgp/geofeed` with `published: false` and no `error` | An empty entry list | The registry object for that resource carries no geofeed. | Not that the lookup failed, and not that the address space is unlocated. |
| Bogons with `FEATURE_BGP_BOGON_FEED` off | `feed.enabled: false` plus `feed.note` | Only the embedded IANA and RFC special-purpose set is in force. | Not that the daily full-bogons space is clean. It was not consulted. |
| `GET /api/bgp/bmp/sessions` with no session | `count: 0` and the coverage note `No router is exporting BMP to this platform. This is an empty FEED, not an empty routing table — point a router's BMP export at the receiver (see the ingestion guide).` | No router has been configured to export BMP to this platform. | Not an empty routing table, and not a converged RIB with no routes. |
| A BMP prefix that is not listed | The prefix is absent from `updates` | It has not been seen recently in the bounded ring. | Not that it is unrouted. The feed is recent updates, not a RIB. |
| `GET /api/security/findings` returning `items: []` | An empty page with `total` and `next_cursor` | The search backend answered and matched nothing. A backend that is not wired returns a "not wired" error instead, and an upstream failure returns `502`. | Not that the estate was assessed and found clean. Assessment coverage lives on the posture surface. |
| Posture `coverage.unassessed` above zero | A non-zero remainder, with the note `assessed_assets counts DISTINCT devices with at least one finding in the window; unassessed is the remainder of the tenant's device registry and is NOT a pass — nobody looked at those assets.` | Those devices produced no finding in the window because nothing evaluated them. | Not a pass for those devices. |
| Compliance `score_percent: null` | No percentage on the framework card | Nothing in that framework's scope was assessed, so there is no ratio to compute. | Not a score of zero. An unassessed control is unknown, never a fail and never a pass. |
| The CTEM funnel stage `validate: 0` | A zero on the validate stage, with the note `always 0: the finding model carries no validation marker (secfindings.Finding has no such field and the bus event carries none), so a non-zero value here would be invented rather than measured.` | The finding model carries no validation marker, so the stage has nothing to count. | Not that zero findings have been validated by a person or a tool. |
| IGP `coverage.live_series: false` | Adjacency history from events only, plus a note naming the reason | No collector emits a live adjacency series for that device, or the metric store could not be queried. | Not zero adjacencies, and not a device with nothing to report. |
| An OSPF summary with no live series | `devices: []`, `source: "none"`, `coverage.live_series: false` and a note | Nothing has collected OSPF adjacency state for the scope. | Not that OSPF is down, and not that no device runs OSPF. |
| An adjacency with `up: null` | A row with `state_source: "events"` and a `current_state` from the last event | The live verdict does not exist. The last thing Correlix was told is shown instead. | Not that the adjacency is up now, and not that it is down. |
| Interfaces with `coverage.vrf_labels: false` | Groups with `membership: "not_collected"` and an empty `vrf` | The collected interface series carry no routing-instance label on this transport. | Not that the interfaces are in the default instance. That would be a claim no series supports. |
| Protocol diagnostics with `matched: false` | `findings: []` and `unmatched: "no known signature matched — the raw captured output is attached for TAC"` | The captured output matched no known signature. The raw capture is attached for escalation. | Not that the protocol is healthy. |
| Protocol diagnostics `collect` returning `503` | `protocol-diagnostics collector is not configured on this deployment` | The read-only command collector is not wired on this deployment, so nothing was captured. | Not a failed device. Paste the command output instead and analyze that. |
| `false_positive_rate: null` on RCA feedback | `n: 0` alongside the null | No operator has judged an RCA case yet, so the ratio has no sample. | Not a false-positive rate of zero. |
| An RCA case reading **Not yet determined** for what is affected | The blast-radius line with no device, peer or application | No affected entity has been established yet. | Not zero affected devices. |
| A device configuration in state `unknown` | `state: "unknown"`, with `last_error` present or absent | With `last_error` set, the last capture failed. With no `last_error` and no row, the device was never captured. | Never rendered green. An unassessed device must not look like a clean one. |
| An audit total of `-1` | `X-Total-Count: -1`, or `total: -1` in the envelope | A backend could not answer the count. | Not zero. On this surface a zero would read as "no privileged actions occurred". |
| `GET /api/telemetry/unrecognized` returning `503` | `no admission verdict available for this lane: no document in the last 7 day(s) carries the ingest admission stamp "cx_admission.by"` | Nothing in the window carries the ingest admission stamp, so the engine's admission verdict cannot be read. | Not that every line is recognized. The endpoint refuses to guess rather than answering `200` with an empty list. |
| A resource id from another tenant returning `404` | An ordinary not-found | You may not see it. The answer is deliberately identical to an absent object. | Not proof that the object does not exist. |

## The governing rule

A missing measure is stated as not measured, never as zero.

Where a surface can be empty for two different reasons, it names the reason.
Where a number exists only as a ratio of things nobody counted, the field is
`null` rather than `0`. Where a lookup failed, the failure is carried on the
response next to the thing it prevented, and the panel that failed says so
instead of rendering blank.

## Related

- [BGP operations](/bgp/overview)
- [Glossary](/reference/glossary)
- [Feature flags and their defaults](/reference/feature-flags)
