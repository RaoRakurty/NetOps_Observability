---
title: Check telemetry parser coverage
sidebar_label: Telemetry Coverage
description: Read what the parser recognises today, find the message shapes your own network sends that it does not, and draft a catalog row.
page_type: task
sidebar_position: 12
---

# Check telemetry parser coverage

**Administration → Data sources → Telemetry Coverage** answers two different questions on one page. The top half is the parser itself: which revision is running, which rules exist, and how much of what it admits becomes a typed observation. The bottom half is your own tenant's traffic: the message shapes arriving that the parser would not admit, with a way to draft a catalog row for one.

## Before you begin

- **Permission, parser statistics:** platform administrator. `GET /api/admin/parser/stats` describes the platform's own parser, which is the same for every tenant. A tenant administrator receives `403 {"error":"platform administrator required"}` and the page renders a card headed **Parser coverage — platform-admin only** with no numbers in it.
- **Permission, unrecognized shapes:** `infrastructure:read`. `GET /api/telemetry/unrecognized` is per-tenant data, scoped to your tenant's indices and your visible devices. A cross-tenant selector is ignored for a scoped principal.
- **Permission, drafting a catalog row:** `alerts:write` for `POST /api/telemetry/unrecognized/{template_id}/propose`.
- The leaf is not platform-only, because a tenant administrator needs the second half.

## Steps

### Read the parser statistics

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/admin/parser/stats
```

```json
{
  "parser_rev": "2026-09-02-a9b",
  "rules_hash": "a0be9de50a0657bc",
  "generated_at": "2026-09-03T04:47:00Z",
  "promotion_rate": null,
  "window_lines": 0,
  "prefilter": { "passed": 122, "rejected": 3798 },
  "generic_fallback": { "syslog": 0, "trap": 0 },
  "rules": [
    {
      "rule_id": "syslog.bgp.adjacency_change",
      "lane": "syslog",
      "kind": "bgp_adjacency_change",
      "fidelity": "code",
      "hits": 0,
      "shadow": false
    },
    {
      "rule_id": "syslog.bgp.route_churn",
      "lane": "syslog",
      "kind": "bgp_route_churn",
      "fidelity": "doc_claimed",
      "hits": 0,
      "shadow": false
    }
  ]
}
```

The capture above is real, from a lab running 40 rules across three lanes: 16 on `syslog`, 12 on `port` and 12 on `trap`.

| Field | What it means |
| --- | --- |
| `parser_rev` | The parser revision the correlation engine is running. |
| `rules_hash` | A hash of the rule set, so two engines running different rules are visible. |
| `generated_at` | When these numbers were read from the engine. |
| `promotion_rate` | The semantic promotion rate. See below. |
| `window_lines` | How many admitted lines the promotion window currently holds. This is the rate's denominator. |
| `prefilter.passed` | Raw syslog lines the ingest screen handed to the full classifiers. |
| `prefilter.rejected` | Raw lines the screen proved cannot promote, so it did not classify them. |
| `generic_fallback` | Emitted observations per lane that fell through to the generic net instead of matching a typed rule. |
| `rules[]` | One row per rule: `rule_id`, `lane`, `kind`, `fidelity`, `hits` and `shadow`. |

If the deployment runs several correlation replicas and they disagree, `parser_rev` and `rules_hash` come back as the distinct values joined together rather than one being picked, so a half-upgraded fleet is visible in the header rather than hidden by it.

### Read the promotion rate honestly

The semantic promotion rate is the share of admitted lines that became a **typed** observation rather than a generic one, over a rolling window of the most recent admitted lines. Lines that classify as nothing at all are not in the denominator; those are the pre-filter's business, not the parser's.

`promotion_rate` is `null` whenever the window is empty, and the console renders it as a dash captioned "no admitted lines yet". It is never coerced to `0`, and never to `100%`. The capture above shows exactly that state: `window_lines` is `0`, so there is no rate to report, and reporting one would be an invention.

### Read the fidelity tiers

Every rule carries the strength of the evidence behind it, not a confidence score.

| Value | Shown as | Means |
| --- | --- | --- |
| `live_validated` | live validated | Confirmed against a device in production traffic. |
| `lab_validated` | lab validated | Confirmed against a device in the validation lab. |
| `code` | unverified | Defined in the product and not yet confirmed against a device. |
| `doc_claimed` | doc claimed | Taken from vendor documentation and confirmed nowhere. |

`code` ranks above `doc_claimed` deliberately: a hand-written, tested branch is evidence about the grammar, and a documentation claim is not. The lab capture above holds 31 rules at `code` and 9 at `doc_claimed`, with no rule yet validated against live or lab traffic.

A rule with `shadow: true` is evaluated and counted and emits nothing. It cannot change what the parser produces. A shadow rule also contributes nothing to the ingest screen: the screen's markers are built only from non-shadow rules, so a shadow row is observed only on lines the screen already admits for some other rule's sake. The lab capture has one, `syslog.config.change`.

### Read your own unrecognized message shapes

The second half lists the message shapes arriving in your tenant that the parser did not admit, newest window first, with a count, the devices they came from, the highest severity seen, first and last seen, and a sample line. Filter by lane with **All lanes**, **Syslog** or **Trap**, and by window with `days`, which accepts 1 to 30 and defaults to 7. `limit` accepts 1 to 200 and defaults to 50.

An unrecognized line is defined as a document in the window that carries no ingest admission stamp. The verdict is read from the stamp the ingest pipeline wrote, and it is never re-derived. That definition is the whole point: transcribing the admission predicate into a third language would produce a fourth answer nobody could reconcile.

When no document in the window carries the stamp, the endpoint refuses rather than returning an empty success:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/telemetry/unrecognized
```

```json
{"error":"no admission verdict available for this lane: no document in the last 7 day(s) carries the ingest admission stamp \"cx_admission.by\" (deployment/docker/vector/vector.yaml `syslog_admission_stamp`, generated by scripts/gen-syslog-admission.py). Without it the engine's admission verdict cannot be read, and this endpoint will not guess it"}
```

The status is `503`. An empty list here would read as "your network sends nothing the parser cannot handle", which is the opposite of what is true. The endpoint says it cannot read the verdict and stops.

The trap lane refuses for a different reason, also with `503`: the SNMP trap lane publishes no admission stamp at all, so unrecognized-shape mining is not defined for it. The syslog lane is the one that is.

### Draft a catalog row

1. Select a template in the unrecognized list.
2. Select the action that proposes a catalog row, or call `POST /api/telemetry/unrecognized/{template_id}/propose`.
3. Read the response. It returns a `proposal_id`, a `status` of `drafted`, a `catalog_row` in YAML and a `fixture` line.
4. Copy both and open a pull request against the catalog.

A proposal applies nothing. It does not write the catalog, does not rebuild the rules, does not touch the parser and does not reload the engine. A human lands it by pull request, and the audit record for the proposal stamps that nothing was applied.

The drafted row is pinned at the weakest rung of both ladders: `fidelity_status: doc_claimed` and `shadow: true`. A row proposed from one observation has no evidence behind it yet, and it must not emit anything until a person has looked at it. The fixture's hostname is a placeholder rather than the observed device, so a pull-request diff cannot leak your topology.

Drafted rows and sample lines are device-authored text, and the console renders them as escaped text in a read-only code block. Nothing from a device is ever executed or injected as markup.

## What you see

On a healthy deployment the header carries a parser revision and a rules hash, and the promotion rate reads either a percentage or an honest dash. The rules table sorts by hits, so you can see which rules your traffic actually exercises. The unrecognized list is either populated or explains in words why it cannot answer. A template id that does not resolve in your own window returns `404 template not found in the caller's current window`, the same answer another tenant's id gets, so the route is not an existence oracle.

## Related

- [Create a pipeline processor](/administration/processors) for shaping events before the parser sees them.
- [Send syslog](/send-data/syslog) and [Send traps](/send-data/traps) for the ingest side.
- [Reading logs](/noc-guide/reading-logs) for what a typed observation buys an operator.
- [Honest states](/reference/honest-states) for the reasoning behind the refusals on this page.
