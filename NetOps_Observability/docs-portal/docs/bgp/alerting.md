---
title: Configure BGP alerting
sidebar_label: Configure alerting
sidebar_position: 7
description: Turn on the watchlist evaluator, declare your expected origins and upstreams, and read the incident class per watched prefix.
page_type: task
---

# Configure BGP alerting

BGP alerting classifies every watched prefix on a fixed cadence and raises an
alert when the class changes. It uses one classifier, so the class on the screen
and the class that pages someone at 03:00 can never disagree.

## Before you begin

- **`FEATURE_BGP_ALERTS=true`.** The default is off. With the flag off nothing
  is constructed, no evaluation runs, and the route answers:

  > BGP alerting is off. Set FEATURE_BGP_ALERTS=true to run the watchlist
  > evaluator. An empty list here means the evaluator has not run, NOT that
  > nothing is wrong.

- **A watchlist.** The evaluator reads the same list the console writes. See
  [watch a prefix or an ASN](/bgp/watchlist).
- **`infrastructure:read` to read alerts, `infrastructure:write` to replace the
  policy.**
- **One tenant selected.** Alerts and policy are per-tenant data, and a
  cross-tenant read is refused:

  ```json
  {"error":"select a tenant to read its BGP alerts (they are per-tenant data; cross-tenant reads are refused)"}
  ```

- **A notification channel**, if you want delivery rather than a screen. BGP
  alerts ride the same dispatcher as every other Correlix alert. See
  [alerting and notification administration](/administration/overview).

## Steps

1. Set `FEATURE_BGP_ALERTS=true` in the stack environment and restart the
   backend.
2. Add the prefixes you care about to the watchlist.
3. Read the current policy and its defaults:

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     "http://localhost:8000/api/bgp/alerts/config?as_tenant=lab"
   ```

   ```json
   {
     "config": {"default": {}},
     "defaults": {"max_asns_per_set": 32, "max_prefixes": 200,
                  "min_vantages": 2, "min_visibility": 0.5},
     "note": "expected_origins empty ⇒ the prefix falls back to its RECORDED origin baseline, the origin set corroborated the first time we measured it (see /api/bgp/alerts/baselines). That is a remembered observation, not a declared intent, and a prefix with no row yet has no origin check at all. Where no baseline register is wired, each pass compares the prefix against its own dominant origin instead, so only a MINORITY unexpected origin is detectable and a change that reaches every vantage point classifies clean. Declaring the expected origin AS overrides both and is the only one of the three somebody asserted. upstreams empty ⇒ the route-leak heuristic does not run (there is nothing to call unexpected).",
     "updated_at": "0001-01-01T00:00:00Z",
     "updated_by": ""
   }
   ```

4. Declare your intent. A `PUT` replaces the whole policy, so send the complete
   document:

   ```bash
   curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"default":{"expected_origins":["AS64500"],"upstreams":["AS64510","AS64511"]},
          "prefixes":{"203.0.113.0/24":{"min_visibility":0.8}}}' \
     "http://localhost:8000/api/bgp/alerts/config?as_tenant=lab"
   ```

5. Read the classification after the next pass:

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     "http://localhost:8000/api/bgp/alerts?as_tenant=lab"
   ```

   ```json
   {"alerts":[],"incidents":[],
    "classes":["origin_change","rpki_invalid","bogon","route_leak","visibility_loss","none","unknown"],
    "status":{"enabled":true,"interval":"5m0s","cooldown":"1h0m0s","evidence_topic":"netops.bgp",
              "last_run":"0001-01-01T00:00:00Z","runs":0,"peer_rule_enabled":true,
              "notify_wired":true,"evidence_wired":true,
              "note":"The evaluator has not completed a pass for this tenant yet — an empty incident list here means 'not evaluated', not 'nothing wrong'."}}
   ```

### Set the policy from the console

The same policy is editable on **Analytics → BGP Operations**, in the **Alert
policy — what counts as an incident** section. It sits directly beneath the
**Incidents — watched prefixes** section, because every verdict there is this
policy's output.

1. Open **Analytics → BGP Operations**.
2. In **Alert policy**, set **Expected origin AS** and **Upstream (transit) AS**
   for the tenant default. Both accept `AS64500` or `64500`, separated by
   commas.
3. Set **Minimum visibility** as a share between 0 and 1, and **Minimum vantage
   points** as a whole number.
4. Select **Add a prefix policy** for a prefix that needs its own origin, its own
   upstreams or its own thresholds. Enter the prefix, then its fields.
5. Select **Save policy**.

The section prints the consequence of each empty set next to the field that is
empty: an empty origin set means the check falls back to the origin recorded the
first time the prefix was measured, and an empty upstream set means the
route-leak check does not run. Neither absence is a clean result.

The platform stores what it normalizes, not what you typed. It removes duplicate
AS numbers, refuses AS0, sorts each set, and rewrites every policy key to its
canonical prefix, so `193.0.0.1/21` is stored as `193.0.0.0/21`. The section
re-renders from the stored policy after each save.

With `FEATURE_BGP_ALERTS` off, the section still saves. It states that the policy
is stored and takes effect when the evaluator runs.

## Result

Each watched prefix carries one class from a closed set. The headline class is
the worst one that fired; every other class that fired rides in `also`, so
nothing measured is discarded.

| Class | Severity | Fires when |
|---|---|---|
| `origin_change` | critical | An AS outside the expected origin set is originating the prefix, corroborated by at least the required number of vantage points. |
| `rpki_invalid` | high | Origin validation returned invalid for the announcement really in the table. |
| `bogon` | high | The prefix falls inside a reserved block that must never appear in the global table. |
| `route_leak` | high | A declared upstream relationship is violated on the observed paths. |
| `visibility_loss` | warning | The prefix is seen by fewer route-collector peers than the visibility threshold, or by none at all. |
| `none` | info | Measured, and nothing is wrong. |
| `unknown` | info | Not measured. The routing lookup did not answer. |

`none` and `unknown` are deliberately different answers. An unmeasurable prefix
is classified `unknown`, raises no alert, and is summarized as "Not measured".

### The rules that stop false positives

- **Two vantage points, minimum.** Every path-derived class needs corroboration
  from at least `min_vantages` distinct collector peers, default 2. A single
  collector holding a stale path is not an origin change.
- **A near miss is reported, not hidden.** When a class almost fired but lacked
  corroboration, the incident carries `corroboration_shortfall` naming the AS,
  how many vantage points saw it, and how many are required.
- **An empty expected-origin set falls back to the RECORDED baseline.** The
  first time a prefix is measured with a corroborated origin, that origin set is
  written down. Every later check compares the prefix against that stored row,
  which does not move, so an origin change is detected however widely it has
  propagated. Three things are deliberately not incidents: a first observation,
  because there is nothing it could have changed from; a prefix you added to the
  watchlist since the last pass, for the same reason; and an origin change you
  have accepted. The incident carries the row it was judged against in
  `origin_baseline`, and a plain-language `baseline_note` saying where the
  baseline came from. See [Origin baselines](#origin-baselines) below.
- **An empty upstream set disables the leak heuristic.** With no declared
  transit set there is nothing to call unexpected, and Correlix does not guess
  one. Full valley-free detection needs AS relationship data that no free
  per-ASN source publishes, so what is derivable from your declared set is
  derived and the rest is declared missing.
- **Two classes need no corroboration**, because neither is path-derived: the
  RPKI verdict is one validator's answer about one pair, and a bogon match is
  arithmetic on the prefix.

### Origin baselines

The baseline is what an origin change is measured against. Correlix records one
per watched prefix, the first time it measures that prefix and sees an origin
corroborated by at least `min_vantages` collector peers. It does not record one
from a pass that already looks wrong: an RPKI-invalid announcement, a bogon
prefix, or a pass that is itself an origin change never becomes the baseline, so
a hijack in progress cannot be adopted as the truth about the prefix.

Read them:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/bgp/alerts/baselines?as_tenant=lab"
```

Each row names the prefix, the origin set, how many collector peers corroborated
it, when the prefix was first measured, and where the row came from:
`first_observation` for one Correlix recorded itself, `operator_accepted` for one
a person stated.

**A baseline is a remembered observation, not a declared intent.** Nobody
confirmed it. If the prefix was already being announced by the wrong AS the
first time Correlix measured it, that is what was recorded. Declaring the
expected origin AS in the policy is the stronger statement, and it overrides the
row.

**When the origin legitimately changes**, accept the new origin. This is what
stops a real re-homing alerting forever:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"prefix":"203.0.113.0/24","origins":["AS64512"]}' \
  "http://localhost:8000/api/bgp/alerts/baselines?as_tenant=lab"
```

You state the origin set you are adopting. Correlix never takes it from the
current announcement on its own, because adopting whatever is being announced
right now is exactly the behaviour the stored baseline replaced. The open
incident clears on the next **measured** pass, not on the accept: Correlix
resolves what it has re-measured, never what it was told.

To make a prefix re-learn from scratch, delete its row with
`DELETE /api/bgp/alerts/baselines?prefix=<prefix>`. Whatever is announcing the
prefix at the next measurement becomes the new baseline, so prefer accepting an
origin you know is right.

Baselines are per tenant. A prefix another tenant holds is absent from your list
and answers 404 on delete, which is the same answer a prefix nobody holds gets.

`netops_bgpwatch_origin_baselines_recorded_total` counts the rows written. A
watchlist with prefixes in it and a flat zero here means every prefix is still
in its first-observation state, so no origin change has anything to be detected
against yet.

### Bounds and cadence

| Setting | Value |
|---|---|
| Evaluation interval | 5 minutes, `BGP_ALERT_INTERVAL` |
| Re-notification cooldown per prefix and class | 60 minutes, `BGP_ALERT_COOLDOWN` |
| Prefixes evaluated per tenant per run | 50 |
| Alert history retained per tenant | 200 |
| Declared ASNs per set | 32 |
| Per-prefix policy overrides per tenant | 200 |

The owner of a policy is stamped from the authenticated principal. There is no
tenant field on the wire to override it with, and `updated_by` reflects the
token that wrote it.

### What the alert does

Alerts have a stable id of the form `bgp:<tenant>:<prefix>:<class>`, so a
destination that deduplicates closes the same incident it opened. Correlix
alerts on transitions and emits a resolution when a class clears. A separate
rule, `bgp_peer_down`, fires from BMP and device peer state. A peer that
disappears from the report is not treated as a recovery, because nothing
measured it coming back.

Each verdict is also published as an evidence event on the `netops.bgp` topic,
where correlation can ground it against the rest of the incident.

## Related

- [Watch a prefix or an ASN](/bgp/watchlist)
- [Review bogon sightings](/bgp/bogons)
- [The alert rule reference](/reference/alert-rules)
- [What an empty result means](/reference/honest-states)
