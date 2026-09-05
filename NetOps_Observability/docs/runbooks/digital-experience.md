# Runbook — Digital Experience (DEM)

What to do when an experience alert fires, and how to tell a real service
problem from a broken measurement. Rules live in the `noc-experience` group of
`src/config/rules.yaml`; the model is `docs/design/DEM_DATA_MODEL_2026-09-05.md`.

**The rule that governs every step below:** an empty experience view means
*nothing was measured*, which is NOT a healthy result. If you take one thing
from this page, take that.

---

## First: is the measurement alive at all?

The prober is **not** a scrape target and exports no `up` gauge. The only
evidence it is alive is that its samples are arriving.

```bash
# Are experience samples landing at all, and for whom?
curl -s 'http://localhost:8000/api/internal/... ' >/dev/null   # (api is behind auth; use the compose network)
docker compose exec victoria wget -qO- \
  'http://localhost:8428/api/v1/query?query=sum%20by%20(tenant)%20(count_over_time(dem_probe_success%5B15m%5D))'

# Is the prober container running at all?
docker compose --profile prober ps
docker compose --profile prober logs --tail=50 prober | grep -i dem

# What did the api publish as the work queue?
docker compose exec redis redis-cli --no-auth-warning GET netops:dem:targets | head -c 400
```

Three distinct answers, three different faults:

| symptom | meaning | fix |
|---|---|---|
| `dem_targets` present, `dem_probe_success` absent | the api is publishing work and the prober is not doing it | prober not running, or `FEATURE_DEM` not `true` on the prober |
| both absent, catalogue has rows | the api is not publishing the work queue | check the api log for `dem` warnings; the published key has a 3-minute TTL, so a stopped projector goes silent within one |
| both absent, catalogue is empty | nobody declared a target | expected; the page says so |

---

## Availability below budget

`ExperienceAvailabilityBelowBudget` — the target's success ratio over 15
minutes fell under its own budget for 10 minutes.

1. **Read the failure reason before believing the service is down.** Open the
   target and look at the fail class: `dns` · `tls` · `connect_refused` ·
   `connect_timeout` · `timeout` · `reset` · `status` · `nxdomain` ·
   `no_answer`. A vantage that lost its own path produces the same *shape* as a
   service that stopped answering, and they need opposite responses.
2. **Check whether the whole site went quiet.** If every target at one site
   failed at the same second, suspect the vantage or the site's uplink, not each
   of the services independently.
3. `connect_refused` is a service that is up and refusing — a process died or a
   listener moved. `connect_timeout` is a path or a firewall.
4. `status` means the endpoint answered with a code other than the one the
   operator declared. Check whether the declared `expect_status` is still right
   before chasing the application.

## Latency over budget

`ExperienceLatencyOverBudget` — p95 over 15 minutes exceeded the **declared**
latency budget for 10 minutes. Targets with no declared budget never fire this.

Read it with the **phase split**, never as a single total: DNS, TCP connect, TLS
handshake and time-to-first-byte fail in different places, and a total that
doubled tells you nothing about which one moved.

| phase that moved | look at |
|---|---|
| `dns_ms` | the resolver (pin one on the target to separate "our resolver" from "the internet") |
| `tcp_connect_ms` | the path, and the server's accept queue |
| `tls_ms` | the server's CPU, or a re-signing middlebox on the path |
| `ttfb_ms` | the application itself — the network already did its part |

## Path instability

`ExperiencePathUnstable` — the observed forward path changed more than 6 times
in 30 minutes. This is deliberately not an outage: a re-route is normal, and it
only becomes evidence when it is frequent and sustained. It usually shows up in
the experience numbers as jitter long before it shows up as loss.

Requires the traceroute collector (`FEATURE_TRACEROUTE`, needs `CAP_NET_RAW`).
Without it there are no path samples and the score honestly reports path
stability as **not measured** — not as stable.

## Prober not reporting

`ExperienceProberNotReporting` — no sample for 15 minutes from a tenant that
was being measured within the last 24 hours.

The 24-hour clause is the guard: a deployment that never had a target must be
silent, not page forever about a feature nobody switched on. (That is the
`CorrProbeLaneFlatlined` lesson, applied before it bit.)

Work the "is the measurement alive" table at the top of this page, in that
order: prober container → `FEATURE_DEM` on the prober → the published work queue.

---

## Turning it on

```bash
# api
FEATURE_DEM=true
# prober (same flag; it gates the collector there)
docker compose --profile prober up -d --force-recreate prober
```

Then declare targets through `POST /api/dem/targets` (or the page, once it
ships). Scores appear within one target interval plus one projector cycle.

## What the numbers mean

* **Availability** is scored as **error-budget burn**, not as a raw percentage.
  99.0% against a 99.9% budget is a tenfold overrun; a raw-percentage score
  would render that as "99 out of 100" and flatter it.
* **A site or app score weights its worst target** at 0.4. Nine healthy targets
  and one dead one is not "90% well", and a plain mean is how a hard outage
  disappears into a green tile.
* **A component that was not measured contributes nothing** and its weight is
  redistributed. A target with no declared latency budget is scored on
  availability and path stability alone, and the response says so.

---

## The Experience screen says a cause is only "suspected"

This is usually correct, and it is the most common question the screen raises.

Correlix confirms a cause only when **two different kinds of instrument, from
two different vantages, observed the same thing** — the correlation engine's
independence rule, applied to experience evidence. Today most deployments run
exactly one anchor-capable evidence class, the synthetic prober, so the honest
ceiling is `suspected`. That is a statement about the evidence, not about the
analysis, and nothing on the screen should be read as a defect.

Check it in one place:

```bash
# Which sources can anchor a verdict, and are they reporting?
curl -sS -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/dem/data-health?window=1h" | jq '.data_health
   | {can_confirm, anchor_sources_flowing, explanation,
      sources: [.sources[] | {source, state, anchor_capable, confidence_influence}]}'
```

`can_confirm: false` with `anchor_sources_flowing: 1` is the expected answer on
a synthetic-only deployment, and `explanation` is the sentence to quote. It
becomes `true` when a second anchor-capable producer reports — flow-derived
application response time, first-party real-user telemetry, or an endpoint
agent (tracker 252).

Open an incident and read `gate_reasons` on the leading hypothesis: it names the
specific thing that is missing, in order. "only one independent modality class
observed it" means the ceiling above. "a source required to confirm this
reported nothing" means a source that WAS reporting has stopped — that one is a
fault, and it is the same investigation as **Prober not reporting** above.

## The Experience score is not shown at all

The score is deliberately withheld rather than rendered as 0 or 100 whenever
fewer than two of its six dimensions were measured. There are two reason codes
to read and they answer different questions: `reason` at the TOP LEVEL of
`GET /api/dem/overview` says why the whole view has nothing, and `score.reason`
says why the score specifically was not published.

Top-level `reason`:

| `reason` | What it means | What to do |
|---|---|---|
| `feature_off` | `FEATURE_DEM` is not true on the api | Turn it on (see **Turning it on**) |
| `no_targets` | the tenant has declared no target and no journey | Declare at least one |
| `query_failed` | the metrics store did not answer | Investigate VictoriaMetrics; this is not a healthy result |

`score.reason`:

| `reason` | What it means | What to do |
|---|---|---|
| `below_evidence_minimum` | fewer than two dimensions had any measurement | Usually no declared latency budget and no observed path; declare a budget, or accept the two-dimension floor |
| `no_dimensions_measured` | on one dimension: nothing produced it in this window | Expected for the two dimensions that have no producer (below) |
| `no_score_policy` | no weights loaded for this application class | A policy-load failure; check the api log for the score-policy line |

A journey's own `health.reason` is separate again: `journey_not_measured` means
no required step is bound to a target that reported, and `step_not_bound` /
`step_no_measurement` say which step.

Two dimensions — error-free interaction and user friction — have **no producer
yet** and will report as not measured on every deployment. That is expected and
is stated in the response; it is not a collection fault.

## A change does not appear on an incident

The change feed only shows what a producer sent to `POST /api/dem/changes`.
Three things suppress a change that exists:

1. **It happened after the first impact.** It is still listed, marked
   `precedes_impact: false`, and can never support a cause — it cannot have
   caused what had already started.
2. **It is outside the lookback** (90 minutes before first impact by default).
3. **Nothing sent it.** The config-capture, cloud and BGP producers do not yet
   write to this feed automatically; an empty feed means "nothing was reported",
   which the response says explicitly and which is not the same as "nothing
   changed".
