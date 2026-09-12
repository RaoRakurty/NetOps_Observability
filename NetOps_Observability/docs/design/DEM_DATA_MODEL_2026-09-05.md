# DEM data model — one fact, many sources (2026-09-05)

Short by design. This is the **data model** the Digital Experience plumbing was
built to, so that the later experience sources land on the same series and the
same score without a schema break. The product design of record is
`docs/design/DEM_2026-09-05.md` (to be merged with the owner's own document);
what actually shipped underneath both is recorded in
`docs/design/DEM_PLUMBING_2026-09-05.md`.

---

## 1. The one fact

Everything reduces to a single fact type:

> **subject X of tenant T, observed from source S, was reachable / not at time
> TS, with these timings and this observed path.**

`internal/dem.Measurement` is that type. `internal/dem.Identity` is its subject.

```
Identity = (tenant, subject, kind, site, app, source)
```

| field | meaning | why it is in the key |
|---|---|---|
| `tenant` | the owning tenant | isolation is a build-time property, not a filter someone remembers to add |
| `subject` (metric label `target`) | the **stable opaque id** of the thing whose experience is measured | a rename of the host must not fork the series |
| `kind` | *what* is measured | an ICMP RTT and a page load are not the same number |
| `site` | where the experience was had | the unit an operator escalates about |
| `app` | which application | the unit a business owner escalates about |
| `source` | **the evidence class that produced it** | "the synthetic said it was fine" and "the user's browser said it was not" are different claims; an RCA that conflates them is lying |

`source` is the dimension that makes this model future-proof, and it is on
**every** series and **every** score from day one — not retrofitted later.

## 2. The source vocabulary (declared now, one producer today)

| `source` | producer | `kind`s it will emit | subject id |
|---|---|---|---|
| `synthetic` | **shipped** — the prober's catalogue-driven checks | `icmp` `tcp` `dns` `http` | catalogue target id (`dem-<32 hex>`) |
| `sdwan` | SD-WAN controller per-app SLA (loss / latency / jitter per tunnel per site) | `tunnel` | `<controller>:<tunnel-or-site-pair>` |
| `wireless` | wireless-controller client experience (RSSI, SNR, retries, roams) | `wlan_client` | `<controller>:<client-id>` (a per-tenant salted hash — see §5) |
| `flow` | flow-derived application response time (TCP handshake / RTT from flow records) | `flow_app` | `<app>@<site>` |
| `agent` | endpoint-agent check results | `agent_check` | `<agent-id>:<check-id>` |
| `rum` | browser RUM beacons (page load, first byte) | `page_load` | `<app>:<route>` |

The reserved `kind` constants already exist in `internal/dem/model.go`. They are
deliberately **not declarable through the catalogue CRUD**: those measurements
arrive from a controller, a flow record or an agent, and minting a catalogue row
for one would create a target nothing will ever measure.

## 3. The series (VictoriaMetrics)

Every source writes the **same** metric names with the **same** label set:

```
dem_probe_success{tenant,target,kind,site,app,source}          1 | 0
dem_probe_latency_ms{...}                                      only when a timing was observed
dem_probe_loss_pct{...}
dem_probe_ttfb_ms{...}                                         http-shaped sources
dem_path_fingerprint{...}                                      only when a path was observed
dem_path_hops{...}
dem_targets{tenant,source}                                     declared-subject census
dem_target_availability_budget_pct{tenant,target,kind,site,app,source}
dem_target_latency_budget_ms{...}                              only when declared
```

Two rules that are load-bearing rather than stylistic:

* **A sample is only written when something was measured.** A failed check
  writes `dem_probe_success 0` and `dem_probe_loss_pct 100` and **no latency
  sample** — emitting a 0 ms would drag every percentile down with a number
  nothing measured.
* **`tenant` is a first-class label.** The legacy `synthetic_*` / `probe_*`
  series carry only `dst` + `check`, which is why the platform's generic
  device/hostname/source scoping matches none of them and a scoped tenant sees
  nothing from them at all. `dem_*` exists partly to fix that; the API filters
  on this label directly (`internal/dem.TenantFilter`, fail-closed).

## 4. Scoring is source-agnostic

`internal/dem/score.go` takes `WindowStats` (counts and percentiles) plus a
budget and returns a verdict. It never asks where the numbers came from, so an
SD-WAN tunnel's loss and a synthetic HTTP check are scored by the same maths and
roll up into the same site/app tile. Three components — availability as
**error-budget burn**, p95 against the **declared** latency budget, and path
stability — each contributing only when it was actually measured, with the
weight of an unmeasured component redistributed rather than assumed.

A window with no measurement returns `measured:false` plus a reason. There is no
code path that produces a score from nothing.

## 5. Identity hygiene for the sources that are not built yet

Three constraints that must hold when they are, because retrofitting them is
what breaks the model:

1. **The subject id is opaque and stable.** Never a hostname, never a URL, never
   a MAC address in the clear. A wireless client id must be a per-tenant salted
   hash: a client identifier is PII and it becomes a metric label, which is the
   one place a value is impossible to redact after the fact.
2. **`tenant` is never a grounding token on the bus.** The correlation engine
   forbids a `tenant:` entity token precisely to stop two tenants' subjects
   merging on a shared token. Tenant belongs in `Signal.tenant_id`, adjudicated
   by `verified_tenant()`; `target:` / `site:` / `app:` are the sanctioned
   grounding prefixes and are what the probe lane now emits.
3. **A source declares its own vantage.** `Observer.location` is the site the
   measurement was taken *from*, which is not always the site it is *about* —
   an agent in dc1 measuring an app in dc2 is one row, not two.

## 6. Bus contract

The additions to `ProbeEvent` (`src/backend/collectors/probe_events.go`) are
`tenant`, `target_id`, `app_id`, `source` — all `omitempty`, so a STAMP,
traceroute or env-synthetics event is byte-identical to what it was before and
`src/contracts/probe_event_wire.json` is unchanged. The correlation side reads
them additively: `handle_probe` accepts `tenant` as a **claim** (still through
`verified_tenant`, so a claim contradicting the registry dead-letters), and
`producers.probe_signals` grounds `target:` / `site:` / `app:` tokens plus
`Signal.site`.
