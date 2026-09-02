# Proactive checks — NetClaw's heartbeat list vs the correlation engine (2026-09-02)

**Project 4 C, Phase A4.** `IRIS_TROUBLESHOOTING_MODEL_2026-09-02.md` §3.4 says:
*"Map NetClaw's heartbeat list onto the engine … Where a rule is missing, add a
symptom rule — the engine flags, Iris narrates."* This is that map, audited
against the code rather than against memory, with the gap closed.

Scope: the **engine** side (`src/correlation/**`). Iris reads the engine's
conclusion; it does not re-derive one. Everything below is evidence with a
`file:line`, and every claim was checked by reading the file at that line.

---

## 0. The finding, in one sentence

**The engine flagged TRANSITIONS. It did not flag a STATE THAT STAYS BAD.**

Every control-plane kind it emits is a *change* — `bgp_adjacency_change`,
`ospf_adjacency_change`, `isis_adjacency_change`. Every metric kind is a
*deviation* — `device_resource_anomaly` is a CUSUM episode against the device's
own rolling baseline (`episodes.py:1-24`). Both are structurally blind to the
condition an operator actually opens a case about:

* a peer parked in ACTIVE for twenty minutes emits **one** adjacency line at
  t=0 and then nothing at all, so nothing ever asks whether it came back;
* a router that has run at 97 % CPU for a week has **97 % as its baseline**, so
  its deviation is zero and the episode detector is right to say nothing.

Five of the ten audited items needed nothing new (rows 6-10 — row 6 with its
syslog half already held at shadow by tracker 220, row 7 emitted but
intentionally unconsumed). The five that did — OSPF, IS-IS, BGP, CPU, memory —
are all instances of that one gap: the phenomenon IS observed, but only in its
transition/deviation form. `src/correlation/proactive.py` closes it.

---

## 1. The audit table

| # | NetClaw heartbeat check | Status | Rule / template id | Evidence |
|---|---|---|---|---|
| 1 | OSPF adjacency not FULL | **partial → covered (shadow)** | flap: `syslog.ospf.adjacency_change`, `trap.ospf.adjacency_change` → `sig.ent.access.ospf-adjacency-flap`. **persistence: NEW** `proactive.ospf.adjacency_not_full` (shadow) | `src/correlation/parser_rules.py:93`, `:1014`; `catalog.py:956`; new: `proactive.py` `CHECKS` |
| 2 | IS-IS adjacency not UP | **partial → covered (shadow)** | flap: `syslog.isis.adjacency_change`, `trap.isis.adjacency_change` → `sig.ent.fabric.isis-adjacency-flap`. **persistence: NEW** `proactive.isis.adjacency_not_up` (shadow) | `parser_rules.py:39`, `:1048`; `catalog.py:992` |
| 3 | BGP peer IDLE/ACTIVE **persisting** (not a flap) | **partial → covered (shadow)** | flap/anomaly: `syslog.bgp.adjacency_change`, `trap.bgp.adjacency_change`, metric episode `bgp_state_anomaly` → `sig.ent.wan-edge.bgp-peer-flap`. **persistence: NEW** `proactive.bgp.not_established` (metric) + `proactive.bgp.adjacency_down_persisting` (signal), both shadow | `parser_rules.py:66`, `:911`; `main.py` `metric_identity` (family `bgp` → `bgp_state_anomaly`); `catalog.py:886` |
| 4 | CPU > threshold | **partial → covered (shadow)** | deviation only: `device_cpu_percent` → `device_resource_anomaly` (CUSUM). **sustained: NEW** `proactive.device.cpu_sustained_high` (shadow) | `src/backend/collectors/metric_events.go:86` (allowlisted); `main.py` `metric_identity` family `device_resource`; `episodes.py:1-24` |
| 5 | Memory > threshold | **partial → covered (shadow)** | as #4, `device_mem_percent`. **sustained: NEW** `proactive.device.mem_sustained_high` (shadow) | `metric_events.go:87`; `layers.py:49`; `confirmability.py:163` |
| 6 | Config change in window | **covered (trap) / SHADOW (syslog)** | `trap.config.change` **emits**; `syslog.config.change` ships `shadow: true` (tracker 220). Consumed as an OPTIONAL clause by five templates. Iris also has the `recent_change` verify module. | `parser_rules.py:1157` (trap), `parser_rules.py:514` + `:524` `'shadow': True`; `catalog.py:899`, `:963`, `:1000`; `src/backend/internal/verify/modules.go:58`; `docs/TRACKER.md` row 220 |
| 7 | Device restart / reload | **covered, intentionally unconsumed** | `trap.device.restart` → kind `device_restart`, declared `INTENTIONAL_BLIND` ("contributing lifecycle context") — emitted and searchable, required by no signature | `parser_rules.py:890`, `:994`; `coverage.py:64` |
| 8 | Interface error-rate rise | **covered** | `device_if_in_errors` / `device_if_out_errors` / discards / FCS are RCA families → `if_metric_anomaly` episodes → `sig.ent.access.local-link-fault`. (The *semantic* kind `if_errors` remains `NORMALIZATION_PENDING` — the counters are polled, the semantic kind is not separately produced.) | `metric_events.go:77-81`; `main.py` `metric_identity` family `interface`; `catalog.py:923`; `coverage.py:233` |
| 9 | CVE match (Project 3 findings lane) | **covered** | secbus → `netops.security` → `security_exposure` → `sig.ent.security.exposure-story` | `src/backend/internal/secbus/event.go:45`; `signals.py:1073-1086`; `catalog.py:3649` |
| 10 | SoT / intent mismatch (config drift) | **covered** | `configdrift` emits a `EvidencePosture` finding onto `netops.security` → `security_posture` → `sig.ent.security.hardening-drift-story` | `src/backend/internal/configdrift/evaluator.go:275`, `:308`; `signals.py:1076`; `catalog.py:3675` |

**Legend.** *covered* = a producer emits it AND a signature consumes it.
*shadow* = the rule/check exists, is evaluated, and deliberately emits nothing
(A8 contract) until promoted. *partial* = the phenomenon is observed but only in
its transition form.

### Two things the audit found that were NOT on the list

* **`Source.SOT_DRIFT` is a dead enum value** (`signals.py:134`): no producer
  in `src/correlation/**` constructs a signal with it. SoT drift reaches the
  engine through the **security** lane (row 10), not through a drift-specific
  source. Harmless, but it reads as a gap that is not one — recorded here so
  the next reader does not re-open it.
* **`device_restart` is `INTENTIONAL_BLIND`** (row 7). NetClaw flags a reload
  proactively; this engine emits the signal and no signature requires it. That
  is a deliberate choice ("contributing lifecycle context"), and the new
  `sig.ent.device.resource-saturation` signature names it as an **optional
  clause** — a box that is busy because it just came up is converging, not
  short of capacity — which is the first reasoning use the kind has had. It is
  optional rather than a discriminator on purpose: the look-alike has no
  competing template to prefer, and pointing `else_prefer` at an unrelated
  signature to satisfy the schema would make the engine argue for a cause
  nobody proposed.

---

## 2. What was built

`src/correlation/proactive.py` — a small, pure, deterministic **dwell-timer
plane**. No IO, no asyncio, no ClickHouse: `ProactiveMonitor` takes
observations and returns events; `main.py` owns every side effect.

| check_id | kind (once promoted) | driven by | fires when |
|---|---|---|---|
| `proactive.bgp.not_established` | `bgp_session_not_established` | metric `device_bgp_peer_state` | value < `established(6)` held ≥ dwell |
| `proactive.bgp.adjacency_down_persisting` | `bgp_session_not_established` | signal `bgp_adjacency_change` | `state=down` held ≥ dwell |
| `proactive.ospf.adjacency_not_full` | `ospf_adjacency_not_full` | signal `ospf_adjacency_change` | `state=down` held ≥ dwell |
| `proactive.isis.adjacency_not_up` | `isis_adjacency_not_up` | signal `isis_adjacency_change` | `state=down` held ≥ dwell |
| `proactive.device.cpu_sustained_high` | `device_resource_saturation` | metric `device_cpu_percent` | ≥ 90 % held ≥ dwell |
| `proactive.device.mem_sustained_high` | `device_resource_saturation` | metric `device_mem_percent` | ≥ 90 % held ≥ dwell |

Dwell defaults to **300 s** (`CORR_PROACTIVE_DWELL_S`) — long enough to outlast
a reload, an IGP dead-timer expiry and re-adjacency, and a BGP idle-hold retry.

Four signatures with `operator_phrase` wording are authored in
`proactive.PROACTIVE_TEMPLATES` and **deliberately not installed** (see §4):
`sig.ent.wan-edge.bgp-session-stuck`, `sig.ent.access.ospf-adjacency-stuck`,
`sig.ent.fabric.isis-adjacency-stuck`, `sig.ent.device.resource-saturation`.

### Flap vs persistent — the discriminator

A watch opens when the state goes bad and **closes** when it goes good. It
fires only when the bad state has been held *continuously* for the dwell.
A flap therefore fires nothing and is left to the existing `*-adjacency-flap`
signatures — which are the right explanation for it and have different first
steps. Each new signature also carries a discriminator that defers to the flap
template when both are present, so the two can never double-count one fault.

### Wiring (three observation points and a sweep)

| where | `main.py` | why |
|---|---|---|
| `handle_metric`, after `feed_episode_detector` | `PROACTIVE.observe_metric(...)` | one dict lookup on the metric name; the ~12 unwatched families return immediately |
| `handle_syslog`, after the control-plane signal is buffered | `PROACTIVE.observe_signal(...)` | the adjacency lane |
| `handle_snmptrap`, after `buffer_signal` | `PROACTIVE.observe_signal(...)` | trap estates get the same check as syslog estates |
| `engine_loop`, after `_drain_epoch_sweep` | `PROACTIVE.sweep(now)` | **required**: a device logs "adjacency down" ONCE, so nothing else would ever come back and ask whether it is still down |

The sweep runs in its own `try` — a dwell timer must never be the reason
correlation stops (§10, no silent failures; the exception is logged).

### The anti-skew gate (two clocks, and neither duration measured on the wrong one)

The sweep reads its **own** clock; `since` and `last_ts` come from the
**device** (a syslog/trap timestamp). Both naive readings are wrong on a box
with a bad NTP config, and in opposite directions:

* a device an hour **behind** opens a run stamped an hour ago, so a naive
  `now - since` fires on the first sweep and invents a five-minute outage out
  of a clock error;
* the same device also looks permanently **silent** under a naive
  `now - last_ts`, so its watch would be expired as stale before it could ever
  fire.

So a sweep-driven firing must have survived the dwell measured from `armed_at`
— the first sweep that saw the run open — and silence is measured by whether
the observation **counter** moved between sweeps, not by subtracting one
clock's timestamp from another's. The reported `held_s` is the conservative,
actually-observed span; the reported `onset_ts` stays the device's own claim,
which is what an operator needs to line the firing up against the rest of the
timeline. The polled lane needs none of this: `_advance` ignores out-of-order
samples, so a backwards clock jump cannot inflate a dwell there.

A watch that expires while it has already fired emits no `clear`: the state is
unknown, not resolved, and manufacturing a recovery for a device that went
silent is the same lie the gate exists to prevent.

---

## 3. The two contract pins, and why one of them blocked a design

### 3.1 `rcaMetricFamilies` / the gnmic shaper — NOT widened

`src/backend/collectors/metric_events.go:72` and its pinned mirror in
`deployment/docker/gnmic/gnmic-correlation.yaml:593` (`corr-rca-shape`) are the
same allowlist, and `tests/test_gnmi_correlation_lane.py` parses both and fails
on any difference.

**CPU and memory are already on it** — `device_cpu_percent`,
`device_mem_percent` (`metric_events.go:86-87`). No widening was needed for
checks #4 and #5, and none was done.

**OSPF and IS-IS neighbour state are NOT on it, deliberately.**
`device_ospf_nbr_state` and `device_isis_adj_state` are canonically mapped for
VictoriaMetrics (`gnmic-correlation.yaml:382`, `normalization.yaml:93`, `:113`)
but the shaper's own comment says they *"are mapped canonically for
VictoriaMetrics but are NOT RCA families, so they stop here"*
(`gnmic-correlation.yaml:581-582`).

So the §3.4 phrasing "from `device_ospf_nbr_state` / `device_isis_adj_state`"
**cannot be implemented today without a contract change**, and the checks were
built on the adjacency-change *signals* instead — which carry the same state in
`attrs.state`, already reach the engine, and work on syslog-only and trap-only
estates as well as gNMI ones.

> **Gap, with the exact change required.** Promoting the IGP checks to the
> metric path (preferred: a polled series answers "is it still bad?" without a
> sweep, and does not depend on receiving a recovery line) requires ALL of:
>
> 1. `rcaMetricFamilies` in `src/backend/collectors/metric_events.go` gains
>    `"device_ospf_nbr_state": {"igp", "state"}` and
>    `"device_isis_adj_state": {"igp", "state"}` — a **new signal family**,
>    because neither is `interface` (no ifName) nor `bgp` (no peer address);
>    the identity is `(device, neighbour)`.
> 2. The same two rows in the `corr-rca-shape` jq table in
>    `deployment/docker/gnmic/gnmic-correlation.yaml`, **plus** an identity
>    `select(...)` for the new family (the shaper refuses evidence it cannot
>    ground — that is the point of the existing interface/bgp selects).
> 3. `tests/test_gnmi_correlation_lane.py` re-run: it parses both tables and
>    fails on any difference, so the two must move together.
> 4. `metric_identity()` in `src/correlation/main.py` gains the `igp` branch
>    returning `(f"{device}:{nbr}", EntityType.DEVICE, "igp_state_anomaly",
>    (device, nbr))` — and the neighbour id becomes a grounding token, which
>    needs the #99 R2 review (an IS-IS system-id is device-local-ish; an OSPF
>    router-id is not).
> 5. `docs/design/correlation-data-contract.md` + the allowlist comment in
>    `metric_events.go` updated in the same change, since the comment is the
>    documentation of record for *why* the list is short.
>
> **This is a real widening and must be judged on EVIDENCE, not convenience.**
> The families qualify (a discrete control-plane state, per-neighbour, exactly
> the kind of thing RCA reasons over), but the change is a volume decision as
> well as a semantic one: adjacency state is per-neighbour-per-level and a
> large fabric has a lot of neighbours. **Not done here; recorded as tracker
> row 222.**

### 3.2 The V1 goldens — byte-identical

`FIXTURE_GOLDEN` (`test_bounded_object_paging.py:78`) pins
`Snapshot.content_hash()`, which includes `catalog_version` — so **any** edit
to `catalog.BUILTIN_TEMPLATES` moves it (that is why it was re-frozen for T2b
and again for A9b). `DEFAULT_SCENARIO_DIGEST` /
`DEFAULT_SCENARIO_EXPECTATION_DIGEST` (`tests/test_storm_scenario_profile.py:1225`,
`:1258`) pin the V1 workload plan and what the harness expects the **parser** to
make of it.

Both are unchanged by this work, and that is a consequence of two deliberate
choices, not an accident:

* **every check is shadow** → no signal is emitted → nothing enters a window,
  opens an object, or changes a snapshot;
* **the four signatures are authored but NOT installed** in
  `BUILTIN_TEMPLATES` → `catalog_version` does not move → `FIXTURE_GOLDEN` does
  not move.

It also adds **no parser rule and no syslog grammar** (`PARSER_REV` is
untouched at `2026-09-02-a9b`), so unlike the tracker-220 case it cannot
re-classify one line of the V1 reference noise pool. The expectation digest
reads the parser's per-line classification (`scripts/scale-miniladder.py:4066`);
this plane reads signals the parser already produced.

`test_proactive_checks_a4.py` asserts all four of those properties directly,
including re-computing `FIXTURE_GOLDEN` from its owning module.

---

## 4. What Iris can and cannot see

**Cannot see, by design.** A shadow check emits nothing. Concretely:

| surface | reads | sees a shadow firing? |
|---|---|---|
| `get_rca_verdict` | `DataSource.GetProblem` → the correlation OBJECT (`src/backend/ai/troubleshoot.go:573`) | **No** — a shadow check creates no signal, so no object |
| `get_case_timeline` | `TroubleshootDeps.CaseTimeline` → the object's timeline (`troubleshoot.go:528`) | **No** — same reason |
| RCA page / ingest screen | `corr_objects` + `corr_signals` | **No** — no `corr_signals` row is written |
| skill `next=` conditions (`verdict:tier`, `verdict:phrase`) | the engine's verdict | **No** |

This mirrors the parser's shadow contract exactly. A shadow parser rule is
counted in `producers.SHADOW_HITS` (`producers.py:440`, gate at `:1205`) and
**does not write a `corr_signals` row at all** — there is no "shadow flag" on a
signal, because a shadow rule never produces one. Tracker 220's "contributes
nothing to the ingest screen" is that same fact stated for the syslog lane.
**This contract is unchanged by A4** — the new plane copies it rather than
inventing a second, weaker one.

**Can see.** Operators (not Iris) read the shadow rate on `/metrics` and
`/healthz`:

```
corr_proactive_shadow_hits_total{check_id="proactive.bgp.not_established"}
corr_proactive_hits_total{check_id="…"}          # promoted checks only
corr_proactive_open_watches                       # the "still wrong" set
corr_proactive_watches / corr_proactive_watch_evictions_total
```

and `/healthz` `.proactive` carries the check table (what each check IS, and
whether it is still shadow) beside those counters, so a shadow rate is readable
against the check that produced it without a second lookup.

**After promotion**, a fired check becomes an ordinary `corr_signals` row with
`kind = bgp_session_not_established` (etc.), `modality_class` per the check, and
`attrs.operator_phrase` carrying the wording. It then reaches Iris through the
existing path — it joins a window, may open or attach to an object, and the
object's verdict is what `get_rca_verdict` returns. **No new Iris surface is
needed**, which is the point of emitting a normal signal rather than a special
one.

---

## 5. Promotion

Per check, one at a time (`proactive.PROMOTION` records the per-check
condition; the recipe is in the `proactive.py` docstring):

1. Read `corr_proactive_shadow_hits_total{check_id}` on real traffic — a firing
   rate that tracks real incidents, not the background.
2. Register the kind: `producers.EMITTED_KINDS`, `confirmability.KIND_MODALITY`,
   `layers.CAUSAL_LAYER`.
3. Install that check's signature from `PROACTIVE_TEMPLATES` into
   `catalog.BUILTIN_TEMPLATES`.
4. Re-freeze `FIXTURE_GOLDEN` with the A9b-style proof: the V1 object is
   byte-identical modulo the `catalog_version` stamp.
5. Flip `shadow=False` on that one check and rerun the qualification.

Steps 2 and 3 must land **together**: the kind without the signature is an
orphan producer, the signature without the kind is a dead template.
`test_promotion_closes_the_coverage_gap` pins exactly that.

Ordering note recorded in `PROMOTION`: the **metric-driven** BGP check is the
first candidate (numeric contract, no noise-pool overlap). The signal-driven
checks depend on receiving the *recovery* line — promote them only after they
have been compared against a metric-driven equivalent on the same estate, or a
lost recovery line becomes a fabricated outage.

---

## 6. Tests

`src/correlation/test_proactive_checks_a4.py` — 38 cases:

* **the discriminator** — persistent fires once; healthy never fires; three
  flaps then a persistent run fires only for the run, and dates the onset from
  the run that *held*; recovery after a fire emits a clear and re-arms;
* **the signal lane** — needs the sweep, is idempotent across sweeps, an
  unreadable `state: unknown` is dropped rather than guessed, and one peer
  recovering does not clear another peer's watch on the same device;
* **CPU/memory** — a spike does not fire, a sustained run does, just below the
  floor never fires however long it is held;
* **the shadow contract** — every check ships shadow, a shadow firing is
  counted and yields nothing, the gate is in one place, and the shadow kinds
  are absent from `EMITTED_KINDS`;
* **the goldens** — `FIXTURE_GOLDEN` recomputed from its owning module,
  built-in catalog untouched, no parser rule added;
* **promotion** — a promoted check builds a well-formed, idempotent Signal that
  grounds on the device, dead-letters a tenant-wide token, the authored
  signatures load into a real `Catalog`, and promotion classifies every new
  kind `fully_connected`;
* **the anti-skew gate** — a device with a backwards clock cannot fabricate a
  dwell (it must persist for the dwell on the *sweep's* clock, while the
  reported onset stays the device's claim), and a recovered run re-arms the
  gate so the previous run's sighting cannot count towards the next one;
* **bounded / tenant-scoped / order-safe** — LRU cap with counted evictions,
  stale expiry measured in sweeps (never pre-empting an earned fire), no dwell
  rewind on an out-of-order sample, and two tenants owning a same-named device
  never share a timer (§3a).
