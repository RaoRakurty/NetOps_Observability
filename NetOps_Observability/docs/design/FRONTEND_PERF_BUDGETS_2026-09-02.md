# Frontend render budgets — perf wave 2

**Date:** 2026-09-02 · **Tracker item:** frontend wave #1 (“Frontend loading latency —
FAANG standards, slick transitions even at high EPS”).

Perf wave 1 (`6f4986d2`) fixed **route** latency: lazy chunks, `startTransition` on hash
routing, idle prefetch, skeletons. It explicitly did *not* profile **page-data** render
under sustained high EPS, and captured no measured budget. That is what this wave does.

The rule this establishes: **every heavy operator surface has a measured, enforced render
budget, and a build that exceeds it fails.**

---

## 1. The harness

`npm run perf:budget` → `vitest run --config vitest.perf.config.ts` → `perf/render.perf.tsx`.

| File | Role |
|---|---|
| `src/frontend/perf/harness.tsx` | Timing rig: warmup, median-of-N, DOM counting, budget compare, table printer |
| `src/frontend/perf/synth.ts` | Deterministic synthetic payload generators (a small LCG — no `Math.random`, so a run is repeatable) |
| `src/frontend/perf/render.perf.tsx` | The scenarios + api stubs |
| `src/frontend/perf/budgets.json` | The budgets, as reviewable data |
| `src/frontend/perf/setup.ts` | act() environment + a realistic viewport (see §1.2) |
| `src/frontend/vitest.perf.config.ts` | Serial, single-threaded run (parallel workers make timings meaningless) |

The behaviour the budgets protect also has ordinary unit tests, so a regression fails the
normal suite too and not only the budget run: `src/components/WindowedList.test.tsx` (9
tests — window size, flat DOM at 100× the data, honest scroll height, scroll paging, the
shrink-reset, empty and short lists) and
`src/features/topology/components/TopologyInventoryPanel.test.tsx` (8 tests — fleet-wide
counts, groups/sites excluded, a screenful of 1 000 devices, flat DOM at 2 000, row picking,
filtering on hostname/IP/vendor/site, and the total staying the fleet while a filter narrows
the list).

### 1.1 What each number means

- **`mount ms`** — median wall time to mount **and settle** the page with the payload:
  React render + effects + the commit from the data the effects await. This is the
  “operator clicked the tab in the middle of a storm” number.
- **`poll ms`** — median wall time for a **re-render** of the settled page. These pages
  refresh every 15–30 s; anything the render body recomputes without a memo is paid again
  on every tick, on top of whatever the operator is doing.
- **`DOM nodes`** — element count after settling. **Deterministic** — identical on every
  run and every machine (verified: three consecutive runs produced byte-identical counts).
  This is the number that actually guards “this list renders every row”: a windowed list
  keeps it flat as the payload grows, an unwindowed one grows with the payload.

Method: `WARMUP` (2) untimed runs prime the JIT and module graph, then `RUNS` (5) timed
runs, **median** reported — median, not mean, so a single GC pause cannot fail a build.
Payloads are built once, outside every timed region.

### 1.2 Honest limits of the measurement

This is **happy-dom, not Chrome.** The milliseconds are **not** a browser frame budget and
must never be quoted as one. They are a repeatable *relative* measure on one machine, and
they catch the class of regression these budgets exist to stop: an O(rows) render blow-up.
Observed run-to-run variance is ±15 %, which is why the ms budgets carry ~2× headroom.

happy-dom does no layout, so every element reports `clientHeight === 0`. A windowed list
measuring a 0 px viewport renders only its overscan — which would make a virtualized
surface look far cheaper than it is *and would let a de-virtualization regression hide*.
`perf/setup.ts` therefore reports a 600 px viewport, so the window sizes to roughly what a
real screen shows and the node budgets mean what they say.

Every scenario carries a **payload sanity guard** (`Scenario.verify`): it asserts the table's
`aria-rowcount` equals the payload size before the result counts. Without it a broken api
stub would render an empty page and the surface would “pass” its budget on nothing at all —
the one way a perf gate can lie.

---

## 2. Before → after

Same machine, same harness, six surfaces, medians.

| Surface | Payload | mount ms | | poll ms | | DOM nodes | |
|---|---|---:|---|---:|---|---:|---|
| | | **before** | **after** | **before** | **after** | **before** | **after** |
| Topology device list | 1 000 nodes | **2 980.6** | **92.8** | **253.5** | **12.9** | **15 174** | **442** |
| RCA / correlation list | 2 000 correlations | 403.6 | 285.1 | — | 32.1 | 959 | 959 |
| Device inventory | 2 000 devices | 428.0 | 272.9 | — | 32.7 | 1 078 | 1 078 |
| Log search | 20 000 hits | 357.8 | 254.4 | — | 66.5 | 778 | 778 |
| Events feed | 5 000 events | 300.6 | 222.2 | — | 49.9 | 713 | 713 |
| BGP operations | 50 prefixes · 500 updates · 30 peers · 20 sightings | **770.3** | **673.8** | **153.4** | **45.3** | **4 727** | **1 571** |

Both columns are single runs of the same harness on the same machine; the ms
carry the ±15 % run-to-run variance described in §1.2, so read them as a ratio,
not a stopwatch. The **DOM-node columns are exact** — three consecutive runs
produced byte-identical counts — and they are where the structural change shows.

Headline: **the topology device list was the only genuinely unwindowed surface, and it was
an order of magnitude worse than everything else.** 2.98 s to mount and 15 174 DOM elements
for a 1 000-device fleet — and it re-paid 253 ms on every topology refresh. It is now
**~32× cheaper to mount, ~20× cheaper per refresh, and holds 34× fewer DOM nodes.**

The four table surfaces were already windowed (`components/DataTable` has rendered only the
rows in view since #45 phase 2) — which is why their node counts are flat and did not need
to change. Their gains came from removing redundant passes and serialized commits.

*(“before” poll ms is blank for the four table surfaces: the re-render measurement was added
to the harness after the first baseline, so their only honest before/after pair is the mount
column. The topology panel's poll number is a true before/after.)*

**BGP operations (added 2026-09-03)** is the one row where "before" and "after" are not the
same screen, and the comparison is only fair once that is stated. *Before* is the tabbed
page **on its default tab with no investigation open** — i.e. the watchlist and the alert
history and nothing else, roughly a third of the evidence. *After* is the single-screen
outage view with **every** section rendered: verdict, AS-path graph, collector paths, update
churn, near-live feed, RPKI, incidents, peers, transit, bogons, ownership, geofeed and ASPA,
for an auto-selected prefix. It shows strictly more and costs **3.0× fewer DOM nodes and
3.4× less per refresh**, because the old page rendered all 50 watchlist rows with full
evidence, all 50 alert rows and the whole feed buffer, while every long list on the new one
is capped to its first N rows behind an explicit "show all" (`pages/bgp/Section.tsx`). The
same payload was fed to both, from the same generators, in one harness file.

---

## 3. The budgets

`perf/budgets.json`, enforced by the run:

| Surface | mount ms | poll ms | DOM nodes |
|---|---:|---:|---:|
| `events-feed` | 500 | 120 | 900 |
| `rca-list` | 700 | 90 | 1 200 |
| `log-search` | 500 | 120 | 1 000 |
| `device-inventory` | 600 | 110 | 1 350 |
| `topology-device-list` | 250 | 40 | 600 |
| `bgp-ops` | 900 | 150 | 2 000 |

Rationale: **node budgets sit ~25 % above the measured value** — tight, because the number is
exact and because the failure they guard against (de-virtualizing a list) multiplies it by
10× or more. **ms budgets sit at ~2× the measured median** — loose, because they are
machine-relative and a slower CI runner must not fail a clean build, while a real O(rows)
regression (5–40×) still does.

---

## 4. What was fixed, and why

### 4.1 Topology device list — windowed (the whole gain)

`features/topology/components/TopologyInventoryPanel.tsx` rendered **one button + one inline
role SVG per device, for the entire fleet**, unconditionally. Three separate problems:

1. **Every row was in the DOM.** ~15 elements per row × 1 000 devices.
2. **`deviceRows(view)` ran three times per render** — for the list, the total, and the
   critical count — each one a filter *and* a `localeCompare` sort of the whole fleet.
3. **The filter box was synchronous**, so each keystroke re-filtered and re-rendered all
   1 000 rows before the character appeared.

Fixes: one memoized pass over the fleet with the counts derived from it; `useDeferredValue`
on the filter so the input never waits on the list; and the list rendered through a new
windowed primitive.

### 4.2 `components/WindowedList.tsx` — new, no new dependency

`DataTable` already windowed big *tables*. Plain lists beside the canvas had no equivalent.
Rather than add a virtualization library, this is the same 60-line technique the table
already uses, matching how the rest of shell-v2 is built and honouring the §6 dependency
rule (no library is foundational for windowing a fixed-height list):

- one full-height spacer, so the scrollbar is honest about the size of the list;
- only the slice intersecting the viewport (plus overscan) rendered, absolutely positioned
  at `index * rowHeight`;
- viewport measured with a `ResizeObserver`, so a resized or collapsed panel windows
  correctly instead of over- or under-rendering;
- a guard that resets the scroll offset when a filter shrinks the list past the current
  scroll position (otherwise the window lands past the end and renders blank).

Rows must be a fixed height. `.topo-inventory-row` was converted from flex-stacked with a
`gap` to a fixed 30 px box on a 32 px pitch; `ROW_H` in the panel and the CSS must stay in
step (noted in both files).

**This also removes the need for a “show more” cap on this surface** — windowing is strictly
better than truncation: the operator still sees the whole fleet and the scrollbar still tells
the truth, but the DOM stays flat.

### 4.3 RCA list — parallel reads, one commit

`tabs/Correlations.tsx` awaited its three reads **one after another**: list → summary →
ticket links. Nothing depended on anything else, so this cost three serial round trips *and*
three separate React commits per refresh, each one re-rendering the whole loaded list. Now a
single `Promise.allSettled` with one batched commit. Failure semantics are preserved exactly:
a failed list keeps the last good page and reports the failed refresh (rather than clearing
to `[]` beside a Live chip, which would claim the engine found nothing); summary and ticket
links stay best-effort.

The three verdict-tier fallback counts (`visible.filter(...)` × 3, run on *every* render
before the server rollup arrives) are now a single memoized pass.

### 4.4 Deferred filters

`useDeferredValue` on the search text in **Events**, **Devices** and the **topology
inventory**. The input keeps the typed value; the list filters against the deferred one. This
is preferred over a `setTimeout` debounce: no timers to leak, nothing for tests to have to
wait on, and React drops intermediate work automatically when the operator keeps typing.

`DataTable`'s filter runs every column's `text` accessor over every row, so on a 2 000-device
fleet an undeferred keystroke was ~20 000 accessor calls before the character rendered.

### 4.5 Poll swaps as transitions

The refresh commits in **Events** (30 s), **Devices** (30 s) and the **log search** result set
are wrapped in `startTransition`. This does not make the commit cheaper — it makes it
**interruptible**, so a background refresh yields to what the operator is doing instead of
blocking a keystroke or a scroll. Measured `poll ms` is 11–44 ms across the five surfaces.

---

## 5. What was checked and deliberately NOT changed

A full scan of JSX-position `.map()` over collection-shaped variables (325 sites) was
triaged for unbounded lists. Beyond the topology inventory, the candidates are all
**bounded at the source**, so windowing them would add machinery for no gain:

| Surface | Why it is already bounded |
|---|---|
| IGP adjacencies (`pages/igp/IgpAdjacencies.tsx`) | Server-capped; the page states the cap (“truncated at N events”) |
| Config drift (`pages/config/ConfigDrift.tsx`) | Cursor pagination |
| Config diff (`pages/config/DeviceConfigPanel.tsx`) | Server-truncated, and the panel says so |
| Alert / finding / incident panels (`pages/panels.tsx`) | Bounded by active-alert count |
| RCA evidence + event timeline (`components/rca/`) | Bounded by the correlation's own signal count |

The four table surfaces already window through `DataTable`; their node counts confirm it
(flat at 713–1 078 for payloads from 2 000 to 20 000 rows).

`Logs`' `lines` memo maps all 20 000 hits eagerly. That is inherent — the table needs the
whole array to sort and filter it — and at 216 ms for 20 000 rows it is within budget. It is
the honest reason `log-search` mount is not lower.

---

## 6. CI

`.github/workflows/frontend-ci.yml` runs `npm run build`, `npm audit`, Playwright e2e and the
panel↔metric contract audit. It does **not** currently run `npm run test` (vitest), and this
change does not add jobs to it — wiring a *new kind* of gate into CI is a separate decision
from measuring, and the workflow header explicitly says the gate “tracks the tooling that's
actually present.”

`perf:budget` is written to be CI-ready when that decision is made: it is a normal
`vitest run`, it exits non-zero on a breach, it needs no browser and no stack, and it prints
the full table on both pass and fail. The job would be:

```yaml
  perf-budget:
    name: render budgets (blocking)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@…
      - uses: actions/setup-node@…
        with: { node-version: '18', cache: npm, cache-dependency-path: NetOps_Observability/src/frontend/package-lock.json }
      - run: npm ci
      - run: npm run perf:budget
```

Note before enabling it: the **DOM-node budgets are safe to enforce anywhere** (exact,
machine-independent). The **ms budgets are machine-relative**; a shared CI runner is slower
and noisier than a dev box, so either confirm the ms headroom on a real runner first or gate
the job on node counts alone.

---

## 7. Re-running

```bash
cd NetOps_Observability/src/frontend
npm run perf:budget                       # 5 runs after 2 warmups (~10s)
PERF_RUNS=15 PERF_WARMUP=5 npm run perf:budget   # tighter medians when re-baselining
```

Re-baseline whenever a budget is deliberately changed, and record the new numbers here.
