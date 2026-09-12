# Fewer words, Iris explains — UI copy programme (2026-09-06)

Owner direction, verbatim: "make sure remove the jargon and lots of words
across the site. Remove so much of explanation, instead train the Iris AI to
answer those questions. Less words UI experience looks clean. observe any
other vendors." Same day: NOC-admin plain language, fonts ≥ 14 px, panels in
one grid (BGP Operations, Investigation, TAC panel reworks).

## Principle

A screen states facts and offers actions. It does not teach. Anything that
teaches (why a metric matters, what a protocol term means, how a lane works,
what a badge implies) leaves the screen and becomes something Iris can answer
when asked, from the exact same text. The screen keeps one short line at most
where a fact would otherwise be ambiguous.

## Word budgets (guarded by test)

| Surface | Budget |
|---|---|
| Page / section heading | ≤ 4 words, a question or a noun phrase, no protocol acronym as the first word |
| Card heading | ≤ 3 words |
| KPI caption | ≤ 3 words |
| Status chip | 1–2 words, sentence case |
| Explanatory note (`mini-meta`, `*-note`) | ≤ 12 words, at most ONE per card, none under a table row |
| Empty state | ≤ 8 words + one action |
| Error / refusal | one sentence, names the thing that failed |
| Tooltip (`title=`) | ≤ 20 words; where the protocol term lives |

Vendor observation (what "clean" looks like in consoles NOC teams already use):
Datadog and Kentik put the number and a two-word caption on the card and every
definition behind an `(i)`; ThousandEyes shows the path and one status word per
hop; Meraki writes statuses as plain outcomes ("Online", "Alerting", "Down")
and never explains the protocol on the page. None of them repeats a caveat per
row. We match that: caveats once, definitions on demand.

## The `AskIris` affordance

One small component replaces inline explanations:

```tsx
<AskIris topic="rpki.origin-validation" />   // renders a 16 px (i); click → Iris lane opens with the canned question
```

- `topic` keys a canned question and the answer text in
  `src/backend/ai/skills/explain/<topic>.md` (knowledge-as-data, the Iris
  troubleshooting model). The removed on-screen prose is moved there verbatim,
  then tightened. Iris answers from that file first and cites it; when the
  file is missing Iris says so instead of improvising.
- The component needs no backend call until clicked. Offline installs get
  the same answer (skill files ship in the image).
- One route already exists (`/api/ai/ask`); the explain skill is selected by
  the `topic` prefix. No new HTTP routes.

## Guard

`src/frontend/src/wordBudget.test.ts` (sibling of `copyVoice.test.ts`): parses
shipped `.tsx` for `mini-meta`/`*-note` string literals and headings and fails
on budget breaches, with a dated allowlist that must shrink (same shape as the
ui:check drift list). Runs in `frontend-ci`.

## Sweep order (one agent per row, after 268/269 land — shared files)

1. Dashboard, Operations (Digital Experience, Devices), Alerts
2. Security (Findings, Exposures, Vulnerabilities, Threat Detection, Lane health, Data Protection)
3. Administration tabs, Licence, Registries, Cloud ingest
4. Topology, WAN circuits, Wireless
5. Iris Knowledge, Reports, Reliability scorecard

Each sweep: apply the budgets, move explanations into `skills/explain/`, add
`AskIris` where a definition was removed, update tests, keep `copyVoice` and
`ui:check` clean. Done = the page renders under budget with no allowlist entry.

## Vendor observation — what sweep 1 actually matched (2026-09-06)

Written from working knowledge of these consoles, not from a fetch.

- **Datadog** — a tile is a number, a two-to-three-word name and nothing else;
  the definition sits behind a hover `(i)`. Matched: KPI captions deleted, one
  `AskIris topic=` per tile that had one.
- **Kentik** — status words are outcomes ("Healthy", "Degraded"), never a
  metric restated in a sentence, and a caveat is stated once per view rather
  than per row. Matched: the repeated Command Center summary sentence removed;
  the DEM honesty caveats cut to one short line each.
- **ThousandEyes** — a path shows one status word per hop and puts the protocol
  vocabulary in the tooltip. Matched: chips are `Watch` / `Critical 0` /
  `Blocked 83`, with the NOC term ("NOC pressure", "RCA blocked on missing
  evidence") moved into `title=`.
- **Meraki** — sentence case everywhere, never SHOUTED state, and column
  headers of one or two words. Matched: `.cc-badge` uppercase dropped on swept
  boards, headers cut ("Incident / correlation group" → "Incident").
- **All four** — none explains a protocol on the page. That is the rule the
  `skills/explain/` corpus now carries instead.

## Vendor observation — what sweep 2 matched (2026-09-06)

Sweep 2 = Security (Overview/Findings, Exposures, Exposure Stories,
Vulnerabilities, Threat Detection, Detection Rules, Saved Views, Lane health,
Seam groups, Compliance + frameworks) and Data Protection. Same four consoles,
same reading.

- **Datadog** — a security tile is a count and a two-word name, with the
  definition behind an `(i)`. Matched: the CTEM band lost its coverage
  paragraph ("N assets were never assessed. Absence of a finding means
  unknown"), the evidence lanes lost their per-lane sentences, and each gained
  one `AskIris topic=`.
- **Kentik** — a caveat is stated once per view, never per row. Matched: the
  five "this is not a clear estate" restatements across Lane health, Exposures,
  Threat Detection and Rules are now one authored file each, cited from the
  `(i)` beside the number they qualify.
- **ThousandEyes** — protocol/lane vocabulary lives in the tooltip, not the
  page. Matched: evidence class, seam group, fidelity, cursor pagination and
  "grounded" all left the screen; `title=` and the `(i)` carry them.
- **Meraki** — plain outcomes, sentence case, one- or two-word column headers.
  Matched: the lane counters read "Over the cap", "Dead-lettered", "No durable
  copy"; badges and chips are sentence case under `.sec` and `.dp-pill`
  (scoped, so an unswept page's raw enum is untouched); nothing on a swept
  Security or Data Protection surface renders below 12.5 px.
- **All four** — none explains a protocol, a framework or a backup verdict on
  the page. 54 more authored files carry it instead.

## Vendor observation — what sweep 3 matched (2026-09-06)

Sweep 3 = Administration (Users, Roles, Tenants, Organizations, Regions,
Security Settings, Assign access, Sessions, API Access with the scope picker,
Authentication + the SSO identity-provider panel, Token policy, Log export
limits, Integrations, Notifications and contact points, RCA Auto-Ticketing,
Ticket Delivery), Licence and its 402 card, Registries, Cloud ingest, and the
Platform tools (Pipeline Debugger, Quarantine). Same four consoles.

- **Datadog** — an admin screen is a table and a form; what a setting *means*
  sits behind an `(i)`, never above the field. Matched: every `AdminHead`
  paragraph is now one short line plus a topic — "People who can sign in.",
  "Isolation units inside an organization.", "How people sign in." — and the
  RFC citations (4511, 8907, 9700, NIST 800-63B) left the screen entirely.
- **Kentik** — a caveat is stated once per view. Matched: "inbound webhooks are
  recorded but not yet driving incident state" appeared three times on the
  Integrations/Notifications surfaces and is now one file cited from one line;
  the four ITSM/PagerDuty/Slack/Jira "one ticket per root cause, never per raw
  alert" restatements are four authored files behind four `(i)`.
- **ThousandEyes** — protocol vocabulary lives in the tooltip. Matched: PBKDF2,
  Authorization Code flow, HMAC, `acr`/`amr`, Events API v2, `client_credentials`
  and STORE_BACKEND all left the page; `title=` and the `(i)` carry them.
- **Meraki** — plain outcomes, sentence case, small print that is still
  readable. Matched: `.adm` scopes badges, connector chips and permission pills
  to sentence case at 12.5 px (they were 11–12 px uppercase), the modal section
  divider stopped SHOUTING, and nothing on a swept Administration, Licence,
  Registries, Cloud-ingest or Platform surface renders below 12.5 px.
- **All four** — a destructive confirmation still reads in full. Deleting a
  tenant, force-deleting one with users, suspending it, hiding it from the
  global view, revoking a session, break-glass and "this credential administers
  the whole platform" keep every word: a consequence you must read before
  confirming is part of the action, not an explanation. Licence conditions,
  the platform's verbatim refusal text and the signing-key notices are
  untouched for the same reason.

`.adm-line` (Administration) and `.lic-line` (Licence) are new names for ink
that already existed — a STATED FACT is not an explanatory note, and the word
budget counts notes. 84 authored files carry what left.

## Vendor observation — what sweep 4 matched (2026-09-06)

Sweep 4 = the topology canvas and everything docked to it (toolbar, device
inventory rail, legend, overlay picker, side drawer, capacity and confidence
panels, the path-trace stage and its hop ladder, the cloud slice), WAN circuits
with its derived registry and measurement policy, Wireless and the wireless
remediation queue, the device drill-down and its neighbour tab, Routing
protocols, Flow Trace and New monitor. Same four consoles.

- **Datadog** — a control is a control; what it *does to the data* sits behind
  an `(i)`. Matched: the canvas toolbar's tooltips were paragraphs ("Regroup the
  canvas by a node dimension — Zone segregates by ownership border (LAN · WAN ·
  DC · Cloud · ISP · DX/ExpressRoute)"); every one is now under twelve words with
  a topic beside the control, and the ten overlay descriptions became ten
  authored files reached from one `(i)` in the legend.
- **Kentik** — a caveat is stated once per view, never per row. Matched: WAN's
  five-tier ranking, the derived-target rules and the "linked interface"
  explanation appeared on the metrics card, in the empty state, in three
  provenance tooltips and again per policy field; they are one line plus an
  `(i)` now, and `targetKindMeaning` per row is a short claim rather than the
  ownership lecture.
- **ThousandEyes** — a path shows one status word per hop and puts the protocol
  vocabulary in the tooltip. Matched: the provenance chip reads **Measured** or
  **Computed · not a live trace**; STAMP, PDV, OWD, ifSpeed, ifMtu, oper-status,
  Paris-consistency, RFC 8762/7679/2680/3393/792 and the BGP/OSPF/IS-IS state
  code tables all left the screen. The honesty states did NOT soften: a computed
  path still says "not a live trace", a hop with no probe still says so, and a
  failed read still says the shape of the network is unknown.
- **Meraki** — sentence case, plain outcomes, small print that is still
  readable. Matched: nothing on a swept topology, WAN, wireless, device-detail
  or routing surface renders below 12.5 px (the legend was 8–11 px, the hop
  ladder 9.5–11 px, the drawer 10–11 px), the SHOUTED section labels
  ("LEGEND", "RCA VERDICT", "ACTIVE MEASUREMENT", "UTILIZATION") are sentence
  case, and tab labels are one word ("Neighbours", "Config", "Capture").
- **All four** — none explains a protocol on the page. 66 more authored files
  carry it instead.

`.proto-key` (routing/path state facts), `.wan-line` / `.wan-count` /
`.wan-mono` / `.stat-foot` (WAN) and `.rem-line` / `.rem-danger` (wireless
remediation) are new names for ink that already existed — a STATED FACT is not
an explanatory note, and the word budget counts notes. The wireless-execute
consequence keeps every word for the sweep-3 reason: a consequence you must
read before typing a confirmation is part of the action.

## Vendor observation — what sweep 5 matched (2026-09-06)

Sweep 5 = everything the debt list still held: the BGP surfaces (watchlist,
prefixes, peers, RPKI, ASPA, bogons, geofeed, live feed, AS-path map, alert
policy), the RCA workspace and its causality path, the account and tenant gates,
Reports, the reliability scorecard, the legacy collection-pipeline board, the
TAC escalation panel and the investigation lanes, the `tabs/` surfaces (flows,
log search, correlations, collectors, SNMP credentials, source of truth,
transport security, tunnels, access explorer and the Iris drawer), device
inventory and geomap, device monitoring, NMS integrations, telemetry coverage,
the app-observability pages and the two shared panel libraries. Same four
consoles, same reading.

- **Datadog** — a screen is a number and a control; what the number MEANS sits
  behind an `(i)`. Matched: the reliability scorecard gave up nine metric
  definitions (MTTI, MTTI p90, MTTC, recovery, closure, MTBF, repeat rate, the
  time-loss driver) and the readiness-score recipe, and reads −47 % of its prose;
  the BGP watchlist's three `Details` disclosures (how the to-do list is built,
  the RDAP provenance paragraph, "what this screen does not show") are three
  authored files.
- **Kentik** — a caveat is stated once per view, never per row. Matched: Flows'
  applications panel carried five small-print paragraphs and its services panel
  three; both are now one note plus one `(i)` per honest blank ("Unknown",
  "Source not resolved", "Not measured"), and the drill caveat moved from a
  repeated paragraph into the per-row tooltip.
- **ThousandEyes** — protocol vocabulary lives in the tooltip, not the page.
  Matched: ROA, RPKI, Routinator, ASPA's IETF-draft status, BMP versus
  collector provenance, RFC 9092 geofeeds, STAMP/RFC 8762, IF-MIB, TUNNEL-MIB,
  WGS 84, SNMPv3 USM, "masked templates" and "admitted lines" all left the
  screen. The honesty states did NOT soften: "Near-live, not live", "an absent
  feed, not a healthy fleet", "A dash is not a zero", "never counted as
  authorised", "not the cause", "the full typed path is not available", "No case
  connector here" and "Not measured" keep their claim word for word in
  substance.
- **Meraki** — sentence case, plain outcomes, small print that is still
  readable. Matched: the Iris drawer, the scorecard, the connector wizard,
  service map, NMS, the tenant gate, discovery, IGP, the report wizard and the
  demo boards stopped SHOUTING (26 rules) and nothing on a swept surface renders
  below 12.5 px (85 rules were 9–12 px); card headings are one or two words
  ("Traffic volume", "Top conversations", "Built bundles", "Set up inventory").
- **All four** — none explains a protocol, a metric or a verdict on the page.
  62 more authored files carry it instead, and the debt list is down to a single
  file.

`.fact-line` (with `.fact-warn` / `.fact-bad` / `.fact-strong`) is the sweep-5
name for ink that already existed, the same move `.adm-line`, `.lic-line`,
`.wan-line` and `.proto-key` made in sweeps 3 and 4: a STATED FACT — a count, a
state, a unit, a timestamp, a provenance stamp — is not an explanatory note, and
the word budget counts notes. Nothing that teaches may be written into one.

Untouched on purpose, for the sweep-3 reason: the RIPE NCC RIS attribution (a
licence condition of the data, not a caveat), the two-factor recovery
consequence, "stored encrypted, never shown again", the platform-operator and
break-glass warnings, the tenant-isolation facts on telemetry coverage and
transport security, and every "not measured" the scorecard prints instead of a
fabricated MTTR.

## Sweep 6 — what is left

`pages/iris/Knowledge.tsx` (9 breaches) is the only file still on
`wordBudget.allow.json`. It was being rewritten in a concurrent change while
sweep 5 ran, so sweeping it here would have clobbered that work. Everything
else on the debt list is gone.

## Sweep 6 — what is left: nothing

`pages/iris/Knowledge.tsx` was swept on 2026-09-06, after the TAC learning work
that had been rewriting it landed. The coverage catalogue, the unplanned
platforms, the command templates, the learning backlog and the whole candidate
review/export surface keep every count, every control and every honest absence;
what left was the teaching around them. The header no longer opens by defining a
vendor dialect, an issue class and a command intent — it states the version pins
and the counts and offers `tac.coverage-catalogue`. "Platforms with no authored
plan" is "Platforms with no plan" with `tac.unplanned-platforms` behind the
`(i)`; the paragraph contrasting read-only Correlix defaults with a tenant's own
saved sets is `tac.command-templates`. The intent table's per-row cells ("this
dialect binds no command for it", "not bound") are `.fact-line` — they were
never notes — and its header stopped SHOUTING; `.tac-learn-meta` and the device
output excerpt went 11.5 px → 12.5 px. Operator-readable prose: 282 → 196 words
(-30%). `wordBudget.allow.json` is `{}`.

## Done (2026-09-06)

The programme is finished. Six sweeps took **118 files** across the whole
console — Command Center and the dashboards, Operations, Alerts, Security and
Data Protection, Administration, Licence, Registries, Cloud ingest, the
Platform tools, the topology canvas, WAN, Wireless, device detail, BGP, the RCA
workspace, Reports, the reliability scorecard, troubleshooting, TAC, the tabs,
telemetry coverage, the app-observability pages and Iris Knowledge — from
**34,812 to 29,601 words** of operator-readable prose (**-15 %**): 4177 → 3444
(sweep 1), 5369 → 4124 (2), 8196 → 6808 (3), 2119 → 1621 (4), 14,669 → 13,408
(5) and 282 → 196 (6). The debt list went from **92 files / 401 breaches to
zero**, and `wordBudget.allow.json` is `{}` — guarded from outside the frontend
by `tests/test_ui_words_programme.py`, so the debt cannot be re-admitted, and
from inside by the "stays swept" pins in `wordBudget.test.ts`. What left the
screens did not evaporate: the explain corpus under
`src/backend/ai/skills/explain/` now holds **337 authored files**, each ≤ 120
words, loader-validated at start-up and cited by name when Iris answers from
one. No honesty state, licence condition, refusal text or destructive-action
consequence was shortened anywhere in the six sweeps — those are the action, not
an explanation — and no test assertion was deleted: each one that read a removed
sentence now reads the short line plus its `Ask Iris about …` affordance.
