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
