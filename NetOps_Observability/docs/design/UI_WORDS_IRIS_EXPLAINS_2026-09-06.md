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
