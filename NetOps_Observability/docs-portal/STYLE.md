# Correlix documentation style guide

This file governs every page under `docs-portal/docs`. It sets the voice, the
page shapes, the information architecture and the terminology. The mechanical
half is enforced by `docs-portal/tests/voice.test.js`; run `npm test` before you
open a change.

The bar is the administration guide of a network security vendor — Fortinet's
FortiOS guides, Palo Alto Networks' PAN-OS documentation, CrowdStrike's Falcon
documentation. Those sets share a small number of habits, and this guide adopts
them.

---

## 1. Voice

**Write to one administrator, in the second person, in the present tense.**

> Correlix polls the device every 60 seconds. To change the interval, edit the
> collector profile.

Not:

> Correlix will poll your devices, allowing you to seamlessly leverage a
> comprehensive view of your network's health.

The rules:

| Rule | Why |
|---|---|
| Second person. "You add a device." Never "we", "our", "let's". | The reader is doing the work; the documentation is not a person in the room. |
| Imperative for steps. "Select **Add device**." | A step is an instruction, not a description of one. |
| Present tense for behaviour. "The status turns green within one poll cycle." | Future tense ("will turn") reads as a promise instead of a fact. |
| One idea per sentence, under 45 words, most under 25. | Long sentences hide the condition the reader needs. |
| Name the thing. "the SNMP collector", not "the system". | An unnamed actor cannot be checked or fixed. |
| State a fact rather than framing it. Write "The list is empty until the first scan runs", not "It is worth noting that the list may be empty." | Framing adds words and removes certainty. |
| No contractions in reference and procedure text. | Contractions read as chat, not as a manual. |

**Banned words and phrases.** These mark machine-written marketing prose and
none of them appear in a Fortinet, Palo Alto or CrowdStrike guide. The test
fails on all of them:

`robust` · `seamless` · `comprehensive` · `powerful` · `intuitive` ·
`cutting-edge` · `state-of-the-art` · `best-in-class` · `world-class` ·
`unparalleled` · `game-changing` · `revolutionary` · `effortless` · `turnkey` ·
`leverage` · `delve` · `empower` · `streamline` · `supercharge` · `elevate` ·
`harness` · `foster` · `unlocks the full potential` · `it's worth noting` ·
`it's important to note` · `in today's` · `fast-paced` · `ever-evolving` ·
`at the end of the day` · `in conclusion` · `moreover` · `furthermore` ·
`additionally,` · `when it comes to` · `that being said` · `dive into` ·
`deep dive` · `in the realm of` · `a myriad of` · `a plethora of` · `tapestry` ·
`journey` · `is a testament to` · `whether you're` · `simply` · `easily` ·
`just click`

**Banned shapes.**

- **Em-dash chains.** One em dash per paragraph, and a page budget of roughly
  one per 250 words. Use a comma, a colon or a full stop. Long product prose
  that reads as a stream of asides is the single clearest tell.
- **The rule of three.** "Fast, simple, and secure." If three items are real,
  put them in a list with the fact each one carries.
- **The reversal.** "It is not just X — it is Y." Say Y.
- **The empty opener.** Do not begin a page by explaining that networks are
  complex or that observability matters. Begin with what the page lets the
  reader do.
- **Emoji.** None, anywhere in a page body.
- **Hedging.** "may", "might", "could potentially". Either the product does it
  or it does not. Where behaviour genuinely varies, name the condition:
  "If `FEATURE_BMP` is off, the route answers 404."
- **The meta-voice opener.** "This page explains how to…", "In this guide we
  will…", "This document describes…". The reader knows they are on a page.
  Open with the product or with the reader: "Correlix polls…", "You can watch a
  prefix…". CrowdStrike's LogScale docs stack a machine-written abstract on top
  of a human paragraph on many pages; it is the clearest tell in an otherwise
  excellent set, and the test fails on it.

---

## 2. Honesty is part of the voice

Correlix distinguishes *not measured* from *measured as zero*, and the
documentation must too. This is the product's defining behaviour and it belongs
in the prose, not in a footnote.

Document these states as behaviour, in these words:

- **"An empty list means not evaluated, not clean."** Where a surface can return
  nothing for two different reasons, say which reason applies and how the reader
  tells them apart.
- **Absent, not zero.** "`adjacencies` is `null` when no collector emits a live
  series for that device. It is never reported as `0`, because zero adjacencies
  is a claim about the device that nothing measured."
- **Not connected vs empty.** "*Not connected* means the source was never wired.
  *Empty* means the source is wired and was quiet. The two are different facts
  and the page never collapses them."
- **Say what a feature does not do.** A page that describes packet capture says
  it captures on one interface, bounded, one per device, and that it does not
  reconfigure the device.

Never write a reassuring blank. "All clear" is a claim; it needs evidence.

---

## 3. Page types

Every page declares its type in front matter. The type decides the shape, and
the test enforces it.

```yaml
---
title: Configure SNMP discovery
description: Scope a subnet sweep, choose the credentials it tries, and onboard what answers.
page_type: task           # task | concept | reference | index | release
sidebar_position: 3
---
```

The `description` is the page's one-sentence abstract. Its grammar is keyed to
the page type, the way Palo Alto keys a DITA `shortdesc`:

| Page type | `description` grammar | Example |
|---|---|---|
| task | Imperative verb, then the benefit | `Scope a subnet sweep, choose the credentials it tries, and onboard what answers.` |
| concept | What the thing is, in one sentence | `How Correlix groups related observations into one case and names the seam that owns it.` |
| reference | Bare noun phrase | `Every FEATURE_ and ENABLE_ switch Correlix reads, with the default the shipped compose file sets.` |
| index | What the section covers, and for whom | `Install, size, secure, verify and upgrade a Correlix deployment.` |
| release | What changed in the period | `The Security section, BGP depth and BMP, the Investigation surface, Iris skills.` |

### 3.1 Task page (`page_type: task`)

One procedure per page. The title starts with an imperative verb.

```markdown
# Configure SNMP discovery

One or two sentences: what the reader will have when they finish, and when to
use this instead of something else.

## Before you begin

- A permission, a credential, a flag, a piece of information to have ready.
- One bullet per prerequisite. Link to the page that provides it.

## Steps

1. Go to **Infrastructure → Discovery & NMS**.
2. Select **Subnet Discovery**.
3. Enter the CIDR ranges to sweep.
4. Select **Start scan**.

## Result

What the reader sees when it worked, concretely: a value, a state, a captured
response. Not "the configuration is applied".

## Related

- [The page that comes next](/…)
- [The reference table for this feature](/…)
```

Rules for task pages:

- **`## Before you begin` opens with permission and scope.** CrowdStrike boxes a
  "Security Requirements and Controls" block above every procedure, naming the
  exact permission it needs. Correlix is tenant-scoped by construction, so the
  documentation says the same thing: the first bullet names the permission
  (`infrastructure:write`, `administration:admin`, platform admin) and whether
  the surface is per-tenant data or platform-global configuration. A reader
  should never discover a `403` by trying.
- **Lead a procedure with a `To …:` line** when a page carries more than one
  procedure, the way Fortinet does: `To add an SNMPv3 credential:`. It gives the
  procedure an anchor and a name without adding a heading level.
- **Title grammar: imperative verb first.** "Configure SNMP discovery",
  "Investigate a BGP prefix", "Back up a device configuration". Never
  "Configuring…", never "How to configure…", never a bare noun.
- **Numbered steps, one action each.** A step that contains "and then" is two
  steps. Bold the UI control exactly as it is labelled: **Add device**.
- **Navigation paths use the arrow form** and the labels the product actually
  shows: **Administration → Data sources → SNMP Profiles**.
- **`## Result` may be titled `## What you see`** when the outcome is a screen
  or a response rather than a state change. Nothing else.
- **A long procedure may use `### Step 1 — …` subheadings** under `## Steps`
  when each step needs its own paragraphs and output.

### 3.2 Concept page (`page_type: concept`)

Explains a thing so the reader can make a decision. Titled as a noun phrase —
"Root-cause analysis", "Seams and ownership", "How correlation works". Never
starts with a verb.

Shape: a one-paragraph definition, then `## How it works`, then the honest
limits, then `## Related`. Keep it under 800 words; if it grows past that, the
task it supports is probably missing.

### 3.3 Reference page (`page_type: reference`)

Tables and lists a reader looks things up in: routes, flags, ports, metrics,
alert rules, the glossary. No narrative. Sorted deterministically. Where a
reference page is generated from source, it carries a generation banner and is
never hand-edited.

### 3.4 Section index (`page_type: index`)

One short paragraph naming what the section covers and who it is for, then a
table of the pages in it with one line each. No cards, no icons, no hero.

### 3.5 Release notes (`page_type: release`)

See §6.

---

## 4. Information architecture

Nine sections, in the order the reader meets them. The sidebar is defined
explicitly in `sidebars.js` so a page's place in the IA is independent of its
file path — existing URLs stay valid when a page moves in the navigation.

| # | Section | Answers |
|---|---|---|
| 1 | **Get started** | What is this, what do the words mean, and how do I see it working? |
| 2 | **Deploy** | How do I install, size, secure, verify and upgrade it? |
| 3 | **Operate** | How do I get data in and keep it flowing: devices, telemetry, monitors, alerts, incidents, dashboards? |
| 4 | **Investigate** | Why did this break? RCA, the troubleshooting workspace, protocol diagnostics, Iris. |
| 5 | **Security** | Continuous threat and exposure management: findings, exposures, compliance, detection rules, configuration backup and drift, packet capture. |
| 6 | **BGP operations** | The routing observatory: watchlist, RPKI, geofeed, AS paths, live feed, BMP, alerting, bogons. |
| 7 | **Administration** | Users, roles, tenants, authentication, API access, audit, data collection administration. |
| 8 | **Reference** | Lookup tables: API, feature flags, alert rules, ports, metrics, glossary. |
| 9 | **Release notes** | What changed, by month. |

Placement rules:

- A page belongs to the section matching the reader's **question**, not the
  code's module.
- A feature that is configured in Administration but used in Operate gets a task
  page in each, not one page in the middle.
- Nothing is filed under a section named for an internal programme or a project
  number.

---

## 5. Elements

**Admonitions.** Four types, used sparingly. More than one per screen means the
body text is not carrying its weight.

| Type | Use for |
|---|---|
| `:::note` | A fact the reader needs at this point and would not guess. |
| `:::tip` | A faster path that is not required. |
| `:::caution` | An action that costs time or data to undo. |
| `:::danger` | An action that destroys data or exposes it. |

Never use an admonition for a step. A step goes in the numbered list.

**Captured output.** Every request, response, command and file excerpt in this
portal is real, taken from a running deployment or from the checked-in source.
Nothing is invented. Show the request and the response together:

````markdown
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/protocols/isis/summary
```

```json
{"coverage":{"events":true,"live_series":true}, …}
```
````

Redact anything that looks like a secret. Tokens are always `$TOKEN`. Lab
addresses (RFC 1918, 198.18/15) and lab device names stay as captured, because a
sanitised example teaches less.

**Sample data.** Both Fortinet and CrowdStrike publish a rule for this, and so
do we. Examples use documentation-reserved values only: RFC 1918 space
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), RFC 5737 (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 (`2001:db8::/32`), RFC 2606
(`example.com`, `example.net`), and private AS numbers (64512–65534). People are
`jdoe@example.com`. Companies are Acme. The exceptions are values whose real
identity is the point — a public prefix in an RPKI example, a public resolver in
a path trace — and captures taken from the validation lab, which is RFC 1918
throughout. Never publish a customer address, a real credential, or a real
tenant's data.

**Screenshot alt text** is a full descriptive sentence saying what the screen
shows, not a label. A reader on a screen reader, and a reader whose image did
not load, both need the content.

**Tables** for anything with more than three parallel facts. Header row states
the fact, not the field name: "What it does", not "description".

**Bold** for UI labels only. `Code` for identifiers, paths, values, env vars,
and API routes. No italics for emphasis.

**Links.** Root-relative, no file extension: `/deploy/install-linux`. Every link
text says what the reader gets — never "click here", never a bare URL.

---

## 6. Release notes

One page per month, newest first, plus a "What's new" index. Each month uses
this shape, and only the headings that have entries:

```markdown
## New features
### Configuration backup and drift
What it does, in two sentences. Where it appears. The flag that controls it.

## Changes
## Fixed
## Known limitations
```

Rules: date format is `2026-09-03` (ISO, unambiguous). Every entry names the
surface it appears on. An entry that shipped behind a flag says the flag and its
default. A feature the reader cannot see yet does not get an entry.

---

## 7. Terminology

One word per concept, everywhere. The left column is the only correct form.

| Use | Not | Note |
|---|---|---|
| Correlix | the platform, the system, the tool | The product name. |
| Iris | the copilot, the AI, the assistant, the chatbot | The assistant is named Iris. |
| device | node, asset, box, element | An entry in the inventory. |
| interface | port, link | "Port" only for a TCP/UDP port number. |
| RCA case | incident story, correlation object, cluster | The object an operator opens. |
| incident | event group, alert group | The operational thing that is happening. |
| alert | alarm, notification | A rule fired. A *notification* is its delivery. |
| finding | vulnerability, issue | A security verdict about an asset. |
| seam | boundary, demarc, handoff point | An ownership transition. "Boundary" is reserved for spine zones. |
| tenant | workspace, customer, account | The isolation unit. |
| organization | org group, parent tenant | A set of tenants. |
| operator | user, NOC guy, engineer | The person using Correlix. |
| collector | poller, agent, probe | The thing that gathers telemetry. |
| the console | the UI, the dashboard, the web app | "Dashboard" means one board. |

Never write "the NOC" as the owner of a fault. Correlix names the seam and the
party that owns it. A verdict is phrased as what the evidence supports —
"possibly because of X" is an honest verdict and is written that way.

Capitalisation: sentence case for headings and titles. Product surface names are
capitalised as the console shows them (**Command Center**, **Action Queue**,
**Exposure Stories**).

---

## 8. Checks before you open a change

```bash
cd docs-portal
npm test          # voice, structure, front matter, internal links
npm run build     # Docusaurus; onBrokenLinks is 'throw'
cd .. && scripts/sync-docs-corpus.sh   # mirror the pages into the Iris corpus
```

The third step is mandatory. `src/backend/ai/docs_corpus/` is a byte-for-byte
mirror of these pages, compiled into the backend so Iris can cite them, and
`src/backend/ai/docs_corpus_drift_test.go` fails the build when the mirror and
the portal disagree.
